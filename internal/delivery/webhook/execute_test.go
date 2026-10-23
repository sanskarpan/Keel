package webhook

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

const testAttemptSecret = "0123456789abcdef0123456789abcdef"

func attemptFixture() AttemptRequest {
	tenant, err := tenancy.ParseTenantID("11111111-1111-1111-1111-111111111111")
	if err != nil {
		panic(err)
	}
	delivery := Delivery{
		ID: "delivery_0001",
		Identity: Identity{
			Tenant:              tenant,
			EventID:             "evt_00000001",
			EndpointID:          "endpoint_01",
			SubscriptionVersion: 1,
		},
	}
	return AttemptRequest{
		Delivery: delivery,
		Endpoint: Endpoint{
			Tenant:              tenant,
			ID:                  "endpoint_01",
			URL:                 "https://hooks.example.com/orders",
			KeyID:               "key_2026",
			SubscriptionVersion: 1,
			Status:              EndpointActive,
		},
		AttemptID:     "attempt_0001",
		AttemptNumber: 1,
		Body:          []byte(`{"event":"order.created","id":"evt_00000001"}`),
		Now:           time.Unix(1_700_000_000, 0).UTC(),
	}
}

func newTestExecutorForServer(t *testing.T, server *httptest.Server) (*Executor, *Keyring) {
	t.Helper()
	resolver := &fakeResolver{answers: map[string][]net.IPAddr{
		"hooks.example.com": publicAnswer("93.184.216.34"),
	}}
	egress := newTestEgress(t, EgressPolicy{Timeout: 5 * time.Second}, resolver)
	transport, ok := egress.client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("egress transport has an unexpected type")
	}
	transport.TLSClientConfig.InsecureSkipVerify = true
	address := server.Listener.Addr().String()
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	egress.dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, address)
	}
	keyring, err := NewKeyring(Key{ID: "key_2026", Secret: []byte(testAttemptSecret)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	executor, err := NewExecutor(egress, keyring)
	if err != nil {
		t.Fatal(err)
	}
	return executor, keyring
}

func newTestExecutor(t *testing.T, handler http.HandlerFunc) (*Executor, *Keyring, *httptest.Server) {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	executor, keyring := newTestExecutorForServer(t, server)
	return executor, keyring, server
}

func TestNewExecutorRequiresDependencies(t *testing.T) {
	egress := newTestEgress(t, EgressPolicy{}, nil)
	keyring, err := NewKeyring(Key{ID: "key_2026", Secret: []byte(testAttemptSecret)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewExecutor(nil, keyring); err == nil {
		t.Fatal("NewExecutor(nil egress) error = nil")
	}
	if _, err := NewExecutor(egress, nil); err == nil {
		t.Fatal("NewExecutor(nil keyring) error = nil")
	}
	if _, err := NewExecutor(egress, keyring); err != nil {
		t.Fatalf("NewExecutor() error = %v", err)
	}
}

func TestExecutorDeliversSignedAttempt(t *testing.T) {
	request := attemptFixture()
	var keyring *Keyring
	executor, keyring, _ := newTestExecutor(t, func(response http.ResponseWriter, received *http.Request) {
		body, err := io.ReadAll(received.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
		}
		if received.Method != http.MethodPost || received.URL.Path != "/orders" {
			t.Errorf("request = %s %s, want POST /orders", received.Method, received.URL.Path)
		}
		if received.Header.Get("Content-Type") != attemptContentType {
			t.Errorf("Content-Type = %q, want %q", received.Header.Get("Content-Type"), attemptContentType)
		}
		if received.Header.Get("User-Agent") != attemptUserAgent {
			t.Errorf("User-Agent = %q, want %q", received.Header.Get("User-Agent"), attemptUserAgent)
		}
		if received.Header.Get(HeaderEventID) != request.Delivery.Identity.EventID ||
			received.Header.Get(HeaderDeliveryID) != request.Delivery.ID ||
			received.Header.Get(HeaderAttemptID) != request.AttemptID {
			t.Errorf("identity headers = %v", received.Header)
		}
		signature, err := ParseSignature(received.Header.Get(HeaderSignature))
		if err != nil {
			t.Errorf("parse signature: %v", err)
		}
		if signature.KeyID != request.Endpoint.KeyID {
			t.Errorf("signature key = %q, want %q", signature.KeyID, request.Endpoint.KeyID)
		}
		if signature.Timestamp != request.Now.Unix() {
			t.Errorf("signature timestamp = %d, want %d", signature.Timestamp, request.Now.Unix())
		}
		if err := keyring.Verify(signature, body, request.Now); err != nil {
			t.Errorf("verify signature: %v", err)
		}
		if !bytes.Equal(body, request.Body) {
			t.Errorf("body = %q, want %q", body, request.Body)
		}
		response.WriteHeader(http.StatusNoContent)
	})
	result, err := executor.Execute(context.Background(), request)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if result.Outcome != OutcomeDelivered || result.HTTPStatus != http.StatusNoContent {
		t.Fatalf("Execute() result = %+v, want delivered/204", result)
	}
	if result.Latency < 0 {
		t.Fatalf("latency = %v", result.Latency)
	}
}

func TestExecutorClassifiesResponse(t *testing.T) {
	cases := map[int]Outcome{
		http.StatusOK:                  OutcomeDelivered,
		http.StatusAccepted:            OutcomeDelivered,
		http.StatusBadRequest:          OutcomePermanent,
		http.StatusNotFound:            OutcomePermanent,
		http.StatusRequestTimeout:      OutcomeRetryable,
		http.StatusTooEarly:            OutcomeRetryable,
		http.StatusTooManyRequests:     OutcomeRetryable,
		http.StatusInternalServerError: OutcomeRetryable,
		http.StatusServiceUnavailable:  OutcomeRetryable,
		http.StatusFound:               OutcomePermanent,
	}
	for status, want := range cases {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			executor, _, _ := newTestExecutor(t, func(response http.ResponseWriter, _ *http.Request) {
				if status == http.StatusFound {
					response.Header().Set("Location", "https://hooks.example.com/elsewhere")
				}
				response.WriteHeader(status)
			})
			result, err := executor.Execute(context.Background(), attemptFixture())
			if err != nil {
				t.Fatalf("Execute() error = %v", err)
			}
			if result.Outcome != want {
				t.Fatalf("status %d outcome = %s, want %s", status, result.Outcome, want)
			}
			if status == http.StatusFound {
				if result.HTTPStatus != 0 {
					t.Fatalf("redirect HTTP status = %d, want 0 (not followed)", result.HTTPStatus)
				}
				return
			}
			if result.HTTPStatus != status {
				t.Fatalf("HTTP status = %d, want %d", result.HTTPStatus, status)
			}
		})
	}
}

func TestExecutorClassifiesTransportFailure(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	executor, _ := newTestExecutorForServer(t, server)
	server.Close()

	result, err := executor.Execute(context.Background(), attemptFixture())
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if result.Outcome != OutcomeRetryable || result.HTTPStatus != 0 {
		t.Fatalf("transport result = %+v, want retryable with no status", result)
	}
}

func TestExecutorEgressDenialIsPermanent(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(server.Close)
	executor, _ := newTestExecutorForServer(t, server)
	egress := executor.egress
	egress.resolver = &fakeResolver{answers: map[string][]net.IPAddr{
		"hooks.example.com": publicAnswer("10.0.0.7"),
	}}

	result, err := executor.Execute(context.Background(), attemptFixture())
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if result.Outcome != OutcomePermanent || result.HTTPStatus != 0 {
		t.Fatalf("egress denial result = %+v, want permanent with no status", result)
	}
}

func TestExecutorRejectsInvalidAttempts(t *testing.T) {
	var requests atomic.Int32
	executor, _, _ := newTestExecutor(t, func(http.ResponseWriter, *http.Request) {
		requests.Add(1)
	})

	oversized := make([]byte, MaxAttemptBodyBytes+1)
	cases := map[string]struct {
		mutate  func(*AttemptRequest)
		wantErr error
	}{
		"endpoint tenant":       {mutate: func(r *AttemptRequest) { r.Endpoint.Tenant = "22222222-2222-2222-2222-222222222222" }, wantErr: ErrInvalidEndpoint},
		"endpoint id":           {mutate: func(r *AttemptRequest) { r.Endpoint.ID = "endpoint_02" }, wantErr: ErrInvalidEndpoint},
		"subscription revision": {mutate: func(r *AttemptRequest) { r.Endpoint.SubscriptionVersion = 2 }, wantErr: ErrInvalidEndpoint},
		"inactive endpoint":     {mutate: func(r *AttemptRequest) { r.Endpoint.Status = EndpointInactive }, wantErr: ErrInvalidEndpoint},
		"http url":              {mutate: func(r *AttemptRequest) { r.Endpoint.URL = "http://hooks.example.com/orders" }, wantErr: ErrInvalidEndpoint},
		"private url":           {mutate: func(r *AttemptRequest) { r.Endpoint.URL = "https://10.0.0.1/orders" }, wantErr: ErrInvalidEndpoint},
		"mismatched key":        {mutate: func(r *AttemptRequest) { r.Endpoint.KeyID = "key_2027" }, wantErr: ErrInvalidKeyring},
		"short attempt id":      {mutate: func(r *AttemptRequest) { r.AttemptID = "short" }, wantErr: ErrInvalidDelivery},
		"zero attempt number":   {mutate: func(r *AttemptRequest) { r.AttemptNumber = 0 }, wantErr: ErrInvalidAttempt},
		"attempt number cap":    {mutate: func(r *AttemptRequest) { r.AttemptNumber = MaxAttemptNumber + 1 }, wantErr: ErrInvalidAttempt},
		"empty body":            {mutate: func(r *AttemptRequest) { r.Body = nil }, wantErr: ErrInvalidDelivery},
		"oversized body":        {mutate: func(r *AttemptRequest) { r.Body = oversized }, wantErr: ErrInvalidDelivery},
		"zero timestamp":        {mutate: func(r *AttemptRequest) { r.Now = time.Time{} }, wantErr: ErrInvalidAttempt},
		"invalid delivery":      {mutate: func(r *AttemptRequest) { r.Delivery.Identity.EventID = "bad event" }, wantErr: ErrInvalidDelivery},
	}
	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			request := attemptFixture()
			testCase.mutate(&request)
			if _, err := executor.Execute(context.Background(), request); !errors.Is(err, testCase.wantErr) {
				t.Fatalf("Execute() error = %v, want %v", err, testCase.wantErr)
			}
		})
	}
	if count := requests.Load(); count != 0 {
		t.Fatalf("invalid attempts sent %d requests", count)
	}
	if _, err := executor.Execute(nil, attemptFixture()); err == nil {
		t.Fatal("Execute(nil context) error = nil")
	}
}
