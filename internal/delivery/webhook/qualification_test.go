package webhook

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestQualificationReceiverFailureThenRecovery(t *testing.T) {
	var requests atomic.Int32
	executor, _, _ := newTestExecutor(t, func(response http.ResponseWriter, received *http.Request) {
		if requests.Add(1) == 1 {
			response.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		response.WriteHeader(http.StatusNoContent)
	})
	request := attemptFixture()

	first, err := executor.Execute(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if first.Outcome != OutcomeRetryable || first.HTTPStatus != http.StatusServiceUnavailable {
		t.Fatalf("failure result = %+v", first)
	}
	second, err := executor.Execute(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if second.Outcome != OutcomeDelivered || second.HTTPStatus != http.StatusNoContent {
		t.Fatalf("recovery result = %+v", second)
	}
	if requests.Load() != 2 {
		t.Fatalf("receiver requests = %d, want 2", requests.Load())
	}
}

func TestQualificationReplayAfterKeyRotationFailsClosed(t *testing.T) {
	var requests atomic.Int32
	executor, _, _ := newTestExecutor(t, func(response http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		response.WriteHeader(http.StatusNoContent)
	})
	request := attemptFixture()
	if result, err := executor.Execute(context.Background(), request); err != nil || result.Outcome != OutcomeDelivered {
		t.Fatalf("original result=%+v err=%v", result, err)
	}

	rotated, err := NewKeyring(Key{ID: "key_2027", Secret: []byte("abcdef0123456789abcdef0123456789")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	rotatedExecutor, err := NewExecutor(executor.egress, rotated)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rotatedExecutor.Execute(context.Background(), request); err != ErrInvalidKeyring {
		t.Fatalf("old key after rotation error = %v, want invalid keyring", err)
	}

	revision := request
	revision.Endpoint.SubscriptionVersion = 2
	revision.Endpoint.KeyID = "key_2027"
	revision.Delivery.Identity.SubscriptionVersion = 1
	if _, err := rotatedExecutor.Execute(context.Background(), revision); err != ErrInvalidEndpoint {
		t.Fatalf("old delivery under new revision error = %v, want invalid endpoint", err)
	}
	if requests.Load() != 1 {
		t.Fatalf("receiver requests = %d, want 1; a rejected replay sent", requests.Load())
	}
}

func TestQualificationReplayAfterDNSChangeFailsClosed(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		response.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)
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
	request := attemptFixture()
	if result, err := executor.Execute(context.Background(), request); err != nil || result.Outcome != OutcomeDelivered {
		t.Fatalf("original result=%+v err=%v", result, err)
	}

	resolver.answers["hooks.example.com"] = publicAnswer("10.0.0.7")
	transport.CloseIdleConnections()
	request.AttemptID = "attempt_0002"
	request.AttemptNumber = 2
	result, err := executor.Execute(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if result.Outcome != OutcomePermanent || result.HTTPStatus != 0 {
		t.Fatalf("rebound result = %+v, want permanent with no response", result)
	}
	if requests.Load() != 1 {
		t.Fatalf("receiver requests = %d, want 1; the rebound replay sent", requests.Load())
	}
}
