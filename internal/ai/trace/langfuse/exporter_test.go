package langfuse

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestNewIsDisabledByDefault(t *testing.T) {
	if e, err := New(Config{}); e != nil || !errors.Is(err, ErrDisabled) {
		t.Fatalf("New(Config{}) = (%v, %v), want nil, ErrDisabled", e, err)
	}
}

func TestExportIsAllowlistedAndContentFree(t *testing.T) {
	var got requestBody
	var authUser, authPass string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != endpointPath {
			t.Errorf("path = %q", r.URL.Path)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("content type = %q", r.Header.Get("Content-Type"))
		}
		if r.Header.Get("x-langfuse-ingestion-version") != "4" {
			t.Errorf("ingestion version = %q", r.Header.Get("x-langfuse-ingestion-version"))
		}
		authUser, authPass, _ = r.BasicAuth()
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		if len(body) > maxPayload {
			t.Errorf("body length %d exceeds limit", len(body))
		}
		if err := json.Unmarshal(body, &got); err != nil {
			t.Error(err)
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()
	e := newTestExporter(t, server, 2)
	defer closeExporter(t, e)
	ref := "80e0b8c3-4c8e-4f22-8f12-1458edca82c1"
	if err := e.Enqueue(context.Background(), Event{Operation: OperationChat, Provider: ProviderOpenAI, Model: ModelStandard, Outcome: OutcomeSuccess, Latency: 37 * time.Millisecond, Retries: 1, VaultRef: ref}); err != nil {
		t.Fatal(err)
	}
	closeExporter(t, e)
	if authUser != "pk-lf-test" || authPass != "sk-lf-test" {
		t.Fatalf("basic auth credentials did not match test fixture")
	}
	if len(got.ResourceSpans) != 1 || len(got.ResourceSpans[0].ScopeSpans) != 1 || len(got.ResourceSpans[0].ScopeSpans[0].Spans) != 1 {
		t.Fatalf("unexpected OTLP structure: %+v", got)
	}
	sp := got.ResourceSpans[0].ScopeSpans[0].Spans[0]
	if sp.TraceID == "" || sp.SpanID == "" || sp.Name != "keel.ai.operation" || sp.StartTime == "" || sp.EndTime == "" || sp.Flags != 1 {
		t.Fatalf("incomplete span: %+v", sp)
	}
	wantKeys := []string{"keel.telemetry.schema_version", "keel.ai.operation", "gen_ai.operation.name", "gen_ai.provider.name", "keel.ai.model_class", "keel.ai.outcome", "keel.ai.latency_ms", "keel.ai.retry_count", "langfuse.observation.type", "keel.context_vault.ref"}
	gotKeys := make([]string, 0, len(sp.Attributes))
	for _, attr := range sp.Attributes {
		gotKeys = append(gotKeys, attr.Key)
	}
	if !reflect.DeepEqual(gotKeys, wantKeys) {
		t.Fatalf("attribute keys = %v, want %v", gotKeys, wantKeys)
	}
	serialized, _ := json.Marshal(got)
	text := string(serialized)
	for _, forbidden := range []string{"prompt", "completion", "tool.arguments", "tool.result", "tenant_id", "customer_id", "input", "output", "sk-lf-test"} {
		if strings.Contains(text, forbidden) {
			t.Errorf("serialized telemetry contains forbidden value %q: %s", forbidden, text)
		}
	}
	if !strings.Contains(text, ref) {
		t.Errorf("opaque vault ref missing from payload: %s", text)
	}
	if !strings.Contains(text, `"intValue":"37"`) {
		t.Errorf("OTLP int64 must use JSON string encoding: %s", text)
	}
	if stats := e.Stats(); stats.Accepted != 1 || stats.Exported != 1 || stats.Failed != 0 {
		t.Fatalf("stats = %+v", stats)
	}
}

func TestValidatedTraceparentIsPreservedAsOTLPParent(t *testing.T) {
	var got requestBody
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &got); err != nil {
			t.Error(err)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	e := newTestExporter(t, server, 1)
	event := validEvent()
	event.Traceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
	if err := e.Enqueue(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	closeExporter(t, e)
	sp := got.ResourceSpans[0].ScopeSpans[0].Spans[0]
	if sp.TraceID != "4bf92f3577b34da6a3ce929d0e0e4736" || sp.ParentSpanID != "00f067aa0ba902b7" || sp.Flags != 1 {
		t.Fatalf("span correlation = %+v", sp)
	}
}

func TestValidationFailsClosed(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := (&Exporter{}).Enqueue(canceled, validEvent()); !errors.Is(err, context.Canceled) {
		t.Errorf("canceled context enqueue error = %v", err)
	}
	cases := []Event{
		{Operation: "user-input", Provider: ProviderOpenAI, Model: ModelSmall, Outcome: OutcomeSuccess},
		{Operation: OperationChat, Provider: "other", Model: ModelSmall, Outcome: OutcomeSuccess},
		{Operation: OperationChat, Provider: ProviderOpenAI, Model: "gpt-secret-model", Outcome: OutcomeSuccess},
		{Operation: OperationChat, Provider: ProviderOpenAI, Model: ModelSmall, Outcome: "raw error: private text"},
		{Operation: OperationChat, Provider: ProviderOpenAI, Model: ModelSmall, Outcome: OutcomeSuccess, Latency: -1},
		{Operation: OperationChat, Provider: ProviderOpenAI, Model: ModelSmall, Outcome: OutcomeSuccess, Retries: maxRetries + 1},
		{Operation: OperationChat, Provider: ProviderOpenAI, Model: ModelSmall, Outcome: OutcomeSuccess, VaultRef: "customer-42/prompt"},
		{Operation: OperationChat, Provider: ProviderOpenAI, Model: ModelSmall, Outcome: OutcomeSuccess, Traceparent: "00-00000000000000000000000000000000-00f067aa0ba902b7-01"},
	}
	for i, event := range cases {
		if err := validate(event); !errors.Is(err, ErrInvalidEvent) {
			t.Errorf("case %d: validate() = %v", i, err)
		}
	}
}

func TestConfigRejectsUnsafeEndpoints(t *testing.T) {
	for _, endpoint := range []string{
		"http://cloud.langfuse.com" + endpointPath,
		"https://user:pass@cloud.langfuse.com" + endpointPath,
		"https://cloud.langfuse.com/other",
		"https://not-allowed.example" + endpointPath,
		"https://cloud.langfuse.com" + endpointPath + "?redirect=https://evil.example",
	} {
		cfg := Config{Enabled: true, Endpoint: endpoint, PublicKey: "pk", SecretKey: "sk", AllowedHosts: []string{"cloud.langfuse.com"}, QueueSize: 1, Timeout: time.Second}
		if _, err := New(cfg); !errors.Is(err, ErrInvalidEvent) {
			t.Errorf("New(%q) error = %v", endpoint, err)
		}
	}
}

func TestQueueSaturationDropsInsteadOfBlocking(t *testing.T) {
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case started <- struct{}{}:
		default:
		}
		<-release
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	e := newTestExporter(t, server, 1)
	event := validEvent()
	if err := e.Enqueue(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("export request did not start")
	}
	if err := e.Enqueue(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if err := e.Enqueue(context.Background(), event); !errors.Is(err, ErrQueueSaturated) {
		t.Fatalf("saturated enqueue error = %v", err)
	}
	if time.Since(start) > 100*time.Millisecond {
		t.Fatal("saturated enqueue blocked")
	}
	close(release)
	closeExporter(t, e)
	if got := e.Stats().Dropped; got != 1 {
		t.Fatalf("dropped = %d, want 1", got)
	}
}

func TestExportTimeoutIsCountedWithoutReturningPayload(t *testing.T) {
	started := make(chan struct{}, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started <- struct{}{}
		select {
		case <-r.Context().Done():
		case <-time.After(150 * time.Millisecond):
		}
	}))
	defer server.Close()
	e := newTestExporter(t, server, 1, 40*time.Millisecond)
	if err := e.Enqueue(context.Background(), validEvent()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("export request did not start")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := e.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if got := e.Stats(); got.Failed != 1 || got.Exported != 0 {
		t.Fatalf("stats = %+v", got)
	}
}

func TestShutdownDeadlineCancelsActiveExportAndDropsQueue(t *testing.T) {
	started := make(chan struct{}, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case started <- struct{}{}:
		default:
		}
		select {
		case <-r.Context().Done():
		case <-time.After(250 * time.Millisecond):
		}
	}))
	defer server.Close()
	e := newTestExporter(t, server, 1)
	if err := e.Enqueue(context.Background(), validEvent()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("export request did not start")
	}
	if err := e.Enqueue(context.Background(), validEvent()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	if err := e.Close(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Close error = %v", err)
	}
	select {
	case <-e.done:
	case <-time.After(time.Second):
		t.Fatal("exporter did not stop after cancellation")
	}
	if got := e.Stats(); got.Failed != 1 || got.Dropped != 1 {
		t.Fatalf("stats = %+v", got)
	}
}

func TestHTTPFailureIsCountedWithoutReturningProviderBody(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("private upstream response"))
	}))
	defer server.Close()
	e := newTestExporter(t, server, 1)
	if err := e.Enqueue(context.Background(), validEvent()); err != nil {
		t.Fatal(err)
	}
	closeExporter(t, e)
	if got := e.Stats(); got.Failed != 1 || got.Exported != 0 {
		t.Fatalf("stats = %+v", got)
	}
}

func validEvent() Event {
	return Event{Operation: OperationChat, Provider: ProviderLocal, Model: ModelSmall, Outcome: OutcomeSuccess, Latency: time.Millisecond}
}

func newTestExporter(t *testing.T, server *httptest.Server, queue int, timeouts ...time.Duration) *Exporter {
	t.Helper()
	timeout := time.Second
	if len(timeouts) > 0 {
		timeout = timeouts[0]
	}
	cfg := Config{Enabled: true, Endpoint: server.URL + endpointPath, PublicKey: "pk-lf-test", SecretKey: "sk-lf-test", AllowedHosts: []string{"127.0.0.1"}, QueueSize: queue, Timeout: timeout, TLSRoots: testRoots(server)}
	e, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func testRoots(server *httptest.Server) *x509.CertPool {
	transport := server.Client().Transport.(*http.Transport)
	return transport.TLSClientConfig.RootCAs
}

func closeExporter(t *testing.T, e *Exporter) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := e.Close(ctx); err != nil {
		t.Fatal(err)
	}
}
