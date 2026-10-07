// Package langfuse exports a deliberately small, content-free trace contract.
// It does not read from or decrypt the context vault.
package langfuse

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/sanskarpan/keel/internal/platform/tracecontext"
)

const (
	SchemaVersion = 1
	maxQueueSize  = 4096
	maxPayload    = 16 * 1024
	maxLatency    = 24 * time.Hour
	maxRetries    = 10
	endpointPath  = "/api/public/otel/v1/traces"
)

var (
	ErrDisabled       = errors.New("langfuse export is disabled")
	ErrClosed         = errors.New("langfuse exporter is closed")
	ErrInvalidEvent   = errors.New("invalid langfuse event")
	ErrQueueSaturated = errors.New("langfuse queue is full")
)

type Operation string

type Provider string

type ModelClass string

type Outcome string

const (
	OperationChat      Operation = "chat"
	OperationEmbedding Operation = "embedding"
	OperationRerank    Operation = "rerank"

	ProviderOpenAI    Provider = "openai"
	ProviderAnthropic Provider = "anthropic"
	ProviderGoogle    Provider = "google"
	ProviderLocal     Provider = "local"

	ModelSmall    ModelClass = "small"
	ModelStandard ModelClass = "standard"
	ModelLarge    ModelClass = "large"

	OutcomeSuccess  Outcome = "success"
	OutcomeError    Outcome = "error"
	OutcomeTimeout  Outcome = "timeout"
	OutcomeCanceled Outcome = "canceled"
)

// Event is the entire accepted telemetry contract. Schema version 1 is immutable;
// any contract change requires a new version. It intentionally has no attribute
// map, input/output field, tenant/customer ID, or tool payload. VaultRef must be
// a random opaque reference, never a tenant, user, or business identifier.
type Event struct {
	Operation   Operation
	Provider    Provider
	Model       ModelClass
	Outcome     Outcome
	Latency     time.Duration
	Retries     int
	VaultRef    string // Optional opaque UUID; never resolved by this package.
	Traceparent string // Optional validated W3C traceparent for correlation.
}

type Config struct {
	Enabled      bool
	Endpoint     string // Exact OTLP/HTTP traces endpoint path.
	PublicKey    string
	SecretKey    string
	AllowedHosts []string
	QueueSize    int
	Timeout      time.Duration
	TLSRoots     *x509.CertPool // Optional additional trust roots for self-hosted Langfuse.
}

type Stats struct {
	Accepted uint64
	Exported uint64
	Failed   uint64
	Dropped  uint64
}

type Exporter struct {
	queue  chan span
	done   chan struct{}
	stop   chan struct{}
	cfg    Config
	url    *url.URL
	client *http.Client

	closeOnce sync.Once
	stopOnce  sync.Once
	mu        sync.Mutex
	ctx       context.Context
	cancel    context.CancelFunc
	closed    atomic.Bool
	accepted  atomic.Uint64
	exported  atomic.Uint64
	failed    atomic.Uint64
	dropped   atomic.Uint64
}

type span struct {
	TraceID      string      `json:"traceId"`
	SpanID       string      `json:"spanId"`
	ParentSpanID string      `json:"parentSpanId,omitempty"`
	Flags        uint32      `json:"flags"`
	Name         string      `json:"name"`
	Kind         int         `json:"kind"`
	StartTime    string      `json:"startTimeUnixNano"`
	EndTime      string      `json:"endTimeUnixNano"`
	Attributes   []attribute `json:"attributes"`
	Status       spanStatus  `json:"status"`
}
type spanStatus struct {
	Code int `json:"code"`
}
type attribute struct {
	Key   string `json:"key"`
	Value value  `json:"value"`
}
type value struct {
	String *string `json:"stringValue,omitempty"`
	Int    *string `json:"intValue,omitempty"`
}
type scopeSpans struct {
	Scope struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"scope"`
	Spans []span `json:"spans"`
}
type resourceSpans struct {
	Resource struct {
		Attributes []attribute `json:"attributes"`
	} `json:"resource"`
	ScopeSpans []scopeSpans `json:"scopeSpans"`
}
type requestBody struct {
	ResourceSpans []resourceSpans `json:"resourceSpans"`
}

// New returns a disabled no-op adapter unless explicitly enabled. Enabled
// instances require an HTTPS endpoint whose hostname appears in AllowedHosts.
func New(cfg Config) (*Exporter, error) {
	if !cfg.Enabled {
		return nil, ErrDisabled
	}
	if cfg.QueueSize < 1 || cfg.QueueSize > maxQueueSize {
		return nil, fmt.Errorf("%w: queue size", ErrInvalidEvent)
	}
	if cfg.Timeout <= 0 || cfg.Timeout > time.Minute {
		return nil, fmt.Errorf("%w: timeout", ErrInvalidEvent)
	}
	if cfg.PublicKey == "" || cfg.SecretKey == "" || len(cfg.PublicKey) > 256 || len(cfg.SecretKey) > 256 || strings.ContainsAny(cfg.PublicKey+cfg.SecretKey, "\r\n") {
		return nil, fmt.Errorf("%w: credentials", ErrInvalidEvent)
	}
	parsed, err := url.Parse(cfg.Endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.Path != endpointPath || parsed.Hostname() == "" {
		return nil, fmt.Errorf("%w: endpoint must be an HTTPS Langfuse OTLP traces URL", ErrInvalidEvent)
	}
	allowed := false
	for _, host := range cfg.AllowedHosts {
		if strings.EqualFold(strings.TrimSpace(host), parsed.Hostname()) {
			allowed = true
			break
		}
	}
	if !allowed {
		return nil, fmt.Errorf("%w: endpoint host is not allowlisted", ErrInvalidEvent)
	}
	if len(cfg.AllowedHosts) == 0 {
		return nil, fmt.Errorf("%w: endpoint host allowlist is required", ErrInvalidEvent)
	}
	roots := cfg.TLSRoots
	if roots != nil {
		roots = roots.Clone()
	}
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots},
		TLSHandshakeTimeout:   cfg.Timeout,
		ResponseHeaderTimeout: cfg.Timeout,
		IdleConnTimeout:       30 * time.Second,
		MaxIdleConns:          2,
		MaxIdleConnsPerHost:   2,
		MaxConnsPerHost:       2,
	}
	client := &http.Client{Timeout: cfg.Timeout, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	ctx, cancel := context.WithCancel(context.Background())
	e := &Exporter{queue: make(chan span, cfg.QueueSize), done: make(chan struct{}), stop: make(chan struct{}), cfg: cfg, url: parsed, client: client, ctx: ctx, cancel: cancel}
	go e.run()
	return e, nil
}

// Enqueue validates the closed event schema and performs a non-blocking queue
// write. Saturation is counted and returned; it never delays business work.
func (e *Exporter) Enqueue(ctx context.Context, event Event) error {
	if e == nil {
		return ErrClosed
	}
	if ctx == nil || ctx.Err() != nil {
		return context.Canceled
	}
	if err := validate(event); err != nil {
		return err
	}
	created := time.Now().UTC()
	tid, err := randomHex(16)
	if err != nil {
		return ErrInvalidEvent
	}
	sid, err := randomHex(8)
	if err != nil {
		return ErrInvalidEvent
	}
	item := makeSpan(event, created, tid, sid)
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed.Load() {
		return ErrClosed
	}
	if ctx.Err() != nil {
		return context.Canceled
	}
	select {
	case <-e.stop:
		return ErrClosed
	case e.queue <- item:
		e.accepted.Add(1)
		return nil
	default:
		e.dropped.Add(1)
		return ErrQueueSaturated
	}
}

// Close drains queued spans within ctx's deadline. If it expires, the active
// HTTP request is canceled and unsent events are counted as dropped.
func (e *Exporter) Close(ctx context.Context) error {
	if e == nil {
		return nil
	}
	if ctx == nil {
		return context.Canceled
	}
	select {
	case <-e.done:
		return nil
	default:
	}
	e.closeOnce.Do(func() {
		e.mu.Lock()
		e.closed.Store(true)
		close(e.queue)
		e.mu.Unlock()
	})
	select {
	case <-e.done:
		return nil
	case <-ctx.Done():
		e.stopOnce.Do(func() { close(e.stop) })
		e.cancel()
		return ctx.Err()
	}
}

func (e *Exporter) Stats() Stats {
	if e == nil {
		return Stats{}
	}
	return Stats{Accepted: e.accepted.Load(), Exported: e.exported.Load(), Failed: e.failed.Load(), Dropped: e.dropped.Load()}
}

func (e *Exporter) run() {
	defer close(e.done)
	defer e.client.CloseIdleConnections()
	for item := range e.queue {
		select {
		case <-e.stop:
			e.dropped.Add(1)
			continue
		default:
		}
		ctx, cancel := context.WithTimeout(e.ctx, e.cfg.Timeout)
		err := e.send(ctx, item)
		cancel()
		if err != nil {
			e.failed.Add(1)
		} else {
			e.exported.Add(1)
		}
	}
}

func (e *Exporter) send(ctx context.Context, item span) error {
	body := otlp(item)
	encoded, err := json.Marshal(body)
	if err != nil || len(encoded) > maxPayload {
		return ErrInvalidEvent
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.url.String(), bytes.NewReader(encoded))
	if err != nil {
		return ErrInvalidEvent
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("x-langfuse-ingestion-version", "4")
	req.SetBasicAuth(e.cfg.PublicKey, e.cfg.SecretKey)
	resp, err := e.client.Do(req)
	if err != nil {
		return errors.New("langfuse request failed")
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return errors.New("langfuse returned non-success status")
	}
	return nil
}

func validate(e Event) error {
	if e.Operation != OperationChat && e.Operation != OperationEmbedding && e.Operation != OperationRerank {
		return ErrInvalidEvent
	}
	if e.Provider != ProviderOpenAI && e.Provider != ProviderAnthropic && e.Provider != ProviderGoogle && e.Provider != ProviderLocal {
		return ErrInvalidEvent
	}
	if e.Model != ModelSmall && e.Model != ModelStandard && e.Model != ModelLarge {
		return ErrInvalidEvent
	}
	if e.Outcome != OutcomeSuccess && e.Outcome != OutcomeError && e.Outcome != OutcomeTimeout && e.Outcome != OutcomeCanceled {
		return ErrInvalidEvent
	}
	if e.Latency < 0 || e.Latency > maxLatency || e.Retries < 0 || e.Retries > maxRetries {
		return ErrInvalidEvent
	}
	if e.Traceparent != "" {
		if _, ok := tracecontext.Parse(e.Traceparent); !ok {
			return ErrInvalidEvent
		}
	}
	if e.VaultRef != "" {
		id, err := uuid.Parse(e.VaultRef)
		if err != nil || id.String() != e.VaultRef {
			return ErrInvalidEvent
		}
	}
	return nil
}

func makeSpan(e Event, at time.Time, traceID, spanID string) span {
	parentSpanID := ""
	traceFlags := uint32(1)
	if e.Traceparent != "" {
		parent, _ := tracecontext.Parse(e.Traceparent) // validated by Enqueue before this call
		traceID, parentSpanID, traceFlags = parent.TraceID, parent.SpanID, uint32(parent.Flags)
	}
	attrs := []attribute{
		stringAttr("keel.telemetry.schema_version", fmt.Sprint(SchemaVersion)),
		stringAttr("keel.ai.operation", string(e.Operation)),
		stringAttr("gen_ai.operation.name", string(e.Operation)),
		stringAttr("gen_ai.provider.name", string(e.Provider)),
		stringAttr("keel.ai.model_class", string(e.Model)),
		stringAttr("keel.ai.outcome", string(e.Outcome)),
		intAttr("keel.ai.latency_ms", e.Latency.Milliseconds()),
		intAttr("keel.ai.retry_count", int64(e.Retries)),
		stringAttr("langfuse.observation.type", "generation"),
	}
	if e.VaultRef != "" {
		attrs = append(attrs, stringAttr("keel.context_vault.ref", e.VaultRef))
	}
	start := at
	end := at.Add(e.Latency)
	status := 1
	if e.Outcome == OutcomeError || e.Outcome == OutcomeTimeout {
		status = 2
	}
	return span{TraceID: traceID, SpanID: spanID, ParentSpanID: parentSpanID, Flags: traceFlags, Name: "keel.ai.operation", Kind: 3, StartTime: fmt.Sprint(start.UnixNano()), EndTime: fmt.Sprint(end.UnixNano()), Attributes: attrs, Status: spanStatus{Code: status}}
}

func otlp(s span) requestBody {
	var resource resourceSpans
	resource.Resource.Attributes = []attribute{stringAttr("service.name", "keel")}
	var scope scopeSpans
	scope.Scope.Name = "github.com/sanskarpan/keel/internal/ai/trace/langfuse"
	scope.Scope.Version = "1"
	scope.Spans = []span{s}
	resource.ScopeSpans = []scopeSpans{scope}
	return requestBody{ResourceSpans: []resourceSpans{resource}}
}

func stringAttr(k, v string) attribute { return attribute{Key: k, Value: value{String: &v}} }
func intAttr(k string, n int64) attribute {
	encoded := fmt.Sprint(n)
	return attribute{Key: k, Value: value{Int: &encoded}}
}
func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
