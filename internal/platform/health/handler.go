// Package health provides low-cardinality health, build identity and Prometheus endpoints.
package health

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sanskarpan/keel/internal/platform/buildinfo"
)

type Probe func(context.Context) error

// MetricsExtension provides additional low-cardinality Prometheus metrics for
// a process role. Implementations must not include tenant, user, resource, or
// request identifiers in labels.
type MetricsExtension interface {
	PrometheusMetrics() string
}

type requestKey struct {
	route  string
	method string
	status int
}

type metrics struct {
	started  time.Time
	mu       sync.Mutex
	counts   map[requestKey]uint64
	duration map[requestKey]uint64
}

// Handler is the management HTTP surface. Startup remains false until the role has
// completed its initialization; NewHandler deliberately fails health gates closed.
type Handler struct {
	http.Handler
	startupComplete atomic.Bool
}

// NewHandler creates the management HTTP surface. Liveness is intentionally independent of
// dependencies; readiness runs bounded dependency checks and returns no failure details.
func NewHandler(info buildinfo.Info, probes ...Probe) *Handler {
	return NewHandlerWithMetrics(info, nil, probes...)
}

// NewHandlerWithMetrics creates the management HTTP surface and appends
// role-specific metrics to the process metrics endpoint.
func NewHandlerWithMetrics(info buildinfo.Info, extension MetricsExtension, probes ...Probe) *Handler {
	probes = append([]Probe(nil), probes...)
	m := &metrics{started: time.Now(), counts: make(map[requestKey]uint64), duration: make(map[requestKey]uint64)}
	h := &Handler{}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health/live", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /health/startup", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if !h.startupComplete.Load() {
			http.Error(w, "not started", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("started\n"))
	})
	mux.HandleFunc("GET /health/ready", func(w http.ResponseWriter, r *http.Request) {
		if len(probes) == 0 {
			w.Header().Set("Cache-Control", "no-store")
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		for _, probe := range probes {
			if probe == nil || probe(ctx) != nil {
				w.Header().Set("Cache-Control", "no-store")
				http.Error(w, "not ready", http.StatusServiceUnavailable)
				return
			}
		}
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready\n"))
	})
	mux.HandleFunc("GET /version", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(info)
	})
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		m.write(w, info)
		if extension != nil {
			if content := extension.PrometheusMetrics(); content != "" {
				if !strings.HasSuffix(content, "\n") {
					content += "\n"
				}
				_, _ = w.Write([]byte(content))
			}
		}
	})
	h.Handler = instrument(mux, m)
	return h
}

// MarkStartupComplete opens the startup endpoint after role initialization has succeeded.
func (h *Handler) MarkStartupComplete() {
	h.startupComplete.Store(true)
}

// ServeHTTP implements http.Handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.Handler.ServeHTTP(w, r)
}

// Run serves the management endpoints with bounded HTTP timeouts and graceful shutdown.
func Run(ctx context.Context, address string, info buildinfo.Info, probes ...Probe) error {
	return RunWithMetrics(ctx, address, info, nil, probes...)
}

// RunWithMetrics serves the management HTTP surface with role-specific metrics
// on the existing Prometheus endpoint.
func RunWithMetrics(ctx context.Context, address string, info buildinfo.Info, extension MetricsExtension, probes ...Probe) error {
	if ctx == nil {
		return fmt.Errorf("health server context is required")
	}
	if strings.TrimSpace(address) == "" {
		return fmt.Errorf("health server address is required")
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("listen for health endpoints: %w", err)
	}
	handler := NewHandlerWithMetrics(info, extension, probes...)
	handler.MarkStartupComplete()
	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	serveResult := make(chan error, 1)
	go func() { serveResult <- server.Serve(listener) }()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			_ = server.Close()
			return fmt.Errorf("shut down health server: %w", err)
		}
		return nil
	case err := <-serveResult:
		if err == http.ErrServerClosed {
			return nil
		}
		return fmt.Errorf("serve health endpoints: %w", err)
	}
}

func instrument(next http.Handler, m *metrics) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		recorder := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(recorder, r)
		status := recorder.status
		if status == 0 {
			status = http.StatusOK
		}
		key := requestKey{route: routeLabel(r.URL.Path), method: methodLabel(r.Method), status: status}
		m.mu.Lock()
		m.counts[key]++
		m.duration[key] += uint64(time.Since(started))
		m.mu.Unlock()
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(body []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(body)
}

func routeLabel(path string) string {
	switch path {
	case "/health/live", "/health/ready", "/health/startup", "/version", "/metrics":
		return path
	default:
		return "other"
	}
}

func methodLabel(method string) string {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodDelete:
		return method
	default:
		return "OTHER"
	}
}

func (m *metrics) write(w http.ResponseWriter, info buildinfo.Info) {
	m.mu.Lock()
	counts := make(map[requestKey]uint64, len(m.counts))
	durations := make(map[requestKey]uint64, len(m.duration))
	for key, count := range m.counts {
		counts[key] = count
	}
	for key, duration := range m.duration {
		durations[key] = duration
	}
	m.mu.Unlock()

	fmt.Fprintln(w, "# HELP keel_build_info Keel build identity.")
	fmt.Fprintln(w, "# TYPE keel_build_info gauge")
	fmt.Fprintf(w, "keel_build_info{version=%q,revision=%q,build_date=%q} 1\n", info.Version, info.Revision, info.BuildDate)
	fmt.Fprintln(w, "# HELP keel_process_uptime_seconds Process uptime in seconds.")
	fmt.Fprintln(w, "# TYPE keel_process_uptime_seconds gauge")
	fmt.Fprintf(w, "keel_process_uptime_seconds %s\n", strconv.FormatFloat(time.Since(m.started).Seconds(), 'f', 3, 64))
	fmt.Fprintln(w, "# HELP keel_process_goroutines Number of currently live Go goroutines.")
	fmt.Fprintln(w, "# TYPE keel_process_goroutines gauge")
	fmt.Fprintf(w, "keel_process_goroutines %d\n", runtime.NumGoroutine())
	fmt.Fprintln(w, "# HELP keel_http_requests_total HTTP responses by bounded route, method and status labels.")
	fmt.Fprintln(w, "# TYPE keel_http_requests_total counter")
	fmt.Fprintln(w, "# HELP keel_http_request_duration_seconds_sum Cumulative HTTP handler duration in seconds.")
	fmt.Fprintln(w, "# TYPE keel_http_request_duration_seconds_sum counter")
	keys := make([]requestKey, 0, len(counts))
	for key := range counts {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].route != keys[j].route {
			return keys[i].route < keys[j].route
		}
		if keys[i].method != keys[j].method {
			return keys[i].method < keys[j].method
		}
		return keys[i].status < keys[j].status
	})
	for _, key := range keys {
		fmt.Fprintf(w, "keel_http_requests_total{route=%q,method=%q,status=%q} %d\n", key.route, key.method, strconv.Itoa(key.status), counts[key])
		fmt.Fprintf(w, "keel_http_request_duration_seconds_sum{route=%q,method=%q,status=%q} %s\n", key.route, key.method, strconv.Itoa(key.status), strconv.FormatFloat(float64(durations[key])/float64(time.Second), 'f', 6, 64))
	}
}
