// Package observability provides privacy-safe HTTP correlation primitives.
package observability

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/sanskarpan/keel/internal/platform/logging"
)

type requestContextKey struct{}

// RequestContext carries server-generated correlation IDs and a validated inbound parent.
type RequestContext struct {
	RequestID     string
	TraceID       string
	SpanID        string
	ParentSpanID  string
	TraceFlags    uint8
}

// RequestContextFromContext returns the typed correlation values for a request.
func RequestContextFromContext(ctx context.Context) (RequestContext, bool) {
	value, ok := ctx.Value(requestContextKey{}).(RequestContext)
	return value, ok
}

// ParseTraceparent parses the supported W3C traceparent version 00 format.
func ParseTraceparent(value string) (traceID, parentSpanID string, flags uint8, ok bool) {
	if len(value) != 55 || value[2] != '-' || value[35] != '-' || value[52] != '-' || value[:2] != "00" {
		return "", "", 0, false
	}
	for _, char := range value {
		if char == '-' {
			continue
		}
		if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f')) {
			return "", "", 0, false
		}
	}
	traceID, parentSpanID = value[3:35], value[36:52]
	if allZero(traceID) || allZero(parentSpanID) {
		return "", "", 0, false
	}
	parsed, err := hex.DecodeString(value[53:55])
	if err != nil || len(parsed) != 1 {
		return "", "", 0, false
	}
	return traceID, parentSpanID, parsed[0], true
}

// HTTP assigns a request ID and a server span ID, stores validated correlation context,
// and logs only a route pattern and fixed safe attributes after the response completes.
func HTTP(logger *slog.Logger, next http.Handler) http.Handler {
	if logger == nil {
		logger = logging.NewJSON(os.Stderr, slog.LevelInfo)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID, err := newRequestID()
		if err != nil {
			http.Error(w, "request unavailable", http.StatusInternalServerError)
			return
		}
		correlation, err := newRequestContext(requestID, r.Header.Values("traceparent"))
		if err != nil {
			http.Error(w, "request unavailable", http.StatusInternalServerError)
			return
		}
		ctx := context.WithValue(r.Context(), requestContextKey{}, correlation)
		r = r.WithContext(ctx)
		w.Header().Set("X-Request-ID", correlation.RequestID)
		tracked := &statusResponseWriter{ResponseWriter: w}
		started := time.Now()
		next.ServeHTTP(tracked, r)
		status := tracked.status
		if status == 0 {
			status = http.StatusOK
		}
		operation := r.Pattern
		if operation == "" {
			operation = r.Method + " unmatched"
		}
		logger.InfoContext(ctx, "http request completed",
			"request_id", correlation.RequestID,
			"trace_id", correlation.TraceID,
			"operation", operation,
			"http_status", status,
			"duration_ms", time.Since(started).Milliseconds(),
		)
	})
}

func newRequestContext(requestID string, traceparents []string) (RequestContext, error) {
	traceID, parentSpanID := "", ""
	var flags uint8
	if len(traceparents) == 1 {
		traceID, parentSpanID, flags, _ = ParseTraceparent(traceparents[0])
	}
	if traceID == "" {
		var err error
		traceID, err = randomHex(16)
		if err != nil {
			return RequestContext{}, err
		}
		parentSpanID = ""
		flags = 0
	}
	spanID, err := randomHex(8)
	if err != nil {
		return RequestContext{}, err
	}
	return RequestContext{RequestID: requestID, TraceID: traceID, SpanID: spanID, ParentSpanID: parentSpanID, TraceFlags: flags}, nil
}

func newRequestID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	bytes[6] = bytes[6]&0x0f | 0x40
	bytes[8] = bytes[8]&0x3f | 0x80
	encoded := hex.EncodeToString(bytes)
	return encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:], nil
}

func randomHex(size int) (string, error) {
	for {
		bytes := make([]byte, size)
		if _, err := rand.Read(bytes); err != nil {
			return "", err
		}
		value := hex.EncodeToString(bytes)
		if !allZero(value) {
			return value, nil
		}
	}
}

func allZero(value string) bool {
	for _, char := range value {
		if char != '0' {
			return false
		}
	}
	return true
}

type statusResponseWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusResponseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *statusResponseWriter) WriteHeader(status int) {
	if status >= 100 && status < 200 && status != http.StatusSwitchingProtocols {
		w.ResponseWriter.WriteHeader(status)
		return
	}
	if w.status != 0 {
		return
	}
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusResponseWriter) Write(data []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(data)
}

func (w *statusResponseWriter) Flush() {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}
