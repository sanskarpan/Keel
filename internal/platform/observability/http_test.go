package observability

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/sanskarpan/keel/internal/platform/logging"
)

const validTraceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"

func TestParseTraceparentAcceptsOnlySupportedNonzeroVersion00(t *testing.T) {
	traceID, parentSpanID, flags, ok := ParseTraceparent(validTraceparent)
	if !ok || traceID != "4bf92f3577b34da6a3ce929d0e0e4736" || parentSpanID != "00f067aa0ba902b7" || flags != 1 {
		t.Fatalf("valid traceparent parse=(%q,%q,%d,%v)", traceID, parentSpanID, flags, ok)
	}
	for _, invalid := range []string{
		"ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
		"00-00000000000000000000000000000000-00f067aa0ba902b7-01",
		"00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01",
		"00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01",
		"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-0g",
		"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7",
	} {
		if _, _, _, ok := ParseTraceparent(invalid); ok {
			t.Fatalf("invalid traceparent accepted: %q", invalid)
		}
	}
}

func TestHTTPAddsValidatedCorrelationAndLogsOnlyRoutePattern(t *testing.T) {
	var output bytes.Buffer
	logger := logging.NewJSON(&output, slog.LevelInfo)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /orders/{order_id}", func(w http.ResponseWriter, r *http.Request) {
		correlation, ok := RequestContextFromContext(r.Context())
		if !ok || correlation.RequestID == "" || correlation.TraceID != "4bf92f3577b34da6a3ce929d0e0e4736" || correlation.ParentSpanID != "00f067aa0ba902b7" || correlation.TraceFlags != 1 || correlation.SpanID == correlation.ParentSpanID {
			t.Errorf("request correlation context=%+v present=%v", correlation, ok)
		}
		w.WriteHeader(http.StatusAccepted)
	})
	request := httptest.NewRequest(http.MethodGet, "/orders/private-order?api_key=do-not-log", nil)
	request.Header.Set("traceparent", validTraceparent)
	request.Header.Set("X-Request-ID", "caller-supplied")
	response := httptest.NewRecorder()
	HTTP(logger, mux).ServeHTTP(response, request)

	requestID := response.Header().Get("X-Request-ID")
	if response.Code != http.StatusAccepted || requestID == "caller-supplied" || !regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`).MatchString(requestID) {
		t.Fatalf("response status/request ID invalid: status=%d request_id=%q", response.Code, requestID)
	}
	var record map[string]any
	if err := json.Unmarshal(output.Bytes(), &record); err != nil {
		t.Fatalf("completion log is not JSON: %v", err)
	}
	if record["request_id"] != requestID || record["trace_id"] != "4bf92f3577b34da6a3ce929d0e0e4736" || record["operation"] != "GET /orders/{order_id}" || record["http_status"] != float64(http.StatusAccepted) {
		t.Fatalf("completion log is missing correlation or route fields: %#v", record)
	}
	if strings.Contains(output.String(), "private-order") || strings.Contains(output.String(), "do-not-log") || strings.Contains(output.String(), "api_key") {
		t.Fatalf("completion log contains concrete path/query data: %s", output.String())
	}
}

func TestHTTPReplacesMalformedOrRepeatedTraceparentAndPreservesWriterControls(t *testing.T) {
	logger := logging.NewJSON(io.Discard, slog.LevelInfo)
	var observed []RequestContext
	handler := HTTP(logger, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		value, ok := RequestContextFromContext(r.Context())
		if !ok {
			t.Error("request context is missing correlation metadata")
		}
		observed = append(observed, value)
		controller := http.NewResponseController(w)
		if err := controller.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
			t.Errorf("middleware hid response deadline support: %v", err)
		}
		if err := controller.SetWriteDeadline(time.Time{}); err != nil {
			t.Errorf("middleware failed to clear response deadline: %v", err)
		}
		w.WriteHeader(http.StatusNoContent)
		if err := controller.Flush(); err != nil {
			t.Errorf("middleware hid response flushing support: %v", err)
		}
	}))

	for _, headers := range [][]string{{"not-a-traceparent"}, {validTraceparent, validTraceparent}} {
		request := httptest.NewRequest(http.MethodGet, "/health/ready", nil)
		for _, header := range headers {
			request.Header.Add("traceparent", header)
		}
		base := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
		handler.ServeHTTP(base, request)
		if base.Code != http.StatusNoContent || len(base.deadlines) != 2 {
			t.Fatalf("middleware did not preserve response writer controls: status=%d deadlines=%d", base.Code, len(base.deadlines))
		}
		if base.Header().Get("X-Request-ID") == "" {
			t.Fatal("request ID response header is missing")
		}
	}
	if len(observed) != 2 || observed[0].TraceID == observed[1].TraceID || observed[0].ParentSpanID != "" || observed[1].ParentSpanID != "" || observed[0].TraceFlags != 0 || observed[1].TraceFlags != 0 {
		t.Fatalf("malformed/repeated caller context was trusted or reused: %+v", observed)
	}
}

type deadlineRecorder struct {
	*httptest.ResponseRecorder
	deadlines []time.Time
}

func (w *deadlineRecorder) SetWriteDeadline(deadline time.Time) error {
	w.deadlines = append(w.deadlines, deadline)
	return nil
}
