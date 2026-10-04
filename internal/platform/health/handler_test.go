package health

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sanskarpan/keel/internal/platform/buildinfo"
)

func TestHealthVersionAndMetrics(t *testing.T) {
	ready := false
	handler := NewHandler(buildinfo.Info{Version: "1.2.3", Revision: "abc123", BuildDate: "2026-10-04T00:00:00Z"}, func(context.Context) error {
		if !ready {
			return errors.New("private dependency detail")
		}
		return nil
	})

	for _, test := range []struct {
		path       string
		statusCode int
		bodyPart   string
	}{
		{path: "/health/live", statusCode: http.StatusOK, bodyPart: "ok"},
		{path: "/health/startup", statusCode: http.StatusServiceUnavailable, bodyPart: "not started"},
		{path: "/health/ready", statusCode: http.StatusServiceUnavailable, bodyPart: "not ready"},
	} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, test.path, nil))
		if response.Code != test.statusCode || !strings.Contains(response.Body.String(), test.bodyPart) {
			t.Fatalf("%s: status=%d body=%q", test.path, response.Code, response.Body.String())
		}
		if strings.Contains(response.Body.String(), "private dependency detail") {
			t.Fatal("readiness response leaked dependency details")
		}
	}

	ready = true
	handler.MarkStartupComplete()
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/health/startup", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("startup status = %d, want 200 after initialization", response.Code)
	}
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/health/ready", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("healthy readiness status = %d, want 200", response.Code)
	}

	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/version", nil))
	for _, expected := range []string{"\"version\":\"1.2.3\"", "\"revision\":\"abc123\"", "\"build_date\":\"2026-10-04T00:00:00Z\""} {
		if !strings.Contains(response.Body.String(), expected) {
			t.Fatalf("version response %q missing %q", response.Body.String(), expected)
		}
	}

	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/customer/guessed/identifier", nil))
	if response.Code != http.StatusNotFound {
		t.Fatalf("unknown route status = %d, want 404", response.Code)
	}
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	metricsText := response.Body.String()
	if !strings.Contains(metricsText, "keel_process_uptime_seconds") || !strings.Contains(metricsText, "keel_http_requests_total") || !strings.Contains(metricsText, `route="other"`) {
		t.Fatalf("metrics missing runtime data or bounded other route: %s", metricsText)
	}
	if strings.Contains(metricsText, "guessed") || strings.Contains(metricsText, "private dependency detail") {
		t.Fatal("metrics leaked request path or dependency details")
	}
}

func TestReadinessFailsClosedWithoutProbes(t *testing.T) {
	handler := NewHandler(buildinfo.Info{})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/health/ready", nil))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("readiness without dependency probes returned %d, want 503", response.Code)
	}
}

func TestReadinessHonorsCanceledContext(t *testing.T) {
	handler := NewHandler(buildinfo.Info{}, func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/health/ready", nil).WithContext(ctx))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("canceled probe status = %d, want 503", response.Code)
	}
}
