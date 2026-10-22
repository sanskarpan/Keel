package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sanskarpan/keel/internal/ai/budget"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

type stubReader struct {
	breakdown budget.CostBreakdown
	entries   []budget.CostEntry
	err       error
	tenant    tenancy.TenantID
	periodID  string
	limit     int
}

func (s *stubReader) CostBreakdown(_ context.Context, tenant tenancy.TenantID, periodID string) (budget.CostBreakdown, error) {
	s.tenant, s.periodID = tenant, periodID
	return s.breakdown, s.err
}

func (s *stubReader) CostEntries(_ context.Context, tenant tenancy.TenantID, periodID string, limit int) ([]budget.CostEntry, error) {
	s.tenant, s.periodID, s.limit = tenant, periodID, limit
	return s.entries, s.err
}

type stubAuthorizer struct {
	allowed bool
	err     error
}

func (s stubAuthorizer) CanReadCost(context.Context, Identity) (bool, error) {
	return s.allowed, s.err
}

func testIdentity() Identity {
	return Identity{TenantID: tenancy.TenantID("11111111-1111-4111-8111-111111111111"), PrincipalRef: "principal:cost-reader"}
}

func testHandler(t *testing.T, reader Reader, authorizer Authorizer) *Handler {
	t.Helper()
	handler, err := NewHandler(reader, authorizer)
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func serve(t *testing.T, handler *Handler, method, target string, identity *Identity) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, target, nil)
	if identity != nil {
		request = request.WithContext(WithIdentity(request.Context(), *identity))
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func TestCostHandlerRequiresIdentity(t *testing.T) {
	handler := testHandler(t, &stubReader{}, stubAuthorizer{allowed: true})
	recorder := serve(t, handler, http.MethodGet, "/v1/costs", nil)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated read returned %d", recorder.Code)
	}
}

func TestCostHandlerHidesDeniedCostView(t *testing.T) {
	handler := testHandler(t, &stubReader{}, stubAuthorizer{allowed: false})
	identity := testIdentity()
	recorder := serve(t, handler, http.MethodGet, "/v1/costs", &identity)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("denied cost read returned %d", recorder.Code)
	}
	if strings.Contains(recorder.Body.String(), "cost") && strings.Contains(recorder.Body.String(), "micro_usd") {
		t.Fatalf("a denied read leaked cost data: %s", recorder.Body.String())
	}
}

func TestCostHandlerFailsClosedWhenAuthorizationIsUnavailable(t *testing.T) {
	handler := testHandler(t, &stubReader{}, stubAuthorizer{err: errors.New("policy unavailable")})
	identity := testIdentity()
	recorder := serve(t, handler, http.MethodGet, "/v1/costs", &identity)
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("unavailable authorization returned %d", recorder.Code)
	}
}

func TestCostHandlerReturnsCurrentPeriodBreakdown(t *testing.T) {
	reader := &stubReader{breakdown: budget.CostBreakdown{
		PeriodID: "22222222-2222-4222-8222-222222222222", Scope: budget.CostScopeInference, Currency: "USD",
		PeriodStart: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), PeriodEnd: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC),
		HardLimitMicroUSD: 1_000, ConfirmedMicroUSD: 5, CarriedMicroUSD: 2, EstimatedMicroUSD: 6,
		UnknownMicroUSD: 14, OutstandingMicroUSD: 14,
		Watermark: budget.CostWatermark{AccountVersion: 4, Entries: 3, LastEntryAt: time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)},
	}}
	handler := testHandler(t, reader, stubAuthorizer{allowed: true})
	identity := testIdentity()
	recorder := serve(t, handler, http.MethodGet, "/v1/costs", &identity)
	if recorder.Code != http.StatusOK {
		t.Fatalf("cost read returned %d: %s", recorder.Code, recorder.Body.String())
	}
	if reader.tenant != identity.TenantID || reader.periodID != "" {
		t.Fatalf("the reader was not scoped to the authenticated tenant: %+v", reader)
	}
	var body map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"period_id", "confirmed_micro_usd", "carried_micro_usd", "estimated_micro_usd",
		"unknown_micro_usd", "outstanding_micro_usd", "hard_limit_micro_usd", "overrun_blocked", "watermark"} {
		if _, ok := body[field]; !ok {
			t.Fatalf("the cost response is missing %q: %s", field, recorder.Body.String())
		}
	}
	if recorder.Header().Get("Cache-Control") != "private, no-store" {
		t.Fatal("the cost response was cacheable")
	}
}

func TestCostHandlerRejectsInvalidPeriodAndLimit(t *testing.T) {
	handler := testHandler(t, &stubReader{}, stubAuthorizer{allowed: true})
	identity := testIdentity()
	if recorder := serve(t, handler, http.MethodGet, "/v1/costs/not-a-period", &identity); recorder.Code != http.StatusBadRequest {
		t.Fatalf("an invalid period returned %d", recorder.Code)
	}
	if recorder := serve(t, handler, http.MethodGet, "/v1/costs/22222222-2222-4222-8222-222222222222/entries?limit=0", &identity); recorder.Code != http.StatusBadRequest {
		t.Fatalf("an invalid limit returned %d", recorder.Code)
	}
	if recorder := serve(t, handler, http.MethodGet, "/v1/costs/22222222-2222-4222-8222-222222222222/entries?limit=1000", &identity); recorder.Code != http.StatusBadRequest {
		t.Fatalf("an unbounded limit returned %d", recorder.Code)
	}
	if recorder := serve(t, handler, http.MethodGet, "/v1/costs?scope=other", &identity); recorder.Code != http.StatusBadRequest {
		t.Fatalf("an unexpected query parameter returned %d", recorder.Code)
	}
}

func TestCostHandlerReturnsBoundedEntries(t *testing.T) {
	reader := &stubReader{entries: []budget.CostEntry{{
		InferenceID: "33333333-3333-4333-8333-333333333333", ConfirmedMicroUSD: 5,
		LiabilityState: "settled", LastActivityAt: time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC),
	}}}
	handler := testHandler(t, reader, stubAuthorizer{allowed: true})
	identity := testIdentity()
	recorder := serve(t, handler, http.MethodGet, "/v1/costs/22222222-2222-4222-8222-222222222222/entries?limit=10", &identity)
	if recorder.Code != http.StatusOK {
		t.Fatalf("cost entries returned %d: %s", recorder.Code, recorder.Body.String())
	}
	if reader.limit != 10 || reader.tenant != identity.TenantID {
		t.Fatalf("the entry read was not scoped and bounded: %+v", reader)
	}
	var body struct {
		PeriodID string `json:"period_id"`
		Entries  []struct {
			InferenceID    string `json:"inference_id"`
			LiabilityState string `json:"liability_state"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.PeriodID != "22222222-2222-4222-8222-222222222222" || len(body.Entries) != 1 {
		t.Fatalf("unexpected cost entries response: %s", recorder.Body.String())
	}
	if body.Entries[0].InferenceID != "33333333-3333-4333-8333-333333333333" || body.Entries[0].LiabilityState != "settled" {
		t.Fatalf("unexpected cost entry: %s", recorder.Body.String())
	}
}

func TestCostHandlerHidesMissingPeriod(t *testing.T) {
	handler := testHandler(t, &stubReader{err: budget.ErrCostUnavailable}, stubAuthorizer{allowed: true})
	identity := testIdentity()
	recorder := serve(t, handler, http.MethodGet, "/v1/costs/22222222-2222-4222-8222-222222222222", &identity)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("a missing period returned %d", recorder.Code)
	}
}

func TestCostHandlerRejectsUnsafeMethods(t *testing.T) {
	handler := testHandler(t, &stubReader{}, stubAuthorizer{allowed: true})
	identity := testIdentity()
	recorder := serve(t, handler, http.MethodPost, "/v1/costs", &identity)
	if recorder.Code != http.StatusMethodNotAllowed && recorder.Code != http.StatusNotFound {
		t.Fatalf("a write method returned %d", recorder.Code)
	}
}
