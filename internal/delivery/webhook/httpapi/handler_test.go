package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sanskarpan/keel/internal/delivery/webhook"
	webhookpostgres "github.com/sanskarpan/keel/internal/delivery/webhook/postgres"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

type testPrincipal struct {
	principal Principal
	ok        bool
}

func (p testPrincipal) Resolve(context.Context, *http.Request) (Principal, bool) {
	return p.principal, p.ok
}

type testAuthorizer struct {
	allowed        bool
	policiesDenied bool
}

func (a testAuthorizer) CanReplayWebhooks(context.Context, Principal) bool { return a.allowed }

func (a testAuthorizer) CanManageWebhookPolicies(context.Context, Principal) bool {
	return a.allowed && !a.policiesDenied
}

type testRepository struct {
	candidates     []webhookpostgres.ReplayCandidateRecord
	candidatesErr  error
	authorization  webhook.ReplayAuthorization
	authorizeErr   error
	request        webhook.ReplayRequest
	runs           []webhook.ReconciliationRunSummary
	runsErr        error
	runsLimit      int
	endpointPolicy webhook.EndpointLimitPolicy
	endpointErr    error
	endpointChange webhook.EndpointLimitChange
	deliveryPolicy webhook.DeliveryBatchPolicy
	deliveryErr    error
	deliveryChange webhook.DeliveryBatchChange
}

func (r *testRepository) ReplayCandidates(context.Context, tenancy.TenantID, int) ([]webhookpostgres.ReplayCandidateRecord, error) {
	return r.candidates, r.candidatesErr
}

func (r *testRepository) ReconciliationRuns(_ context.Context, _ tenancy.TenantID, limit int) ([]webhook.ReconciliationRunSummary, error) {
	r.runsLimit = limit
	return r.runs, r.runsErr
}

func (r *testRepository) SetEndpointLimit(_ context.Context, change webhook.EndpointLimitChange) (webhook.EndpointLimitPolicy, error) {
	r.endpointChange = change
	return r.endpointPolicy, r.endpointErr
}

func (r *testRepository) SetDeliveryBatchLimit(_ context.Context, change webhook.DeliveryBatchChange) (webhook.DeliveryBatchPolicy, error) {
	r.deliveryChange = change
	return r.deliveryPolicy, r.deliveryErr
}

func (r *testRepository) AuthorizeReplay(_ context.Context, request webhook.ReplayRequest) (webhook.ReplayAuthorization, error) {
	r.request = request
	return r.authorization, r.authorizeErr
}

func testTenant(t *testing.T) tenancy.TenantID {
	t.Helper()
	tenant, err := tenancy.ParseTenantID("11111111-1111-4111-8111-111111111111")
	if err != nil {
		t.Fatal(err)
	}
	return tenant
}

func candidateRecord(t *testing.T, deliveryID, endpointID string, status webhook.EndpointStatus) webhookpostgres.ReplayCandidateRecord {
	t.Helper()
	return webhookpostgres.ReplayCandidateRecord{
		Delivery: webhook.Delivery{ID: deliveryID, Identity: webhook.Identity{
			Tenant: testTenant(t), EventID: "evt_00000001", EndpointID: endpointID,
			SubscriptionVersion: 1,
		}},
		State: webhook.StateFailed, Attempts: 2, EndpointStatus: status, KeyID: "key_2026",
	}
}

func newTestHandler(t *testing.T, repo *testRepository, allowed bool) *Handler {
	t.Helper()
	handler, err := New(repo, testPrincipal{principal: Principal{
		TenantID: testTenant(t), ActorRef: "operator@example.com",
	}, ok: true}, testAuthorizer{allowed: allowed}, func(key string) bool { return key == "key_2026" })
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func TestListCandidatesSelectsEligibleAndSkips(t *testing.T) {
	repo := &testRepository{candidates: []webhookpostgres.ReplayCandidateRecord{
		candidateRecord(t, "delivery_0001", "endpoint_01", webhook.EndpointActive),
		candidateRecord(t, "delivery_0002", "endpoint_02", webhook.EndpointInactive),
	}}
	response := httptest.NewRecorder()
	newTestHandler(t, repo, true).ServeHTTP(response,
		httptest.NewRequest(http.MethodGet, "/v1/webhooks/replay-candidates?limit=10", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", response.Code, response.Body)
	}
	var body candidateResponse
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Limit != 10 || len(body.Selected) != 1 || body.Selected[0].DeliveryID != "delivery_0001" {
		t.Fatalf("selected = %+v", body)
	}
	if len(body.Skipped) != 1 || body.Skipped[0].DeliveryID != "delivery_0002" || body.Skipped[0].Reason != string(webhook.ReplaySkipEndpointInactive) {
		t.Fatalf("skipped = %+v", body.Skipped)
	}
	if strings.Contains(response.Body.String(), "https://") || strings.Contains(response.Body.String(), "key_2026") {
		t.Fatalf("response leaked endpoint data: %s", response.Body)
	}
}

func TestListCandidatesFiltersByDeliveryID(t *testing.T) {
	repo := &testRepository{candidates: []webhookpostgres.ReplayCandidateRecord{
		candidateRecord(t, "delivery_0001", "endpoint_01", webhook.EndpointActive),
		candidateRecord(t, "delivery_0002", "endpoint_02", webhook.EndpointActive),
	}}
	response := httptest.NewRecorder()
	newTestHandler(t, repo, true).ServeHTTP(response,
		httptest.NewRequest(http.MethodGet, "/v1/webhooks/replay-candidates?limit=10&delivery_id=delivery_0002", nil))
	var body candidateResponse
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || len(body.Selected) != 1 || body.Selected[0].DeliveryID != "delivery_0002" {
		t.Fatalf("filtered body=%+v err=%v", body, err)
	}
}

func TestListCandidatesRequiresKeyReadiness(t *testing.T) {
	repo := &testRepository{candidates: []webhookpostgres.ReplayCandidateRecord{
		candidateRecord(t, "delivery_0001", "endpoint_01", webhook.EndpointActive),
	}}
	handler, err := New(repo, testPrincipal{principal: Principal{TenantID: testTenant(t), ActorRef: "operator@example.com"}, ok: true},
		testAuthorizer{allowed: true}, func(string) bool { return false })
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/webhooks/replay-candidates", nil))
	var body candidateResponse
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Selected) != 0 || len(body.Skipped) != 1 || body.Skipped[0].Reason != string(webhook.ReplaySkipSignatureUnavailable) {
		t.Fatalf("key readiness result = %+v", body)
	}
}

func TestListCandidatesRejectsBadRequests(t *testing.T) {
	repo := &testRepository{candidates: []webhookpostgres.ReplayCandidateRecord{
		candidateRecord(t, "delivery_0001", "endpoint_01", webhook.EndpointActive),
		candidateRecord(t, "delivery_0002", "endpoint_02", webhook.EndpointActive),
	}}
	handler := newTestHandler(t, repo, true)
	for _, path := range []string{
		"/v1/webhooks/replay-candidates?limit=0",
		"/v1/webhooks/replay-candidates?limit=501",
		"/v1/webhooks/replay-candidates?limit=2&limit=3",
		"/v1/webhooks/replay-candidates?other=1",
		"/v1/webhooks/replay-candidates?delivery_id=short",
	} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusBadRequest {
			t.Fatalf("%s status = %d", path, response.Code)
		}
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/webhooks/replay-candidates?limit=1", nil))
	if response.Code != http.StatusConflict {
		t.Fatalf("cap status = %d", response.Code)
	}
}

func TestListCandidatesAuthorizationAndAuthentication(t *testing.T) {
	repo := &testRepository{}
	response := httptest.NewRecorder()
	newTestHandler(t, repo, false).ServeHTTP(response,
		httptest.NewRequest(http.MethodGet, "/v1/webhooks/replay-candidates", nil))
	if response.Code != http.StatusForbidden {
		t.Fatalf("forbidden status = %d", response.Code)
	}
	handler, err := New(repo, testPrincipal{ok: false}, testAuthorizer{allowed: true}, func(string) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/webhooks/replay-candidates", nil))
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d", response.Code)
	}
}

func TestReplayAuthorizesWithTrustedPrincipal(t *testing.T) {
	repo := &testRepository{authorization: webhook.ReplayAuthorization{
		ReplayID: "replay_0001", DeliveryID: "delivery_0001", RequestedBy: "operator@example.com",
		Reason: "receiver requested a retry", PriorState: webhook.StateFailed, PriorAttempts: 2,
		PriorFinishedAt: time.Now(), RequestedAt: time.Now(), AuthorizedAt: time.Now(), Created: true,
	}}
	body := bytes.NewBufferString(`{"replay_id":"replay_0001","delivery_id":"delivery_0001","reason":"receiver requested a retry"}`)
	response := httptest.NewRecorder()
	newTestHandler(t, repo, true).ServeHTTP(response,
		httptest.NewRequest(http.MethodPost, "/v1/webhooks/replays", body))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", response.Code, response.Body)
	}
	if repo.request.Tenant != testTenant(t) || repo.request.RequestedBy != "operator@example.com" ||
		repo.request.ReplayID != "replay_0001" || repo.request.DeliveryID != "delivery_0001" {
		t.Fatalf("replay request = %+v", repo.request)
	}
	var result replayResponse
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.ReplayID != "replay_0001" || result.DeliveryID != "delivery_0001" || !result.Created {
		t.Fatalf("replay response = %+v", result)
	}
}

func TestReplayMapsDomainErrors(t *testing.T) {
	for _, test := range []struct {
		err    error
		status int
	}{
		{webhook.ErrReplayUnauthorized, http.StatusForbidden},
		{webhook.ErrReplayNotFound, http.StatusNotFound},
		{webhook.ErrReplayNotEligible, http.StatusConflict},
		{webhook.ErrReplayConflict, http.StatusConflict},
		{webhook.ErrInvalidReplay, http.StatusBadRequest},
		{errors.New("database detail"), http.StatusInternalServerError},
	} {
		repo := &testRepository{authorizeErr: test.err}
		body := bytes.NewBufferString(`{"replay_id":"replay_0001","delivery_id":"delivery_0001","reason":"retry"}`)
		response := httptest.NewRecorder()
		newTestHandler(t, repo, true).ServeHTTP(response,
			httptest.NewRequest(http.MethodPost, "/v1/webhooks/replays", body))
		if response.Code != test.status {
			t.Fatalf("%v status = %d, want %d", test.err, response.Code, test.status)
		}
		if strings.Contains(response.Body.String(), "database detail") {
			t.Fatal("error response leaked a database detail")
		}
	}
}

func TestListRunsReturnsSummaries(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	repo := &testRepository{runs: []webhook.ReconciliationRunSummary{
		{
			RunID: "rec_0123456789abcdef", RequestedBy: "operator@example.com",
			FromCreatedAt: now.Add(-time.Hour), CursorToCreatedAt: now.Add(-30 * time.Minute),
			CursorToEventID: "11111111-1111-4111-8111-111111111111",
			EventsScanned:   3, GapEvents: 1, MissingDeliveries: 2,
			RepairedDeliveries: 1, SkippedIdentities: 1, CreatedAt: now,
		},
		{
			RunID: "rec_fedcba9876543210", RequestedBy: "operator@example.com",
			FromCreatedAt: now.Add(-2 * time.Hour),
			EventsScanned: 0, CreatedAt: now.Add(-time.Hour),
		},
	}}
	response := httptest.NewRecorder()
	newTestHandler(t, repo, true).ServeHTTP(response,
		httptest.NewRequest(http.MethodGet, "/v1/webhooks/reconciliation-runs?limit=2", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", response.Code, response.Body)
	}
	if repo.runsLimit != 2 {
		t.Fatalf("runs limit = %d, want 2", repo.runsLimit)
	}
	var result runsResponse
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Limit != 2 || len(result.Runs) != 2 {
		t.Fatalf("runs response = %+v", result)
	}
	first := result.Runs[0]
	if first.RunID != "rec_0123456789abcdef" || first.GapEvents != 1 || first.MissingDeliveries != 2 ||
		first.RepairedDeliveries != 1 || first.SkippedIdentities != 1 ||
		first.CursorToEventID != "11111111-1111-4111-8111-111111111111" ||
		first.CursorToCreatedAt == nil || !first.CursorToCreatedAt.Equal(now.Add(-30*time.Minute)) {
		t.Fatalf("first run = %+v", first)
	}
	if result.Runs[1].CursorToEventID != "" || result.Runs[1].CursorToCreatedAt != nil {
		t.Fatalf("empty page run = %+v", result.Runs[1])
	}
}

func TestListRunsRejectsBadRequests(t *testing.T) {
	repo := &testRepository{runsErr: errors.New("database detail")}
	for _, test := range []struct {
		path   string
		status int
	}{
		{"/v1/webhooks/reconciliation-runs?limit=0", http.StatusBadRequest},
		{"/v1/webhooks/reconciliation-runs?limit=101", http.StatusBadRequest},
		{"/v1/webhooks/reconciliation-runs?limit=two", http.StatusBadRequest},
		{"/v1/webhooks/reconciliation-runs?unknown=1", http.StatusBadRequest},
		{"/v1/webhooks/reconciliation-runs", http.StatusInternalServerError},
	} {
		response := httptest.NewRecorder()
		newTestHandler(t, repo, true).ServeHTTP(response, httptest.NewRequest(http.MethodGet, test.path, nil))
		if response.Code != test.status {
			t.Fatalf("%s status = %d, want %d", test.path, response.Code, test.status)
		}
		if strings.Contains(response.Body.String(), "database detail") {
			t.Fatal("error response leaked a database detail")
		}
	}
	response := httptest.NewRecorder()
	newTestHandler(t, &testRepository{}, false).ServeHTTP(response,
		httptest.NewRequest(http.MethodGet, "/v1/webhooks/reconciliation-runs", nil))
	if response.Code != http.StatusForbidden {
		t.Fatalf("denied status = %d, want 403", response.Code)
	}
}

func TestSetEndpointLimitUsesTrustedPrincipal(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	repo := &testRepository{endpointPolicy: webhook.EndpointLimitPolicy{
		ChangeID: "pol_0123456789abcdef", Version: 2, ActiveEndpointLimit: 50, UpdatedAt: now,
	}}
	request := `{"change_id":"pol_0123456789abcdef","limit":50,"expected_version":1,"reason":"halve the tenant endpoint cap"}`
	response := httptest.NewRecorder()
	newTestHandler(t, repo, true).ServeHTTP(response,
		httptest.NewRequest(http.MethodPost, "/v1/webhooks/endpoint-limits", strings.NewReader(request)))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", response.Code, response.Body)
	}
	if repo.endpointChange.Tenant != testTenant(t) || repo.endpointChange.RequestedBy != "operator@example.com" ||
		repo.endpointChange.Limit != 50 || repo.endpointChange.ExpectedVersion != 1 {
		t.Fatalf("endpoint change = %+v", repo.endpointChange)
	}
	var result policyChangeResponse
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.ChangeID != "pol_0123456789abcdef" || result.Version != 2 || result.Limit != 50 || !result.UpdatedAt.Equal(now) {
		t.Fatalf("policy response = %+v", result)
	}
}

func TestSetDeliveryBatchLimitUsesTrustedPrincipal(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	repo := &testRepository{deliveryPolicy: webhook.DeliveryBatchPolicy{
		ChangeID: "pol_0123456789abcdef", Version: 1, BatchLimit: 2, UpdatedAt: now,
	}}
	request := `{"change_id":"pol_0123456789abcdef","limit":2,"expected_version":0,"reason":"throttle the tenant batch"}`
	response := httptest.NewRecorder()
	newTestHandler(t, repo, true).ServeHTTP(response,
		httptest.NewRequest(http.MethodPost, "/v1/webhooks/delivery-limits", strings.NewReader(request)))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", response.Code, response.Body)
	}
	if repo.deliveryChange.Tenant != testTenant(t) || repo.deliveryChange.Limit != 2 || repo.deliveryChange.ExpectedVersion != 0 {
		t.Fatalf("delivery change = %+v", repo.deliveryChange)
	}
}

func TestSetPolicyLimitsMapsErrors(t *testing.T) {
	for _, test := range []struct {
		path   string
		body   string
		err    error
		status int
	}{
		{"/v1/webhooks/endpoint-limits", `{"change_id":"pol_0123456789abcdef","limit":50,"expected_version":1,"reason":"ok"}`, webhook.ErrEndpointPolicyConflict, http.StatusConflict},
		{"/v1/webhooks/endpoint-limits", `{"change_id":"pol_0123456789abcdef","limit":50,"expected_version":1,"reason":"ok"}`, webhook.ErrInvalidEndpoint, http.StatusBadRequest},
		{"/v1/webhooks/endpoint-limits", `{"change_id":"pol_0123456789abcdef","limit":50,"expected_version":1,"reason":"ok"}`, errors.New("database detail"), http.StatusInternalServerError},
		{"/v1/webhooks/delivery-limits", `{"change_id":"pol_0123456789abcdef","limit":2,"expected_version":0,"reason":"ok"}`, webhook.ErrDeliveryPolicyConflict, http.StatusConflict},
		{"/v1/webhooks/delivery-limits", `{"change_id":"pol_0123456789abcdef","limit":2,"expected_version":0,"reason":"ok"}`, webhook.ErrInvalidEndpoint, http.StatusBadRequest},
		{"/v1/webhooks/endpoint-limits", `{}`, nil, http.StatusBadRequest},
		{"/v1/webhooks/endpoint-limits", `{"change_id":"short","limit":50,"expected_version":1,"reason":"ok"}`, nil, http.StatusBadRequest},
		{"/v1/webhooks/endpoint-limits", `{"change_id":"pol_0123456789abcdef","limit":0,"expected_version":1,"reason":"ok"}`, nil, http.StatusBadRequest},
		{"/v1/webhooks/delivery-limits", `{"change_id":"pol_0123456789abcdef","limit":101,"expected_version":0,"reason":"ok"}`, nil, http.StatusBadRequest},
		{"/v1/webhooks/delivery-limits", `{"change_id":"pol_0123456789abcdef","limit":2,"expected_version":0,"reason":"ok","tenant_id":"other"}`, nil, http.StatusBadRequest},
	} {
		repo := &testRepository{endpointErr: test.err, deliveryErr: test.err}
		response := httptest.NewRecorder()
		newTestHandler(t, repo, true).ServeHTTP(response,
			httptest.NewRequest(http.MethodPost, test.path, strings.NewReader(test.body)))
		if response.Code != test.status {
			t.Fatalf("%s %s status = %d, want %d", test.path, test.body, response.Code, test.status)
		}
		if strings.Contains(response.Body.String(), "database detail") {
			t.Fatal("error response leaked a database detail")
		}
	}
	response := httptest.NewRecorder()
	handler, err := New(&testRepository{}, testPrincipal{principal: Principal{
		TenantID: testTenant(t), ActorRef: "operator@example.com",
	}, ok: true}, testAuthorizer{allowed: true, policiesDenied: true}, func(string) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	handler.ServeHTTP(response,
		httptest.NewRequest(http.MethodPost, "/v1/webhooks/endpoint-limits", strings.NewReader(`{"change_id":"pol_0123456789abcdef","limit":50,"expected_version":1,"reason":"ok"}`)))
	if response.Code != http.StatusForbidden {
		t.Fatalf("denied policy status = %d, want 403", response.Code)
	}
}

func TestReplayRejectsMalformedBodies(t *testing.T) {
	repo := &testRepository{}
	for _, body := range []string{
		`{}`,
		`{"replay_id":"short","delivery_id":"delivery_0001","reason":"retry"}`,
		`{"replay_id":"replay_0001","delivery_id":"delivery_0001","reason":"retry","tenant_id":"other"}`,
		`{"replay_id":"replay_0001","delivery_id":"delivery_0001","reason":""}`,
		`{"replay_id":"replay_0001","delivery_id":"delivery_0001","reason":"retry"} {}`,
	} {
		response := httptest.NewRecorder()
		newTestHandler(t, repo, true).ServeHTTP(response,
			httptest.NewRequest(http.MethodPost, "/v1/webhooks/replays", strings.NewReader(body)))
		if response.Code != http.StatusBadRequest {
			t.Fatalf("body %s status = %d", body, response.Code)
		}
	}
}
