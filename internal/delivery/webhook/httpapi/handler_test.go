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

type testAuthorizer struct{ allowed bool }

func (a testAuthorizer) CanReplayWebhooks(context.Context, Principal) bool { return a.allowed }

type testRepository struct {
	candidates    []webhookpostgres.ReplayCandidateRecord
	candidatesErr error
	authorization webhook.ReplayAuthorization
	authorizeErr  error
	request       webhook.ReplayRequest
}

func (r *testRepository) ReplayCandidates(context.Context, tenancy.TenantID, int) ([]webhookpostgres.ReplayCandidateRecord, error) {
	return r.candidates, r.candidatesErr
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
