package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sanskarpan/keel/internal/platform/tenancy"
	"github.com/sanskarpan/keel/internal/supplier/cases"
	"github.com/sanskarpan/keel/internal/supplier/cases/postgres"
)

type staticPrincipal struct {
	principal Principal
	ok        bool
}

func (p staticPrincipal) Resolve(context.Context, *http.Request) (Principal, bool) {
	return p.principal, p.ok
}

type allowCaseActions struct{ publish, create, manage, submit bool }

func (a allowCaseActions) CanPublishReviewPolicy(context.Context, Principal) bool { return a.publish }
func (a allowCaseActions) CanCreateSupplierCase(context.Context, Principal, string, string) bool {
	return a.create
}
func (a allowCaseActions) CanManageSupplierCase(context.Context, Principal, string) bool {
	return a.manage
}
func (a allowCaseActions) CanSubmitSupplierCase(context.Context, Principal, string) bool {
	return a.submit
}

type fakeRepository struct {
	created      cases.Case
	createTenant tenancy.TenantID
	createKey    string
	actor        string
	policy       cases.Policy
	attached     bool
	submitted    bool
}

func (r *fakeRepository) PublishPolicy(_ context.Context, _ tenancy.TenantID, p cases.Policy, _ string) (cases.Policy, error) {
	r.policy = p
	p.Digest = strings.Repeat("a", 64)
	if p.PublishedAt.IsZero() {
		p.PublishedAt = time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC)
	}
	return p, nil
}
func (r *fakeRepository) Create(_ context.Context, t tenancy.TenantID, key, supplier, policy string, version uint32, actor string) (cases.Case, error) {
	r.createTenant = t
	r.createKey = key
	r.actor = actor
	r.created = cases.Case{TenantID: string(t), CaseID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", SupplierID: supplier, PolicyID: policy, PolicyVersion: version, Status: cases.Collecting, Version: 1, DeadlineAt: time.Date(2026, 10, 7, 0, 0, 0, 0, time.UTC)}
	return r.created, nil
}
func (r *fakeRepository) AttachEvidence(_ context.Context, t tenancy.TenantID, id, eid, slot, kind, upload, actor string) (cases.Case, error) {
	r.attached = true
	r.actor = actor
	return cases.Case{CaseID: id, SupplierID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", Status: cases.Collecting, Version: 2, PolicyID: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", PolicyVersion: 1}, nil
}
func (r *fakeRepository) Submit(_ context.Context, t tenancy.TenantID, id, actor string) (cases.Case, error) {
	r.submitted = true
	r.actor = actor
	return cases.Case{CaseID: id, Status: cases.Submitted, Version: 3}, nil
}
func (r *fakeRepository) Get(_ context.Context, _ tenancy.TenantID, id string) (postgres.CaseView, error) {
	return postgres.CaseView{Case: cases.Case{CaseID: id, Status: cases.Collecting, Version: 1}}, nil
}

func testHandler(t *testing.T, principal Principal, authenticated bool, authz allowCaseActions, repo *fakeRepository) *Handler {
	t.Helper()
	handler, err := New(repo, staticPrincipal{principal: principal, ok: authenticated}, authz, func() time.Time { return time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC) })
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func TestCreateCaseUsesAuthenticatedTenantAndHidesDeniedSupplier(t *testing.T) {
	tenant, _ := tenancy.ParseTenantID("11111111-1111-4111-8111-111111111111")
	repo := &fakeRepository{}
	h := testHandler(t, Principal{TenantID: tenant, ActorRef: "principal:buyer-1"}, true, allowCaseActions{create: true}, repo)
	request := httptest.NewRequest(http.MethodPost, "/v1/supplier-cases", strings.NewReader(`{"supplier_id":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb","policy_id":"cccccccc-cccc-4ccc-8ccc-cccccccccccc","policy_version":1}`))
	request.Header.Set("Idempotency-Key", "supplier-case-create-1")
	response := httptest.NewRecorder()
	h.ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", response.Code, response.Body.String())
	}
	if response.Header().Get("Cache-Control") != "no-store" || repo.createTenant != tenant || repo.actor != "principal:buyer-1" || repo.createKey != "supplier-case-create-1" {
		t.Fatal("case create did not use trusted tenant/actor or no-store headers")
	}
	var payload caseResponse
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if !uuid.MatchString(payload.CaseID) || payload.Status != cases.Collecting {
		t.Fatalf("invalid create response: %+v", payload)
	}

	repo = &fakeRepository{}
	h = testHandler(t, Principal{TenantID: tenant, ActorRef: "principal:buyer-1"}, true, allowCaseActions{}, repo)
	request = httptest.NewRequest(http.MethodPost, "/v1/supplier-cases", strings.NewReader(`{"supplier_id":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb","policy_id":"cccccccc-cccc-4ccc-8ccc-cccccccccccc","policy_version":1}`))
	request.Header.Set("Idempotency-Key", "supplier-case-create-1")
	response = httptest.NewRecorder()
	h.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("denied supplier status=%d", response.Code)
	}
}

func TestPolicyPublishingBoundsAndStrictJSON(t *testing.T) {
	tenant, _ := tenancy.ParseTenantID("11111111-1111-4111-8111-111111111111")
	repo := &fakeRepository{}
	h := testHandler(t, Principal{TenantID: tenant, ActorRef: "principal:policy-admin"}, true, allowCaseActions{publish: true}, repo)
	body := `{"policy_id":"cccccccc-cccc-4ccc-8ccc-cccccccccccc","version":1,"name":"Standard","deadline_seconds":259201,"required_evidence":[],"steps":[{"key":"risk","role":"risk:reviewer"}]}`
	request := httptest.NewRequest(http.MethodPost, "/v1/supplier-review-policies", strings.NewReader(body))
	response := httptest.NewRecorder()
	h.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("overlong deadline status=%d", response.Code)
	}
	body = `{"policy_id":"cccccccc-cccc-4ccc-8ccc-cccccccccccc","version":1,"name":"Standard","required_evidence":[],"steps":[{"key":"risk","role":"risk:reviewer"}],"tenant_id":"22222222-2222-4222-8222-222222222222"}`
	request = httptest.NewRequest(http.MethodPost, "/v1/supplier-review-policies", strings.NewReader(body))
	response = httptest.NewRecorder()
	h.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("unknown tenant input status=%d", response.Code)
	}
}

func TestSupplierCaseRoutesRequireIdentityAndScopedAuthorization(t *testing.T) {
	tenant, _ := tenancy.ParseTenantID("11111111-1111-4111-8111-111111111111")
	repo := &fakeRepository{}
	h := testHandler(t, Principal{}, false, allowCaseActions{manage: true, submit: true}, repo)
	request := httptest.NewRequest(http.MethodGet, "/v1/supplier-cases/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", nil)
	response := httptest.NewRecorder()
	h.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous read status=%d", response.Code)
	}
	var problem problemResponse
	if err := json.Unmarshal(response.Body.Bytes(), &problem); err != nil || problem.Code != "unauthenticated" || !uuid.MatchString(problem.RequestID) {
		t.Fatalf("invalid problem response %+v err=%v", problem, err)
	}

	h = testHandler(t, Principal{TenantID: tenant, ActorRef: "principal:buyer-1"}, true, allowCaseActions{}, repo)
	request = httptest.NewRequest(http.MethodPost, "/v1/supplier-cases/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa/evidence", strings.NewReader(`{"upload_id":"dddddddd-dddd-4ddd-8ddd-dddddddddddd","slot":"tax","kind":"tax"}`))
	response = httptest.NewRecorder()
	h.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound || repo.attached {
		t.Fatal("unauthorized caller reached evidence repository")
	}
}
