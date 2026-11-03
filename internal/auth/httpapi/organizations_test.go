package httpapi

import (
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/sanskarpan/keel/internal/auth"
	"github.com/sanskarpan/keel/internal/auth/postgres"
)

func orgSessionRepo(principal uuid.UUID) *fakeRepo {
	repo, _ := fakeSessionRepo(principal)
	return repo
}

func TestCreateOrganizationMapsOutcomes(t *testing.T) {
	principal := uuid.New()
	for _, tc := range []struct {
		outcome string
		err     error
		status  int
		code    string
	}{
		{"created", nil, http.StatusCreated, ""},
		{"already_bound", postgres.ErrConflict, http.StatusConflict, "already_bound"},
		{"slug_conflict", postgres.ErrConflict, http.StatusConflict, "slug_conflict"},
		{"not_active", postgres.ErrNotVerified, http.StatusForbidden, "forbidden"},
	} {
		repo := orgSessionRepo(principal)
		repo.createOrgOutcome, repo.createOrgErr = tc.outcome, tc.err
		h := newTestHandler(repo, &fakeSender{}, &fakeSender{})
		response := doRequest(h, http.MethodPost, "/v1/auth/organizations",
			map[string]string{"slug": "acme-corp", "display_name": "Acme", "region": "home"}, "token")
		if response.Code != tc.status {
			t.Fatalf("%s: status=%d body=%s", tc.outcome, response.Code, response.Body.String())
		}
		if tc.code != "" && problemCode(t, response) != tc.code {
			t.Fatalf("%s: body=%s", tc.outcome, response.Body.String())
		}
	}
	repo := orgSessionRepo(principal)
	repo.createOrgOutcome = "created"
	h := newTestHandler(repo, &fakeSender{}, &fakeSender{})
	for _, body := range []any{
		map[string]string{"slug": "Bad Slug!", "display_name": "Acme", "region": "home"},
		map[string]string{"slug": "acme", "display_name": "", "region": "home"},
		map[string]string{"slug": "acme", "display_name": "Acme", "region": "Home"},
		map[string]string{"slug": "acme", "display_name": "Acme", "region": "home", "extra": "no"},
	} {
		if response := doRequest(h, http.MethodPost, "/v1/auth/organizations", body, "token"); response.Code != http.StatusBadRequest {
			t.Fatalf("body=%v status=%d", body, response.Code)
		}
	}
	if response := doRequest(h, http.MethodPost, "/v1/auth/organizations",
		map[string]string{"slug": "acme", "display_name": "Acme", "region": "home"}, ""); response.Code != http.StatusUnauthorized {
		t.Fatalf("missing bearer: %d", response.Code)
	}
}

func TestAddOrganizationMemberMapsOutcomes(t *testing.T) {
	actor := uuid.New()
	member := uuid.New()
	orgID := uuid.New()
	target := "/v1/auth/organizations/" + orgID.String() + "/members"
	for _, tc := range []struct {
		name    string
		credErr error
		state   string
		outcome string
		err     error
		status  int
		code    string
	}{
		{"added", nil, auth.PrincipalActive, "added", nil, http.StatusCreated, ""},
		{"unknown", postgres.ErrNotFound, "", "", nil, http.StatusNotFound, "not_found"},
		{"inactive", nil, auth.PrincipalPending, "", nil, http.StatusUnprocessableEntity, "member_inactive"},
		{"forbidden", nil, auth.PrincipalActive, "not_authorized", postgres.ErrNotAuthorized, http.StatusForbidden, "forbidden"},
		{"conflict", nil, auth.PrincipalActive, "already_member", postgres.ErrConflict, http.StatusConflict, "already_member"},
		{"tenant", nil, auth.PrincipalActive, "tenant_conflict", postgres.ErrConflict, http.StatusConflict, "tenant_conflict"},
	} {
		repo := orgSessionRepo(actor)
		repo.credID, repo.credState, repo.credErr = member, tc.state, tc.credErr
		repo.addMemberOutcome, repo.addMemberErr = tc.outcome, tc.err
		h := newTestHandler(repo, &fakeSender{}, &fakeSender{})
		response := doRequest(h, http.MethodPost, target,
			map[string]string{"email": "member@example.test", "role": "member"}, "token")
		if response.Code != tc.status {
			t.Fatalf("%s: status=%d body=%s", tc.name, response.Code, response.Body.String())
		}
		if tc.code != "" && problemCode(t, response) != tc.code {
			t.Fatalf("%s: body=%s", tc.name, response.Body.String())
		}
		if tc.status == http.StatusCreated && (repo.addedActor != actor || repo.addedOrg != orgID || repo.addedMember != member || repo.addedRole != "member") {
			t.Fatalf("actor not threaded: %+v", repo)
		}
	}
	repo := orgSessionRepo(actor)
	h := newTestHandler(repo, &fakeSender{}, &fakeSender{})
	for _, body := range []any{
		map[string]string{"email": "member@example.test", "role": "owner"},
		map[string]string{"email": "not-an-email", "role": "member"},
		map[string]string{"email": "member@example.test", "role": "superadmin"},
	} {
		if response := doRequest(h, http.MethodPost, target, body, "token"); response.Code != http.StatusBadRequest {
			t.Fatalf("body=%v status=%d", body, response.Code)
		}
	}
	if response := doRequest(h, http.MethodPost, "/v1/auth/organizations/not-a-uuid/members",
		map[string]string{"email": "member@example.test", "role": "member"}, "token"); response.Code != http.StatusBadRequest {
		t.Fatalf("bad org id: %d", response.Code)
	}
}

func TestListOrganizations(t *testing.T) {
	principal := uuid.New()
	repo := orgSessionRepo(principal)
	orgID := uuid.New()
	repo.orgs = []postgres.Organization{{
		OrgID: orgID, Slug: "acme", DisplayName: "Acme",
		Region: "home", Role: auth.OrgRoleOwner,
	}}
	h := newTestHandler(repo, &fakeSender{}, &fakeSender{})
	response := doRequest(h, http.MethodGet, "/v1/auth/organizations", nil, "token")
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if got := response.Body.String(); !contains(got, orgID.String()) || !contains(got, "acme") {
		t.Fatalf("body=%s", got)
	}
	empty := orgSessionRepo(principal)
	h = newTestHandler(empty, &fakeSender{}, &fakeSender{})
	response = doRequest(h, http.MethodGet, "/v1/auth/organizations", nil, "token")
	if response.Code != http.StatusOK || !contains(response.Body.String(), "[]") {
		t.Fatalf("empty: %d %s", response.Code, response.Body.String())
	}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
