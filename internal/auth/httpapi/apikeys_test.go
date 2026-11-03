package httpapi

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/sanskarpan/keel/internal/auth/postgres"
)

func newTokenRequest(token string) *http.Request {
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	return request
}

func TestCreateServicePrincipalMapsOutcomes(t *testing.T) {
	actor := uuid.New()
	orgID := uuid.New()
	for _, tc := range []struct {
		outcome string
		err     error
		status  int
		code    string
	}{
		{"created", nil, http.StatusCreated, ""},
		{"", postgres.ErrNotAuthorized, http.StatusForbidden, "forbidden"},
	} {
		repo := orgSessionRepo(actor)
		repo.createSPOutcome, repo.createSPErr = tc.outcome, tc.err
		h := newTestHandler(repo, &fakeSender{}, &fakeSender{})
		response := doRequest(h, http.MethodPost, "/v1/auth/service-principals",
			map[string]string{"org_id": orgID.String(), "name": "etl-worker"}, "token")
		if response.Code != tc.status {
			t.Fatalf("%s: status=%d body=%s", tc.outcome, response.Code, response.Body.String())
		}
		if tc.code != "" && problemCode(t, response) != tc.code {
			t.Fatalf("%s: body=%s", tc.outcome, response.Body.String())
		}
	}
	repo := orgSessionRepo(actor)
	h := newTestHandler(repo, &fakeSender{}, &fakeSender{})
	for _, body := range []any{
		map[string]string{"org_id": "not-a-uuid", "name": "etl"},
		map[string]string{"org_id": orgID.String(), "name": ""},
	} {
		if response := doRequest(h, http.MethodPost, "/v1/auth/service-principals", body, "token"); response.Code != http.StatusBadRequest {
			t.Fatalf("body=%v status=%d", body, response.Code)
		}
	}
}

func TestIssueAPIKeyMapsOutcomes(t *testing.T) {
	actor := uuid.New()
	spID := uuid.New()
	target := "/v1/auth/service-principals/" + spID.String() + "/keys"
	for _, tc := range []struct {
		wire   string
		err    error
		status int
		code   string
	}{
		{"keel_abcdefgh0123456789abcdefgh0123456789ab", nil, http.StatusCreated, ""},
		{"", postgres.ErrNotAuthorized, http.StatusForbidden, "forbidden"},
		{"", postgres.ErrNotFound, http.StatusNotFound, "not_found"},
	} {
		repo := orgSessionRepo(actor)
		repo.issueWire, repo.issueErr = tc.wire, tc.err
		h := newTestHandler(repo, &fakeSender{}, &fakeSender{})
		response := doRequest(h, http.MethodPost, target, map[string]any{}, "token")
		if response.Code != tc.status {
			t.Fatalf("%s: status=%d body=%s", tc.wire, response.Code, response.Body.String())
		}
		if tc.code != "" && problemCode(t, response) != tc.code {
			t.Fatalf("%s: body=%s", tc.wire, response.Body.String())
		}
	}
}

func TestRevokeAndDisableAPIKey(t *testing.T) {
	actor := uuid.New()
	spID := uuid.New()
	keyID := uuid.New()
	revokeTarget := "/v1/auth/service-principals/" + spID.String() + "/keys/" + keyID.String() + "/revoke"
	disableTarget := "/v1/auth/service-principals/" + spID.String() + "/disable"
	for _, tc := range []struct {
		name   string
		target string
		setup  func(r *fakeRepo)
		status int
		code   string
	}{
		{"revoked", revokeTarget, func(r *fakeRepo) { r.revokeKeyOutcome = "revoked" }, http.StatusNoContent, ""},
		{"revoke unknown", revokeTarget, func(r *fakeRepo) { r.revokeKeyErr = postgres.ErrNotFound }, http.StatusNotFound, "not_found"},
		{"revoke denied", revokeTarget, func(r *fakeRepo) { r.revokeKeyErr = postgres.ErrNotAuthorized }, http.StatusForbidden, "forbidden"},
		{"disabled", disableTarget, func(r *fakeRepo) { r.disableSPOutcome = "disabled" }, http.StatusNoContent, ""},
		{"disable unknown", disableTarget, func(r *fakeRepo) { r.disableSPErr = postgres.ErrNotFound }, http.StatusNotFound, "not_found"},
		{"disable denied", disableTarget, func(r *fakeRepo) { r.disableSPErr = postgres.ErrNotAuthorized }, http.StatusForbidden, "forbidden"},
	} {
		repo := orgSessionRepo(actor)
		tc.setup(repo)
		h := newTestHandler(repo, &fakeSender{}, &fakeSender{})
		response := doRequest(h, http.MethodPost, tc.target, nil, "token")
		if response.Code != tc.status {
			t.Fatalf("%s: status=%d body=%s", tc.name, response.Code, response.Body.String())
		}
		if tc.code != "" && problemCode(t, response) != tc.code {
			t.Fatalf("%s: body=%s", tc.name, response.Body.String())
		}
	}
}

func TestAPIKeyIdentityHelper(t *testing.T) {
	identity := postgres.APIKeyIdentity{
		KeyID: uuid.New(), ServicePrincipalID: uuid.New(), OrgID: uuid.New(),
	}
	repo := orgSessionRepo(uuid.New())
	repo.verifyOutcome, repo.verifyIdentity = "valid", identity
	h := newTestHandler(repo, &fakeSender{}, &fakeSender{})
	request := newTokenRequest("keel_abcdefgh0123456789abcdefgh0123456789ab")
	got, ok := h.apiKeyIdentity(request)
	if !ok || got != identity {
		t.Fatalf("valid: %+v %v", got, ok)
	}
	for _, tc := range []struct {
		name    string
		outcome string
	}{
		{"revoked", "revoked"},
		{"unknown", "unknown"},
		{"expired", "expired"},
	} {
		repo.verifyOutcome = tc.outcome
		if _, ok := h.apiKeyIdentity(newTokenRequest("keel_abcdefgh0123456789abcdefgh0123456789ab")); ok {
			t.Fatalf("%s accepted", tc.name)
		}
	}
	// Store errors fail closed too.
	repo.verifyOutcome, repo.verifyErr = "", errors.New("boom")
	if _, ok := h.apiKeyIdentity(newTokenRequest("keel_abcdefgh0123456789abcdefgh0123456789ab")); ok {
		t.Fatal("error accepted")
	}
	if _, ok := h.apiKeyIdentity(newTokenRequest("")); ok {
		t.Fatal("empty token accepted")
	}
}
