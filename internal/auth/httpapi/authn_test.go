package httpapi

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/sanskarpan/keel/internal/auth"
	"github.com/sanskarpan/keel/internal/auth/postgres"
)

func TestIdentifyPrefersSessions(t *testing.T) {
	principal, org := uuid.New(), uuid.New()
	now := time.Date(2026, time.November, 2, 12, 0, 0, 0, time.UTC)
	repo := &fakeRepo{
		session: auth.Session{
			SessionID: uuid.NewString(), PrincipalID: principal.String(),
			PrincipalState: auth.PrincipalActive, OrgID: org.String(),
			ExpiresAt: now.Add(time.Hour),
		},
		verifyOutcome:  "valid",
		verifyIdentity: postgres.APIKeyIdentity{KeyID: uuid.New(), ServicePrincipalID: uuid.New(), OrgID: uuid.New()},
	}
	h := newTestHandler(repo, &fakeSender{}, &fakeSender{})
	h.now = func() time.Time { return now }
	request := httptest.NewRequest("GET", "/", nil)
	request.Header.Set("Authorization", "Bearer session-token")
	identity, ok := h.Identify(request)
	if !ok || identity.Kind != IdentitySession || identity.PrincipalID != principal || identity.OrgID != org || string(identity.Tenant) != org.String() {
		t.Fatalf("session: %+v %v", identity, ok)
	}
	// Without an active org the session does not resolve, and the API-key
	// path is consulted next.
	repo.session.OrgID = ""
	identity, ok = h.Identify(request)
	if !ok || identity.Kind != IdentityAPIKey || identity.ServicePrincipalID != repo.verifyIdentity.ServicePrincipalID {
		t.Fatalf("apikey: %+v %v", identity, ok)
	}
	repo.verifyOutcome = "revoked"
	if _, ok := h.Identify(request); ok {
		t.Fatal("revoked key resolved")
	}
	repo.sessionErr = postgres.ErrNotFound
	repo.verifyErr = postgres.ErrNotFound
	if _, ok := h.Identify(request); ok {
		t.Fatal("unknown resolved")
	}
	if _, ok := h.Identify(httptest.NewRequest("GET", "/", nil)); ok {
		t.Fatal("bearerless resolved")
	}
}

func TestWhoamiServesBothKinds(t *testing.T) {
	principal, org := uuid.New(), uuid.New()
	now := time.Date(2026, time.November, 2, 12, 0, 0, 0, time.UTC)
	repo := &fakeRepo{
		session: auth.Session{
			SessionID: uuid.NewString(), PrincipalID: principal.String(),
			PrincipalState: auth.PrincipalActive, OrgID: org.String(),
			ExpiresAt: now.Add(time.Hour),
		},
	}
	h := newTestHandler(repo, &fakeSender{}, &fakeSender{})
	h.now = func() time.Time { return now }
	response := doRequest(h, "GET", "/v1/auth/whoami", nil, "session-token")
	if response.Code != 200 {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	for _, fragment := range []string{`"kind":"session"`, org.String(), principal.String()} {
		if !contains(response.Body.String(), fragment) {
			t.Fatalf("body=%s", response.Body.String())
		}
	}
	repo.sessionErr = postgres.ErrNotFound
	repo.verifyErr = postgres.ErrNotFound
	if response := doRequest(h, "GET", "/v1/auth/whoami", nil, "bad"); response.Code != 401 {
		t.Fatalf("bad: %d", response.Code)
	}
}
