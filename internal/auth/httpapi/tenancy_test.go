package httpapi

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/sanskarpan/keel/internal/auth"
	"github.com/sanskarpan/keel/internal/auth/postgres"
)

func TestTenantForRequest(t *testing.T) {
	principal := uuid.New()
	orgID := uuid.New()
	now := time.Date(2026, time.November, 2, 12, 0, 0, 0, time.UTC)
	active := auth.Session{
		SessionID: uuid.NewString(), PrincipalID: principal.String(),
		PrincipalState: auth.PrincipalActive,
		ExpiresAt:      now.Add(time.Hour), OrgID: orgID.String(),
	}
	for _, tc := range []struct {
		name    string
		session auth.Session
		err     error
		ok      bool
	}{
		{"active with org", active, nil, true},
		{"no org", func() auth.Session { s := active; s.OrgID = ""; return s }(), nil, false},
		{"revoked", func() auth.Session {
			s := active
			s.RevokedAt = now.Add(-time.Minute)
			return s
		}(), nil, false},
		{"expired", func() auth.Session {
			s := active
			s.ExpiresAt = now.Add(-time.Minute)
			return s
		}(), nil, false},
		{"unknown token", auth.Session{}, postgres.ErrNotFound, false},
	} {
		repo := orgSessionRepo(principal)
		repo.session, repo.sessionErr = tc.session, tc.err
		h := newTestHandler(repo, &fakeSender{}, &fakeSender{})
		h.now = func() time.Time { return now }
		request := httptest.NewRequest("GET", "/", nil)
		request.Header.Set("Authorization", "Bearer session-token")
		tenant, ok := h.TenantForRequest(request)
		if ok != tc.ok {
			t.Fatalf("%s: ok=%v", tc.name, ok)
		}
		if ok && string(tenant) != orgID.String() {
			t.Fatalf("%s: tenant=%s", tc.name, tenant)
		}
		if _, ok := h.TenantForRequest(httptest.NewRequest("GET", "/", nil)); ok {
			t.Fatalf("%s: missing bearer resolved", tc.name)
		}
	}
}
