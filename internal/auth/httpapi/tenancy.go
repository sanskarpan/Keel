// Tenant resolution bridges identity sessions into the tenancy mechanism.
// A bearer session with an explicitly switched active org resolves to the
// tenant id that trusted service code passes to tenancy.WithTenantTx.
// Sessions without an active org, revoked sessions and expired sessions do
// not resolve: callers treat that as unauthenticated, never as a default
// tenant. Identity itself stays pre-tenant; this helper is the single point
// where a verified session becomes a tenant context.
package httpapi

import (
	"net/http"

	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

// TenantForRequest resolves the calling session's active organization.
func (h *Handler) TenantForRequest(r *http.Request) (tenancy.TenantID, bool) {
	token := bearerToken(r)
	if token == "" {
		return "", false
	}
	session, err := h.repo.SessionForToken(r.Context(), token, h.pepper)
	if err != nil || !session.Valid(h.now()) || session.OrgID == "" {
		return "", false
	}
	tenant, err := tenancy.ParseTenantID(session.OrgID)
	if err != nil {
		return "", false
	}
	return tenant, true
}
