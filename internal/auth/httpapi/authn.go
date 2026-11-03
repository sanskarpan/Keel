// Unified authentication: one bearer credential, session or API key,
// resolves to the same identity shape. Sessions win when both are present;
// an API key is accepted only with a valid digest-bound secret. The tenant
// is the session's active org or the key's owning org, parsed as a
// tenancy.TenantID for future WithTenantTx call sites. Anything else fails
// closed with no identity. This package stays unmounted; the helper is the
// composition point for a serving gateway.
package httpapi

import (
	"net/http"

	"github.com/google/uuid"

	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

// IdentityKind names the credential that authenticated a request.
type IdentityKind string

const (
	// IdentitySession authenticates a human principal through a session.
	IdentitySession IdentityKind = "session"
	// IdentityAPIKey authenticates a machine principal through a bearer key.
	IdentityAPIKey IdentityKind = "api_key"
)

// Identity is the verified caller: exactly one of PrincipalID or
// ServicePrincipalID is set, and OrgID/Tenant always agree.
type Identity struct {
	Kind               IdentityKind
	PrincipalID        uuid.UUID
	ServicePrincipalID uuid.UUID
	OrgID              uuid.UUID
	Tenant             tenancy.TenantID
}

// Identify resolves one bearer credential, preferring sessions. API keys
// authenticate only through a valid stored digest; revoked, expired and
// unknown keys fail closed without an identity.
func (h *Handler) Identify(r *http.Request) (Identity, bool) {
	token := bearerToken(r)
	if token == "" {
		return Identity{}, false
	}
	if session, err := h.repo.SessionForToken(r.Context(), token, h.pepper); err == nil && session.Valid(h.now()) && session.OrgID != "" {
		principalID, err := uuid.Parse(session.PrincipalID)
		if err != nil || principalID == uuid.Nil {
			return Identity{}, false
		}
		orgID, err := uuid.Parse(session.OrgID)
		if err != nil || orgID == uuid.Nil {
			return Identity{}, false
		}
		tenant, err := tenancy.ParseTenantID(session.OrgID)
		if err != nil {
			return Identity{}, false
		}
		return Identity{Kind: IdentitySession, PrincipalID: principalID, OrgID: orgID, Tenant: tenant}, true
	}
	outcome, key, err := h.repo.VerifyAPIKey(r.Context(), token)
	if err != nil || outcome != "valid" {
		return Identity{}, false
	}
	tenant, err := tenancy.ParseTenantID(key.OrgID.String())
	if err != nil {
		return Identity{}, false
	}
	return Identity{Kind: IdentityAPIKey, ServicePrincipalID: key.ServicePrincipalID, OrgID: key.OrgID, Tenant: tenant}, true
}

type whoamiResponse struct {
	Kind               string `json:"kind"`
	OrgID              string `json:"org_id"`
	TenantID           string `json:"tenant_id"`
	PrincipalID        string `json:"principal_id,omitempty"`
	ServicePrincipalID string `json:"service_principal_id,omitempty"`
}

// GET /v1/auth/whoami proves the unified chain: the same shape answers for
// a session and for an API key.
func (h *Handler) whoami(w http.ResponseWriter, r *http.Request) {
	identity, ok := h.Identify(r)
	if !ok {
		writeProblem(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	response := whoamiResponse{
		Kind: string(identity.Kind), OrgID: identity.OrgID.String(), TenantID: string(identity.Tenant),
	}
	if identity.Kind == IdentitySession {
		response.PrincipalID = identity.PrincipalID.String()
	} else {
		response.ServicePrincipalID = identity.ServicePrincipalID.String()
	}
	writeJSON(w, http.StatusOK, response)
}
