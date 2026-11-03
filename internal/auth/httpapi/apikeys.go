// Service-principal and API-key endpoints. Creation requires an owner or
// admin of the target org; issued keys are returned exactly once and never
// logged. Key verification itself is a repository call consumed by future
// middleware; a helper exposes it for composition without mounting anything.
package httpapi

import (
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/sanskarpan/keel/internal/auth"
	"github.com/sanskarpan/keel/internal/auth/postgres"
)

type createServicePrincipalRequest struct {
	OrgID string `json:"org_id"`
	Name  string `json:"name"`
}

// POST /v1/auth/service-principals (Bearer owner/admin of the org).
func (h *Handler) createServicePrincipal(w http.ResponseWriter, r *http.Request) {
	actorID, ok := h.authenticatedPrincipal(w, r)
	if !ok {
		return
	}
	var input createServicePrincipalRequest
	if decode(w, r, &input) != nil || input.OrgID == "" {
		writeProblem(w, http.StatusBadRequest, "invalid_request")
		return
	}
	orgID, err := uuid.Parse(input.OrgID)
	if err != nil || orgID == uuid.Nil {
		writeProblem(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if err := auth.ValidateServiceName(input.Name); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_request")
		return
	}
	servicePrincipalID := uuid.New()
	outcome, err := h.repo.CreateServicePrincipal(r.Context(), servicePrincipalID, actorID, orgID, input.Name)
	if err != nil {
		if errors.Is(err, postgres.ErrNotAuthorized) {
			writeProblem(w, http.StatusForbidden, "forbidden")
			return
		}
		writeProblem(w, http.StatusInternalServerError, "request_failed")
		return
	}
	if outcome != "created" {
		writeProblem(w, http.StatusInternalServerError, "request_failed")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{
		"service_principal_id": servicePrincipalID.String(),
		"org_id":               orgID.String(),
	})
}

type issueAPIKeyRequest struct {
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

type issueAPIKeyResponse struct {
	KeyID  string `json:"key_id"`
	APIKey string `json:"api_key"`
	Prefix string `json:"prefix"`
}

// POST /v1/auth/service-principals/{service_principal_id}/keys (Bearer
// owner/admin of the owning org; the org is resolved from the principal).
func (h *Handler) issueAPIKey(w http.ResponseWriter, r *http.Request) {
	actorID, ok := h.authenticatedPrincipal(w, r)
	if !ok {
		return
	}
	servicePrincipalID, err := uuid.Parse(r.PathValue("service_principal_id"))
	if err != nil || servicePrincipalID == uuid.Nil {
		writeProblem(w, http.StatusBadRequest, "invalid_request")
		return
	}
	var input issueAPIKeyRequest
	if decode(w, r, &input) != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_request")
		return
	}
	var expires time.Time
	if input.ExpiresAt != nil {
		expires = input.ExpiresAt.UTC()
		if err := auth.ValidateAPIKeyTTL(h.now(), expires); err != nil {
			writeProblem(w, http.StatusBadRequest, "invalid_request")
			return
		}
	}
	keyID := uuid.New()
	wire, err := h.repo.IssueAPIKey(r.Context(), keyID, actorID, servicePrincipalID, h.now(), expires)
	if err != nil {
		if errors.Is(err, postgres.ErrNotAuthorized) {
			writeProblem(w, http.StatusForbidden, "forbidden")
			return
		}
		if errors.Is(err, postgres.ErrNotFound) {
			writeProblem(w, http.StatusNotFound, "not_found")
			return
		}
		writeProblem(w, http.StatusInternalServerError, "request_failed")
		return
	}
	if wire == "" {
		writeProblem(w, http.StatusInternalServerError, "request_failed")
		return
	}
	prefix, _, err := auth.ParseAPIKey(wire)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "request_failed")
		return
	}
	writeJSON(w, http.StatusCreated, issueAPIKeyResponse{KeyID: keyID.String(), APIKey: wire, Prefix: prefix})
}

// POST /v1/auth/service-principals/{service_principal_id}/keys/{key_id}/revoke.
func (h *Handler) revokeAPIKey(w http.ResponseWriter, r *http.Request) {
	actorID, ok := h.authenticatedPrincipal(w, r)
	if !ok {
		return
	}
	keyID, err := uuid.Parse(r.PathValue("key_id"))
	if err != nil || keyID == uuid.Nil {
		writeProblem(w, http.StatusBadRequest, "invalid_request")
		return
	}
	outcome, err := h.repo.RevokeAPIKey(r.Context(), actorID, keyID)
	if err != nil {
		if errors.Is(err, postgres.ErrNotFound) {
			writeProblem(w, http.StatusNotFound, "not_found")
			return
		}
		if errors.Is(err, postgres.ErrNotAuthorized) {
			writeProblem(w, http.StatusForbidden, "forbidden")
			return
		}
		writeProblem(w, http.StatusInternalServerError, "request_failed")
		return
	}
	if outcome != "revoked" {
		writeProblem(w, http.StatusInternalServerError, "request_failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// POST /v1/auth/service-principals/{service_principal_id}/disable.
func (h *Handler) disableServicePrincipal(w http.ResponseWriter, r *http.Request) {
	actorID, ok := h.authenticatedPrincipal(w, r)
	if !ok {
		return
	}
	servicePrincipalID, err := uuid.Parse(r.PathValue("service_principal_id"))
	if err != nil || servicePrincipalID == uuid.Nil {
		writeProblem(w, http.StatusBadRequest, "invalid_request")
		return
	}
	outcome, err := h.repo.DisableServicePrincipal(r.Context(), actorID, servicePrincipalID)
	if err != nil {
		if errors.Is(err, postgres.ErrNotFound) {
			writeProblem(w, http.StatusNotFound, "not_found")
			return
		}
		if errors.Is(err, postgres.ErrNotAuthorized) {
			writeProblem(w, http.StatusForbidden, "forbidden")
			return
		}
		writeProblem(w, http.StatusInternalServerError, "request_failed")
		return
	}
	if outcome != "disabled" {
		writeProblem(w, http.StatusInternalServerError, "request_failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// apiKeyIdentity resolves one bearer API key for future middleware. Only a
// valid key returns an identity; everything else fails closed without one.
func (h *Handler) apiKeyIdentity(r *http.Request) (postgres.APIKeyIdentity, bool) {
	token := bearerToken(r)
	if token == "" {
		return postgres.APIKeyIdentity{}, false
	}
	outcome, identity, err := h.repo.VerifyAPIKey(r.Context(), token)
	if err != nil || outcome != "valid" {
		return postgres.APIKeyIdentity{}, false
	}
	return identity, true
}
