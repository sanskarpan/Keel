// Organization endpoints. Creating seats the caller as owner and binds an
// unbound principal's tenant; owners and admins seat admin/member seats with
// tenant convergence. All three routes require an authenticated session; the
// session principal is the actor, never a request field.
package httpapi

import (
	"errors"
	"net/http"

	"github.com/google/uuid"

	"github.com/sanskarpan/keel/internal/auth"
	"github.com/sanskarpan/keel/internal/auth/postgres"
)

// authenticatedPrincipal resolves the bearer session to an active principal.
func (h *Handler) authenticatedPrincipal(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	token := bearerToken(r)
	if token == "" {
		writeProblem(w, http.StatusUnauthorized, "unauthenticated")
		return uuid.Nil, false
	}
	session, err := h.repo.SessionForToken(r.Context(), token, h.pepper)
	if err != nil || !session.Valid(h.now()) {
		writeProblem(w, http.StatusUnauthorized, "unauthenticated")
		return uuid.Nil, false
	}
	principalID, err := uuid.Parse(session.PrincipalID)
	if err != nil || principalID == uuid.Nil {
		writeProblem(w, http.StatusInternalServerError, "request_failed")
		return uuid.Nil, false
	}
	return principalID, true
}

type createOrganizationRequest struct {
	Slug        string `json:"slug"`
	DisplayName string `json:"display_name"`
	Region      string `json:"region"`
}

type organizationResponse struct {
	OrgID       string `json:"org_id"`
	Slug        string `json:"slug"`
	DisplayName string `json:"display_name"`
	Region      string `json:"region"`
	Role        string `json:"role"`
}

// POST /v1/auth/organizations (Bearer session).
func (h *Handler) createOrganization(w http.ResponseWriter, r *http.Request) {
	principalID, ok := h.authenticatedPrincipal(w, r)
	if !ok {
		return
	}
	var input createOrganizationRequest
	if decode(w, r, &input) != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if err := auth.ValidateOrgSlug(input.Slug); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if err := auth.ValidateOrgName(input.DisplayName); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if err := auth.ValidateOrgRegion(input.Region); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_request")
		return
	}
	orgID := uuid.New()
	outcome, err := h.repo.CreateOrganization(r.Context(), orgID, principalID, input.Slug, input.DisplayName, input.Region)
	if err != nil {
		switch {
		case errors.Is(err, postgres.ErrConflict):
			if outcome == "already_bound" {
				writeProblem(w, http.StatusConflict, "already_bound")
				return
			}
			writeProblem(w, http.StatusConflict, "slug_conflict")
			return
		case errors.Is(err, postgres.ErrNotVerified):
			writeProblem(w, http.StatusForbidden, "forbidden")
			return
		default:
			writeProblem(w, http.StatusInternalServerError, "request_failed")
			return
		}
	}
	if outcome != "created" {
		writeProblem(w, http.StatusInternalServerError, "request_failed")
		return
	}
	writeJSON(w, http.StatusCreated, organizationResponse{
		OrgID: orgID.String(), Slug: input.Slug,
		DisplayName: input.DisplayName, Region: input.Region, Role: auth.OrgRoleOwner,
	})
}

type addMemberRequest struct {
	Email string `json:"email"`
	Role  string `json:"role"`
}

type memberResponse struct {
	OrgID       string `json:"org_id"`
	PrincipalID string `json:"principal_id"`
	Role        string `json:"role"`
}

// POST /v1/auth/organizations/{org_id}/members (Bearer session of an
// owner/admin). The member is named by email; unknown addresses resolve to
// 404 without revealing account state beyond the caller's own directory.
func (h *Handler) addOrganizationMember(w http.ResponseWriter, r *http.Request) {
	actorID, ok := h.authenticatedPrincipal(w, r)
	if !ok {
		return
	}
	orgID, err := uuid.Parse(r.PathValue("org_id"))
	if err != nil || orgID == uuid.Nil {
		writeProblem(w, http.StatusBadRequest, "invalid_request")
		return
	}
	var input addMemberRequest
	if decode(w, r, &input) != nil || input.Email == "" {
		writeProblem(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if _, err := auth.CanonicalizeEmail(input.Email); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if input.Role != auth.OrgRoleAdmin && input.Role != auth.OrgRoleMember {
		writeProblem(w, http.StatusBadRequest, "invalid_request")
		return
	}
	memberID, state, _, err := h.repo.CredentialForEmail(r.Context(), input.Email, h.pepper)
	if err != nil {
		if errors.Is(err, postgres.ErrNotFound) {
			writeProblem(w, http.StatusNotFound, "not_found")
			return
		}
		writeProblem(w, http.StatusInternalServerError, "request_failed")
		return
	}
	if state != auth.PrincipalActive {
		writeProblem(w, http.StatusUnprocessableEntity, "member_inactive")
		return
	}
	outcome, err := h.repo.AddOrganizationMember(r.Context(), actorID, orgID, memberID, input.Role)
	if err != nil {
		switch {
		case errors.Is(err, postgres.ErrNotAuthorized):
			writeProblem(w, http.StatusForbidden, "forbidden")
			return
		case errors.Is(err, postgres.ErrNotVerified):
			writeProblem(w, http.StatusUnprocessableEntity, "member_inactive")
			return
		case errors.Is(err, postgres.ErrConflict):
			if outcome == "tenant_conflict" {
				writeProblem(w, http.StatusConflict, "tenant_conflict")
				return
			}
			writeProblem(w, http.StatusConflict, "already_member")
			return
		default:
			writeProblem(w, http.StatusInternalServerError, "request_failed")
			return
		}
	}
	if outcome != "added" {
		writeProblem(w, http.StatusInternalServerError, "request_failed")
		return
	}
	writeJSON(w, http.StatusCreated, memberResponse{
		OrgID: orgID.String(), PrincipalID: memberID.String(), Role: input.Role,
	})
}

// GET /v1/auth/organizations (Bearer session).
func (h *Handler) listOrganizations(w http.ResponseWriter, r *http.Request) {
	principalID, ok := h.authenticatedPrincipal(w, r)
	if !ok {
		return
	}
	orgs, err := h.repo.OrganizationsFor(r.Context(), principalID)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "request_failed")
		return
	}
	response := struct {
		Organizations []organizationResponse `json:"organizations"`
	}{Organizations: make([]organizationResponse, 0, len(orgs))}
	for _, org := range orgs {
		response.Organizations = append(response.Organizations, organizationResponse{
			OrgID: org.OrgID.String(), Slug: org.Slug,
			DisplayName: org.DisplayName, Region: org.Region, Role: org.Role,
		})
	}
	writeJSON(w, http.StatusOK, response)
}
