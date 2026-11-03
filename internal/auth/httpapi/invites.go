// Invite, transfer and session-switch endpoints. Invites name an email that
// needs no account yet; the token leaves through the injected reset sender
// (email in production) and acceptance binds the matching principal.
// Transfer is immediate per owner direction. Switching moves a live session
// to a membership the principal holds.
package httpapi

import (
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/sanskarpan/keel/internal/auth"
	"github.com/sanskarpan/keel/internal/auth/postgres"
)

type inviteRequest struct {
	Email string `json:"email"`
	Role  string `json:"role"`
}

type inviteResponse struct {
	InviteID string `json:"invite_id"`
}

// POST /v1/auth/organizations/{org_id}/invites (Bearer owner/admin).
// The token is delivered to the invitee; the response carries only the id.
func (h *Handler) inviteMember(w http.ResponseWriter, r *http.Request) {
	actorID, ok := h.authenticatedPrincipal(w, r)
	if !ok {
		return
	}
	orgID, err := uuid.Parse(r.PathValue("org_id"))
	if err != nil || orgID == uuid.Nil {
		writeProblem(w, http.StatusBadRequest, "invalid_request")
		return
	}
	var input inviteRequest
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
	token, err := auth.NewSecret(nil)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "request_failed")
		return
	}
	now := h.now()
	inviteID := uuid.New()
	outcome, err := h.repo.InviteMember(r.Context(), inviteID, actorID, orgID, input.Email, h.pepper, token, input.Role, now, now.Add(24*time.Hour))
	if err != nil {
		switch {
		case errors.Is(err, postgres.ErrNotAuthorized):
			writeProblem(w, http.StatusForbidden, "forbidden")
			return
		case errors.Is(err, postgres.ErrConflict):
			writeProblem(w, http.StatusConflict, "already_member")
			return
		default:
			writeProblem(w, http.StatusInternalServerError, "request_failed")
			return
		}
	}
	if outcome != "invited" {
		writeProblem(w, http.StatusInternalServerError, "request_failed")
		return
	}
	_ = h.resetSender.SendReset(input.Email, token)
	writeJSON(w, http.StatusCreated, inviteResponse{InviteID: inviteID.String()})
}

type acceptInviteRequest struct {
	Token string `json:"token"`
}

// POST /v1/auth/invites/accept (Bearer session of the matching principal).
func (h *Handler) acceptInvite(w http.ResponseWriter, r *http.Request) {
	principalID, ok := h.authenticatedPrincipal(w, r)
	if !ok {
		return
	}
	var input acceptInviteRequest
	if decode(w, r, &input) != nil || input.Token == "" {
		writeProblem(w, http.StatusBadRequest, "invalid_request")
		return
	}
	outcome, orgID, err := h.repo.AcceptInvite(r.Context(), input.Token, principalID)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "request_failed")
		return
	}
	switch outcome {
	case "accepted":
		writeJSON(w, http.StatusOK, map[string]string{"org_id": orgID.String()})
	case "unknown":
		writeProblem(w, http.StatusNotFound, "not_found")
	case "duplicate":
		writeProblem(w, http.StatusConflict, "invite_reuse")
	case "expired":
		writeProblem(w, http.StatusGone, "invite_expired")
	case "email_mismatch":
		writeProblem(w, http.StatusForbidden, "forbidden")
	case "not_active":
		writeProblem(w, http.StatusForbidden, "forbidden")
	case "already_member":
		writeProblem(w, http.StatusConflict, "already_member")
	default:
		writeProblem(w, http.StatusInternalServerError, "request_failed")
	}
}

type transferRequest struct {
	PrincipalID string `json:"principal_id"`
}

// POST /v1/auth/organizations/{org_id}/transfer (Bearer owner).
func (h *Handler) transferOwnership(w http.ResponseWriter, r *http.Request) {
	actorID, ok := h.authenticatedPrincipal(w, r)
	if !ok {
		return
	}
	orgID, err := uuid.Parse(r.PathValue("org_id"))
	if err != nil || orgID == uuid.Nil {
		writeProblem(w, http.StatusBadRequest, "invalid_request")
		return
	}
	var input transferRequest
	if decode(w, r, &input) != nil || input.PrincipalID == "" {
		writeProblem(w, http.StatusBadRequest, "invalid_request")
		return
	}
	targetID, err := uuid.Parse(input.PrincipalID)
	if err != nil || targetID == uuid.Nil {
		writeProblem(w, http.StatusBadRequest, "invalid_request")
		return
	}
	outcome, err := h.repo.TransferOwnership(r.Context(), actorID, orgID, targetID)
	if err != nil {
		switch {
		case errors.Is(err, postgres.ErrNotAuthorized):
			writeProblem(w, http.StatusForbidden, "forbidden")
			return
		case errors.Is(err, postgres.ErrNotFound):
			writeProblem(w, http.StatusNotFound, "not_found")
			return
		default:
			writeProblem(w, http.StatusInternalServerError, "request_failed")
			return
		}
	}
	if outcome != "transferred" {
		writeProblem(w, http.StatusInternalServerError, "request_failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type switchRequest struct {
	OrgID string `json:"org_id"`
}

// POST /v1/auth/sessions/switch (Bearer session; moves it to a membership).
func (h *Handler) switchSessionOrg(w http.ResponseWriter, r *http.Request) {
	token := bearerToken(r)
	if token == "" {
		writeProblem(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	session, err := h.repo.SessionForToken(r.Context(), token, h.pepper)
	if err != nil || !session.Valid(h.now()) {
		writeProblem(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	sessionID, err := uuid.Parse(session.SessionID)
	if err != nil || sessionID == uuid.Nil {
		writeProblem(w, http.StatusInternalServerError, "request_failed")
		return
	}
	var input switchRequest
	if decode(w, r, &input) != nil || input.OrgID == "" {
		writeProblem(w, http.StatusBadRequest, "invalid_request")
		return
	}
	orgID, err := uuid.Parse(input.OrgID)
	if err != nil || orgID == uuid.Nil {
		writeProblem(w, http.StatusBadRequest, "invalid_request")
		return
	}
	outcome, err := h.repo.SwitchSessionOrg(r.Context(), sessionID, orgID)
	if err != nil {
		if errors.Is(err, postgres.ErrNotFound) {
			writeProblem(w, http.StatusUnauthorized, "unauthenticated")
			return
		}
		writeProblem(w, http.StatusInternalServerError, "request_failed")
		return
	}
	switch outcome {
	case "switched":
		writeJSON(w, http.StatusOK, map[string]string{"org_id": orgID.String()})
	case "not_member":
		writeProblem(w, http.StatusForbidden, "forbidden")
	default:
		writeProblem(w, http.StatusInternalServerError, "request_failed")
	}
}
