package httpapi

import (
	"encoding/hex"
	"errors"
	"net/http"

	"github.com/google/uuid"

	"github.com/sanskarpan/keel/internal/auth/postgres"
)

// memberOf reports whether the actor belongs to the org, backing the
// directory endpoints' 403 without trusting any request content.
func (h *Handler) memberOf(r *http.Request, actorID, orgID uuid.UUID) bool {
	orgs, err := h.repo.OrganizationsFor(r.Context(), actorID)
	if err != nil {
		return false
	}
	for _, org := range orgs {
		if org.OrgID == orgID {
			return true
		}
	}
	return false
}

type memberEntry struct {
	PrincipalID string `json:"principal_id"`
	Role        string `json:"role"`
}

// GET /v1/auth/organizations/{org_id}/members (Bearer member).
func (h *Handler) listMembers(w http.ResponseWriter, r *http.Request) {
	actorID, ok := h.authenticatedPrincipal(w, r)
	if !ok {
		return
	}
	orgID, err := uuid.Parse(r.PathValue("org_id"))
	if err != nil || orgID == uuid.Nil {
		writeProblem(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if !h.memberOf(r, actorID, orgID) {
		writeProblem(w, http.StatusForbidden, "forbidden")
		return
	}
	members, err := h.repo.MembersFor(r.Context(), actorID, orgID)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "request_failed")
		return
	}
	response := struct {
		Members []memberEntry `json:"members"`
	}{Members: make([]memberEntry, 0, len(members))}
	for _, member := range members {
		response.Members = append(response.Members, memberEntry{
			PrincipalID: member.PrincipalID.String(), Role: member.Role,
		})
	}
	writeJSON(w, http.StatusOK, response)
}

type inviteEntry struct {
	InviteID    string `json:"invite_id"`
	EmailDigest string `json:"email_digest"`
	Role        string `json:"role"`
}

// GET /v1/auth/organizations/{org_id}/invites (Bearer owner/admin).
func (h *Handler) listInvites(w http.ResponseWriter, r *http.Request) {
	actorID, ok := h.authenticatedPrincipal(w, r)
	if !ok {
		return
	}
	orgID, err := uuid.Parse(r.PathValue("org_id"))
	if err != nil || orgID == uuid.Nil {
		writeProblem(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if !h.memberOf(r, actorID, orgID) {
		writeProblem(w, http.StatusForbidden, "forbidden")
		return
	}
	invites, err := h.repo.InvitesFor(r.Context(), actorID, orgID)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "request_failed")
		return
	}
	response := struct {
		Invites []inviteEntry `json:"invites"`
	}{Invites: make([]inviteEntry, 0, len(invites))}
	for _, invite := range invites {
		response.Invites = append(response.Invites, inviteEntry{
			InviteID:    invite.InviteID.String(),
			EmailDigest: hex.EncodeToString(invite.EmailDigest),
			Role:        invite.Role,
		})
	}
	writeJSON(w, http.StatusOK, response)
}

// POST /v1/auth/invites/{invite_id}/revoke (Bearer owner/admin).
func (h *Handler) revokeInvite(w http.ResponseWriter, r *http.Request) {
	actorID, ok := h.authenticatedPrincipal(w, r)
	if !ok {
		return
	}
	inviteID, err := uuid.Parse(r.PathValue("invite_id"))
	if err != nil || inviteID == uuid.Nil {
		writeProblem(w, http.StatusBadRequest, "invalid_request")
		return
	}
	outcome, err := h.repo.RevokeInvite(r.Context(), actorID, inviteID)
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
	if outcome != "revoked" {
		writeProblem(w, http.StatusInternalServerError, "request_failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
