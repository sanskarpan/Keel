// Package httpapi provides the unmounted first-party identity surface.
// Registration, verification, session and recovery routes are served without
// tenant context: identity is pre-tenant and principals carry no tenant
// binding yet (K8.1/K8.2). The runtime does not mount these routes; a future
// composition wires trusted rate limiting, pepper provisioning and email
// transport, then mounts explicitly.
//
// Pepper is provisioned from a deploy-time secret file (see auth.ReadPepperFile),
// never committed, mirroring the OnCall url_file pattern. Verification and
// reset tokens leave the process only through the injected senders (email in
// production, capturing fakes in tests) and never in logs or error bodies.
// Session tokens are shown exactly once in the login response.
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"

	"github.com/sanskarpan/keel/internal/auth"
	"github.com/sanskarpan/keel/internal/auth/postgres"
)

const maxBodyBytes = 8 << 10

// Repository is the identity data surface. The store must use the
// keel_identity capability; *postgres.Repository satisfies this interface.
type Repository interface {
	BootstrapPrincipal(ctx context.Context, principalID uuid.UUID, email string, pepper []byte, passwordHash string, tenant *uuid.UUID) (string, error)
	RecordEmailVerification(ctx context.Context, principalID uuid.UUID, token string, pepper []byte, now, expires time.Time) (string, error)
	ConsumeEmailVerification(ctx context.Context, token string, pepper []byte) (string, uuid.UUID, error)
	CredentialForEmail(ctx context.Context, email string, pepper []byte) (uuid.UUID, string, string, error)
	RecordSession(ctx context.Context, sessionID, principalID uuid.UUID, token string, pepper []byte, now, expires time.Time) (string, error)
	SessionForToken(ctx context.Context, token string, pepper []byte) (auth.Session, error)
	RevokeSession(ctx context.Context, sessionID uuid.UUID) (string, error)
	RecordPasswordReset(ctx context.Context, principalID uuid.UUID, token string, pepper []byte, now, expires time.Time) (string, error)
	RotateCredential(ctx context.Context, token string, pepper []byte, newHash string) (string, uuid.UUID, error)
	RecordLoginFailure(ctx context.Context, principalID uuid.UUID) (string, error)
	ResetLoginThrottle(ctx context.Context, principalID uuid.UUID) (int, error)
	ThrottleFor(ctx context.Context, principalID uuid.UUID) (int, time.Time, error)
	RecordWebAuthnChallenge(ctx context.Context, challengeID, principalID uuid.UUID, purpose string, challenge []byte, now, expires time.Time) (string, error)
	ConsumeWebAuthnChallenge(ctx context.Context, challengeID uuid.UUID) (string, uuid.UUID, string, []byte, error)
	KeysFor(ctx context.Context, principalID uuid.UUID) ([]postgres.WebAuthnKey, error)
	AdvanceSignCount(ctx context.Context, credentialID []byte, presented uint32) (string, uuid.UUID, error)
	StoreWebAuthnCredential(ctx context.Context, principalID uuid.UUID, credentialID, publicKey []byte, transports string, backupEligible, backupState bool, signCount uint32) (string, error)
	CreateOrganization(ctx context.Context, orgID, principalID uuid.UUID, slug, displayName, region string) (string, error)
	AddOrganizationMember(ctx context.Context, actorID, orgID, memberID uuid.UUID, role string) (string, error)
	OrganizationsFor(ctx context.Context, principalID uuid.UUID) ([]postgres.Organization, error)
	InviteMember(ctx context.Context, inviteID, actorID, orgID uuid.UUID, email string, pepper []byte, token string, role string, now, expires time.Time) (string, error)
	AcceptInvite(ctx context.Context, token string, principalID uuid.UUID) (string, uuid.UUID, error)
	TransferOwnership(ctx context.Context, actorID, orgID, newOwnerID uuid.UUID) (string, error)
	SwitchSessionOrg(ctx context.Context, sessionID, orgID uuid.UUID) (string, error)
	SetMemberRole(ctx context.Context, actorID, orgID, memberID uuid.UUID, role string) (string, error)
	RemoveMember(ctx context.Context, actorID, orgID, memberID uuid.UUID) (string, error)
	ReapExpiredInvites(ctx context.Context, actorID, orgID uuid.UUID) (int, error)
	MembersFor(ctx context.Context, actorID, orgID uuid.UUID) ([]postgres.Membership, error)
	InvitesFor(ctx context.Context, actorID, orgID uuid.UUID) ([]postgres.Invite, error)
	RevokeInvite(ctx context.Context, actorID, inviteID uuid.UUID) (string, error)
	CreateServicePrincipal(ctx context.Context, servicePrincipalID, actorID, orgID uuid.UUID, name string) (string, error)
	IssueAPIKey(ctx context.Context, keyID, actorID, servicePrincipalID uuid.UUID, now, expires time.Time) (string, error)
	VerifyAPIKey(ctx context.Context, formattedKey string) (string, postgres.APIKeyIdentity, error)
	RevokeAPIKey(ctx context.Context, actorID, keyID uuid.UUID) (string, error)
	DisableServicePrincipal(ctx context.Context, actorID, servicePrincipalID uuid.UUID) (string, error)
}

type APIKeyIdentity = postgres.APIKeyIdentity

// VerificationSender delivers email-verification tokens. Production sends
// email; tests capture the token.
type VerificationSender interface {
	SendVerification(email, token string) error
}

// ResetSender delivers password-reset tokens under the same contract.
type ResetSender interface {
	SendReset(email, token string) error
}

type Handler struct {
	repo         Repository
	pepper       []byte
	hashParams   auth.ArgonParams
	verifySender VerificationSender
	resetSender  ResetSender
	now          func() time.Time
	mux          *http.ServeMux
	wa           *webauthn.WebAuthn
}

// New builds the unmounted identity handler. Pepper must hold at least
// auth.MinPepperBytes; hashParams selects the Argon2 effort (production uses
// auth.DefaultArgonParams, tests use auth.TestArgonParams).
func New(repo Repository, pepper []byte, hashParams auth.ArgonParams, verifySender VerificationSender, resetSender ResetSender) (*Handler, error) {
	if repo == nil || verifySender == nil || resetSender == nil {
		return nil, errors.New("identity HTTP dependencies are incomplete")
	}
	if len(pepper) < auth.MinPepperBytes {
		return nil, errors.New("identity pepper is invalid")
	}
	if hashParams.MemoryKiB < auth.MinArgonMemoryKiB || hashParams.MemoryKiB > auth.MaxArgonMemoryKiB ||
		hashParams.Time < auth.MinArgonTime || hashParams.Time > auth.MaxArgonTime ||
		hashParams.Threads < 1 || hashParams.Threads > auth.MaxArgonThreads {
		return nil, errors.New("identity hash parameters are invalid")
	}
	h := &Handler{
		repo: repo, pepper: pepper, hashParams: hashParams,
		verifySender: verifySender, resetSender: resetSender,
		now: func() time.Time { return time.Now().UTC() },
		mux: http.NewServeMux(),
	}
	h.mux.HandleFunc("POST /v1/auth/principals", h.register)
	h.mux.HandleFunc("POST /v1/auth/verifications/consume", h.consumeVerification)
	h.mux.HandleFunc("POST /v1/auth/sessions", h.login)
	h.mux.HandleFunc("POST /v1/auth/sessions/revoke", h.logout)
	h.mux.HandleFunc("POST /v1/auth/password-resets", h.requestReset)
	h.mux.HandleFunc("POST /v1/auth/password-resets/rotate", h.rotate)
	h.mux.HandleFunc("POST /v1/auth/webauthn/registration/options", h.webauthnRegistrationOptions)
	h.mux.HandleFunc("POST /v1/auth/webauthn/registration/verify", h.webauthnRegistrationVerify)
	h.mux.HandleFunc("POST /v1/auth/webauthn/authentication/options", h.webauthnAuthenticationOptions)
	h.mux.HandleFunc("POST /v1/auth/webauthn/authentication/verify", h.webauthnAuthenticationVerify)
	h.mux.HandleFunc("POST /v1/auth/organizations", h.createOrganization)
	h.mux.HandleFunc("POST /v1/auth/organizations/{org_id}/members", h.addOrganizationMember)
	h.mux.HandleFunc("GET /v1/auth/organizations", h.listOrganizations)
	h.mux.HandleFunc("POST /v1/auth/organizations/{org_id}/invites", h.inviteMember)
	h.mux.HandleFunc("POST /v1/auth/invites/accept", h.acceptInvite)
	h.mux.HandleFunc("POST /v1/auth/organizations/{org_id}/transfer", h.transferOwnership)
	h.mux.HandleFunc("POST /v1/auth/sessions/switch", h.switchSessionOrg)
	h.mux.HandleFunc("GET /v1/auth/organizations/{org_id}/members", h.listMembers)
	h.mux.HandleFunc("GET /v1/auth/organizations/{org_id}/invites", h.listInvites)
	h.mux.HandleFunc("POST /v1/auth/invites/{invite_id}/revoke", h.revokeInvite)
	h.mux.HandleFunc("POST /v1/auth/organizations/{org_id}/members/{principal_id}/role", h.setMemberRole)
	h.mux.HandleFunc("POST /v1/auth/organizations/{org_id}/members/{principal_id}/remove", h.removeMember)
	h.mux.HandleFunc("POST /v1/auth/organizations/{org_id}/invites/reap", h.reapInvites)
	h.mux.HandleFunc("POST /v1/auth/service-principals", h.createServicePrincipal)
	h.mux.HandleFunc("POST /v1/auth/service-principals/{service_principal_id}/keys", h.issueAPIKey)
	h.mux.HandleFunc("POST /v1/auth/service-principals/{service_principal_id}/keys/{key_id}/revoke", h.revokeAPIKey)
	h.mux.HandleFunc("POST /v1/auth/service-principals/{service_principal_id}/disable", h.disableServicePrincipal)
	return h, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
	h.mux.ServeHTTP(w, r)
}

type registerRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type registerResponse struct {
	PrincipalID string `json:"principal_id"`
	State       string `json:"state"`
}

func (h *Handler) register(w http.ResponseWriter, r *http.Request) {
	var input registerRequest
	if decode(w, r, &input) != nil || input.Email == "" || input.Password == "" {
		writeProblem(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if _, err := auth.CanonicalizeEmail(input.Email); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if err := auth.ValidatePassword(input.Password); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_request")
		return
	}
	hash, err := auth.HashPassword(input.Password, h.hashParams)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "request_failed")
		return
	}
	now := h.now()
	principalID := uuid.New()
	outcome, err := h.repo.BootstrapPrincipal(r.Context(), principalID, input.Email, h.pepper, hash, nil)
	if err != nil {
		if errors.Is(err, postgres.ErrConflict) {
			writeProblem(w, http.StatusConflict, "email_conflict")
			return
		}
		writeProblem(w, http.StatusInternalServerError, "request_failed")
		return
	}
	if outcome != "created" {
		writeProblem(w, http.StatusInternalServerError, "request_failed")
		return
	}
	token, err := auth.NewSecret(nil)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "request_failed")
		return
	}
	if outcome, err := h.repo.RecordEmailVerification(r.Context(), principalID, token, h.pepper, now, now.Add(auth.MaxVerificationTTL)); err != nil || outcome != "recorded" {
		writeProblem(w, http.StatusInternalServerError, "request_failed")
		return
	}
	if err := h.verifySender.SendVerification(input.Email, token); err != nil {
		writeProblem(w, http.StatusInternalServerError, "request_failed")
		return
	}
	writeJSON(w, http.StatusCreated, registerResponse{PrincipalID: principalID.String(), State: auth.PrincipalPending})
}

type tokenRequest struct {
	Token string `json:"token"`
}

type verificationResponse struct {
	PrincipalID string `json:"principal_id"`
}

func (h *Handler) consumeVerification(w http.ResponseWriter, r *http.Request) {
	var input tokenRequest
	if decode(w, r, &input) != nil || input.Token == "" {
		writeProblem(w, http.StatusBadRequest, "invalid_request")
		return
	}
	outcome, principalID, err := h.repo.ConsumeEmailVerification(r.Context(), input.Token, h.pepper)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "request_failed")
		return
	}
	switch outcome {
	case "verified":
		writeJSON(w, http.StatusOK, verificationResponse{PrincipalID: principalID.String()})
	case "duplicate":
		writeProblem(w, http.StatusConflict, "token_reuse")
	case "expired":
		writeProblem(w, http.StatusGone, "token_expired")
	case "unknown":
		writeProblem(w, http.StatusNotFound, "not_found")
	default:
		writeProblem(w, http.StatusInternalServerError, "request_failed")
	}
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type loginResponse struct {
	SessionID string    `json:"session_id"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (h *Handler) login(w http.ResponseWriter, r *http.Request) {
	var input loginRequest
	if decode(w, r, &input) != nil || input.Email == "" || input.Password == "" {
		writeProblem(w, http.StatusBadRequest, "invalid_request")
		return
	}
	principalID, state, stored, err := h.repo.CredentialForEmail(r.Context(), input.Email, h.pepper)
	if err != nil {
		if errors.Is(err, postgres.ErrNotFound) {
			writeProblem(w, http.StatusUnauthorized, "invalid_credentials")
			return
		}
		writeProblem(w, http.StatusInternalServerError, "request_failed")
		return
	}
	if state != auth.PrincipalActive {
		writeProblem(w, http.StatusUnauthorized, "invalid_credentials")
		return
	}
	now := h.now()
	if _, lockedUntil, err := h.repo.ThrottleFor(r.Context(), principalID); err != nil {
		writeProblem(w, http.StatusInternalServerError, "request_failed")
		return
	} else if !lockedUntil.IsZero() && lockedUntil.After(now) {
		writeLocked(w, lockedUntil.Sub(now))
		return
	}
	ok, err := auth.VerifyPassword(input.Password, stored)
	if err != nil || !ok {
		outcome, recordErr := h.repo.RecordLoginFailure(r.Context(), principalID)
		if recordErr != nil {
			writeProblem(w, http.StatusInternalServerError, "request_failed")
			return
		}
		if outcome == "locked" {
			if _, lockedUntil, err := h.repo.ThrottleFor(r.Context(), principalID); err == nil && !lockedUntil.IsZero() {
				writeLocked(w, lockedUntil.Sub(now))
				return
			}
			writeProblem(w, http.StatusTooManyRequests, "locked")
			return
		}
		writeProblem(w, http.StatusUnauthorized, "invalid_credentials")
		return
	}
	// Best-effort: a throttle reset outage must not lock out a principal that
	// just proved its password.
	_, _ = h.repo.ResetLoginThrottle(r.Context(), principalID)
	expires := now.Add(24 * time.Hour)
	if err := auth.ValidateSessionTTL(now, expires); err != nil {
		writeProblem(w, http.StatusInternalServerError, "request_failed")
		return
	}
	sessionID := uuid.New()
	token, err := auth.NewSecret(nil)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "request_failed")
		return
	}
	if outcome, err := h.repo.RecordSession(r.Context(), sessionID, principalID, token, h.pepper, now, expires); err != nil || outcome != "created" {
		if errors.Is(err, postgres.ErrNotVerified) {
			writeProblem(w, http.StatusUnauthorized, "invalid_credentials")
			return
		}
		writeProblem(w, http.StatusInternalServerError, "request_failed")
		return
	}
	writeJSON(w, http.StatusCreated, loginResponse{SessionID: sessionID.String(), Token: token, ExpiresAt: expires})
}

func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	token := bearerToken(r)
	if token == "" {
		writeProblem(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	session, err := h.repo.SessionForToken(r.Context(), token, h.pepper)
	if err != nil {
		if errors.Is(err, postgres.ErrNotFound) {
			writeProblem(w, http.StatusUnauthorized, "unauthenticated")
			return
		}
		writeProblem(w, http.StatusInternalServerError, "request_failed")
		return
	}
	sessionID, err := uuid.Parse(session.SessionID)
	if err != nil || sessionID == uuid.Nil {
		writeProblem(w, http.StatusInternalServerError, "request_failed")
		return
	}
	if _, err := h.repo.RevokeSession(r.Context(), sessionID); err != nil && !errors.Is(err, postgres.ErrNotFound) {
		writeProblem(w, http.StatusInternalServerError, "request_failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type resetRequest struct {
	Email string `json:"email"`
}

func (h *Handler) requestReset(w http.ResponseWriter, r *http.Request) {
	var input resetRequest
	if decode(w, r, &input) != nil || input.Email == "" {
		writeProblem(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if _, err := auth.CanonicalizeEmail(input.Email); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_request")
		return
	}
	// Anti-enumeration: every well-formed address gets 202, whether or not
	// an active principal exists or a reset was recorded.
	principalID, _, _, err := h.repo.CredentialForEmail(r.Context(), input.Email, h.pepper)
	if err != nil {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	now := h.now()
	token, err := auth.NewSecret(nil)
	if err != nil {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	outcome, err := h.repo.RecordPasswordReset(r.Context(), principalID, token, h.pepper, now, now.Add(auth.MaxVerificationTTL))
	if err != nil || outcome != "recorded" {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	_ = h.resetSender.SendReset(input.Email, token)
	w.WriteHeader(http.StatusAccepted)
}

type rotateRequest struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}

type rotateResponse struct {
	PrincipalID string `json:"principal_id"`
}

func (h *Handler) rotate(w http.ResponseWriter, r *http.Request) {
	var input rotateRequest
	if decode(w, r, &input) != nil || input.Token == "" || input.NewPassword == "" {
		writeProblem(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if err := auth.ValidatePassword(input.NewPassword); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_request")
		return
	}
	hash, err := auth.HashPassword(input.NewPassword, h.hashParams)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "request_failed")
		return
	}
	outcome, principalID, err := h.repo.RotateCredential(r.Context(), input.Token, h.pepper, hash)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "request_failed")
		return
	}
	switch outcome {
	case "rotated":
		writeJSON(w, http.StatusOK, rotateResponse{PrincipalID: principalID.String()})
	case "duplicate":
		writeProblem(w, http.StatusConflict, "token_reuse")
	case "expired":
		writeProblem(w, http.StatusGone, "token_expired")
	case "unknown":
		writeProblem(w, http.StatusNotFound, "not_found")
	case "principal_inactive":
		writeProblem(w, http.StatusForbidden, "forbidden")
	default:
		writeProblem(w, http.StatusInternalServerError, "request_failed")
	}
}

func bearerToken(r *http.Request) string {
	header := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(header) <= len(prefix) || header[:len(prefix)] != prefix {
		return ""
	}
	return header[len(prefix):]
}

func decode(w http.ResponseWriter, r *http.Request, destination any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("request must contain one JSON value")
	}
	return nil
}

type problemResponse struct {
	Type   string `json:"type"`
	Title  string `json:"title"`
	Status int    `json:"status"`
	Code   string `json:"code"`
}

func writeLocked(w http.ResponseWriter, remaining time.Duration) {
	seconds := int64(remaining.Seconds()) + 1
	if seconds < 1 {
		seconds = 1
	}
	w.Header().Set("Retry-After", strconv.FormatInt(seconds, 10))
	writeProblem(w, http.StatusTooManyRequests, "locked")
}

func writeProblem(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(problemResponse{
		Type: "about:blank", Title: http.StatusText(status), Status: status, Code: code,
	})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
