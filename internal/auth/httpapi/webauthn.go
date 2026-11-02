// WebAuthn ceremony endpoints. Registration binds a passkey to the caller's
// authenticated session; authentication starts from an email and mints a
// session on a verified assertion. Challenges are the single-use,
// database-backed nonces from slice 5: options calls record one, verify calls
// consume it before any cryptography runs, so a response can never be
// replayed and a crashed ceremony is retried with a fresh challenge.
//
// The go-webauthn library verifies attestation and assertion cryptography
// against the configured RP; Keel owns challenge lifecycle, key storage,
// sign-count clone detection (slice 5) and session issuance. Transports are
// joined to the validated comma list; backup flags persist for future
// synced-passkey policy.
package httpapi

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"

	"github.com/sanskarpan/keel/internal/auth"
	"github.com/sanskarpan/keel/internal/auth/postgres"
)

// WebAuthn ceremony TTL. Interactive ceremonies get five minutes, inside the
// 1-10 minute storage window.
const webAuthnCeremonyTTL = 5 * time.Minute

// WebAuthnConfig is the deploy-time relying-party identity. RPID and origins
// come from deployment configuration, never from request content.
type WebAuthnConfig struct {
	RPDisplayName string
	RPID          string
	RPOrigins     []string
}

func (c WebAuthnConfig) validate() error {
	if strings.TrimSpace(c.RPDisplayName) == "" || strings.TrimSpace(c.RPID) == "" || len(c.RPOrigins) == 0 {
		return errors.New("webauthn relying party configuration is incomplete")
	}
	for _, origin := range c.RPOrigins {
		if strings.TrimSpace(origin) == "" {
			return errors.New("webauthn relying party configuration is incomplete")
		}
	}
	return nil
}

// EnableWebAuthn attaches ceremony verification to an unmounted handler.
// Without it the ceremony routes answer 501.
func (h *Handler) EnableWebAuthn(config WebAuthnConfig) error {
	if err := config.validate(); err != nil {
		return err
	}
	wa, err := webauthn.New(&webauthn.Config{
		RPDisplayName: config.RPDisplayName,
		RPID:          config.RPID,
		RPOrigins:     config.RPOrigins,
	})
	if err != nil {
		return err
	}
	h.wa = wa
	return nil
}

// webauthnUser adapts one principal and its stored keys to the library.
type webauthnUser struct {
	principalID uuid.UUID
	name        string
	keys        []postgres.WebAuthnKey
}

func (u webauthnUser) WebAuthnID() []byte {
	id := u.principalID
	return append([]byte(nil), id[:]...)
}

func (u webauthnUser) WebAuthnName() string { return u.name }

func (u webauthnUser) WebAuthnDisplayName() string { return u.name }

func (u webauthnUser) WebAuthnCredentials() []webauthn.Credential {
	credentials := make([]webauthn.Credential, 0, len(u.keys))
	for _, key := range u.keys {
		var transports []protocol.AuthenticatorTransport
		if key.Transports != "" {
			for _, token := range strings.Split(key.Transports, ",") {
				transports = append(transports, protocol.AuthenticatorTransport(token))
			}
		}
		credentials = append(credentials, webauthn.Credential{
			ID:        append([]byte(nil), key.CredentialID...),
			PublicKey: append([]byte(nil), key.PublicKey...),
			Transport: transports,
			Flags: webauthn.CredentialFlags{
				BackupEligible: key.BackupEligible,
				BackupState:    key.BackupState,
			},
			Authenticator: webauthn.Authenticator{SignCount: key.SignCount},
		})
	}
	return credentials
}

func joinTransports(transports []protocol.AuthenticatorTransport) string {
	tokens := make([]string, 0, len(transports))
	for _, transport := range transports {
		tokens = append(tokens, string(transport))
	}
	return strings.Join(tokens, ",")
}

func sessionChallenge(nonce []byte, principalID uuid.UUID, allowed [][]byte) webauthn.SessionData {
	return webauthn.SessionData{
		Challenge:            base64.RawURLEncoding.EncodeToString(nonce),
		UserID:               append([]byte(nil), principalID[:]...),
		AllowedCredentialIDs: allowed,
		Expires:              time.Now().UTC().Add(webAuthnCeremonyTTL),
		UserVerification:     protocol.VerificationPreferred,
		CredParams:           webauthn.CredentialParametersDefault(),
	}
}

func challengeQuery(r *http.Request) (uuid.UUID, bool) {
	raw := r.URL.Query().Get("challenge_id")
	id, err := uuid.Parse(raw)
	if err != nil || id == uuid.Nil {
		return uuid.Nil, false
	}
	return id, true
}

// POST /v1/auth/webauthn/registration/options (Bearer session).
func (h *Handler) webauthnRegistrationOptions(w http.ResponseWriter, r *http.Request) {
	if h.wa == nil {
		writeProblem(w, http.StatusNotImplemented, "not_implemented")
		return
	}
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
	principalID, err := uuid.Parse(session.PrincipalID)
	if err != nil || principalID == uuid.Nil {
		writeProblem(w, http.StatusInternalServerError, "request_failed")
		return
	}
	keys, err := h.repo.KeysFor(r.Context(), principalID)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "request_failed")
		return
	}
	user := webauthnUser{principalID: principalID, name: principalID.String(), keys: keys}
	excluded := make([]protocol.CredentialDescriptor, 0, len(keys))
	for _, key := range keys {
		excluded = append(excluded, protocol.CredentialDescriptor{
			CredentialID: key.CredentialID,
			Type:         protocol.PublicKeyCredentialType,
		})
	}
	creation, sessionData, err := h.wa.BeginRegistration(user, webauthn.WithExclusions(excluded))
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "request_failed")
		return
	}
	nonce, err := base64.RawURLEncoding.DecodeString(sessionData.Challenge)
	if err != nil || len(nonce) != auth.WebAuthnChallengeBytes {
		writeProblem(w, http.StatusInternalServerError, "request_failed")
		return
	}
	now := h.now()
	challengeID := uuid.New()
	if outcome, err := h.repo.RecordWebAuthnChallenge(r.Context(), challengeID, principalID, auth.PurposeWebAuthnRegistration, nonce, now, now.Add(webAuthnCeremonyTTL)); err != nil || outcome != "recorded" {
		writeProblem(w, http.StatusInternalServerError, "request_failed")
		return
	}
	w.Header().Set("X-Challenge-ID", challengeID.String())
	writeJSON(w, http.StatusOK, creation)
}

// POST /v1/auth/webauthn/registration/verify?challenge_id= (Bearer session,
// body is the raw attestation response).
func (h *Handler) webauthnRegistrationVerify(w http.ResponseWriter, r *http.Request) {
	if h.wa == nil {
		writeProblem(w, http.StatusNotImplemented, "not_implemented")
		return
	}
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
	principalID, err := uuid.Parse(session.PrincipalID)
	if err != nil || principalID == uuid.Nil {
		writeProblem(w, http.StatusInternalServerError, "request_failed")
		return
	}
	challengeID, ok := challengeQuery(r)
	if !ok {
		writeProblem(w, http.StatusBadRequest, "invalid_request")
		return
	}
	outcome, consumedPrincipal, purpose, nonce, err := h.repo.ConsumeWebAuthnChallenge(r.Context(), challengeID)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "request_failed")
		return
	}
	switch outcome {
	case "ready":
	case "duplicate":
		writeProblem(w, http.StatusConflict, "challenge_reuse")
		return
	case "expired":
		writeProblem(w, http.StatusGone, "challenge_expired")
		return
	case "unknown":
		writeProblem(w, http.StatusNotFound, "not_found")
		return
	default:
		writeProblem(w, http.StatusInternalServerError, "request_failed")
		return
	}
	if purpose != auth.PurposeWebAuthnRegistration || consumedPrincipal != principalID {
		writeProblem(w, http.StatusForbidden, "forbidden")
		return
	}
	keys, err := h.repo.KeysFor(r.Context(), principalID)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "request_failed")
		return
	}
	user := webauthnUser{principalID: principalID, name: principalID.String(), keys: keys}
	credential, err := h.wa.FinishRegistration(user, sessionChallenge(nonce, principalID, nil), r)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_request")
		return
	}
	transports := joinTransports(credential.Transport)
	if err := auth.ValidateCredentialID(credential.ID); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if err := auth.ValidatePublicKey(credential.PublicKey); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if err := auth.ValidateTransports(transports); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_request")
		return
	}
	outcome, err = h.repo.StoreWebAuthnCredential(r.Context(), principalID, credential.ID, credential.PublicKey,
		transports, credential.Flags.BackupEligible, credential.Flags.BackupState, credential.Authenticator.SignCount)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "request_failed")
		return
	}
	switch outcome {
	case "stored":
		writeJSON(w, http.StatusCreated, map[string]string{
			"credential_id": base64.RawURLEncoding.EncodeToString(credential.ID),
		})
	case "credential_reuse":
		writeProblem(w, http.StatusConflict, "credential_conflict")
	case "principal_inactive":
		writeProblem(w, http.StatusForbidden, "forbidden")
	default:
		writeProblem(w, http.StatusInternalServerError, "request_failed")
	}
}

type webauthnOptionsRequest struct {
	Email string `json:"email"`
}

// POST /v1/auth/webauthn/authentication/options {email}.
func (h *Handler) webauthnAuthenticationOptions(w http.ResponseWriter, r *http.Request) {
	if h.wa == nil {
		writeProblem(w, http.StatusNotImplemented, "not_implemented")
		return
	}
	var input webauthnOptionsRequest
	if decode(w, r, &input) != nil || input.Email == "" {
		writeProblem(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if _, err := auth.CanonicalizeEmail(input.Email); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_request")
		return
	}
	principalID, state, _, err := h.repo.CredentialForEmail(r.Context(), input.Email, h.pepper)
	if err != nil || state != auth.PrincipalActive {
		writeProblem(w, http.StatusNotFound, "not_found")
		return
	}
	keys, err := h.repo.KeysFor(r.Context(), principalID)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "request_failed")
		return
	}
	if len(keys) == 0 {
		writeProblem(w, http.StatusNotFound, "not_found")
		return
	}
	user := webauthnUser{principalID: principalID, name: principalID.String(), keys: keys}
	assertion, sessionData, err := h.wa.BeginLogin(user)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "request_failed")
		return
	}
	nonce, err := base64.RawURLEncoding.DecodeString(sessionData.Challenge)
	if err != nil || len(nonce) != auth.WebAuthnChallengeBytes {
		writeProblem(w, http.StatusInternalServerError, "request_failed")
		return
	}
	now := h.now()
	challengeID := uuid.New()
	if outcome, err := h.repo.RecordWebAuthnChallenge(r.Context(), challengeID, principalID, auth.PurposeWebAuthnAuthentication, nonce, now, now.Add(webAuthnCeremonyTTL)); err != nil || outcome != "recorded" {
		writeProblem(w, http.StatusInternalServerError, "request_failed")
		return
	}
	w.Header().Set("X-Challenge-ID", challengeID.String())
	writeJSON(w, http.StatusOK, assertion)
}

// POST /v1/auth/webauthn/authentication/verify?challenge_id= (body is the
// raw assertion response; verified assertions mint a session).
func (h *Handler) webauthnAuthenticationVerify(w http.ResponseWriter, r *http.Request) {
	if h.wa == nil {
		writeProblem(w, http.StatusNotImplemented, "not_implemented")
		return
	}
	challengeID, ok := challengeQuery(r)
	if !ok {
		writeProblem(w, http.StatusBadRequest, "invalid_request")
		return
	}
	outcome, principalID, purpose, nonce, err := h.repo.ConsumeWebAuthnChallenge(r.Context(), challengeID)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "request_failed")
		return
	}
	switch outcome {
	case "ready":
	case "duplicate":
		writeProblem(w, http.StatusConflict, "challenge_reuse")
		return
	case "expired":
		writeProblem(w, http.StatusGone, "challenge_expired")
		return
	case "unknown":
		writeProblem(w, http.StatusNotFound, "not_found")
		return
	default:
		writeProblem(w, http.StatusInternalServerError, "request_failed")
		return
	}
	if purpose != auth.PurposeWebAuthnAuthentication || principalID == uuid.Nil {
		writeProblem(w, http.StatusBadRequest, "invalid_request")
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
	keys, err := h.repo.KeysFor(r.Context(), principalID)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "request_failed")
		return
	}
	allowed := make([][]byte, 0, len(keys))
	for _, key := range keys {
		allowed = append(allowed, key.CredentialID)
	}
	user := webauthnUser{principalID: principalID, name: principalID.String(), keys: keys}
	credential, err := h.wa.FinishLogin(user, sessionChallenge(nonce, principalID, allowed), r)
	if err != nil {
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
	advance, _, err := h.repo.AdvanceSignCount(r.Context(), credential.ID, credential.Authenticator.SignCount)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "request_failed")
		return
	}
	switch advance {
	case "advanced":
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
			writeProblem(w, http.StatusInternalServerError, "request_failed")
			return
		}
		writeJSON(w, http.StatusCreated, loginResponse{SessionID: sessionID.String(), Token: token, ExpiresAt: expires})
	case "cloned":
		_, _ = h.repo.RecordLoginFailure(r.Context(), principalID)
		writeProblem(w, http.StatusForbidden, "credential_cloned")
	default:
		writeProblem(w, http.StatusInternalServerError, "request_failed")
	}
}
