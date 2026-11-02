package httpapi

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/sanskarpan/keel/internal/auth"
	"github.com/sanskarpan/keel/internal/auth/postgres"
)

// testAuthenticator is a synthetic P-256 authenticator speaking fmt=none.
// It performs real ECDSA so ceremony verification is cryptographic, not
// mocked: only the transport (in-process JSON) is synthetic.
type testAuthenticator struct {
	t      *testing.T
	priv   *ecdsa.PrivateKey
	credID []byte
	cose   []byte
	rpID   string
	origin string
}

func newTestAuthenticator(t *testing.T, rpID, origin string) *testAuthenticator {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	credID := make([]byte, 32)
	if _, err := rand.Read(credID); err != nil {
		t.Fatal(err)
	}
	x := priv.PublicKey.X.FillBytes(make([]byte, 32))
	y := priv.PublicKey.Y.FillBytes(make([]byte, 32))
	cose, err := cbor.Marshal(map[int64]any{
		1:  int64(2),
		3:  int64(-7),
		-1: int64(1),
		-2: x,
		-3: y,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &testAuthenticator{t: t, priv: priv, credID: credID, cose: cose, rpID: rpID, origin: origin}
}

func (a *testAuthenticator) rpHash() []byte {
	sum := sha256.Sum256([]byte(a.rpID))
	return sum[:]
}

func (a *testAuthenticator) clientDataJSON(ceremony, challenge string) []byte {
	raw, err := json.Marshal(map[string]string{
		"type":      ceremony,
		"challenge": challenge,
		"origin":    a.origin,
	})
	if err != nil {
		a.t.Fatal(err)
	}
	return raw
}

// attestationResponse builds a fmt=none credential-creation response for the
// given options challenge.
func (a *testAuthenticator) attestationResponse(challenge string) map[string]any {
	a.t.Helper()
	clientData := a.clientDataJSON("webauthn.create", challenge)
	authData := append([]byte(nil), a.rpHash()...)
	authData = append(authData, 0x45, 0, 0, 0, 0)
	authData = append(authData, make([]byte, 16)...)
	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, uint16(len(a.credID)))
	authData = append(authData, length...)
	authData = append(authData, a.credID...)
	authData = append(authData, a.cose...)
	attestationObject, err := cbor.Marshal(map[string]any{
		"fmt":      "none",
		"attStmt":  map[string]any{},
		"authData": authData,
	})
	if err != nil {
		a.t.Fatal(err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(a.credID)
	return map[string]any{
		"id":    encoded,
		"rawId": encoded,
		"type":  "public-key",
		"response": map[string]any{
			"clientDataJSON":    base64.RawURLEncoding.EncodeToString(clientData),
			"attestationObject": base64.RawURLEncoding.EncodeToString(attestationObject),
			"transports":        []string{"internal"},
		},
	}
}

// assertionResponse signs an authentication ceremony with the given counter.
func (a *testAuthenticator) assertionResponse(challenge string, counter uint32, userHandle []byte) map[string]any {
	a.t.Helper()
	clientData := a.clientDataJSON("webauthn.get", challenge)
	clientHash := sha256.Sum256(clientData)
	authData := append([]byte(nil), a.rpHash()...)
	authData = append(authData, 0x05)
	count := make([]byte, 4)
	binary.BigEndian.PutUint32(count, counter)
	authData = append(authData, count...)
	signed := append([]byte(nil), authData...)
	signed = append(signed, clientHash[:]...)
	digest := sha256.Sum256(signed)
	signature, err := ecdsa.SignASN1(rand.Reader, a.priv, digest[:])
	if err != nil {
		a.t.Fatal(err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(a.credID)
	response := map[string]any{
		"id":    encoded,
		"rawId": encoded,
		"type":  "public-key",
		"response": map[string]any{
			"clientDataJSON":    base64.RawURLEncoding.EncodeToString(clientData),
			"authenticatorData": base64.RawURLEncoding.EncodeToString(authData),
			"signature":         base64.RawURLEncoding.EncodeToString(signature),
		},
	}
	if userHandle != nil {
		response["response"].(map[string]any)["userHandle"] = base64.RawURLEncoding.EncodeToString(userHandle)
	}
	return response
}

func testWebAuthnConfig() WebAuthnConfig {
	return WebAuthnConfig{
		RPDisplayName: "Keel Test",
		RPID:          "example.test",
		RPOrigins:     []string{"https://example.test"},
	}
}

func enableTestWebAuthn(t *testing.T, h *Handler) {
	t.Helper()
	if err := h.EnableWebAuthn(testWebAuthnConfig()); err != nil {
		t.Fatal(err)
	}
	h.now = func() time.Time { return time.Date(2026, time.November, 2, 12, 0, 0, 0, time.UTC) }
}

// postRawJSON posts a pre-encoded JSON body (ceremony responses) and returns
// the recorder. Query carries the challenge id.
func postRawJSON(h *Handler, target string, body []byte, bearer string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, target, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		request.Header.Set("Authorization", "Bearer "+bearer)
	}
	response := httptest.NewRecorder()
	h.ServeHTTP(response, request)
	return response
}

func mustTestSecret(t *testing.T) string {
	t.Helper()
	secret, err := auth.NewSecret(nil)
	if err != nil {
		t.Fatalf("secret: %v", err)
	}
	return secret
}

func challengeID(t *testing.T, response *httptest.ResponseRecorder) string {
	t.Helper()
	id := response.Header().Get("X-Challenge-ID")
	if _, err := uuid.Parse(id); err != nil {
		t.Fatalf("challenge header %q: %v body=%s", id, err, response.Body.String())
	}
	return id
}

// fakeSessionRepo returns a fake whose session token resolves to principal.
func fakeSessionRepo(principal uuid.UUID) (*fakeRepo, string) {
	token := "session-token-for-" + principal.String()
	return &fakeRepo{
		session: auth.Session{
			SessionID:      uuid.NewString(),
			PrincipalID:    principal.String(),
			PrincipalState: auth.PrincipalActive,
			ExpiresAt:      time.Date(2026, time.November, 3, 12, 0, 0, 0, time.UTC),
		},
	}, token
}

func TestWebAuthnRequiresConfiguration(t *testing.T) {
	h := newTestHandler(&fakeRepo{}, &fakeSender{}, &fakeSender{})
	response := doRequest(h, http.MethodPost, "/v1/auth/webauthn/registration/options", nil, "token")
	if response.Code != http.StatusNotImplemented {
		t.Fatalf("status=%d", response.Code)
	}
	if err := h.EnableWebAuthn(WebAuthnConfig{}); err == nil {
		t.Fatal("empty config accepted")
	}
	if err := h.EnableWebAuthn(WebAuthnConfig{RPDisplayName: "x", RPID: "example.test"}); err == nil {
		t.Fatal("originless config accepted")
	}
}

func TestWebAuthnRegistrationOptionsNeedsSession(t *testing.T) {
	h := newTestHandler(&fakeRepo{sessionErr: postgres.ErrNotFound}, &fakeSender{}, &fakeSender{})
	enableTestWebAuthn(t, h)
	response := doRequest(h, http.MethodPost, "/v1/auth/webauthn/registration/options", nil, "bad")
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestWebAuthnRegistrationVerifyMappings(t *testing.T) {
	principal := uuid.New()
	repo, token := fakeSessionRepo(principal)
	h := newTestHandler(repo, &fakeSender{}, &fakeSender{})
	enableTestWebAuthn(t, h)
	for _, tc := range []struct {
		outcome string
		status  int
		code    string
	}{
		{"duplicate", http.StatusConflict, "challenge_reuse"},
		{"expired", http.StatusGone, "challenge_expired"},
		{"unknown", http.StatusNotFound, "not_found"},
	} {
		repo.consumeChallengeOutcome = tc.outcome
		response := postRawJSON(h, "/v1/auth/webauthn/registration/verify?challenge_id="+uuid.NewString(), []byte(`{}`), token)
		if response.Code != tc.status {
			t.Fatalf("%s: status=%d body=%s", tc.outcome, response.Code, response.Body.String())
		}
		if got := problemCode(t, response); got != tc.code {
			t.Fatalf("%s: code=%s", tc.outcome, got)
		}
	}
	// Wrong purpose and foreign principal are forbidden without touching crypto.
	repo.consumeChallengeOutcome = "ready"
	repo.consumeChallengePurpose = auth.PurposeWebAuthnAuthentication
	repo.consumeChallengePrincipal = principal
	response := postRawJSON(h, "/v1/auth/webauthn/registration/verify?challenge_id="+uuid.NewString(), []byte(`{}`), token)
	if response.Code != http.StatusForbidden {
		t.Fatalf("wrong purpose: %d", response.Code)
	}
	repo.consumeChallengePurpose = auth.PurposeWebAuthnRegistration
	repo.consumeChallengePrincipal = uuid.New()
	response = postRawJSON(h, "/v1/auth/webauthn/registration/verify?challenge_id="+uuid.NewString(), []byte(`{}`), token)
	if response.Code != http.StatusForbidden {
		t.Fatalf("foreign challenge: %d", response.Code)
	}
}

func TestWebAuthnAuthenticationOptionsHidesNothing(t *testing.T) {
	h := newTestHandler(&fakeRepo{credErr: postgres.ErrNotFound}, &fakeSender{}, &fakeSender{})
	enableTestWebAuthn(t, h)
	response := doRequest(h, http.MethodPost, "/v1/auth/webauthn/authentication/options",
		map[string]string{"email": "missing@example.test"}, "")
	if response.Code != http.StatusNotFound {
		t.Fatalf("unknown: %d %s", response.Code, response.Body.String())
	}
	enrolled := &fakeRepo{
		credID: uuid.New(), credState: auth.PrincipalActive, credHash: "hash",
		keys: nil, keysErr: nil,
	}
	h = newTestHandler(enrolled, &fakeSender{}, &fakeSender{})
	enableTestWebAuthn(t, h)
	response = doRequest(h, http.MethodPost, "/v1/auth/webauthn/authentication/options",
		map[string]string{"email": "owner@example.test"}, "")
	if response.Code != http.StatusNotFound {
		t.Fatalf("keyless: %d %s", response.Code, response.Body.String())
	}
	response = doRequest(h, http.MethodPost, "/v1/auth/webauthn/authentication/options",
		map[string]string{"email": "not-an-email"}, "")
	if response.Code != http.StatusBadRequest {
		t.Fatalf("malformed: %d", response.Code)
	}
}

// TestWebAuthnCloneFailsClosed drives two counterless assertions through a
// fake store: the first advances, the replayed counter is reported cloned
// and the ceremony fails 403 without a session.
func TestWebAuthnCloneFailsClosed(t *testing.T) {
	principal := uuid.New()
	authenticator := newTestAuthenticator(t, "example.test", "https://example.test")
	key := postgres.WebAuthnKey{
		CredentialID: append([]byte(nil), authenticator.credID...),
		PublicKey:    append([]byte(nil), authenticator.cose...),
		SignCount:    0,
		Transports:   "internal",
	}
	repo := &fakeRepo{
		consumeChallengeOutcome:   "ready",
		consumeChallengePrincipal: principal,
		consumeChallengePurpose:   auth.PurposeWebAuthnAuthentication,
		consumeChallengeNonce:     make([]byte, auth.WebAuthnChallengeBytes),
		keys:                      []postgres.WebAuthnKey{key},
		advanceOutcome:            "cloned",
		advanceID:                 principal,
	}
	h := newTestHandler(repo, &fakeSender{}, &fakeSender{})
	enableTestWebAuthn(t, h)
	if _, err := rand.Read(repo.consumeChallengeNonce); err != nil {
		t.Fatal(err)
	}
	challenge := base64.RawURLEncoding.EncodeToString(repo.consumeChallengeNonce)
	body, err := json.Marshal(authenticator.assertionResponse(challenge, 0, principal[:]))
	if err != nil {
		t.Fatal(err)
	}
	response := postRawJSON(h, "/v1/auth/webauthn/authentication/verify?challenge_id="+uuid.NewString(), body, "")
	if response.Code != http.StatusForbidden || problemCode(t, response) != "credential_cloned" {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

// TestHTTPWebAuthnCeremonyAgainstPostgres drives real cryptographic ceremonies
// through the unmounted handler into the capability-gated store: fmt=none
// registration binds a key, assertion mints a session, and a regressed
// counter fails closed.
func TestHTTPWebAuthnCeremonyAgainstPostgres(t *testing.T) {
	identityDSN := os.Getenv("KEEL_TEST_IDENTITY_DATABASE_URL")
	adminDSN := os.Getenv("KEEL_TEST_ADMIN_DATABASE_URL")
	if identityDSN == "" || adminDSN == "" {
		t.Skip("set identity and admin PostgreSQL URLs to run identity HTTP integration tests")
	}
	db, err := sql.Open("pgx", identityDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.Ping(); err != nil {
		t.Fatal(err)
	}
	repo, err := postgres.New(db)
	if err != nil {
		t.Fatal(err)
	}
	pepper := []byte("keel-http-pepper-keel-http-pepper-32-keel")
	verify, reset := &fakeSender{}, &fakeSender{}
	h, err := New(repo, pepper, auth.TestArgonParams(), verify, reset)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.EnableWebAuthn(testWebAuthnConfig()); err != nil {
		t.Fatal(err)
	}
	authenticator := newTestAuthenticator(t, "example.test", "https://example.test")

	email := "waceremony-" + uuid.NewString() + "@example.test"
	password := "waceremony-pass-phrase"
	hash, err := auth.HashPassword(password, auth.TestArgonParams())
	if err != nil {
		t.Fatal(err)
	}
	principalID := uuid.New()
	tenantID := uuid.MustParse("55555555-5555-4555-8555-555555555555")
	if outcome, err := repo.BootstrapPrincipal(context.Background(), principalID, email, pepper, hash, &tenantID); err != nil || outcome != "created" {
		t.Fatalf("bootstrap: %v (outcome %q)", err, outcome)
	}
	verifyToken := mustTestSecret(t)
	now := time.Now().UTC()
	if _, err := repo.RecordEmailVerification(context.Background(), principalID, verifyToken, pepper, now, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if outcome, _, err := repo.ConsumeEmailVerification(context.Background(), verifyToken, pepper); err != nil || outcome != "verified" {
		t.Fatal(err)
	}

	response := doRequest(h, http.MethodPost, "/v1/auth/sessions",
		map[string]string{"email": email, "password": password}, "")
	if response.Code != http.StatusCreated {
		t.Fatalf("login: %d %s", response.Code, response.Body.String())
	}
	var login struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &login); err != nil || login.Token == "" {
		t.Fatal(err)
	}

	// Registration ceremony with a synthetic fmt=none authenticator.
	response = doRequest(h, http.MethodPost, "/v1/auth/webauthn/registration/options", nil, login.Token)
	if response.Code != http.StatusOK {
		t.Fatalf("reg options: %d %s", response.Code, response.Body.String())
	}
	regChallengeID := challengeID(t, response)
	var creationRaw struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &creationRaw); err != nil || creationRaw.PublicKey.Challenge == "" {
		t.Fatalf("creation challenge: %v body=%s", err, response.Body.String())
	}
	attestation, err := json.Marshal(authenticator.attestationResponse(creationRaw.PublicKey.Challenge))
	if err != nil {
		t.Fatal(err)
	}
	response = postRawJSON(h, "/v1/auth/webauthn/registration/verify?challenge_id="+regChallengeID, attestation, login.Token)
	if response.Code != http.StatusCreated {
		t.Fatalf("reg verify: %d %s", response.Code, response.Body.String())
	}
	var registered struct {
		CredentialID string `json:"credential_id"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &registered); err != nil || registered.CredentialID == "" {
		t.Fatal(err)
	}

	// The same physical key cannot register twice.
	response = doRequest(h, http.MethodPost, "/v1/auth/webauthn/registration/options", nil, login.Token)
	if response.Code != http.StatusOK {
		t.Fatalf("reg options 2: %d %s", response.Code, response.Body.String())
	}
	secondChallengeID := challengeID(t, response)
	var creation2 struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &creation2); err != nil {
		t.Fatal(err)
	}
	attestation2, err := json.Marshal(authenticator.attestationResponse(creation2.PublicKey.Challenge))
	if err != nil {
		t.Fatal(err)
	}
	response = postRawJSON(h, "/v1/auth/webauthn/registration/verify?challenge_id="+secondChallengeID, attestation2, login.Token)
	if response.Code != http.StatusConflict {
		t.Fatalf("duplicate key: %d %s", response.Code, response.Body.String())
	}

	// Authentication ceremony mints a session.
	response = doRequest(h, http.MethodPost, "/v1/auth/webauthn/authentication/options",
		map[string]string{"email": email}, "")
	if response.Code != http.StatusOK {
		t.Fatalf("auth options: %d %s", response.Code, response.Body.String())
	}
	authChallengeID := challengeID(t, response)
	var assertionOptions struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &assertionOptions); err != nil {
		t.Fatal(err)
	}
	assertion, err := json.Marshal(authenticator.assertionResponse(assertionOptions.PublicKey.Challenge, 1, nil))
	if err != nil {
		t.Fatal(err)
	}
	response = postRawJSON(h, "/v1/auth/webauthn/authentication/verify?challenge_id="+authChallengeID, assertion, "")
	if response.Code != http.StatusCreated {
		t.Fatalf("auth verify: %d %s", response.Code, response.Body.String())
	}
	var assertedLogin struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &assertedLogin); err != nil || assertedLogin.Token == "" {
		t.Fatal(err)
	}
	// The asserted session resolves and is valid.
	session, err := repo.SessionForToken(context.Background(), assertedLogin.Token, pepper)
	if err != nil || !session.Valid(time.Now().UTC()) {
		t.Fatalf("asserted session: %v %+v", err, session)
	}

	// A regressed counter fails closed without a session.
	response = doRequest(h, http.MethodPost, "/v1/auth/webauthn/authentication/options",
		map[string]string{"email": email}, "")
	if response.Code != http.StatusOK {
		t.Fatalf("auth options 2: %d %s", response.Code, response.Body.String())
	}
	regressChallengeID := challengeID(t, response)
	var assertionOptions2 struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &assertionOptions2); err != nil {
		t.Fatal(err)
	}
	regressed, err := json.Marshal(authenticator.assertionResponse(assertionOptions2.PublicKey.Challenge, 0, nil))
	if err != nil {
		t.Fatal(err)
	}
	response = postRawJSON(h, "/v1/auth/webauthn/authentication/verify?challenge_id="+regressChallengeID, regressed, "")
	if response.Code != http.StatusForbidden {
		t.Fatalf("regressed counter: %d %s", response.Code, response.Body.String())
	}
}

// TestWebAuthnRegistrationVerifyStoresKey runs a real fmt=none ceremony
// against a fake store: the verified key is stored once and a replayed
// physical key maps to 409.
func TestWebAuthnRegistrationVerifyStoresKey(t *testing.T) {
	principal := uuid.New()
	authenticator := newTestAuthenticator(t, "example.test", "https://example.test")
	repo, token := fakeSessionRepo(principal)
	repo.consumeChallengeOutcome = "ready"
	repo.consumeChallengePrincipal = principal
	repo.consumeChallengePurpose = auth.PurposeWebAuthnRegistration
	repo.consumeChallengeNonce = make([]byte, auth.WebAuthnChallengeBytes)
	if _, err := rand.Read(repo.consumeChallengeNonce); err != nil {
		t.Fatal(err)
	}
	repo.storeOutcome = "stored"
	h := newTestHandler(repo, &fakeSender{}, &fakeSender{})
	enableTestWebAuthn(t, h)
	body, err := json.Marshal(authenticator.attestationResponse(
		base64.RawURLEncoding.EncodeToString(repo.consumeChallengeNonce)))
	if err != nil {
		t.Fatal(err)
	}
	response := postRawJSON(h, "/v1/auth/webauthn/registration/verify?challenge_id="+uuid.NewString(), body, token)
	if response.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var stored struct {
		CredentialID string `json:"credential_id"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &stored); err != nil || stored.CredentialID == "" {
		t.Fatal(err)
	}
	want := base64.RawURLEncoding.EncodeToString(authenticator.credID)
	if stored.CredentialID != want {
		t.Fatalf("credential id %q want %q", stored.CredentialID, want)
	}
	repo.storeOutcome = "credential_reuse"
	response = postRawJSON(h, "/v1/auth/webauthn/registration/verify?challenge_id="+uuid.NewString(), body, token)
	if response.Code != http.StatusConflict {
		t.Fatalf("reuse: %d %s", response.Code, response.Body.String())
	}
}
