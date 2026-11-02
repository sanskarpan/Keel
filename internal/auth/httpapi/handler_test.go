package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/sanskarpan/keel/internal/auth"
	"github.com/sanskarpan/keel/internal/auth/postgres"
)

type fakeRepo struct {
	bootstrapOutcome string
	bootstrapErr     error
	bootstrapID      uuid.UUID

	recordVerifyOutcome string
	recordVerifyErr     error

	consumeOutcome string
	consumeID      uuid.UUID
	consumeErr     error

	credID    uuid.UUID
	credState string
	credHash  string
	credErr   error

	recordSessionOutcome string
	recordSessionErr     error

	session    auth.Session
	sessionErr error

	revokeOutcome string
	revokeErr     error
	revokedID     uuid.UUID

	recordResetOutcome string
	recordResetErr     error

	rotateOutcome string
	rotateID      uuid.UUID
	rotateErr     error

	throttleCount int
	throttleUntil time.Time
	throttleErr   error

	failureOutcome string
	failureErr     error

	resetCount int
	resetErr   error
}

func (f *fakeRepo) BootstrapPrincipal(_ context.Context, id uuid.UUID, _ string, _ []byte, _ string, _ *uuid.UUID) (string, error) {
	f.bootstrapID = id
	return f.bootstrapOutcome, f.bootstrapErr
}

func (f *fakeRepo) RecordEmailVerification(_ context.Context, _ uuid.UUID, _ string, _ []byte, _, _ time.Time) (string, error) {
	return f.recordVerifyOutcome, f.recordVerifyErr
}

func (f *fakeRepo) ConsumeEmailVerification(_ context.Context, _ string, _ []byte) (string, uuid.UUID, error) {
	return f.consumeOutcome, f.consumeID, f.consumeErr
}

func (f *fakeRepo) CredentialForEmail(_ context.Context, _ string, _ []byte) (uuid.UUID, string, string, error) {
	return f.credID, f.credState, f.credHash, f.credErr
}

func (f *fakeRepo) RecordSession(_ context.Context, _, _ uuid.UUID, _ string, _ []byte, _, _ time.Time) (string, error) {
	return f.recordSessionOutcome, f.recordSessionErr
}

func (f *fakeRepo) SessionForToken(_ context.Context, _ string, _ []byte) (auth.Session, error) {
	return f.session, f.sessionErr
}

func (f *fakeRepo) RevokeSession(_ context.Context, id uuid.UUID) (string, error) {
	f.revokedID = id
	return f.revokeOutcome, f.revokeErr
}

func (f *fakeRepo) RecordPasswordReset(_ context.Context, _ uuid.UUID, _ string, _ []byte, _, _ time.Time) (string, error) {
	return f.recordResetOutcome, f.recordResetErr
}

func (f *fakeRepo) RotateCredential(_ context.Context, _ string, _ []byte, _ string) (string, uuid.UUID, error) {
	return f.rotateOutcome, f.rotateID, f.rotateErr
}

func (f *fakeRepo) RecordLoginFailure(_ context.Context, _ uuid.UUID) (string, error) {
	return f.failureOutcome, f.failureErr
}

func (f *fakeRepo) ResetLoginThrottle(_ context.Context, _ uuid.UUID) (int, error) {
	return f.resetCount, f.resetErr
}

func (f *fakeRepo) ThrottleFor(_ context.Context, _ uuid.UUID) (int, time.Time, error) {
	return f.throttleCount, f.throttleUntil, f.throttleErr
}

type fakeSender struct {
	email string
	token string
	err   error
	calls int
}

func (f *fakeSender) SendVerification(email, token string) error {
	f.email, f.token, f.calls = email, token, f.calls+1
	return f.err
}

func (f *fakeSender) SendReset(email, token string) error {
	f.email, f.token, f.calls = email, token, f.calls+1
	return f.err
}

func testPepper() []byte {
	return []byte("test-pepper-32-bytes-long-test!!")
}

func newTestHandler(repo *fakeRepo, verify, reset *fakeSender) *Handler {
	h, err := New(repo, testPepper(), auth.TestArgonParams(), verify, reset)
	if err != nil {
		panic(err)
	}
	h.now = func() time.Time { return time.Date(2026, time.November, 2, 12, 0, 0, 0, time.UTC) }
	return h
}

func doRequest(h *Handler, method, target string, body any, bearer string) *httptest.ResponseRecorder {
	var reader *bytes.Reader
	if body == nil {
		reader = bytes.NewReader(nil)
	} else {
		raw, _ := json.Marshal(body)
		reader = bytes.NewReader(raw)
	}
	request := httptest.NewRequest(method, target, reader)
	if bearer != "" {
		request.Header.Set("Authorization", "Bearer "+bearer)
	}
	response := httptest.NewRecorder()
	h.ServeHTTP(response, request)
	return response
}

func problemCode(t *testing.T, response *httptest.ResponseRecorder) string {
	t.Helper()
	var problem struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &problem); err != nil {
		t.Fatalf("decode problem: %v body=%s", err, response.Body.String())
	}
	return problem.Code
}

func TestRegisterSuccessSendsVerification(t *testing.T) {
	repo := &fakeRepo{bootstrapOutcome: "created", recordVerifyOutcome: "recorded"}
	verify, reset := &fakeSender{}, &fakeSender{}
	response := doRequest(newTestHandler(repo, verify, reset), http.MethodPost, "/v1/auth/principals",
		map[string]string{"email": "owner@example.com", "password": "correct-horse-battery"}, "")
	if response.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var body struct {
		PrincipalID string `json:"principal_id"`
		State       string `json:"state"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if _, err := uuid.Parse(body.PrincipalID); err != nil || body.State != auth.PrincipalPending {
		t.Fatalf("response=%+v err=%v", body, err)
	}
	if verify.calls != 1 || verify.email != "owner@example.com" || verify.token == "" {
		t.Fatalf("sender=%+v", verify)
	}
	if strings.Contains(response.Body.String(), verify.token) {
		t.Fatal("verification token leaked in response")
	}
}

func TestRegisterConflictAndBadInput(t *testing.T) {
	repo := &fakeRepo{bootstrapOutcome: "", bootstrapErr: postgres.ErrConflict}
	verify, reset := &fakeSender{}, &fakeSender{}
	response := doRequest(newTestHandler(repo, verify, reset), http.MethodPost, "/v1/auth/principals",
		map[string]string{"email": "owner@example.com", "password": "correct-horse-battery"}, "")
	if response.Code != http.StatusConflict || problemCode(t, response) != "email_conflict" {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	for _, body := range []any{
		map[string]string{"email": "not-an-email", "password": "correct-horse-battery"},
		map[string]string{"email": "owner@example.com", "password": "short"},
		map[string]string{"email": "", "password": "correct-horse-battery"},
		map[string]string{"email": "owner@example.com", "password": "correct-horse-battery", "extra": "no"},
	} {
		response := doRequest(newTestHandler(&fakeRepo{}, verify, reset), http.MethodPost, "/v1/auth/principals", body, "")
		if response.Code != http.StatusBadRequest {
			t.Fatalf("body=%v status=%d", body, response.Code)
		}
	}
}

func TestConsumeVerificationOutcomes(t *testing.T) {
	id := uuid.New()
	cases := []struct {
		outcome string
		status  int
		code    string
	}{
		{"verified", http.StatusOK, ""},
		{"duplicate", http.StatusConflict, "token_reuse"},
		{"expired", http.StatusGone, "token_expired"},
		{"unknown", http.StatusNotFound, "not_found"},
	}
	for _, tc := range cases {
		repo := &fakeRepo{consumeOutcome: tc.outcome, consumeID: id}
		response := doRequest(newTestHandler(repo, &fakeSender{}, &fakeSender{}), http.MethodPost,
			"/v1/auth/verifications/consume", map[string]string{"token": "s3cr3t"}, "")
		if response.Code != tc.status {
			t.Fatalf("%s: status=%d body=%s", tc.outcome, response.Code, response.Body.String())
		}
		if tc.code != "" && problemCode(t, response) != tc.code {
			t.Fatalf("%s: body=%s", tc.outcome, response.Body.String())
		}
	}
}

func TestLoginSuccessAndFailuresConverge(t *testing.T) {
	hash, err := auth.HashPassword("correct-horse-battery", auth.TestArgonParams())
	if err != nil {
		t.Fatal(err)
	}
	good := &fakeRepo{
		credID: uuid.New(), credState: auth.PrincipalActive, credHash: hash,
		recordSessionOutcome: "created",
	}
	response := doRequest(newTestHandler(good, &fakeSender{}, &fakeSender{}), http.MethodPost,
		"/v1/auth/sessions", map[string]string{"email": "owner@example.com", "password": "correct-horse-battery"}, "")
	if response.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var body struct {
		SessionID string `json:"session_id"`
		Token     string `json:"token"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if _, err := uuid.Parse(body.SessionID); err != nil || body.Token == "" {
		t.Fatalf("login response=%+v", body)
	}
	// Wrong password, unknown email and pending principal converge on 401.
	wrong := &fakeRepo{credID: uuid.New(), credState: auth.PrincipalActive, credHash: hash}
	response = doRequest(newTestHandler(wrong, &fakeSender{}, &fakeSender{}), http.MethodPost,
		"/v1/auth/sessions", map[string]string{"email": "owner@example.com", "password": "wrong-horse-battery!"}, "")
	if response.Code != http.StatusUnauthorized || problemCode(t, response) != "invalid_credentials" {
		t.Fatalf("wrong password: %d %s", response.Code, response.Body.String())
	}
	unknown := &fakeRepo{credErr: postgres.ErrNotFound}
	response = doRequest(newTestHandler(unknown, &fakeSender{}, &fakeSender{}), http.MethodPost,
		"/v1/auth/sessions", map[string]string{"email": "missing@example.com", "password": "correct-horse-battery"}, "")
	if response.Code != http.StatusUnauthorized || problemCode(t, response) != "invalid_credentials" {
		t.Fatalf("unknown: %d %s", response.Code, response.Body.String())
	}
	pending := &fakeRepo{credID: uuid.New(), credState: auth.PrincipalPending, credHash: hash}
	response = doRequest(newTestHandler(pending, &fakeSender{}, &fakeSender{}), http.MethodPost,
		"/v1/auth/sessions", map[string]string{"email": "owner@example.com", "password": "correct-horse-battery"}, "")
	if response.Code != http.StatusUnauthorized || problemCode(t, response) != "invalid_credentials" {
		t.Fatalf("pending: %d %s", response.Code, response.Body.String())
	}
}

func TestLogoutRevokesOnce(t *testing.T) {
	sessionID := uuid.New()
	repo := &fakeRepo{
		session:       auth.Session{SessionID: sessionID.String(), PrincipalID: uuid.New().String(), PrincipalState: auth.PrincipalActive},
		revokeOutcome: "revoked",
	}
	response := doRequest(newTestHandler(repo, &fakeSender{}, &fakeSender{}), http.MethodPost,
		"/v1/auth/sessions/revoke", nil, "session-token")
	if response.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if repo.revokedID != sessionID {
		t.Fatalf("revoked=%v want %v", repo.revokedID, sessionID)
	}
	unauth := &fakeRepo{sessionErr: postgres.ErrNotFound}
	response = doRequest(newTestHandler(unauth, &fakeSender{}, &fakeSender{}), http.MethodPost,
		"/v1/auth/sessions/revoke", nil, "bad-token")
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("unknown token: %d", response.Code)
	}
	response = doRequest(newTestHandler(repo, &fakeSender{}, &fakeSender{}), http.MethodPost,
		"/v1/auth/sessions/revoke", nil, "")
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("missing bearer: %d", response.Code)
	}
}

func TestResetRequestNeverEnumerates(t *testing.T) {
	active := &fakeRepo{
		credID: uuid.New(), credState: auth.PrincipalActive, credHash: "hash",
		recordResetOutcome: "recorded",
	}
	sender := &fakeSender{}
	response := doRequest(newTestHandler(active, &fakeSender{}, sender), http.MethodPost,
		"/v1/auth/password-resets", map[string]string{"email": "owner@example.com"}, "")
	if response.Code != http.StatusAccepted || sender.calls != 1 {
		t.Fatalf("active: %d calls=%d", response.Code, sender.calls)
	}
	for _, repo := range []*fakeRepo{
		{credErr: postgres.ErrNotFound},
		{credID: uuid.New(), credState: auth.PrincipalPending, credHash: "hash", recordResetOutcome: "", recordResetErr: postgres.ErrNotVerified},
	} {
		sender := &fakeSender{}
		response := doRequest(newTestHandler(repo, &fakeSender{}, sender), http.MethodPost,
			"/v1/auth/password-resets", map[string]string{"email": "owner@example.com"}, "")
		if response.Code != http.StatusAccepted || sender.calls != 0 {
			t.Fatalf("enumeration: %d calls=%d body=%s", response.Code, sender.calls, response.Body.String())
		}
	}
}

func TestRotateOutcomes(t *testing.T) {
	id := uuid.New()
	cases := []struct {
		outcome string
		status  int
		code    string
	}{
		{"rotated", http.StatusOK, ""},
		{"duplicate", http.StatusConflict, "token_reuse"},
		{"expired", http.StatusGone, "token_expired"},
		{"unknown", http.StatusNotFound, "not_found"},
		{"principal_inactive", http.StatusForbidden, "forbidden"},
	}
	for _, tc := range cases {
		repo := &fakeRepo{rotateOutcome: tc.outcome, rotateID: id}
		response := doRequest(newTestHandler(repo, &fakeSender{}, &fakeSender{}), http.MethodPost,
			"/v1/auth/password-resets/rotate", map[string]string{"token": "t", "new_password": "new-horse-battery"}, "")
		if response.Code != tc.status {
			t.Fatalf("%s: status=%d body=%s", tc.outcome, response.Code, response.Body.String())
		}
		if tc.code != "" && problemCode(t, response) != tc.code {
			t.Fatalf("%s: body=%s", tc.outcome, response.Body.String())
		}
	}
	response := doRequest(newTestHandler(&fakeRepo{}, &fakeSender{}, &fakeSender{}), http.MethodPost,
		"/v1/auth/password-resets/rotate", map[string]string{"token": "t", "new_password": "short"}, "")
	if response.Code != http.StatusBadRequest {
		t.Fatalf("short password: %d", response.Code)
	}
}

func TestNewRejectsWeakPepperAndParams(t *testing.T) {
	if _, err := New(&fakeRepo{}, []byte("short"), auth.TestArgonParams(), &fakeSender{}, &fakeSender{}); err == nil {
		t.Fatal("short pepper accepted")
	}
	if _, err := New(nil, testPepper(), auth.TestArgonParams(), &fakeSender{}, &fakeSender{}); err == nil {
		t.Fatal("nil repo accepted")
	}
	if _, err := New(&fakeRepo{}, testPepper(), auth.ArgonParams{}, &fakeSender{}, &fakeSender{}); err == nil {
		t.Fatal("empty params accepted")
	}
}

func TestLoginLockedPrincipalGets429(t *testing.T) {
	hash, err := auth.HashPassword("correct-horse-battery", auth.TestArgonParams())
	if err != nil {
		t.Fatal(err)
	}
	repo := &fakeRepo{
		credID: uuid.New(), credState: auth.PrincipalActive, credHash: hash,
		throttleCount: 5, throttleUntil: time.Date(2026, time.November, 2, 12, 10, 0, 0, time.UTC),
	}
	response := doRequest(newTestHandler(repo, &fakeSender{}, &fakeSender{}), http.MethodPost,
		"/v1/auth/sessions", map[string]string{"email": "owner@example.com", "password": "correct-horse-battery"}, "")
	if response.Code != http.StatusTooManyRequests || problemCode(t, response) != "locked" {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if response.Header().Get("Retry-After") == "" {
		t.Fatal("missing Retry-After header")
	}
}

func TestLoginFifthFailureLocks(t *testing.T) {
	hash, err := auth.HashPassword("correct-horse-battery", auth.TestArgonParams())
	if err != nil {
		t.Fatal(err)
	}
	lockedAt := time.Date(2026, time.November, 2, 12, 10, 0, 0, time.UTC)
	fifth := &fakeRepo{
		credID: uuid.New(), credState: auth.PrincipalActive, credHash: hash,
		failureOutcome: "locked", throttleCount: 5, throttleUntil: lockedAt,
	}
	response := doRequest(newTestHandler(fifth, &fakeSender{}, &fakeSender{}), http.MethodPost,
		"/v1/auth/sessions", map[string]string{"email": "owner@example.com", "password": "wrong-horse-battery!"}, "")
	if response.Code != http.StatusTooManyRequests || problemCode(t, response) != "locked" {
		t.Fatalf("fifth failure: %d %s", response.Code, response.Body.String())
	}
	earlier := &fakeRepo{
		credID: uuid.New(), credState: auth.PrincipalActive, credHash: hash,
		failureOutcome: "counted",
	}
	response = doRequest(newTestHandler(earlier, &fakeSender{}, &fakeSender{}), http.MethodPost,
		"/v1/auth/sessions", map[string]string{"email": "owner@example.com", "password": "wrong-horse-battery!"}, "")
	if response.Code != http.StatusUnauthorized || problemCode(t, response) != "invalid_credentials" {
		t.Fatalf("earlier failure: %d %s", response.Code, response.Body.String())
	}
}
