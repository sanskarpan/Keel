package httpapi

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/sanskarpan/keel/internal/auth"
	"github.com/sanskarpan/keel/internal/auth/postgres"
)

// TestHTTPIdentityLifecycleAgainstPostgres wires the unmounted handler to the
// real capability-gated store and drives the full loop over HTTP. It skips
// unless the identity/admin PostgreSQL URLs are set (same gates as the store
// integration test).
func TestHTTPIdentityLifecycleAgainstPostgres(t *testing.T) {
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

	email := "http-" + uuid.NewString() + "@example.test"
	password := "http-pass-phrase-one"

	response := doRequest(h, http.MethodPost, "/v1/auth/principals",
		map[string]string{"email": email, "password": password}, "")
	if response.Code != http.StatusCreated {
		t.Fatalf("register: %d %s", response.Code, response.Body.String())
	}
	if verify.calls != 1 || verify.token == "" {
		t.Fatalf("verification not sent: %+v", verify)
	}
	response = doRequest(h, http.MethodPost, "/v1/auth/verifications/consume",
		map[string]string{"token": verify.token}, "")
	if response.Code != http.StatusOK {
		t.Fatalf("verify: %d %s", response.Code, response.Body.String())
	}

	response = doRequest(h, http.MethodPost, "/v1/auth/sessions",
		map[string]string{"email": email, "password": password}, "")
	if response.Code != http.StatusCreated {
		t.Fatalf("login: %d %s", response.Code, response.Body.String())
	}
	var login struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &login); err != nil || login.Token == "" {
		t.Fatalf("login body: %v", err)
	}
	response = doRequest(h, http.MethodPost, "/v1/auth/sessions/revoke", nil, login.Token)
	if response.Code != http.StatusNoContent {
		t.Fatalf("logout: %d %s", response.Code, response.Body.String())
	}

	response = doRequest(h, http.MethodPost, "/v1/auth/password-resets",
		map[string]string{"email": email}, "")
	if response.Code != http.StatusAccepted || reset.calls != 1 || reset.token == "" {
		t.Fatalf("reset: %d sender=%+v", response.Code, reset)
	}
	newPassword := "http-pass-phrase-two"
	response = doRequest(h, http.MethodPost, "/v1/auth/password-resets/rotate",
		map[string]string{"token": reset.token, "new_password": newPassword}, "")
	if response.Code != http.StatusOK {
		t.Fatalf("rotate: %d %s", response.Code, response.Body.String())
	}

	response = doRequest(h, http.MethodPost, "/v1/auth/sessions",
		map[string]string{"email": email, "password": password}, "")
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("old password: %d %s", response.Code, response.Body.String())
	}
	response = doRequest(h, http.MethodPost, "/v1/auth/sessions",
		map[string]string{"email": email, "password": newPassword}, "")
	if response.Code != http.StatusCreated {
		t.Fatalf("new login: %d %s", response.Code, response.Body.String())
	}
	// Lockout over HTTP: four wrong passwords are 401, the fifth is 429
	// with Retry-After, and the correct password stays locked.
	for i := 0; i < 4; i++ {
		response = doRequest(h, http.MethodPost, "/v1/auth/sessions",
			map[string]string{"email": email, "password": "wrong-pass-phrase!"}, "")
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("wrong %d: %d %s", i+1, response.Code, response.Body.String())
		}
	}
	response = doRequest(h, http.MethodPost, "/v1/auth/sessions",
		map[string]string{"email": email, "password": "wrong-pass-phrase!"}, "")
	if response.Code != http.StatusTooManyRequests {
		t.Fatalf("fifth wrong: %d %s", response.Code, response.Body.String())
	}
	var problem struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &problem); err != nil || problem.Code != "locked" {
		t.Fatalf("lock code: %v body=%s", err, response.Body.String())
	}
	if response.Header().Get("Retry-After") == "" {
		t.Fatal("missing Retry-After on lockout")
	}
	response = doRequest(h, http.MethodPost, "/v1/auth/sessions",
		map[string]string{"email": email, "password": newPassword}, "")
	if response.Code != http.StatusTooManyRequests {
		t.Fatalf("correct while locked: %d %s", response.Code, response.Body.String())
	}
	_ = httptest.NewRecorder
}
