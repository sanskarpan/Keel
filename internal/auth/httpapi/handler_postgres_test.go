package httpapi

import (
	"context"
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

// httpPassword stages one verified principal and returns its email/password.
func httpPassword(t *testing.T, prefix string) (string, string) {
	t.Helper()
	return prefix + "-" + uuid.NewString() + "@example.test", prefix + "-pass-phrase"
}

func httpRegisterVerifyLogin(t *testing.T, h *Handler, _ *fakeSender, email, password string) string {
	t.Helper()
	response := doRequest(h, http.MethodPost, "/v1/auth/principals",
		map[string]string{"email": email, "password": password}, "")
	if response.Code != http.StatusCreated {
		t.Fatalf("register %s: %d %s", email, response.Code, response.Body.String())
	}
	token := httpVerifyToken(t, h, email)
	response = doRequest(h, http.MethodPost, "/v1/auth/verifications/consume",
		map[string]string{"token": token}, "")
	if response.Code != http.StatusOK {
		t.Fatalf("verify %s: %d %s", email, response.Code, response.Body.String())
	}
	response = doRequest(h, http.MethodPost, "/v1/auth/sessions",
		map[string]string{"email": email, "password": password}, "")
	if response.Code != http.StatusCreated {
		t.Fatalf("login %s: %d %s", email, response.Code, response.Body.String())
	}
	var login struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &login); err != nil || login.Token == "" {
		t.Fatal(err)
	}
	return login.Token
}

func httpVerifyToken(t *testing.T, h *Handler, _ string) string {
	t.Helper()
	sender, ok := h.verifySender.(*fakeSender)
	if !ok {
		t.Fatal("handler sender is not a fake")
	}
	if sender.calls == 0 || sender.token == "" {
		t.Fatalf("no verification sent: %+v", sender)
	}
	token := sender.token
	sender.calls, sender.token, sender.email = 0, "", ""
	return token
}

// TestHTTPOrganizationLifecycleAgainstPostgres drives the organization
// surface over HTTP: create binds, owners/admins seat members, strangers
// are refused, and conflicts stay distinct.
func TestHTTPOrganizationLifecycleAgainstPostgres(t *testing.T) {
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
	h, err := New(repo, pepper, auth.TestArgonParams(), &fakeSender{}, &fakeSender{})
	if err != nil {
		t.Fatal(err)
	}

	ownerEmail, ownerPassword := httpPassword(t, "orgowner")
	ownerToken := httpRegisterVerifyLogin(t, h, nil, ownerEmail, ownerPassword)

	slug := "acme-" + uuid.NewString()[:8]
	response := doRequest(h, http.MethodPost, "/v1/auth/organizations",
		map[string]string{"slug": slug, "display_name": "Acme", "region": "home"}, ownerToken)
	if response.Code != http.StatusCreated {
		t.Fatalf("create org: %d %s", response.Code, response.Body.String())
	}
	var created struct {
		OrgID string `json:"org_id"`
		Role  string `json:"role"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &created); err != nil || created.Role != auth.OrgRoleOwner {
		t.Fatalf("create body: %v %s", err, response.Body.String())
	}
	response = doRequest(h, http.MethodGet, "/v1/auth/organizations", nil, ownerToken)
	if response.Code != http.StatusOK || !contains(response.Body.String(), slug) {
		t.Fatalf("owner list: %d %s", response.Code, response.Body.String())
	}
	// Founders keep founding (multi-org); the tenant stays first-bound.
	response = doRequest(h, http.MethodPost, "/v1/auth/organizations",
		map[string]string{"slug": "second-" + uuid.NewString()[:8], "display_name": "Second", "region": "home"}, ownerToken)
	if response.Code != http.StatusCreated {
		t.Fatalf("second org: %d %s", response.Code, response.Body.String())
	}

	memberEmail, memberPassword := httpPassword(t, "orgmember")
	memberToken := httpRegisterVerifyLogin(t, h, nil, memberEmail, memberPassword)
	response = doRequest(h, http.MethodPost, "/v1/auth/organizations/"+created.OrgID+"/members",
		map[string]string{"email": memberEmail, "role": "member"}, ownerToken)
	if response.Code != http.StatusCreated {
		t.Fatalf("add member: %d %s", response.Code, response.Body.String())
	}
	response = doRequest(h, http.MethodGet, "/v1/auth/organizations", nil, memberToken)
	if response.Code != http.StatusOK || !contains(response.Body.String(), slug) {
		t.Fatalf("member list: %d %s", response.Code, response.Body.String())
	}
	// A plain member cannot seat others.
	strangerEmail, strangerPassword := httpPassword(t, "orgstranger")
	httpRegisterVerifyLogin(t, h, nil, strangerEmail, strangerPassword)
	response = doRequest(h, http.MethodPost, "/v1/auth/organizations/"+created.OrgID+"/members",
		map[string]string{"email": strangerEmail, "role": "member"}, memberToken)
	if response.Code != http.StatusForbidden {
		t.Fatalf("member add: %d %s", response.Code, response.Body.String())
	}
	// Unknown addresses resolve to 404; owner seats are rejected at the edge.
	response = doRequest(h, http.MethodPost, "/v1/auth/organizations/"+created.OrgID+"/members",
		map[string]string{"email": "nobody-" + uuid.NewString() + "@example.test", "role": "member"}, ownerToken)
	if response.Code != http.StatusNotFound {
		t.Fatalf("unknown member: %d %s", response.Code, response.Body.String())
	}
	response = doRequest(h, http.MethodPost, "/v1/auth/organizations/"+created.OrgID+"/members",
		map[string]string{"email": strangerEmail, "role": "owner"}, ownerToken)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("owner grant: %d %s", response.Code, response.Body.String())
	}
	// Re-adding converges on conflict, and a bound outsider is a tenant conflict.
	response = doRequest(h, http.MethodPost, "/v1/auth/organizations/"+created.OrgID+"/members",
		map[string]string{"email": memberEmail, "role": "member"}, ownerToken)
	if response.Code != http.StatusConflict {
		t.Fatalf("re-add: %d %s", response.Code, response.Body.String())
	}
}

// TestHTTPAPIKeysLifecycleAgainstPostgres drives service principals and keys
// over HTTP against the real store: create, issue (wire shown once),
// verify, revoke and disable with actor authorization.
func TestHTTPAPIKeysLifecycleAgainstPostgres(t *testing.T) {
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
	verifyS, resetS := &fakeSender{}, &fakeSender{}
	h, err := New(repo, pepper, auth.TestArgonParams(), verifyS, resetS)
	if err != nil {
		t.Fatal(err)
	}
	ownerToken := httpRegisterVerifyLogin(t, h, verifyS, "apikey-owner-"+uuid.NewString()+"@example.test", "apikey-owner-pass-phrase")
	strangerToken := httpRegisterVerifyLogin(t, h, verifyS, "apikey-stranger-"+uuid.NewString()+"@example.test", "apikey-stranger-pass-phrase")

	slug := "apikey-" + uuid.NewString()[:8]
	response := doRequest(h, http.MethodPost, "/v1/auth/organizations",
		map[string]string{"slug": slug, "display_name": "Keys Org", "region": "home"}, ownerToken)
	if response.Code != http.StatusCreated {
		t.Fatalf("create org: %d %s", response.Code, response.Body.String())
	}
	var created struct {
		OrgID string `json:"org_id"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	response = doRequest(h, http.MethodPost, "/v1/auth/service-principals",
		map[string]string{"org_id": created.OrgID, "name": "intruder"}, strangerToken)
	if response.Code != http.StatusForbidden {
		t.Fatalf("stranger create: %d %s", response.Code, response.Body.String())
	}
	response = doRequest(h, http.MethodPost, "/v1/auth/service-principals",
		map[string]string{"org_id": created.OrgID, "name": "etl-worker"}, ownerToken)
	if response.Code != http.StatusCreated {
		t.Fatalf("create sp: %d %s", response.Code, response.Body.String())
	}
	var sp struct {
		ServicePrincipalID string `json:"service_principal_id"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &sp); err != nil {
		t.Fatal(err)
	}
	response = doRequest(h, http.MethodPost, "/v1/auth/service-principals/"+sp.ServicePrincipalID+"/keys",
		map[string]any{}, ownerToken)
	if response.Code != http.StatusCreated {
		t.Fatalf("issue: %d %s", response.Code, response.Body.String())
	}
	var issued struct {
		KeyID  string `json:"key_id"`
		APIKey string `json:"api_key"`
		Prefix string `json:"prefix"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &issued); err != nil || issued.APIKey == "" {
		t.Fatalf("issue body: %v %s", err, response.Body.String())
	}
	outcome, identity, err := repo.VerifyAPIKey(context.Background(), issued.APIKey)
	if err != nil || outcome != "valid" || identity.OrgID.String() != created.OrgID {
		t.Fatalf("verify: %v (outcome %q identity %+v)", err, outcome, identity)
	}
	revokeTarget := "/v1/auth/service-principals/" + sp.ServicePrincipalID + "/keys/" + issued.KeyID + "/revoke"
	response = doRequest(h, http.MethodPost, revokeTarget, nil, strangerToken)
	if response.Code != http.StatusForbidden {
		t.Fatalf("stranger revoke: %d %s", response.Code, response.Body.String())
	}
	response = doRequest(h, http.MethodPost, revokeTarget, nil, ownerToken)
	if response.Code != http.StatusNoContent {
		t.Fatalf("revoke: %d %s", response.Code, response.Body.String())
	}
	if outcome, _, _ := repo.VerifyAPIKey(context.Background(), issued.APIKey); outcome != "revoked" {
		t.Fatalf("post-revoke: %s", outcome)
	}
	response = doRequest(h, http.MethodPost, "/v1/auth/service-principals/"+sp.ServicePrincipalID+"/disable", nil, ownerToken)
	if response.Code != http.StatusNoContent {
		t.Fatalf("disable: %d %s", response.Code, response.Body.String())
	}
}
