package runtime

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sanskarpan/keel/internal/platform/config"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

func operatorAPIDatabase(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("KEEL_TEST_OPERATOR_DATABASE_URL")
	if dsn == "" {
		t.Skip("set KEEL_TEST_OPERATOR_DATABASE_URL for operator API serving coverage")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func randomBearerToken(t *testing.T) string {
	t.Helper()
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

func waitForOperatorReady(t *testing.T, base string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		response, err := http.Get(base + "/health/ready")
		if err == nil {
			body, _ := io.ReadAll(response.Body)
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return
			}
			_ = body
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("operator API did not become ready")
}

func operatorRequest(t *testing.T, method, url, token, body string) (int, []byte) {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	request, err := http.NewRequest(method, url, reader)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	payload, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, payload
}

func TestOperatorAPIServesAuthenticatedRoutes(t *testing.T) {
	operatorAPIDatabase(t)
	tenant, err := tenancy.ParseTenantID(uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	token := randomBearerToken(t)
	values := map[string]string{
		operatorAPIDatabaseEnv: os.Getenv("KEEL_TEST_OPERATOR_DATABASE_URL"),
		operatorAPITokensEnv:   string(tenant) + ":local-ops:" + token,
	}
	cfg := config.Config{
		Role: config.RoleOperatorAPI, Environment: config.EnvironmentTest,
		ListenAddress: "127.0.0.1:18083", ShutdownTimeout: 5 * time.Second,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- runOperatorAPI(ctx, cfg, operatorLookup(values)) }()
	base := "http://127.0.0.1:18083"
	waitForOperatorReady(t, base)

	if status, _ := operatorRequest(t, "GET", base+"/v1/webhooks/reconciliation-runs", "", ""); status != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d, want 401", status)
	}
	if status, _ := operatorRequest(t, "GET", base+"/v1/webhooks/reconciliation-runs", strings.Repeat("z", 32), ""); status != http.StatusUnauthorized {
		t.Fatalf("wrong token status = %d, want 401", status)
	}
	status, payload := operatorRequest(t, "GET", base+"/v1/webhooks/reconciliation-runs?limit=10", token, "")
	if status != http.StatusOK {
		t.Fatalf("runs status = %d body=%s", status, payload)
	}
	var runs struct {
		Limit int   `json:"limit"`
		Runs  []any `json:"runs"`
	}
	if err := json.Unmarshal(payload, &runs); err != nil {
		t.Fatal(err)
	}
	if runs.Limit != 10 || len(runs.Runs) != 0 {
		t.Fatalf("runs response = %s", payload)
	}

	change := `{"change_id":"pol_0123456789abcdef","limit":50,"expected_version":0,"reason":"serve the policy API"}`
	status, payload = operatorRequest(t, "POST", base+"/v1/webhooks/endpoint-limits", token, change)
	if status != http.StatusOK {
		t.Fatalf("policy status = %d body=%s", status, payload)
	}
	if !strings.Contains(string(payload), `"version":1`) || !strings.Contains(string(payload), `"limit":50`) {
		t.Fatalf("policy response = %s", payload)
	}
	status, _ = operatorRequest(t, "POST", base+"/v1/webhooks/endpoint-limits", token, change)
	if status != http.StatusConflict {
		t.Fatalf("duplicate change status = %d, want 409", status)
	}
	if strings.Contains(string(payload), token) {
		t.Fatal("response leaked the bearer token")
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run returned %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("operator API did not shut down")
	}
}
