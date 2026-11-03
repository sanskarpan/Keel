package runtime

import (
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sanskarpan/keel/internal/platform/config"
)

func identityAPIDatabase(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("KEEL_TEST_IDENTITY_DATABASE_URL")
	if dsn == "" {
		t.Skip("set KEEL_TEST_IDENTITY_DATABASE_URL for identity API serving coverage")
	}
	return dsn
}

func identityAPIValues(t *testing.T, dsn string) map[string]string {
	t.Helper()
	pepperPath := filepath.Join(t.TempDir(), "pepper")
	if err := os.WriteFile(pepperPath, []byte(strings.Repeat("s", 32)), 0600); err != nil {
		t.Fatal(err)
	}
	return map[string]string{
		identityAPIDatabaseEnv:   dsn,
		identityAPIPepperFileEnv: pepperPath,
	}
}

func waitForIdentityReady(t *testing.T, base string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		response, err := http.Get(base + "/health/ready")
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("identity API did not become ready")
}

func identityRequest(t *testing.T, method, url, token, body string) (int, []byte) {
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

// TestIdentityAPIServesMountedRoutes boots the real role in-process and
// proves the mounted surface: health, fail-closed auth, validation and one
// full registration through the runner-wired handler.
func TestIdentityAPIServesMountedRoutes(t *testing.T) {
	dsn := identityAPIDatabase(t)
	cfg := config.Config{
		Role: config.RoleIdentityAPI, Environment: config.EnvironmentTest,
		ListenAddress: "127.0.0.1:18084", ShutdownTimeout: 5 * time.Second,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- runIdentityAPI(ctx, cfg, identityLookup(identityAPIValues(t, dsn))) }()
	base := "http://127.0.0.1:18084"
	deadline := time.Now().Add(10 * time.Second)
	ready := false
	for time.Now().Before(deadline) && !ready {
		select {
		case err := <-done:
			t.Fatalf("server exited: %v", err)
		default:
		}
		if response, err := http.Get(base + "/health/ready"); err == nil {
			_ = response.Body.Close()
			ready = response.StatusCode == http.StatusOK
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ready {
		t.Fatal("identity API did not become ready")
	}

	if status, _ := identityRequest(t, "GET", base+"/v1/auth/organizations", "", ""); status != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d, want 401", status)
	}
	if status, _ := identityRequest(t, "POST", base+"/v1/auth/principals", "", `{"email":"x"}`); status != http.StatusBadRequest {
		t.Fatalf("bad register status = %d, want 400", status)
	}
	if status, _ := identityRequest(t, "POST", base+"/v1/auth/sessions", "", `{"email":"nobody@example.test","password":"correct-horse-battery"}`); status != http.StatusUnauthorized {
		t.Fatalf("unknown login status = %d, want 401", status)
	}
	status, payload := identityRequest(t, "POST", base+"/v1/auth/principals", "",
		`{"email":"serve-owner@example.test","password":"correct-horse-battery"}`)
	if status != http.StatusCreated {
		t.Fatalf("register status = %d body=%s", status, payload)
	}
	if !strings.Contains(string(payload), `"state":"pending_verification"`) {
		t.Fatalf("register response = %s", payload)
	}
	select {
	case err := <-done:
		t.Fatalf("server exited early: %v", err)
	default:
	}
}
