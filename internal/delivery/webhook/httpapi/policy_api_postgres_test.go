package httpapi

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
	webhookpostgres "github.com/sanskarpan/keel/internal/delivery/webhook/postgres"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

func policyAPIDatabases(t *testing.T) (*sql.DB, *sql.DB) {
	t.Helper()
	operatorDSN := os.Getenv("KEEL_TEST_OPERATOR_DATABASE_URL")
	adminDSN := os.Getenv("KEEL_TEST_ADMIN_DATABASE_URL")
	if operatorDSN == "" || adminDSN == "" {
		t.Skip("set operator and admin DSNs for quota policy API coverage")
	}
	open := func(dsn string) *sql.DB {
		db, err := sql.Open("pgx", dsn)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		return db
	}
	return open(operatorDSN), open(adminDSN)
}

func newPolicyAPIHandler(t *testing.T, operatorDB *sql.DB) (*Handler, tenancy.TenantID) {
	t.Helper()
	tenant, err := tenancy.ParseTenantID(uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	repo, err := webhookpostgres.New(operatorDB)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := New(repo, testPrincipal{principal: Principal{
		TenantID: tenant, ActorRef: "operator@example.com",
	}, ok: true}, testAuthorizer{allowed: true}, func(string) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	return handler, tenant
}

func postPolicy(t *testing.T, handler *Handler, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, path, strings.NewReader(body)))
	return response
}

func TestPolicyAPIEndToEnd(t *testing.T) {
	operatorDB, adminDB := policyAPIDatabases(t)
	ctx := context.Background()
	handler, tenantID := newPolicyAPIHandler(t, operatorDB)
	tenant := string(tenantID)

	response := postPolicy(t, handler, "/v1/webhooks/endpoint-limits",
		`{"change_id":"pol_0123456789abcdef","limit":50,"expected_version":0,"reason":"cap the tenant endpoints"}`)
	if response.Code != http.StatusOK {
		t.Fatalf("endpoint limit status = %d body=%s", response.Code, response.Body)
	}
	var limit int
	var version int64
	if err := adminDB.QueryRowContext(ctx,
		`SELECT active_endpoint_limit,version FROM keel_meta.webhook_tenant_policies WHERE tenant_id=$1`,
		tenant).Scan(&limit, &version); err != nil {
		t.Fatal(err)
	}
	if limit != 50 || version != 1 {
		t.Fatalf("endpoint policy limit=%d version=%d", limit, version)
	}

	response = postPolicy(t, handler, "/v1/webhooks/endpoint-limits",
		`{"change_id":"pol_0123456789abcdef","limit":60,"expected_version":1,"reason":"reuse the change identity"}`)
	if response.Code != http.StatusConflict {
		t.Fatalf("duplicate change status = %d body=%s", response.Code, response.Body)
	}

	response = postPolicy(t, handler, "/v1/webhooks/delivery-limits",
		`{"change_id":"pol_fedcba9876543210","limit":2,"expected_version":0,"reason":"throttle the tenant batch"}`)
	if response.Code != http.StatusOK {
		t.Fatalf("delivery limit status = %d body=%s", response.Code, response.Body)
	}
	var batch int
	if err := adminDB.QueryRowContext(ctx,
		`SELECT delivery_batch_limit FROM keel_meta.webhook_tenant_delivery_policies WHERE tenant_id=$1`,
		tenant).Scan(&batch); err != nil {
		t.Fatal(err)
	}
	if batch != 2 {
		t.Fatalf("delivery batch limit = %d, want 2", batch)
	}
	response = postPolicy(t, handler, "/v1/webhooks/delivery-limits",
		`{"change_id":"pol_0123456789abcdef","limit":3,"expected_version":1,"reason":"raise the tenant batch"}`)
	if response.Code != http.StatusOK {
		t.Fatalf("delivery limit update status = %d body=%s", response.Code, response.Body)
	}
	if !strings.Contains(response.Body.String(), `"version":2`) ||
		!strings.Contains(response.Body.String(), `"limit":3`) {
		t.Fatalf("delivery limit update missed version 2 / limit 3: %s", response.Body)
	}
}
