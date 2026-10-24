package postgres

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sanskarpan/keel/internal/delivery/webhook"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

func tenantSourceDatabases(t *testing.T) (*sql.DB, *sql.DB, *sql.DB) {
	t.Helper()
	webhookDSN := os.Getenv("KEEL_TEST_WEBHOOK_DATABASE_URL")
	appDSN := os.Getenv("KEEL_TEST_DATABASE_URL")
	adminDSN := os.Getenv("KEEL_TEST_ADMIN_DATABASE_URL")
	if webhookDSN == "" || appDSN == "" || adminDSN == "" {
		t.Skip("set KEEL_TEST_WEBHOOK_DATABASE_URL, KEEL_TEST_DATABASE_URL and KEEL_TEST_ADMIN_DATABASE_URL for tenant scheduling coverage")
	}
	return webhookTestDB(t, webhookDSN), webhookTestDB(t, appDSN), webhookTestDB(t, adminDSN)
}

func insertScheduledDelivery(t *testing.T, adminDB *sql.DB, tenant tenancy.TenantID, state string, due time.Time) string {
	t.Helper()
	deliveryID := "whd_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := adminDB.ExecContext(context.Background(),
		`INSERT INTO keel_meta.webhook_deliveries
		 (tenant_id,event_id,endpoint_id,subscription_version,delivery_id)
		 VALUES ($1,$2,$3,1,$4)`,
		string(tenant), uuid.NewString(), "ep_"+strings.ReplaceAll(uuid.NewString(), "-", ""), deliveryID); err != nil {
		t.Fatalf("insert scheduled delivery: %v", err)
	}
	switch state {
	case "pending":
		if _, err := adminDB.ExecContext(context.Background(),
			`UPDATE keel_meta.webhook_delivery_state SET next_attempt_at=$3
			  WHERE tenant_id=$1 AND delivery_id=$2`, string(tenant), deliveryID, due); err != nil {
			t.Fatalf("schedule pending delivery: %v", err)
		}
	case "in_flight":
		if _, err := adminDB.ExecContext(context.Background(),
			`UPDATE keel_meta.webhook_delivery_state
			    SET state='in_flight',next_attempt_at=NULL,lease_expires_at=$3,lease_epoch=1,
			        attempts=1,first_attempt_at=$4
			  WHERE tenant_id=$1 AND delivery_id=$2`,
			string(tenant), deliveryID, due, due.Add(-time.Minute)); err != nil {
			t.Fatalf("schedule in-flight delivery: %v", err)
		}
	default:
		t.Fatalf("unsupported state %q", state)
	}
	return deliveryID
}

func dueTenants(t *testing.T, source *TenantSource, limit int) []webhook.DueTenant {
	t.Helper()
	tenants, err := source.DueTenants(context.Background(), limit)
	if err != nil {
		t.Fatalf("DueTenants: %v", err)
	}
	return tenants
}

func dueTenantIDs(t *testing.T, source *TenantSource, limit int) []string {
	t.Helper()
	tenants := dueTenants(t, source, limit)
	ids := make([]string, len(tenants))
	for i, tenant := range tenants {
		ids[i] = string(tenant.Tenant)
	}
	return ids
}

func TestPostgreSQLTenantSourceReturnsDueAndExpiredTenants(t *testing.T) {
	webhookDB, _, adminDB := tenantSourceDatabases(t)
	source, err := NewTenantSource(webhookDB)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	first := payloadTenant(t)
	second := payloadTenant(t)
	third := payloadTenant(t)
	future := payloadTenant(t)
	leased := payloadTenant(t)

	insertScheduledDelivery(t, adminDB, first, "pending", now.Add(-10*time.Minute))
	insertScheduledDelivery(t, adminDB, first, "pending", now.Add(-time.Minute))
	insertScheduledDelivery(t, adminDB, second, "in_flight", now.Add(-5*time.Minute))
	insertScheduledDelivery(t, adminDB, third, "pending", now.Add(-time.Minute))
	insertScheduledDelivery(t, adminDB, future, "pending", now.Add(time.Hour))
	insertScheduledDelivery(t, adminDB, leased, "in_flight", now.Add(time.Hour))

	got := dueTenantIDs(t, source, 1000)
	want := []string{string(first), string(second), string(third)}
	var expected []string
	for _, tenant := range got {
		if tenant == string(future) || tenant == string(leased) {
			t.Fatalf("not-due tenant %s was returned", tenant)
		}
		for _, candidate := range want {
			if tenant == candidate {
				expected = append(expected, tenant)
			}
		}
	}
	if len(expected) != len(want) {
		t.Fatalf("due tenants = %v, missing one of %v", got, want)
	}
	for i := range want {
		if expected[i] != want[i] {
			t.Fatalf("due tenant order = %v, want %v", expected, want)
		}
	}
	if limited := dueTenantIDs(t, source, 1); len(limited) != 1 {
		t.Fatalf("limit 1 returned %d tenants", len(limited))
	}
	if limited := dueTenantIDs(t, source, 2); len(limited) != 2 {
		t.Fatalf("limit 2 returned %d tenants", len(limited))
	}
	for _, entry := range dueTenants(t, source, 1000) {
		switch entry.Tenant {
		case first:
			if entry.DueCount != 2 {
				t.Fatalf("first tenant due count = %d, want 2", entry.DueCount)
			}
			if entry.DueAt.After(now.Add(-9*time.Minute)) || entry.DueAt.Before(now.Add(-11*time.Minute)) {
				t.Fatalf("first tenant earliest due = %v", entry.DueAt)
			}
			if entry.BatchLimit != webhook.DefaultDeliveryBatchLimit {
				t.Fatalf("first tenant batch limit = %d, want default %d",
					entry.BatchLimit, webhook.DefaultDeliveryBatchLimit)
			}
		case second, third:
			if entry.DueCount != 1 {
				t.Fatalf("tenant %s due count = %d, want 1", entry.Tenant, entry.DueCount)
			}
			if entry.BatchLimit != webhook.DefaultDeliveryBatchLimit {
				t.Fatalf("tenant %s batch limit = %d, want default %d",
					entry.Tenant, entry.BatchLimit, webhook.DefaultDeliveryBatchLimit)
			}
		}
	}
}

func TestPostgreSQLTenantSourceRequiresWebhookCapability(t *testing.T) {
	webhookDB, appDB, adminDB := tenantSourceDatabases(t)
	source, err := NewTenantSource(webhookDB)
	if err != nil {
		t.Fatal(err)
	}
	insertScheduledDelivery(t, adminDB, payloadTenant(t), "pending", time.Now().UTC().Add(-time.Minute))
	if _, err := appDB.ExecContext(context.Background(),
		`SELECT keel_meta.list_webhook_delivery_tenants(10)`); err == nil {
		t.Fatal("application capability listed delivery tenants")
	}
	if _, err := webhookDB.ExecContext(context.Background(),
		`SELECT count(*) FROM keel_meta.webhook_delivery_state`); err == nil {
		t.Fatal("webhook capability read the delivery state table directly")
	}
	if _, err := source.DueTenants(context.Background(), 0); err == nil {
		t.Fatal("zero tenant limit was accepted")
	}
	if _, err := source.DueTenants(context.Background(), 1001); err == nil {
		t.Fatal("oversized tenant limit was accepted")
	}
}

func TestNewTenantSourceRequiresDatabase(t *testing.T) {
	if _, err := NewTenantSource(nil); err == nil {
		t.Fatal("nil tenant source database was accepted")
	}
}
