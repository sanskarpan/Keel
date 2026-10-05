package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
	"github.com/sanskarpan/keel/internal/supplier/cases"
)

func TestPostgreSQLRejectsExpiryBeforePersistedDeadline(t *testing.T) {
	appDSN := os.Getenv("KEEL_TEST_DATABASE_URL")
	if appDSN == "" {
		t.Skip("set KEEL_TEST_DATABASE_URL to exercise the expiry guard with the non-owner app role")
	}
	appDB := integrationRoleDB(t, appDSN, "keel_local_app", "keel-app-local-only")
	repo, err := New(appDB)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	tenant, _ := tenancy.ParseTenantID("11111111-1111-4111-8111-111111111111")
	policyID, supplierID := testUUID(t), testUUID(t)
	policy := cases.Policy{TenantID: string(tenant), PolicyID: policyID, Version: 1, Name: "Expiry guard", Deadline: time.Hour, Steps: []cases.ReviewStep{{Key: "risk-review", Role: "risk:reviewer"}}}
	if _, err := repo.PublishPolicy(ctx, tenant, policy, "principal:policy-admin"); err != nil {
		t.Fatal(err)
	}
	created, err := repo.Create(ctx, tenant, testUUID(t), supplierID, policyID, 1, "principal:requester")
	if err != nil {
		t.Fatal(err)
	}
	assertEarlyExpiryRejected(t, ctx, appDB, tenant, created, 0x43)
	submitted, err := repo.Submit(ctx, tenant, created.CaseID, "principal:requester")
	if err != nil {
		t.Fatal(err)
	}
	assertEarlyExpiryRejected(t, ctx, appDB, tenant, submitted, 0x44)
}

func assertEarlyExpiryRejected(t *testing.T, ctx context.Context, appDB *sql.DB, tenant tenancy.TenantID, current cases.Case, hashByte byte) {
	t.Helper()
	payload, err := json.Marshal(cases.CaseExpiredData{DeadlineAt: current.DeadlineAt.UTC().Format(time.RFC3339Nano)})
	if err != nil {
		t.Fatal(err)
	}
	err = tenancy.WithTenantTx(ctx, appDB, tenant, nil, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO keel_meta.supplier_case_events
			(tenant_id,case_id,aggregate_version,event_type,actor_ref,occurred_at,event_data,previous_hash,event_hash)
			VALUES ($1,$2,$3,'supplier.case.expired','service-principal:keel-supplier-case-expirer',clock_timestamp(),$4,$5,$6)`,
			string(tenant), current.CaseID, current.Version+1, payload, mustDecode(current.LastEventHash), bytesOf(hashByte, 32))
		return err
	})
	if err == nil {
		t.Fatalf("database accepted early expiry for %s case", current.Status)
	}
}
