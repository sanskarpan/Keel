package postgres

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
	"github.com/sanskarpan/keel/internal/supplier/cases"
	casepg "github.com/sanskarpan/keel/internal/supplier/cases/postgres"
)

func openRole(t *testing.T, rawURL, role, password string) *sql.DB {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	parsed.User = url.UserPassword(role, password)
	db, err := sql.Open("pgx", parsed.String())
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(4)
	if err := db.PingContext(context.Background()); err != nil {
		_ = db.Close()
		t.Fatalf("connect as %s: %v", role, err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func randomUUID(t *testing.T) string {
	t.Helper()
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		t.Fatal(err)
	}
	raw[6] = (raw[6] & 0x0f) | 0x40
	raw[8] = (raw[8] & 0x3f) | 0x80
	encoded := hex.EncodeToString(raw[:])
	return fmt.Sprintf("%s-%s-%s-%s-%s", encoded[:8], encoded[8:12], encoded[12:16], encoded[16:20], encoded[20:])
}

func TestPostgreSQLWorkflowIntentLeaseOrderingAndFencing(t *testing.T) {
	appURL, workerURL, adminURL := os.Getenv("KEEL_TEST_DATABASE_URL"), os.Getenv("KEEL_TEST_WORKER_DATABASE_URL"), os.Getenv("KEEL_TEST_ADMIN_DATABASE_URL")
	if appURL == "" || workerURL == "" || adminURL == "" {
		t.Skip("set app, worker, and admin PostgreSQL URLs to run workflow dispatch integration tests")
	}
	appDB := openRole(t, appURL, "keel_local_app", "keel-app-local-only")
	workerDB := openRole(t, workerURL, "keel_local_worker", "keel-worker-local-only")
	adminDB := openRole(t, adminURL, "postgres", "keel-local-only")
	caseRepo, err := casepg.New(appDB)
	if err != nil {
		t.Fatal(err)
	}
	repo, err := New(workerDB)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	tenant, _ := tenancy.ParseTenantID(randomUUID(t))
	other, _ := tenancy.ParseTenantID(randomUUID(t))
	policyID, supplierID := randomUUID(t), randomUUID(t)
	policy := cases.Policy{TenantID: string(tenant), PolicyID: policyID, Version: 1, Name: "Dispatch test", Deadline: 48 * time.Hour, Steps: []cases.ReviewStep{{Key: "review", Role: "risk:reviewer"}}}
	if _, err := caseRepo.PublishPolicy(ctx, tenant, policy, "principal:dispatch-test"); err != nil {
		t.Fatal(err)
	}
	created, err := caseRepo.Create(ctx, tenant, randomUUID(t), supplierID, policyID, 1, "principal:dispatch-test")
	if err != nil {
		t.Fatal(err)
	}
	if err := tenancy.WithTenantTx(ctx, appDB, tenant, nil, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `SELECT intent_id FROM keel_meta.supplier_workflow_dispatch LIMIT 1`)
		return err
	}); err == nil {
		t.Fatal("application role unexpectedly accessed mutable workflow delivery state")
	}
	ownerA, ownerB := randomUUID(t), randomUUID(t)
	first, found, err := repo.Claim(ctx, tenant, ownerA, time.Minute)
	if err != nil || !found || first.Version != 1 || first.EventType != "supplier.case.created" || len(first.EventHash) != 64 {
		t.Fatalf("claim first intent: lease=%+v found=%v err=%v", first, found, err)
	}
	if _, found, err := repo.Claim(ctx, tenant, ownerB, time.Minute); err != nil || found {
		t.Fatalf("leased head did not serialize case intents: found=%v err=%v", found, err)
	}
	if _, err := adminDB.ExecContext(ctx, `UPDATE keel_meta.supplier_workflow_dispatch SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE tenant_id=$1 AND intent_id=$2`, string(tenant), first.IntentID); err != nil {
		t.Fatal(err)
	}
	reclaimed, found, err := repo.Claim(ctx, tenant, ownerB, time.Minute)
	if err != nil || !found || reclaimed.IntentID != first.IntentID || reclaimed.Epoch != first.Epoch+1 || reclaimed.Attempt != first.Attempt+1 {
		t.Fatalf("expired intent was not safely reclaimed: lease=%+v found=%v err=%v", reclaimed, found, err)
	}
	if err := repo.Complete(ctx, first); !errors.Is(err, ErrStaleLease) {
		t.Fatalf("stale lease completed after reclaim: %v", err)
	}
	if err := repo.Complete(ctx, reclaimed); err != nil {
		t.Fatal(err)
	}
	if _, err := caseRepo.Submit(ctx, tenant, created.CaseID, "principal:dispatch-test"); err != nil {
		t.Fatal(err)
	}
	second, found, err := repo.Claim(ctx, tenant, ownerA, time.Minute)
	if err != nil || !found || second.Version != 2 || second.EventType != "supplier.case.submitted" {
		t.Fatalf("next case version was not released in order: lease=%+v found=%v err=%v", second, found, err)
	}
	if err := repo.Fail(ctx, second, 10*time.Second, "temporal_timeout"); err != nil {
		t.Fatal(err)
	}
	if _, found, err := repo.Claim(ctx, tenant, ownerB, time.Minute); err != nil || found {
		t.Fatalf("delayed retry became claimable early: found=%v err=%v", found, err)
	}
	if _, err := adminDB.ExecContext(ctx, `UPDATE keel_meta.supplier_workflow_dispatch SET available_at=clock_timestamp()-interval '1 second' WHERE tenant_id=$1 AND intent_id=$2`, string(tenant), second.IntentID); err != nil {
		t.Fatal(err)
	}
	retry, found, err := repo.Claim(ctx, tenant, ownerB, time.Minute)
	if err != nil || !found || retry.Epoch != second.Epoch+1 {
		t.Fatalf("persisted intent did not retry: lease=%+v found=%v err=%v", retry, found, err)
	}
	if err := repo.Complete(ctx, retry); err != nil {
		t.Fatal(err)
	}

	var crossTenantRows int
	if err := tenancy.WithTenantTx(ctx, workerDB, other, nil, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT count(*) FROM keel_meta.supplier_workflow_dispatch WHERE tenant_id=$1`, string(tenant)).Scan(&crossTenantRows)
	}); err != nil {
		t.Fatal(err)
	}
	if crossTenantRows != 0 {
		t.Fatalf("worker saw %d rows outside its transaction tenant", crossTenantRows)
	}
	if err := tenancy.WithTenantTx(ctx, workerDB, tenant, nil, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO keel_meta.supplier_workflow_dispatch (tenant_id,intent_id,case_id,aggregate_version,intent_type,event_hash) VALUES ($1,$2,$3,1,'supplier.case.created',decode(repeat('a',64),'hex'))`, string(tenant), randomUUID(t), randomUUID(t))
		return err
	}); err == nil {
		t.Fatal("workflow worker unexpectedly created dispatch work outside an immutable intent")
	}
	if err := tenancy.WithTenantTx(ctx, workerDB, tenant, nil, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `DELETE FROM keel_meta.supplier_workflow_dispatch WHERE tenant_id=$1 AND intent_id=$2`, string(tenant), first.IntentID)
		return err
	}); err == nil {
		t.Fatal("workflow worker unexpectedly deleted durable dispatch evidence")
	}
}
