package postgres

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

func TestPostgreSQLContextLegalHoldLifecycleAndDeletionSerialization(t *testing.T) {
	vaultDB := openLegalHoldTestDB(t, "KEEL_TEST_CONTEXT_VAULT_DATABASE_URL")
	policyDB := openLegalHoldTestDB(t, "KEEL_TEST_CONTEXT_POLICY_DATABASE_URL")
	erasureDB := openLegalHoldTestDB(t, "KEEL_TEST_CONTEXT_ERASURE_DATABASE_URL")
	workerDB := openLegalHoldTestDB(t, "KEEL_TEST_CONTEXT_ERASURE_WORKER_DATABASE_URL")
	holdDB := openLegalHoldTestDB(t, "KEEL_TEST_CONTEXT_LEGAL_HOLD_DATABASE_URL")
	adminDB := openLegalHoldTestDB(t, "KEEL_TEST_ADMIN_DATABASE_URL")
	vault, _ := NewStore(vaultDB)
	erasure, _ := NewErasureStore(erasureDB)
	worker, _ := NewErasureWorkerStore(workerDB)
	holds, _ := NewLegalHoldStore(holdDB)
	ctx := context.Background()
	actor := uuid.NewString()

	tenant := mustTenant(t, uuid.NewString())
	foreignTenant := mustTenant(t, uuid.NewString())
	setRetentionPolicy(t, policyDB, tenant, PurposeReadOnlyReplay, 1, true, 1, uuid.NewString())
	setRetentionPolicy(t, policyDB, foreignTenant, PurposeReadOnlyReplay, 1, true, 1, uuid.NewString())
	scope := testScope(string(tenant), uuid.NewString(), 1)
	if err := vault.Put(ctx, tenant, scope, testEnvelope(), RetentionPolicy{Purpose: PurposeReadOnlyReplay, Version: 1}); err != nil {
		t.Fatalf("put held context: %v", err)
	}
	for _, test := range []struct {
		name, actor, reason string
		interval            int64
	}{
		{name: "invalid actor", actor: "00000000-0000-0000-0000-000000000000", reason: string(LegalHoldLitigation), interval: 1000},
		{name: "invalid reason", actor: actor, reason: "free-form-sensitive-text", interval: 1000},
		{name: "unbounded review", actor: actor, reason: string(LegalHoldLitigation), interval: 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := tenancy.WithTenantTx(ctx, holdDB, tenant, nil, func(tx *sql.Tx) error {
				var holdID string
				return tx.QueryRow(`SELECT hold_id::text FROM keel_meta.create_context_vault_legal_hold($1,1,$2,$3,$4)`,
					scope.RecordID, test.actor, test.reason, test.interval).Scan(&holdID)
			})
			if err == nil {
				t.Fatal("invalid hold actor, reason or review interval was accepted")
			}
		})
	}
	hold, err := holds.Create(ctx, tenant, scope.RecordID, 1, actor, LegalHoldLitigation, time.Second)
	if err != nil || hold.Revision != 1 || hold.ID == "" {
		t.Fatalf("create hold=%+v err=%v", hold, err)
	}
	if err := assertContextErasureJobState(adminDB, tenant, scope.RecordID, "held"); err != nil {
		t.Fatal(err)
	}
	if _, err := holds.Review(ctx, foreignTenant, hold.ID, actor, LegalHoldExtend, LegalHoldLitigation, time.Second); err == nil {
		t.Fatal("cross-tenant hold review succeeded")
	}
	assertLegalHoldCapabilityCannotReadOrWriteVault(t, holdDB, tenant)
	time.Sleep(1100 * time.Millisecond)
	if count, err := erasure.DeleteExpiredBatch(ctx, tenant, 10); err != nil || count != 0 {
		t.Fatalf("overdue unreviewed hold deletion count=%d err=%v", count, err)
	}
	if job, claimed, err := worker.Claim(ctx, tenant, "hold-test-worker", time.Minute); err != nil || claimed {
		t.Fatalf("held job was claimable: job=%+v claimed=%v err=%v", job, claimed, err)
	}
	if err := assertContextErasureJobState(adminDB, tenant, scope.RecordID, "held"); err != nil {
		t.Fatal(err)
	}

	extended, err := holds.Extend(ctx, tenant, hold.ID, actor, LegalHoldInvestigation, 24*time.Hour)
	if err != nil || extended.Revision != 2 || extended.Released || !extended.ReviewDueAt.After(time.Now().Add(23*time.Hour)) {
		t.Fatalf("extend overdue hold=%+v err=%v", extended, err)
	}
	released, err := holds.Release(ctx, tenant, hold.ID, actor, LegalHoldRegulatory)
	if err != nil || released.Revision != 3 || !released.Released {
		t.Fatalf("release hold=%+v err=%v", released, err)
	}
	if err := assertContextErasureJobState(adminDB, tenant, scope.RecordID, "pending"); err != nil {
		t.Fatal(err)
	}
	if count, err := erasure.DeleteExpiredBatch(ctx, tenant, 10); err != nil || count != 1 {
		t.Fatalf("released hold deletion count=%d err=%v", count, err)
	}
	var receiptCount, liveCount, retainedHoldCount int
	if err := adminDB.QueryRow(`SELECT count(*) FROM keel_meta.context_vault_erasure_receipts
		WHERE tenant_id=$1 AND record_id=$2 AND version=1`, string(tenant), scope.RecordID).Scan(&receiptCount); err != nil {
		t.Fatal(err)
	}
	if err := adminDB.QueryRow(`SELECT count(*) FROM keel_meta.context_vault_records
		WHERE tenant_id=$1 AND record_id=$2 AND version=1`, string(tenant), scope.RecordID).Scan(&liveCount); err != nil {
		t.Fatal(err)
	}
	if err := adminDB.QueryRow(`SELECT count(*) FROM keel_meta.context_vault_legal_holds
		WHERE tenant_id=$1 AND hold_id=$2 AND released_at IS NOT NULL`, string(tenant), hold.ID).Scan(&retainedHoldCount); err != nil {
		t.Fatal(err)
	}
	if receiptCount != 1 || liveCount != 0 || retainedHoldCount != 1 {
		t.Fatalf("tombstone/hold audit integrity: receipts=%d live_records=%d retained_holds=%d", receiptCount, liveCount, retainedHoldCount)
	}
	job, claimed, err := worker.Claim(ctx, tenant, "hold-test-worker", time.Minute)
	if err != nil || !claimed {
		t.Fatalf("claim receipt-backed erasure job: job=%+v claimed=%v err=%v", job, claimed, err)
	}
	if outcome, err := worker.Process(ctx, tenant, job); err != nil || outcome != ErasureProcessAlreadyDone {
		t.Fatalf("idempotent receipt completion outcome=%q err=%v", outcome, err)
	}
	if err := assertContextErasureJobState(adminDB, tenant, scope.RecordID, "complete"); err != nil {
		t.Fatal(err)
	}

	var events int
	if err := adminDB.QueryRow(`SELECT count(*) FROM keel_meta.context_vault_legal_hold_events
		WHERE tenant_id=$1 AND hold_id=$2`, string(tenant), hold.ID).Scan(&events); err != nil || events != 3 {
		t.Fatalf("legal hold event count=%d err=%v", events, err)
	}
	var lastAction, lastDecision, lastReason, lastActor string
	var lastRevision int
	if err := adminDB.QueryRow(`SELECT action,decision,reason_code,actor_id::text,revision
		FROM keel_meta.context_vault_legal_hold_events WHERE tenant_id=$1 AND hold_id=$2 ORDER BY revision DESC LIMIT 1`,
		string(tenant), hold.ID).Scan(&lastAction, &lastDecision, &lastReason, &lastActor, &lastRevision); err != nil {
		t.Fatal(err)
	}
	if lastAction != "reviewed" || lastDecision != "release" || lastReason != string(LegalHoldRegulatory) ||
		lastActor != actor || lastRevision != 3 {
		t.Fatalf("last legal hold event action=%s decision=%s reason=%s actor=%s revision=%d",
			lastAction, lastDecision, lastReason, lastActor, lastRevision)
	}
	if _, err := adminDB.Exec(`UPDATE keel_meta.context_vault_legal_hold_events SET reason_code='litigation'
		WHERE tenant_id=$1 AND hold_id=$2 AND revision=1`, string(tenant), hold.ID); err == nil {
		t.Fatal("legal hold event update succeeded")
	}
	if _, err := adminDB.Exec(`DELETE FROM keel_meta.context_vault_legal_hold_events
		WHERE tenant_id=$1 AND hold_id=$2 AND revision=1`, string(tenant), hold.ID); err == nil {
		t.Fatal("legal hold event delete succeeded")
	}

	testLegalHoldWinsDeletionRace(t, ctx, vault, policyDB, holds, erasure, worker, adminDB, mustTenant(t, uuid.NewString()), actor)
	testDeletionWinsLegalHoldRace(t, ctx, vault, policyDB, holds, erasure, mustTenant(t, uuid.NewString()), actor)
	testActiveHoldDoesNotStarveExpiryBatch(t, ctx, vault, policyDB, holds, erasure, adminDB, mustTenant(t, uuid.NewString()), actor)
}

func openLegalHoldTestDB(t *testing.T, env string) *sql.DB {
	t.Helper()
	dsn := os.Getenv(env)
	if dsn == "" {
		t.Skip("set context-vault, context-policy, context-erasure, context-erasure-worker, context-legal-hold and admin URLs for PostgreSQL legal hold integration coverage")
	}
	return openTestDB(t, dsn)
}

func assertLegalHoldCapabilityCannotReadOrWriteVault(t *testing.T, db *sql.DB, tenant tenancy.TenantID) {
	t.Helper()
	var canReadRecords, canReadPolicies, canInsertPolicies, canWriteEvents bool
	err := tenancy.WithTenantTx(context.Background(), db, tenant, nil, func(tx *sql.Tx) error {
		return tx.QueryRow(`SELECT has_table_privilege(current_user,'keel_meta.context_vault_records','SELECT'),
		has_table_privilege(current_user,'keel_meta.context_retention_policies','SELECT'),
		has_table_privilege(current_user,'keel_meta.context_retention_policies','INSERT'),
		has_table_privilege(current_user,'keel_meta.context_vault_legal_hold_events','INSERT')`).Scan(
			&canReadRecords, &canReadPolicies, &canInsertPolicies, &canWriteEvents)
	})
	if err != nil || canReadRecords || canReadPolicies || canInsertPolicies || canWriteEvents {
		t.Fatalf("legal hold capability grants: records_read=%v policies_read=%v policies_insert=%v events_insert=%v err=%v",
			canReadRecords, canReadPolicies, canInsertPolicies, canWriteEvents, err)
	}
	for _, query := range []string{
		`SELECT count(*) FROM keel_meta.context_vault_records`,
		`SELECT count(*) FROM keel_meta.context_retention_policies`,
		`SELECT count(*) FROM keel_meta.context_vault_legal_holds`,
		`SELECT count(*) FROM keel_meta.context_vault_legal_hold_events`,
		`SELECT keel_meta.erase_expired_context_vault(1)`,
	} {
		err := tenancy.WithTenantTx(context.Background(), db, tenant, nil, func(tx *sql.Tx) error {
			var count int
			return tx.QueryRow(query).Scan(&count)
		})
		if err == nil {
			t.Fatalf("legal hold capability had direct access for query %q", query)
		}
	}
}

func testLegalHoldWinsDeletionRace(t *testing.T, ctx context.Context, vault *Store, policyDB *sql.DB,
	holds *LegalHoldStore, erasure *ErasureStore, worker *ErasureWorkerStore, adminDB *sql.DB, tenant tenancy.TenantID, actor string) {
	t.Helper()
	setRetentionPolicy(t, policyDB, tenant, PurposeReadOnlyReplay, 1, true, 1, uuid.NewString())
	scope := testScope(string(tenant), uuid.NewString(), 1)
	if err := vault.Put(ctx, tenant, scope, testEnvelope(), RetentionPolicy{Purpose: PurposeReadOnlyReplay, Version: 1}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)
	staleJob, claimed, err := worker.Claim(ctx, tenant, "race-worker", time.Minute)
	if err != nil || !claimed {
		t.Fatalf("claim before hold-placement race: job=%+v claimed=%v err=%v", staleJob, claimed, err)
	}
	locked := make(chan struct{})
	commit := make(chan struct{})
	writeDone := make(chan error, 1)
	go func() {
		writeDone <- tenancy.WithTenantTx(ctx, holds.db, tenant, nil, func(tx *sql.Tx) error {
			var holdID string
			if err := tx.QueryRow(`SELECT hold_id::text FROM keel_meta.create_context_vault_legal_hold($1,1,$2,'litigation',1000)`,
				scope.RecordID, actor).Scan(&holdID); err != nil {
				return err
			}
			close(locked)
			<-commit
			return nil
		})
	}()
	<-locked
	if count, err := erasure.DeleteExpiredBatch(ctx, tenant, 10); err != nil || count != 0 {
		t.Fatalf("erasure raced through uncommitted hold count=%d err=%v", count, err)
	}
	close(commit)
	if err := <-writeDone; err != nil {
		t.Fatalf("commit concurrent hold placement: %v", err)
	}
	if _, err := worker.Process(ctx, tenant, staleJob); !errors.Is(err, ErrErasureJobLeaseLost) {
		t.Fatalf("worker lease survived legal hold placement: err=%v", err)
	}
	if count, err := erasure.DeleteExpiredBatch(ctx, tenant, 10); err != nil || count != 0 {
		t.Fatalf("erasure deleted active held record count=%d err=%v", count, err)
	}
	if err := assertContextErasureJobState(adminDB, tenant, scope.RecordID, "held"); err != nil {
		t.Fatal(err)
	}
}

func testDeletionWinsLegalHoldRace(t *testing.T, ctx context.Context, vault *Store, policyDB *sql.DB,
	holds *LegalHoldStore, erasure *ErasureStore, tenant tenancy.TenantID, actor string) {
	t.Helper()
	setRetentionPolicy(t, policyDB, tenant, PurposeReadOnlyReplay, 1, true, 1, uuid.NewString())
	scope := testScope(string(tenant), uuid.NewString(), 1)
	if err := vault.Put(ctx, tenant, scope, testEnvelope(), RetentionPolicy{Purpose: PurposeReadOnlyReplay, Version: 1}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)
	erasureLocked := make(chan struct{})
	commit := make(chan struct{})
	erasureDone := make(chan error, 1)
	go func() {
		erasureDone <- tenancy.WithTenantTx(ctx, erasure.db, tenant, nil, func(tx *sql.Tx) error {
			var deleted int
			if err := tx.QueryRow(`SELECT keel_meta.erase_expired_context_vault(10)`).Scan(&deleted); err != nil {
				return err
			}
			if deleted != 1 {
				return errors.New("erasure did not acquire the record first")
			}
			close(erasureLocked)
			<-commit
			return nil
		})
	}()
	<-erasureLocked
	holdDone := make(chan error, 1)
	go func() {
		_, err := holds.Create(ctx, tenant, scope.RecordID, 1, actor, LegalHoldLitigation, time.Second)
		holdDone <- err
	}()
	time.Sleep(100 * time.Millisecond)
	close(commit)
	if err := <-erasureDone; err != nil {
		t.Fatalf("commit concurrent erasure: %v", err)
	}
	if err := <-holdDone; err == nil {
		t.Fatal("legal hold placement succeeded after the exact record was erased")
	}
}

func testActiveHoldDoesNotStarveExpiryBatch(t *testing.T, ctx context.Context, vault *Store, policyDB *sql.DB,
	holds *LegalHoldStore, erasure *ErasureStore, adminDB *sql.DB, tenant tenancy.TenantID, actor string) {
	t.Helper()
	setRetentionPolicy(t, policyDB, tenant, PurposeReadOnlyReplay, 1, true, 1, uuid.NewString())
	heldScope := testScope(string(tenant), uuid.NewString(), 1)
	freeScope := testScope(string(tenant), uuid.NewString(), 1)
	retention := RetentionPolicy{Purpose: PurposeReadOnlyReplay, Version: 1}
	if err := vault.Put(ctx, tenant, heldScope, testEnvelope(), retention); err != nil {
		t.Fatal(err)
	}
	if err := vault.Put(ctx, tenant, freeScope, testEnvelope(), retention); err != nil {
		t.Fatal(err)
	}
	firstHold, err := holds.Create(ctx, tenant, heldScope.RecordID, 1, actor, LegalHoldLitigation, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := holds.Create(ctx, tenant, heldScope.RecordID, 1, actor, LegalHoldInvestigation, time.Second); err != nil {
		t.Fatal(err)
	}
	if _, err := holds.Release(ctx, tenant, firstHold.ID, actor, LegalHoldRegulatory); err != nil {
		t.Fatalf("release one of multiple holds: %v", err)
	}
	if err := assertContextErasureJobState(adminDB, tenant, heldScope.RecordID, "held"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)
	if count, err := erasure.DeleteExpiredBatch(ctx, tenant, 1); err != nil || count != 1 {
		t.Fatalf("held row starved eligible expiry batch count=%d err=%v", count, err)
	}
	var heldCount, freeCount int
	if err := adminDB.QueryRow(`SELECT count(*) FROM keel_meta.context_vault_records
		WHERE tenant_id=$1 AND record_id=$2`, string(tenant), heldScope.RecordID).Scan(&heldCount); err != nil {
		t.Fatal(err)
	}
	if err := adminDB.QueryRow(`SELECT count(*) FROM keel_meta.context_vault_records
		WHERE tenant_id=$1 AND record_id=$2`, string(tenant), freeScope.RecordID).Scan(&freeCount); err != nil {
		t.Fatal(err)
	}
	if heldCount != 1 || freeCount != 0 {
		t.Fatalf("held record count=%d free record count=%d after bounded deletion", heldCount, freeCount)
	}
}

func assertContextErasureJobState(db *sql.DB, tenant tenancy.TenantID, recordID, want string) error {
	var state string
	err := db.QueryRow(`SELECT state FROM keel_meta.context_vault_erasure_jobs
		WHERE tenant_id=$1 AND record_id=$2 AND version=1`, string(tenant), recordID).Scan(&state)
	if err == nil && state != want {
		return errors.New("context erasure job state was " + state + ", want " + want)
	}
	return err
}
