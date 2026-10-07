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

func TestPostgreSQLContextErasureJobTenantScopeFencingRetryAndAtomicCompletion(t *testing.T) {
	vaultDSN := os.Getenv("KEEL_TEST_CONTEXT_VAULT_DATABASE_URL")
	policyDSN := os.Getenv("KEEL_TEST_CONTEXT_POLICY_DATABASE_URL")
	workerDSN := os.Getenv("KEEL_TEST_CONTEXT_ERASURE_WORKER_DATABASE_URL")
	adminDSN := os.Getenv("KEEL_TEST_ADMIN_DATABASE_URL")
	if vaultDSN == "" || policyDSN == "" || workerDSN == "" || adminDSN == "" {
		t.Skip("set context-vault, context-policy, context-erasure-worker and admin database URLs for PostgreSQL integration coverage")
	}
	vaultDB := openTestDB(t, vaultDSN)
	policyDB := openTestDB(t, policyDSN)
	workerDB := openTestDB(t, workerDSN)
	adminDB := openTestDB(t, adminDSN)
	store, err := NewStore(vaultDB)
	if err != nil {
		t.Fatal(err)
	}
	worker, err := NewErasureWorkerStore(workerDB)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	tenantA := mustTenant(t, uuid.NewString())
	tenantB := mustTenant(t, uuid.NewString())
	setRetentionPolicy(t, policyDB, tenantA, PurposeReadOnlyReplay, 1, true, 3, uuid.NewString())
	setRetentionPolicy(t, policyDB, tenantB, PurposeReadOnlyReplay, 1, true, 3, uuid.NewString())
	scopeA := testScope(string(tenantA), uuid.NewString(), 1)
	scopeB := testScope(string(tenantB), uuid.NewString(), 1)
	if err := store.Put(ctx, tenantA, scopeA, testEnvelope(), RetentionPolicy{Purpose: PurposeReadOnlyReplay, Version: 1}); err != nil {
		t.Fatalf("put tenant A context: %v", err)
	}
	if err := store.Put(ctx, tenantB, scopeB, testEnvelope(), RetentionPolicy{Purpose: PurposeReadOnlyReplay, Version: 1}); err != nil {
		t.Fatalf("put tenant B context: %v", err)
	}
	if job, claimed, err := worker.Claim(ctx, tenantA, "worker-a", time.Second); err != nil || claimed {
		t.Fatalf("claimed before database expiry: job=%+v claimed=%v err=%v", job, claimed, err)
	}
	time.Sleep(3100 * time.Millisecond)

	jobA, claimed, err := worker.Claim(ctx, tenantA, "worker-a", time.Second)
	if err != nil || !claimed || jobA.TenantID != tenantA || jobA.RecordID != scopeA.RecordID || jobA.LeaseEpoch != 1 || jobA.Failures != 0 {
		t.Fatalf("tenant A claim: job=%+v claimed=%v err=%v", jobA, claimed, err)
	}
	jobB, claimed, err := worker.Claim(ctx, tenantB, "worker-b", 5*time.Minute)
	if err != nil || !claimed || jobB.TenantID != tenantB || jobB.RecordID != scopeB.RecordID {
		t.Fatalf("tenant A scope leaked or tenant B job missing: job=%+v claimed=%v err=%v", jobB, claimed, err)
	}
	if job, claimed, err := worker.Claim(ctx, tenantA, "worker-b", time.Second); err != nil || claimed {
		t.Fatalf("second worker duplicated a live claim: job=%+v claimed=%v err=%v", job, claimed, err)
	}
	time.Sleep(1100 * time.Millisecond)
	jobA2, claimed, err := worker.Claim(ctx, tenantA, "worker-b", time.Second)
	if err != nil || !claimed || jobA2.LeaseEpoch != jobA.LeaseEpoch+1 || jobA2.Failures != 1 {
		t.Fatalf("expired lease was not fenced on takeover: job=%+v claimed=%v err=%v", jobA2, claimed, err)
	}
	jobA.WorkerID = "worker-a"
	if _, err := worker.Process(ctx, tenantA, jobA); !errors.Is(err, ErrErasureJobLeaseLost) {
		t.Fatalf("stale worker process error=%v, want lease lost", err)
	}
	jobA2.WorkerID = "worker-b"
	if deleted, err := worker.Process(ctx, tenantA, jobA2); err != nil || !deleted {
		t.Fatalf("fenced worker deletion deleted=%v err=%v", deleted, err)
	}
	assertErasureJobTerminalState(t, adminDB, tenantA, scopeA.RecordID, "complete")

	jobB.WorkerID = "worker-b"
	rollbackCause := errors.New("force erasure job rollback")
	err = tenancy.WithTenantTx(ctx, workerDB, tenantB, nil, func(tx *sql.Tx) error {
		deleted, err := worker.ProcessTx(ctx, tx, tenantB, jobB)
		if err != nil {
			return err
		}
		if !deleted {
			t.Fatal("job reported an already-deleted record before rollback")
		}
		return rollbackCause
	})
	if !errors.Is(err, rollbackCause) {
		t.Fatalf("job processing rollback error=%v", err)
	}
	var receiptCount, liveCount int
	if err := adminDB.QueryRowContext(ctx, `SELECT count(*) FROM keel_meta.context_vault_erasure_receipts
		WHERE tenant_id=$1 AND record_id=$2 AND version=1`, string(tenantB), scopeB.RecordID).Scan(&receiptCount); err != nil || receiptCount != 0 {
		t.Fatalf("rolled-back job left receipt count=%d err=%v", receiptCount, err)
	}
	if err := adminDB.QueryRowContext(ctx, `SELECT count(*) FROM keel_meta.context_vault_records
		WHERE tenant_id=$1 AND record_id=$2 AND version=1`, string(tenantB), scopeB.RecordID).Scan(&liveCount); err != nil || liveCount != 1 {
		t.Fatalf("rolled-back job removed ciphertext: live_count=%d err=%v", liveCount, err)
	}
	if deleted, err := worker.Process(ctx, tenantB, jobB); err != nil || !deleted {
		t.Fatalf("retry job deletion deleted=%v err=%v", deleted, err)
	}
	assertErasureJobTerminalState(t, adminDB, tenantB, scopeB.RecordID, "complete")

	directReadErr := tenancy.WithTenantTx(ctx, workerDB, tenantB, nil, func(tx *sql.Tx) error {
		var count int
		return tx.QueryRowContext(ctx, `SELECT count(*) FROM keel_meta.context_vault_records`).Scan(&count)
	})
	if directReadErr == nil {
		t.Fatal("context erasure worker could directly read vault ciphertext")
	}
	directJobReadErr := tenancy.WithTenantTx(ctx, workerDB, tenantB, nil, func(tx *sql.Tx) error {
		var count int
		return tx.QueryRowContext(ctx, `SELECT count(*) FROM keel_meta.context_vault_erasure_jobs`).Scan(&count)
	})
	if directJobReadErr == nil {
		t.Fatal("context erasure worker could directly enumerate queue metadata")
	}
	directDeleteErr := tenancy.WithTenantTx(ctx, workerDB, tenantB, nil, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `DELETE FROM keel_meta.context_vault_records WHERE tenant_id=$1`, string(tenantB))
		return err
	})
	if directDeleteErr == nil {
		t.Fatal("context erasure worker could directly delete vault ciphertext")
	}
	directBatchErr := tenancy.WithTenantTx(ctx, workerDB, tenantB, nil, func(tx *sql.Tx) error {
		var count int
		return tx.QueryRowContext(ctx, `SELECT keel_meta.erase_expired_context_vault(1)`).Scan(&count)
	})
	if directBatchErr == nil {
		t.Fatal("context erasure worker bypassed the fenced job transition")
	}

	tenantD := mustTenant(t, uuid.NewString())
	setRetentionPolicy(t, policyDB, tenantD, PurposeReadOnlyReplay, 1, true, 1, uuid.NewString())
	scopeD := testScope(string(tenantD), uuid.NewString(), 1)
	if err := store.Put(ctx, tenantD, scopeD, testEnvelope(), RetentionPolicy{Purpose: PurposeReadOnlyReplay, Version: 1}); err != nil {
		t.Fatalf("put concurrent-claim context: %v", err)
	}
	time.Sleep(1100 * time.Millisecond)
	type claimResult struct {
		claimed bool
		err     error
	}
	concurrentResult := make(chan claimResult, 1)
	err = tenancy.WithTenantTx(ctx, workerDB, tenantD, nil, func(tx *sql.Tx) error {
		first, claimed, err := worker.ClaimTx(ctx, tx, tenantD, "worker-d1", time.Minute)
		if err != nil || !claimed || first.RecordID != scopeD.RecordID {
			t.Fatalf("transactional first claim: job=%+v claimed=%v err=%v", first, claimed, err)
		}
		go func() {
			_, claimed, err := worker.Claim(ctx, tenantD, "worker-d2", time.Minute)
			concurrentResult <- claimResult{claimed: claimed, err: err}
		}()
		select {
		case result := <-concurrentResult:
			if result.err != nil || result.claimed {
				return errors.New("concurrent worker duplicated a locked context erasure claim")
			}
		case <-time.After(5 * time.Second):
			return errors.New("concurrent context erasure claim timed out")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("concurrent claim transaction: %v", err)
	}

	tenantC := mustTenant(t, uuid.NewString())
	setRetentionPolicy(t, policyDB, tenantC, PurposeReadOnlyReplay, 1, true, 1, uuid.NewString())
	scopeC := testScope(string(tenantC), uuid.NewString(), 1)
	if err := store.Put(ctx, tenantC, scopeC, testEnvelope(), RetentionPolicy{Purpose: PurposeReadOnlyReplay, Version: 1}); err != nil {
		t.Fatalf("put retry-exhaustion context: %v", err)
	}
	time.Sleep(1100 * time.Millisecond)
	job, claimed, err := worker.Claim(ctx, tenantC, "worker-c", time.Second)
	if err != nil || !claimed {
		t.Fatalf("initial retry-exhaustion claim: claimed=%v err=%v", claimed, err)
	}
	job.WorkerID = "worker-c"
	for failure := 1; failure <= MaxErasureJobFailures; failure++ {
		state, err := worker.Retry(ctx, tenantC, job, "delete_failed", MinErasureJobBackoff)
		if err != nil {
			t.Fatalf("persist failure %d: %v", failure, err)
		}
		if failure == MaxErasureJobFailures {
			if state != "blocked" {
				t.Fatalf("failure %d state=%q, want blocked", failure, state)
			}
			break
		}
		if state != "pending" {
			t.Fatalf("failure %d state=%q, want pending", failure, state)
		}
		time.Sleep(MinErasureJobBackoff + 100*time.Millisecond)
		job, claimed, err = worker.Claim(ctx, tenantC, "worker-c", time.Second)
		if err != nil || !claimed || job.Failures != failure {
			t.Fatalf("claim after failure %d: job=%+v claimed=%v err=%v", failure, job, claimed, err)
		}
		job.WorkerID = "worker-c"
	}
	if job, claimed, err := worker.Claim(ctx, tenantC, "worker-c", time.Second); err != nil || claimed {
		t.Fatalf("blocked job became claimable: job=%+v claimed=%v err=%v", job, claimed, err)
	}
	assertErasureJobTerminalState(t, adminDB, tenantC, scopeC.RecordID, "blocked")
}

func assertErasureJobTerminalState(t *testing.T, db *sql.DB, tenant tenancy.TenantID, recordID, want string) {
	t.Helper()
	var state string
	if err := db.QueryRow(`SELECT state FROM keel_meta.context_vault_erasure_jobs
		WHERE tenant_id=$1 AND record_id=$2 AND version=1`, string(tenant), recordID).Scan(&state); err != nil || state != want {
		t.Fatalf("context erasure job state=%q want=%q err=%v", state, want, err)
	}
}
