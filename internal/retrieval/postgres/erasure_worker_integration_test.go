package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
	"github.com/sanskarpan/keel/internal/retrieval/index"
)

func TestPostgreSQLErasureWorkerLeaseRetryAndPoisonState(t *testing.T) {
	appDB, indexerDB := retrievalTestDBs(t)
	app, err := New(appDB)
	if err != nil {
		t.Fatal(err)
	}
	worker, err := New(indexerDB)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	tenant := tenancy.TenantID(uuid.NewString())
	visibility := "erasure:" + uuid.NewString()
	hasher, err := index.NewHMACTermHasher(string(tenant), "erasure-worker-v1", []byte(strings.Repeat("e", 32)))
	if err != nil {
		t.Fatal(err)
	}
	chunk := preparedChunk(t, hasher, uuid.New(), "source to erase after withdrawal")
	createReadyBuild(t, worker, tenant, visibility, buildSpec(uuid.New(), hasher.KeyID(), 1), chunk)
	request, err := app.WithdrawSource(ctx, tenant, visibility, uuid.New(), chunk.DocumentVersionID, uuid.New())
	if err != nil || request.State != "fenced" || request.AttemptCount != 0 || request.FailureCount != 0 {
		t.Fatalf("withdrawal request=%+v err=%v", request, err)
	}
	scope, err := newScope(tenant, visibility)
	if err != nil {
		t.Fatal(err)
	}
	var actionCount int
	if err := withScope(ctx, appDB, scope, nil, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT count(*) FROM keel_meta.retrieval_erasure_action_manifest
			WHERE tenant_id=$1 AND visibility_key=$2 AND job_id=$3`, string(tenant), visibility, request.ID).Scan(&actionCount)
	}); err != nil || actionCount != 6 {
		t.Fatalf("seeded action manifest count=%d err=%v", actionCount, err)
	}

	if _, claimed, err := app.ClaimErasureJob(ctx, tenant, visibility, "app-role", 3*time.Second); err == nil || claimed {
		t.Fatalf("app role unexpectedly claimed cleanup work: claimed=%t err=%v", claimed, err)
	}
	claim, claimed, err := worker.ClaimErasureJob(ctx, tenant, visibility, "eraser-a", 3*time.Second)
	if err != nil || !claimed || claim.State != "cleanup_pending" || claim.AttemptCount != 1 || claim.FailureCount != 0 ||
		claim.LeaseEpoch != 1 || !claim.LeaseOwner.Valid {
		t.Fatalf("first erasure claim=%+v claimed=%t err=%v", claim, claimed, err)
	}
	if _, claimed, err := worker.ClaimErasureJob(ctx, tenant, visibility, "eraser-b", 3*time.Second); err != nil || claimed {
		t.Fatalf("live lease was claimed twice: claimed=%t err=%v", claimed, err)
	}
	if _, err := worker.CompleteErasureJob(ctx, tenant, visibility, "eraser-b", claim.ID, claim.LeaseEpoch); !errors.Is(err, ErrErasureLeaseLost) {
		t.Fatalf("different worker completed live lease: %v", err)
	}
	renewed, err := worker.RenewErasureJobLease(ctx, tenant, visibility, "eraser-a", claim.ID, claim.LeaseEpoch, 4*time.Second)
	if err != nil || renewed.LeaseEpoch != claim.LeaseEpoch || renewed.AttemptCount != claim.AttemptCount ||
		renewed.FailureCount != claim.FailureCount || !renewed.LeaseUntil.Time.After(claim.LeaseUntil.Time) {
		t.Fatalf("lease renewal=%+v err=%v", renewed, err)
	}

	retry, err := worker.RetryErasureJob(ctx, tenant, visibility, "eraser-a", claim.ID, claim.LeaseEpoch, "object_store_timeout", time.Second)
	if err != nil || retry.State != "cleanup_pending" || retry.LeaseOwner.Valid || !retry.LastErrorCode.Valid || retry.LastErrorCode.String != "object_store_timeout" {
		t.Fatalf("scheduled retry=%+v err=%v", retry, err)
	}
	if retry.AttemptCount != claim.AttemptCount || retry.FailureCount != 1 {
		t.Fatalf("failed action counters=%+v", retry)
	}
	if _, claimed, err := worker.ClaimErasureJob(ctx, tenant, visibility, "eraser-b", 3*time.Second); err != nil || claimed {
		t.Fatalf("job bypassed retry backoff: claimed=%t err=%v", claimed, err)
	}
	if _, err := worker.BlockErasureJob(ctx, tenant, visibility, "eraser-a", claim.ID, claim.LeaseEpoch, "legal_hold_active"); !errors.Is(err, ErrErasureLeaseLost) {
		t.Fatalf("released stale worker blocked a retried job: %v", err)
	}
	if delay := time.Until(retry.AvailableAt); delay > 0 {
		time.Sleep(delay + 20*time.Millisecond)
	}
	second, claimed, err := worker.ClaimErasureJob(ctx, tenant, visibility, "eraser-b", 3*time.Second)
	if err != nil || !claimed || second.AttemptCount != 2 || second.FailureCount != 1 || second.LeaseEpoch != claim.LeaseEpoch+1 {
		t.Fatalf("second erasure claim=%+v claimed=%t err=%v", second, claimed, err)
	}
	if _, err := worker.CompleteErasureJob(ctx, tenant, visibility, "eraser-a", claim.ID, claim.LeaseEpoch); !errors.Is(err, ErrErasureLeaseLost) {
		t.Fatalf("stale worker completed reclaimed job: %v", err)
	}
	blocked, err := worker.BlockErasureJob(ctx, tenant, visibility, "eraser-b", second.ID, second.LeaseEpoch, "legal_hold")
	if err != nil || blocked.State != "blocked" || !blocked.BlockedAt.Valid || blocked.LeaseOwner.Valid || blocked.LastErrorCode.String != "legal_hold" {
		t.Fatalf("blocked erasure job=%+v err=%v", blocked, err)
	}
	if _, claimed, err := worker.ClaimErasureJob(ctx, tenant, visibility, "eraser-c", 3*time.Second); err != nil || claimed {
		t.Fatalf("blocked poison job was reclaimed: claimed=%t err=%v", claimed, err)
	}
	loaded, err := app.ErasureJob(ctx, tenant, visibility, request.ID)
	if err != nil || loaded.State != "blocked" || loaded.AttemptCount != 2 || loaded.FailureCount != 1 || loaded.LeaseEpoch != 2 {
		t.Fatalf("durable blocked state=%+v err=%v", loaded, err)
	}

	secondChunk := preparedChunk(t, hasher, uuid.New(), "separate source erasure completion")
	secondBuild := buildSpec(uuid.New(), hasher.KeyID(), 1)
	createReadyBuild(t, worker, tenant, visibility, secondBuild, secondChunk)
	completedRequest, err := app.WithdrawSource(ctx, tenant, visibility, uuid.New(), secondChunk.DocumentVersionID, uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	completionClaim, claimed, err := worker.ClaimErasureJob(ctx, tenant, visibility, "eraser-a", 3*time.Second)
	if err != nil || !claimed || completionClaim.ID != completedRequest.ID {
		t.Fatalf("completion claim=%+v claimed=%t err=%v", completionClaim, claimed, err)
	}
	if _, err := worker.CompleteErasureJob(ctx, tenant, visibility, "eraser-a", completionClaim.ID, completionClaim.LeaseEpoch); !errors.Is(err, ErrErasureActionManifestIncomplete) {
		t.Fatalf("job completed without action receipts: %v", err)
	}
	actorID := uuid.New()
	if _, err := worker.RecordErasureActionReceipt(ctx, tenant, visibility, "eraser-a", completionClaim.ID,
		completionClaim.LeaseEpoch, ErasureActionLegalHoldCheck, ErasureReceiptNotApplicable, actorID,
		"no hold adapter", sha256.Sum256([]byte("invalid legal hold decision"))); err == nil {
		t.Fatal("legal hold check was accepted as not applicable")
	}
	for _, action := range []string{ErasureActionLegalHoldCheck, ErasureActionSupplierSourceObject, ErasureActionDerivedIndex, ErasureActionBackupExpiry} {
		if _, err := worker.RecordErasureActionReceipt(ctx, tenant, visibility, "eraser-a", completionClaim.ID,
			completionClaim.LeaseEpoch, action, ErasureReceiptNotApplicable, actorID,
			"provider not configured", sha256.Sum256([]byte("invalid N/A:"+action))); err == nil {
			t.Fatalf("required action %s was accepted as not applicable by repository", action)
		}
		// Bypass the Go method to prove PostgreSQL itself rejects a forged worker
		// receipt that would otherwise satisfy the immutable manifest guard.
		directDigest := sha256.Sum256([]byte("direct N/A:" + action))
		err := withScope(ctx, indexerDB, scope, nil, func(tx *sql.Tx) error {
			_, err := tx.ExecContext(ctx, `INSERT INTO keel_meta.retrieval_erasure_action_receipts
				(tenant_id,visibility_key,job_id,action_key,lease_owner,lease_epoch,disposition,decision_actor_id,decision_reason,receipt_sha256)
				VALUES ($1,$2,$3,$4,$5,$6,'not_applicable',$7,'provider not configured',$8)`,
				string(tenant), visibility, completionClaim.ID, action, "eraser-a", completionClaim.LeaseEpoch,
				actorID, directDigest[:])
			return err
		})
		if err == nil {
			t.Fatalf("PostgreSQL accepted direct not-applicable receipt for required action %s", action)
		}
	}
	if _, err := worker.RecordErasureActionReceipt(ctx, tenant, visibility, "eraser-b", completionClaim.ID,
		completionClaim.LeaseEpoch, ErasureActionLegalHoldCheck, ErasureReceiptComplete, actorID,
		"", sha256.Sum256([]byte("stale worker"))); err == nil {
		t.Fatal("receipt from a non-owner worker was accepted")
	}
	if _, err := worker.RecordErasureActionReceipt(ctx, tenancy.TenantID(uuid.NewString()), visibility, "eraser-a", completionClaim.ID,
		completionClaim.LeaseEpoch, ErasureActionLegalHoldCheck, ErasureReceiptComplete, actorID,
		"", sha256.Sum256([]byte("cross-tenant"))); err == nil {
		t.Fatal("cross-tenant receipt was accepted")
	}
	actions := []struct {
		key, disposition, reason string
	}{
		{ErasureActionLegalHoldCheck, ErasureReceiptComplete, ""},
		{ErasureActionSupplierSourceObject, ErasureReceiptComplete, ""},
		{ErasureActionDerivedIndex, ErasureReceiptComplete, ""},
		{ErasureActionCacheRevocation, ErasureReceiptNotApplicable, "synthetic fixture has no content cache"},
		{ErasureActionQueuedWorkRevocation, ErasureReceiptNotApplicable, "synthetic fixture has no queued retrieval work"},
		{ErasureActionBackupExpiry, ErasureReceiptComplete, ""},
	}
	for _, action := range actions {
		digest := sha256.Sum256([]byte("test receipt:" + action.key))
		receipt, err := worker.RecordErasureActionReceipt(ctx, tenant, visibility, "eraser-a", completionClaim.ID,
			completionClaim.LeaseEpoch, action.key, action.disposition, actorID, action.reason, digest)
		if err != nil || receipt.ActionKey != action.key || receipt.LeaseOwner != "eraser-a" {
			t.Fatalf("record receipt %s: receipt=%+v err=%v", action.key, receipt, err)
		}
		if action.key == ErasureActionLegalHoldCheck {
			replayed, err := worker.RecordErasureActionReceipt(ctx, tenant, visibility, "eraser-a", completionClaim.ID,
				completionClaim.LeaseEpoch, action.key, action.disposition, actorID, action.reason, digest)
			if err != nil || replayed.RecordedAt != receipt.RecordedAt {
				t.Fatalf("identical receipt replay was not idempotent: replay=%+v err=%v", replayed, err)
			}
			if _, err := worker.RecordErasureActionReceipt(ctx, tenant, visibility, "eraser-a", completionClaim.ID,
				completionClaim.LeaseEpoch, action.key, action.disposition, actorID, action.reason, sha256.Sum256([]byte("tampered"))); !errors.Is(err, ErrErasureActionReceiptConflict) {
				t.Fatalf("conflicting receipt replay was accepted: %v", err)
			}
		}
	}
	if err := withScope(ctx, indexerDB, scope, nil, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE keel_meta.retrieval_erasure_action_receipts
			SET disposition='not_applicable',decision_reason='tampered'
			WHERE tenant_id=$1 AND visibility_key=$2 AND job_id=$3 AND action_key=$4`,
			string(tenant), visibility, completionClaim.ID, ErasureActionLegalHoldCheck)
		return err
	}); err == nil {
		t.Fatal("indexer modified an immutable erasure action receipt")
	}
	completed, err := worker.CompleteErasureJob(ctx, tenant, visibility, "eraser-a", completionClaim.ID, completionClaim.LeaseEpoch)
	if err != nil || completed.State != "complete" || !completed.CompletedAt.Valid || completed.LeaseOwner.Valid {
		t.Fatalf("completed erasure job=%+v err=%v", completed, err)
	}
	if _, err := worker.CompleteErasureJob(ctx, tenant, visibility, "eraser-a", completionClaim.ID, completionClaim.LeaseEpoch); !errors.Is(err, ErrErasureLeaseLost) {
		t.Fatalf("duplicate completion bypassed terminal state: %v", err)
	}
}

func TestPostgreSQLErasureWorkerBlocksAnExpiredFinalAttempt(t *testing.T) {
	appDB, indexerDB := retrievalTestDBs(t)
	app, err := New(appDB)
	if err != nil {
		t.Fatal(err)
	}
	worker, err := New(indexerDB)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	tenant := tenancy.TenantID(uuid.NewString())
	visibility := "erasure-exhaust:" + uuid.NewString()
	hasher, err := index.NewHMACTermHasher(string(tenant), "erasure-exhaust-v1", []byte(strings.Repeat("x", 32)))
	if err != nil {
		t.Fatal(err)
	}
	chunk := preparedChunk(t, hasher, uuid.New(), "retry budget exhaustion source")
	createReadyBuild(t, worker, tenant, visibility, buildSpec(uuid.New(), hasher.KeyID(), 1), chunk)
	request, err := app.WithdrawSource(ctx, tenant, visibility, uuid.New(), chunk.DocumentVersionID, uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	for attempt := 1; attempt <= MaxErasureAttempts; attempt++ {
		claim, claimed, err := worker.ClaimErasureJob(ctx, tenant, visibility, "eraser-budget", time.Second)
		if err != nil || !claimed || claim.AttemptCount != attempt || claim.FailureCount != attempt-1 {
			t.Fatalf("claim attempt %d: claim=%+v claimed=%t err=%v", attempt, claim, claimed, err)
		}
		if attempt == MaxErasureAttempts {
			if delay := time.Until(claim.LeaseUntil.Time); delay > 0 {
				time.Sleep(delay + 20*time.Millisecond)
			}
			if _, claimed, err := worker.ClaimErasureJob(ctx, tenant, visibility, "eraser-budget", time.Second); err != nil || claimed {
				t.Fatalf("expired final attempt was re-leased: claimed=%t err=%v", claimed, err)
			}
			break
		}
		retry, err := worker.RetryErasureJob(ctx, tenant, visibility, "eraser-budget", claim.ID, claim.LeaseEpoch, "cleanup_retry", time.Second)
		if err != nil || retry.AttemptCount != attempt || retry.FailureCount != attempt {
			t.Fatalf("retry after attempt %d: job=%+v err=%v", attempt, retry, err)
		}
		if delay := time.Until(retry.AvailableAt); delay > 0 {
			time.Sleep(delay + 20*time.Millisecond)
		}
	}
	blocked, err := app.ErasureJob(ctx, tenant, visibility, request.ID)
	if err != nil || blocked.State != "blocked" || blocked.AttemptCount != MaxErasureAttempts || blocked.FailureCount != MaxErasureAttempts ||
		!blocked.BlockedAt.Valid || !blocked.LastErrorCode.Valid || blocked.LastErrorCode.String != "attempts_exhausted" {
		t.Fatalf("exhausted erasure state=%+v err=%v", blocked, err)
	}
}
