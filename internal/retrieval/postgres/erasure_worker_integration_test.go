package postgres

import (
	"context"
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
	if err != nil || request.State != "fenced" || request.AttemptCount != 0 {
		t.Fatalf("withdrawal request=%+v err=%v", request, err)
	}

	if _, claimed, err := app.ClaimErasureJob(ctx, tenant, visibility, "app-role", 3*time.Second); err == nil || claimed {
		t.Fatalf("app role unexpectedly claimed cleanup work: claimed=%t err=%v", claimed, err)
	}
	claim, claimed, err := worker.ClaimErasureJob(ctx, tenant, visibility, "eraser-a", 3*time.Second)
	if err != nil || !claimed || claim.State != "cleanup_pending" || claim.AttemptCount != 1 || claim.LeaseEpoch != 1 || !claim.LeaseOwner.Valid {
		t.Fatalf("first erasure claim=%+v claimed=%t err=%v", claim, claimed, err)
	}
	if _, claimed, err := worker.ClaimErasureJob(ctx, tenant, visibility, "eraser-b", 3*time.Second); err != nil || claimed {
		t.Fatalf("live lease was claimed twice: claimed=%t err=%v", claimed, err)
	}
	if _, err := worker.CompleteErasureJob(ctx, tenant, visibility, "eraser-b", claim.ID, claim.LeaseEpoch); !errors.Is(err, ErrErasureLeaseLost) {
		t.Fatalf("different worker completed live lease: %v", err)
	}
	renewed, err := worker.RenewErasureJobLease(ctx, tenant, visibility, "eraser-a", claim.ID, claim.LeaseEpoch, 4*time.Second)
	if err != nil || renewed.LeaseEpoch != claim.LeaseEpoch || renewed.AttemptCount != claim.AttemptCount || !renewed.LeaseUntil.Time.After(claim.LeaseUntil.Time) {
		t.Fatalf("lease renewal=%+v err=%v", renewed, err)
	}

	retry, err := worker.RetryErasureJob(ctx, tenant, visibility, "eraser-a", claim.ID, claim.LeaseEpoch, "object_store_timeout", time.Second)
	if err != nil || retry.State != "cleanup_pending" || retry.LeaseOwner.Valid || !retry.LastErrorCode.Valid || retry.LastErrorCode.String != "object_store_timeout" {
		t.Fatalf("scheduled retry=%+v err=%v", retry, err)
	}
	if _, claimed, err := worker.ClaimErasureJob(ctx, tenant, visibility, "eraser-b", 3*time.Second); err != nil || claimed {
		t.Fatalf("job bypassed retry backoff: claimed=%t err=%v", claimed, err)
	}
	if delay := time.Until(retry.AvailableAt); delay > 0 {
		time.Sleep(delay + 20*time.Millisecond)
	}
	second, claimed, err := worker.ClaimErasureJob(ctx, tenant, visibility, "eraser-b", 3*time.Second)
	if err != nil || !claimed || second.AttemptCount != 2 || second.LeaseEpoch != claim.LeaseEpoch+1 {
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
	if err != nil || loaded.State != "blocked" || loaded.AttemptCount != 2 || loaded.LeaseEpoch != 2 {
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
		if err != nil || !claimed || claim.AttemptCount != attempt {
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
		if err != nil || retry.AttemptCount != attempt {
			t.Fatalf("retry after attempt %d: job=%+v err=%v", attempt, retry, err)
		}
		if delay := time.Until(retry.AvailableAt); delay > 0 {
			time.Sleep(delay + 20*time.Millisecond)
		}
	}
	blocked, err := app.ErasureJob(ctx, tenant, visibility, request.ID)
	if err != nil || blocked.State != "blocked" || blocked.AttemptCount != MaxErasureAttempts ||
		!blocked.BlockedAt.Valid || !blocked.LastErrorCode.Valid || blocked.LastErrorCode.String != "attempts_exhausted" {
		t.Fatalf("exhausted erasure state=%+v err=%v", blocked, err)
	}
}
