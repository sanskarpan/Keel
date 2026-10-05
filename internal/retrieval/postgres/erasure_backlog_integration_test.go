package postgres

import (
	"context"
	"crypto/sha256"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
	"github.com/sanskarpan/keel/internal/retrieval/index"
)

func TestPostgreSQLErasureBacklogIsScopedBoundedAndClassified(t *testing.T) {
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
	visibility := "erasure-backlog:" + uuid.NewString()
	hasher, err := index.NewHMACTermHasher(string(tenant), "erasure-backlog-v1", []byte(strings.Repeat("b", 32)))
	if err != nil {
		t.Fatal(err)
	}
	request := func(text string) ErasureJob {
		t.Helper()
		chunk := preparedChunk(t, hasher, uuid.New(), text)
		createReadyBuild(t, worker, tenant, visibility, buildSpec(uuid.New(), hasher.KeyID(), 1), chunk)
		job, err := app.WithdrawSource(ctx, tenant, visibility, uuid.New(), chunk.DocumentVersionID, uuid.New())
		if err != nil {
			t.Fatal(err)
		}
		return job
	}
	complete := func(job ErasureJob) {
		t.Helper()
		claim, claimed, err := worker.ClaimErasureJob(ctx, tenant, visibility, "backlog-worker", 30*time.Second)
		if err != nil || !claimed || claim.ID != job.ID {
			t.Fatalf("claim for completed fixture=%+v claimed=%t err=%v", claim, claimed, err)
		}
		actor := uuid.New()
		for _, action := range []string{ErasureActionLegalHoldCheck, ErasureActionSupplierSourceObject, ErasureActionDerivedIndex,
			ErasureActionCacheRevocation, ErasureActionQueuedWorkRevocation, ErasureActionBackupExpiry} {
			if _, err := worker.RecordErasureActionReceipt(ctx, tenant, visibility, "backlog-worker", claim.ID, claim.LeaseEpoch,
				action, ErasureReceiptComplete, actor, "", sha256.Sum256([]byte("synthetic:"+action))); err != nil {
				t.Fatalf("record synthetic %s receipt: %v", action, err)
			}
		}
		if completed, err := worker.CompleteErasureJob(ctx, tenant, visibility, "backlog-worker", claim.ID, claim.LeaseEpoch); err != nil || completed.State != "complete" {
			t.Fatalf("complete backlog fixture=%+v err=%v", completed, err)
		}
	}

	completedJob := request("completed backlog fixture")
	complete(completedJob)
	request("fenced backlog fixture one")
	request("fenced backlog fixture two")
	request("deferred backlog fixture")
	request("blocked backlog fixture")
	request("leased backlog fixture")

	first, claimed, err := worker.ClaimErasureJob(ctx, tenant, visibility, "backlog-worker", 30*time.Second)
	if err != nil || !claimed {
		t.Fatalf("claim for blocked fixture=%+v claimed=%t err=%v", first, claimed, err)
	}
	if _, err := worker.BlockErasureJob(ctx, tenant, visibility, "backlog-worker", first.ID, first.LeaseEpoch, "synthetic_terminal"); err != nil {
		t.Fatalf("block backlog fixture: %v", err)
	}
	second, claimed, err := worker.ClaimErasureJob(ctx, tenant, visibility, "backlog-worker", 30*time.Second)
	if err != nil || !claimed {
		t.Fatalf("claim for deferred fixture=%+v claimed=%t err=%v", second, claimed, err)
	}
	if _, err := worker.RetryErasureJob(ctx, tenant, visibility, "backlog-worker", second.ID, second.LeaseEpoch, "synthetic_retry", time.Hour); err != nil {
		t.Fatalf("defer backlog fixture: %v", err)
	}
	third, claimed, err := worker.ClaimErasureJob(ctx, tenant, visibility, "backlog-worker", 30*time.Second)
	if err != nil || !claimed {
		t.Fatalf("claim for live lease fixture=%+v claimed=%t err=%v", third, claimed, err)
	}

	time.Sleep(10 * time.Millisecond)
	backlog, err := worker.ReadErasureBacklog(ctx, tenant, visibility)
	if err != nil {
		t.Fatal(err)
	}
	if backlog.SampledAt.IsZero() || backlog.OldestOutstanding <= 0 || backlog.Truncated {
		t.Fatalf("invalid bounded backlog sample: %+v", backlog)
	}
	if backlog.Fenced != 2 || backlog.CleanupPending != 2 || backlog.Blocked != 1 || backlog.Due != 2 ||
		backlog.Deferred != 1 || backlog.Leased != 1 || backlog.ExpiredLease != 0 {
		t.Fatalf("unexpected backlog state classification: %+v", backlog)
	}

	otherCohort, err := worker.ReadErasureBacklog(ctx, tenant, visibility+":other")
	if err != nil || otherCohort.Fenced+otherCohort.CleanupPending+otherCohort.Blocked != 0 {
		t.Fatalf("backlog crossed visibility scope: %+v err=%v", otherCohort, err)
	}
	otherTenant, err := worker.ReadErasureBacklog(ctx, tenancy.TenantID(uuid.NewString()), visibility)
	if err != nil || otherTenant.Fenced+otherTenant.CleanupPending+otherTenant.Blocked != 0 {
		t.Fatalf("backlog crossed tenant scope: %+v err=%v", otherTenant, err)
	}
	appBacklog, err := app.ReadErasureBacklog(ctx, tenant, visibility)
	if err != nil || appBacklog.Fenced != backlog.Fenced || appBacklog.Blocked != backlog.Blocked {
		t.Fatalf("app read did not remain scope-local: %+v err=%v", appBacklog, err)
	}
}

func TestErasureBacklogRejectsNilRepository(t *testing.T) {
	repository, err := New(nil)
	if err == nil || repository != nil {
		t.Fatal("repository unexpectedly accepted a nil DB")
	}
	if _, err := (*Repository)(nil).ReadErasureBacklog(context.Background(), tenancy.TenantID(uuid.NewString()), "valid"); err == nil {
		t.Fatal("nil repository accepted a backlog read")
	}
}
