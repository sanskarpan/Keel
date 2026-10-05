package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
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
	if backlog.SampledAt.IsZero() || backlog.OldestOutstandingAgeSeconds <= 0 || backlog.Truncated {
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

func TestPostgreSQLErasureBacklogSampleCapAndCompletedAgeExclusion(t *testing.T) {
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
	visibility := "erasure-cap:" + uuid.NewString()

	// This completed job is deliberately much older than the outstanding
	// sample. It must not influence either its lower bound or its oldest age.
	seedBacklogRows(t, app, worker, tenant, visibility, "completed-old", 1, 100)
	claim, claimed, err := worker.ClaimErasureJob(ctx, tenant, visibility, "backlog-worker", 30*time.Second)
	if err != nil || !claimed {
		t.Fatalf("claim old completed fixture=%+v claimed=%t err=%v", claim, claimed, err)
	}
	actor := uuid.New()
	for _, action := range []string{ErasureActionLegalHoldCheck, ErasureActionSupplierSourceObject, ErasureActionDerivedIndex,
		ErasureActionCacheRevocation, ErasureActionQueuedWorkRevocation, ErasureActionBackupExpiry} {
		if _, err := worker.RecordErasureActionReceipt(ctx, tenant, visibility, "backlog-worker", claim.ID, claim.LeaseEpoch,
			action, ErasureReceiptComplete, actor, "", sha256.Sum256([]byte("synthetic:"+action))); err != nil {
			t.Fatalf("record completed fixture receipt %s: %v", action, err)
		}
	}
	if completed, err := worker.CompleteErasureJob(ctx, tenant, visibility, "backlog-worker", claim.ID, claim.LeaseEpoch); err != nil || completed.State != "complete" {
		t.Fatalf("complete old fixture=%+v err=%v", completed, err)
	}

	seedBacklogRows(t, app, worker, tenant, visibility, "outstanding", MaxErasureBacklogSample, 50)
	exact, err := worker.ReadErasureBacklog(ctx, tenant, visibility)
	if err != nil {
		t.Fatal(err)
	}
	if exact.Truncated || exact.Fenced != MaxErasureBacklogSample || exact.Due != MaxErasureBacklogSample {
		t.Fatalf("exact cap should report 10,000 exact due rows: %+v", exact)
	}
	if exact.OldestOutstandingAgeSeconds < 49*365*24*60*60 || exact.OldestOutstandingAgeSeconds > 51*365*24*60*60 {
		t.Fatalf("old completed job affected or corrupted oldest age: %+v", exact)
	}

	seedBacklogRows(t, app, worker, tenant, visibility, "overflow", 1, 50)
	truncated, err := worker.ReadErasureBacklog(ctx, tenant, visibility)
	if err != nil {
		t.Fatal(err)
	}
	if !truncated.Truncated || truncated.Fenced != MaxErasureBacklogSample || truncated.Due != MaxErasureBacklogSample {
		t.Fatalf("10,001 rows should return capped lower-bound counts: %+v", truncated)
	}
	if truncated.OldestOutstandingAgeSeconds < 49*365*24*60*60 || truncated.OldestOutstandingAgeSeconds > 51*365*24*60*60 {
		t.Fatalf("truncated sample lost its true oldest outstanding age: %+v", truncated)
	}
}

func TestPostgreSQLErasureBacklogClassifiesExpiredLease(t *testing.T) {
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
	visibility := "erasure-expired:" + uuid.NewString()
	hasher, err := index.NewHMACTermHasher(string(tenant), "erasure-expired-v1", []byte(strings.Repeat("c", 32)))
	if err != nil {
		t.Fatal(err)
	}
	chunk := preparedChunk(t, hasher, uuid.New(), "expired lease fixture")
	createReadyBuild(t, worker, tenant, visibility, buildSpec(uuid.New(), hasher.KeyID(), 1), chunk)
	if _, err := app.WithdrawSource(ctx, tenant, visibility, uuid.New(), chunk.DocumentVersionID, uuid.New()); err != nil {
		t.Fatal(err)
	}
	if _, claimed, err := worker.ClaimErasureJob(ctx, tenant, visibility, "backlog-worker", time.Second); err != nil || !claimed {
		t.Fatalf("claim expiring fixture claimed=%t err=%v", claimed, err)
	}
	time.Sleep(1100 * time.Millisecond)
	backlog, err := worker.ReadErasureBacklog(ctx, tenant, visibility)
	if err != nil {
		t.Fatal(err)
	}
	if backlog.ExpiredLease != 1 || backlog.Leased != 0 || backlog.Truncated {
		t.Fatalf("expired lease was not counted as outstanding expired work: %+v", backlog)
	}
}

// seedBacklogRows creates an indexed-equivalent source fence and durable job
// rows in bulk under the same forced-RLS tenant/cohort roles used in runtime.
func seedBacklogRows(t *testing.T, app, worker *Repository, tenant tenancy.TenantID, visibility, seed string, count, ageYears int) {
	t.Helper()
	scoped, err := newScope(tenant, visibility)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := withScope(ctx, worker.db, scoped, nil, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO keel_meta.retrieval_source_eligibility
			(tenant_id,visibility_key,document_version_id,state,generation,changed_at)
			SELECT $1,$2,md5($3||':doc:'||n::text)::uuid,'active',1,clock_timestamp()-interval '100 years'
			FROM generate_series(1,$4::integer) AS n`, string(tenant), visibility, seed, count)
		return err
	}); err != nil {
		t.Fatalf("seed backlog source rows: %v", err)
	}
	if err := withScope(ctx, app.db, scoped, nil, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE keel_meta.retrieval_source_eligibility
			SET state='withdrawn',generation=2,changed_at=clock_timestamp()-interval '90 years'
			WHERE tenant_id=$1 AND visibility_key=$2
			  AND document_version_id IN (SELECT md5($3||':doc:'||n::text)::uuid FROM generate_series(1,$4::integer) AS n)`,
			string(tenant), visibility, seed, count); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO keel_meta.retrieval_erasure_jobs
			(tenant_id,visibility_key,job_id,requested_by,document_version_id,eligibility_generation,requested_at,updated_at)
			SELECT $1,$2,md5($3||':job:'||n::text)::uuid,md5($3||':actor')::uuid,
			       md5($3||':doc:'||n::text)::uuid,2,
			       clock_timestamp()-make_interval(years=>$4)+(n::double precision*interval '1 second'),
			       clock_timestamp()
			  FROM generate_series(1,$5::integer) AS n`, string(tenant), visibility, seed, ageYears, count)
		return err
	}); err != nil {
		t.Fatalf("seed backlog jobs: %v", err)
	}
}
