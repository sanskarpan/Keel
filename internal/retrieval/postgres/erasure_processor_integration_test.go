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

type testErasureExecutor func(context.Context, ErasureJob, string, string) (ErasureActionExecution, error)

func (f testErasureExecutor) Execute(ctx context.Context, job ErasureJob, tenant, visibility string) (ErasureActionExecution, error) {
	return f(ctx, job, tenant, visibility)
}

func TestErasureActionProcessorRequiresEveryManifestExecutor(t *testing.T) {
	if _, err := NewErasureActionProcessor(&Repository{}, "eraser-test", time.Minute, time.Second, map[string]ErasureActionExecutor{}); err == nil {
		t.Fatal("processor accepted a missing action executor")
	}
	var nilExecutor ErasureActionExecutorFunc
	if _, err := nilExecutor.Execute(context.Background(), ErasureJob{}, "tenant", "cohort"); err == nil {
		t.Fatal("nil executor function did not fail closed")
	}
}

func TestSupplierSourceObjectsExecutorRequiresLiveLease(t *testing.T) {
	eraser := &receiptWritingSupplierEraser{}
	executor, err := NewSupplierSourceObjectsExecutor(eraser)
	if err != nil {
		t.Fatal(err)
	}
	job := ErasureJob{ID: uuid.New(), State: "cleanup_pending", LeaseOwner: sql.NullString{String: "eraser-adapter", Valid: true}, LeaseEpoch: 3}
	if _, err := executor.Execute(context.Background(), job, uuid.NewString(), "adapter-cohort"); err != nil {
		t.Fatalf("execute with current claim: %v", err)
	}
	if eraser.calls != 1 || eraser.worker != job.LeaseOwner.String || eraser.epoch != job.LeaseEpoch {
		t.Fatalf("eraser did not receive current lease: %+v", eraser)
	}
	job.LeaseOwner.Valid = false
	if _, err := executor.Execute(context.Background(), job, uuid.NewString(), "adapter-cohort"); err == nil {
		t.Fatal("executor accepted an unclaimed job")
	}
}

func TestDerivedIndexCleanupExecutorRequiresLiveLease(t *testing.T) {
	eraser := &receiptWritingDerivedIndexEraser{}
	executor, err := NewDerivedIndexCleanupExecutor(eraser)
	if err != nil {
		t.Fatal(err)
	}
	job := ErasureJob{ID: uuid.New(), State: "cleanup_pending", LeaseOwner: sql.NullString{String: "index-adapter", Valid: true}, LeaseEpoch: 7}
	if _, err := executor.Execute(context.Background(), job, uuid.NewString(), "adapter-cohort"); err != nil {
		t.Fatalf("execute with current claim: %v", err)
	}
	if eraser.calls != 1 || eraser.worker != job.LeaseOwner.String || eraser.epoch != job.LeaseEpoch {
		t.Fatalf("eraser did not receive current lease: %+v", eraser)
	}
	job.LeaseOwner.Valid = false
	if _, err := executor.Execute(context.Background(), job, uuid.NewString(), "adapter-cohort"); err == nil {
		t.Fatal("executor accepted an unclaimed job")
	}
}

func TestPostgreSQLErasureActionProcessorOrdersReceiptsAndCompletes(t *testing.T) {
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
	visibility := "erasure-processor:" + strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	hasher, err := index.NewHMACTermHasher(string(tenant), "erasure-processor-v1", []byte(strings.Repeat("p", 32)))
	if err != nil {
		t.Fatal(err)
	}
	chunk := preparedChunk(t, hasher, uuid.New(), "source processed under an injected action plan")
	createReadyBuild(t, worker, tenant, visibility, buildSpec(uuid.New(), hasher.KeyID(), 1), chunk)
	request, err := app.WithdrawSource(ctx, tenant, visibility, uuid.New(), chunk.DocumentVersionID, uuid.New())
	if err != nil {
		t.Fatal(err)
	}

	var order []string
	executors := testErasureExecutors(&order)
	processor, err := NewErasureActionProcessor(worker, "eraser-processor", time.Minute, time.Second, executors)
	if err != nil {
		t.Fatal(err)
	}
	completed, claimed, err := processor.ProcessOne(ctx, tenant, visibility)
	if err != nil || !claimed || completed.ID != request.ID || completed.State != "complete" || !completed.CompletedAt.Valid {
		t.Fatalf("processed erasure job=%+v claimed=%t err=%v", completed, claimed, err)
	}
	if strings.Join(order, ",") != strings.Join(erasureActionOrder[:], ",") {
		t.Fatalf("action order=%v want=%v", order, erasureActionOrder)
	}
	var receipts int
	scope, err := newScope(tenant, visibility)
	if err != nil {
		t.Fatal(err)
	}
	if err := withScope(ctx, appDB, scope, &sql.TxOptions{ReadOnly: true}, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT count(*) FROM keel_meta.retrieval_erasure_action_receipts
			WHERE tenant_id=$1 AND visibility_key=$2 AND job_id=$3`, string(tenant), visibility, request.ID).Scan(&receipts)
	}); err != nil || receipts != len(erasureActionOrder) {
		t.Fatalf("processor receipt count=%d err=%v", receipts, err)
	}
	if _, claimed, err := processor.ProcessOne(ctx, tenant, visibility); err != nil || claimed {
		t.Fatalf("completed job was claimed again: claimed=%t err=%v", claimed, err)
	}
}

func TestPostgreSQLErasureActionProcessorRenewsLeaseDuringProviderAction(t *testing.T) {
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
	visibility := "erasure-lease-heartbeat:" + strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	hasher, err := index.NewHMACTermHasher(string(tenant), "erasure-lease-heartbeat-v1", []byte(strings.Repeat("h", 32)))
	if err != nil {
		t.Fatal(err)
	}
	chunk := preparedChunk(t, hasher, uuid.New(), "source held while the external handler is running")
	createReadyBuild(t, worker, tenant, visibility, buildSpec(uuid.New(), hasher.KeyID(), 1), chunk)
	request, err := app.WithdrawSource(ctx, tenant, visibility, uuid.New(), chunk.DocumentVersionID, uuid.New())
	if err != nil {
		t.Fatal(err)
	}

	entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	var order []string
	executors := testErasureExecutors(&order)
	executors[ErasureActionLegalHoldCheck] = testErasureExecutor(func(ctx context.Context, _ ErasureJob, _, _ string) (ErasureActionExecution, error) {
		close(entered)
		select {
		case <-release:
			return completeTestErasureAction(ErasureActionLegalHoldCheck), nil
		case <-ctx.Done():
			return ErasureActionExecution{}, ctx.Err()
		}
	})
	processor, err := NewErasureActionProcessor(worker, "eraser-heartbeat", MinErasureLease, time.Second, executors)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		job, claimed, err := processor.ProcessOne(ctx, tenant, visibility)
		if err == nil && (!claimed || job.ID != request.ID || job.State != "complete") {
			err = errors.New("processor did not complete the leased job")
		}
		finished <- err
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("provider action did not start")
	}
	// Cross the original one-second lease boundary. A competing worker must not
	// reclaim the job while the first provider action is still active.
	time.Sleep(1300 * time.Millisecond)
	if _, claimed, err := worker.ClaimErasureJob(ctx, tenant, visibility, "eraser-competitor", MinErasureLease); err != nil || claimed {
		t.Fatalf("competing worker reclaimed a live renewed lease: claimed=%t err=%v", claimed, err)
	}
	close(release)
	select {
	case err := <-finished:
		if err != nil {
			t.Fatalf("processor failed after provider completion: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("processor did not finish after provider release")
	}
}

func TestPostgreSQLErasureActionProcessorCancelsWhenLeaseRenewalStalls(t *testing.T) {
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
	visibility := "erasure-renew-stall:" + strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	hasher, err := index.NewHMACTermHasher(string(tenant), "erasure-renew-stall-v1", []byte(strings.Repeat("s", 32)))
	if err != nil {
		t.Fatal(err)
	}
	chunk := preparedChunk(t, hasher, uuid.New(), "source must stop processing when renewal cannot be confirmed")
	createReadyBuild(t, worker, tenant, visibility, buildSpec(uuid.New(), hasher.KeyID(), 1), chunk)
	request, err := app.WithdrawSource(ctx, tenant, visibility, uuid.New(), chunk.DocumentVersionID, uuid.New())
	if err != nil {
		t.Fatal(err)
	}

	entered, actionCanceled, finished := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	var order []string
	executors := testErasureExecutors(&order)
	executors[ErasureActionLegalHoldCheck] = testErasureExecutor(func(ctx context.Context, _ ErasureJob, _, _ string) (ErasureActionExecution, error) {
		close(entered)
		<-ctx.Done()
		close(actionCanceled)
		return ErasureActionExecution{}, ctx.Err()
	})
	processor, err := NewErasureActionProcessor(worker, "eraser-renew-stall", MinErasureLease, time.Second, executors)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		job, claimed, err := processor.ProcessOne(ctx, tenant, visibility)
		if err == nil && (!claimed || job.ID != request.ID || job.State != "cleanup_pending") {
			err = errors.New("stalled renewal did not safely reschedule the job")
		}
		finished <- err
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("provider action did not start")
	}

	// Hold the job row so lease renewal cannot complete. The handler must receive
	// cancellation within its short renewal deadline, well before lease expiry.
	tx, err := appDB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `SELECT set_config('keel.tenant_id',$1,true)`, string(tenant)); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `SELECT set_config('keel.visibility_key',$1,true)`, visibility); err != nil {
		t.Fatal(err)
	}
	var lockedID uuid.UUID
	if err := tx.QueryRowContext(ctx, `SELECT job_id FROM keel_meta.retrieval_erasure_jobs
		WHERE tenant_id=$1 AND visibility_key=$2 AND job_id=$3 FOR UPDATE`, string(tenant), visibility, request.ID).Scan(&lockedID); err != nil {
		t.Fatal(err)
	}
	select {
	case <-actionCanceled:
	case <-time.After(2 * time.Second):
		t.Fatal("stalled lease renewal did not cancel the provider action")
	}
	select {
	case <-finished:
		t.Fatal("processor returned before the stalled renewal row lock was released")
	default:
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-finished:
		if !errors.Is(err, ErrErasureActionFailed) {
			t.Fatalf("stalled lease renewal should consume a retry safely: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("processor did not finish after renewal lock was released")
	}
}

func TestPostgreSQLErasureActionProcessorResumesAfterPartialSuccess(t *testing.T) {
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
	visibility := "erasure-retry:" + strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	hasher, err := index.NewHMACTermHasher(string(tenant), "erasure-retry-v1", []byte(strings.Repeat("r", 32)))
	if err != nil {
		t.Fatal(err)
	}
	chunk := preparedChunk(t, hasher, uuid.New(), "source processed across a retried erasure lease")
	createReadyBuild(t, worker, tenant, visibility, buildSpec(uuid.New(), hasher.KeyID(), 1), chunk)
	request, err := app.WithdrawSource(ctx, tenant, visibility, uuid.New(), chunk.DocumentVersionID, uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	var order []string
	executors := testErasureExecutors(&order)
	sourceEraser := &receiptWritingSupplierEraser{repository: worker, order: &order, failFirst: true, actorID: uuid.New()}
	sourceExecutor, err := NewSupplierSourceObjectsExecutor(sourceEraser)
	if err != nil {
		t.Fatal(err)
	}
	executors[ErasureActionSupplierSourceObject] = sourceExecutor
	processor, err := NewErasureActionProcessor(worker, "eraser-retry", time.Minute, time.Second, executors)
	if err != nil {
		t.Fatal(err)
	}
	job, claimed, err := processor.ProcessOne(ctx, tenant, visibility)
	if !claimed || !errors.Is(err, ErrErasureActionFailed) || job.State != "cleanup_pending" || job.LeaseOwner.Valid {
		t.Fatalf("failed action retry state=%+v claimed=%t err=%v", job, claimed, err)
	}
	if len(order) != 2 || order[0] != ErasureActionLegalHoldCheck || order[1] != ErasureActionSupplierSourceObject {
		t.Fatalf("first attempt action order=%v", order)
	}
	if delay := time.Until(job.AvailableAt); delay > 0 {
		time.Sleep(delay + 25*time.Millisecond)
	}
	completed, claimed, err := processor.ProcessOne(ctx, tenant, visibility)
	if err != nil || !claimed || completed.ID != request.ID || completed.State != "complete" {
		t.Fatalf("resumed erasure job=%+v claimed=%t err=%v", completed, claimed, err)
	}
	if sourceEraser.calls != 2 || order[2] != ErasureActionSupplierSourceObject || len(order) != 7 {
		t.Fatalf("partial success was repeated incorrectly: attempts=%d order=%v", sourceEraser.calls, order)
	}
	if order[3] != ErasureActionDerivedIndex || order[4] != ErasureActionCacheRevocation ||
		order[5] != ErasureActionQueuedWorkRevocation || order[6] != ErasureActionBackupExpiry {
		t.Fatalf("retry did not resume in manifest order: %v", order)
	}
}

func TestPostgreSQLErasureActionProcessorResumesDerivedIndexReceiptHandoff(t *testing.T) {
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
	visibility := "erasure-index-retry:" + strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	hasher, err := index.NewHMACTermHasher(string(tenant), "erasure-index-retry-v1", []byte(strings.Repeat("i", 32)))
	if err != nil {
		t.Fatal(err)
	}
	chunk := preparedChunk(t, hasher, uuid.New(), "source processed across a retried derived-index erasure lease")
	createReadyBuild(t, worker, tenant, visibility, buildSpec(uuid.New(), hasher.KeyID(), 1), chunk)
	request, err := app.WithdrawSource(ctx, tenant, visibility, uuid.New(), chunk.DocumentVersionID, uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	var order []string
	executors := testErasureExecutors(&order)
	indexEraser := &receiptWritingDerivedIndexEraser{repository: worker, order: &order, progressPasses: MaxErasureAttempts + 1, actorID: uuid.New()}
	indexExecutor, err := NewDerivedIndexCleanupExecutor(indexEraser)
	if err != nil {
		t.Fatal(err)
	}
	executors[ErasureActionDerivedIndex] = indexExecutor
	processor, err := NewErasureActionProcessor(worker, "eraser-index-retry", time.Minute, time.Second, executors)
	if err != nil {
		t.Fatal(err)
	}
	var job ErasureJob
	for pass := 0; pass < indexEraser.progressPasses; pass++ {
		var claimed bool
		job, claimed, err = processor.ProcessOne(ctx, tenant, visibility)
		if err != nil || !claimed || job.State != "cleanup_pending" || job.LeaseOwner.Valid ||
			job.AttemptCount != pass+1 || job.FailureCount != 0 {
			t.Fatalf("progress pass %d did not yield without consuming failure budget: job=%+v claimed=%t err=%v", pass, job, claimed, err)
		}
		if pass == 0 {
			if _, err := worker.YieldErasureJob(ctx, tenant, visibility, "eraser-index-retry", job.ID, job.LeaseEpoch, MinErasureProgressDelay); !errors.Is(err, ErrErasureLeaseLost) {
				t.Fatalf("stale worker yielded a released lease: %v", err)
			}
		}
		if delay := time.Until(job.AvailableAt); delay > 0 {
			time.Sleep(delay + 10*time.Millisecond)
		}
	}
	completed, claimed, err := processor.ProcessOne(ctx, tenant, visibility)
	if err != nil || !claimed || completed.ID != request.ID || completed.State != "complete" {
		t.Fatalf("resumed erasure job=%+v claimed=%t err=%v", completed, claimed, err)
	}
	if indexEraser.calls != indexEraser.progressPasses+1 || completed.LeaseEpoch <= MaxErasureAttempts ||
		completed.AttemptCount != indexEraser.progressPasses+1 || completed.FailureCount != 0 {
		t.Fatalf("progress pass lease/failure accounting mismatch: calls=%d job=%+v", indexEraser.calls, completed)
	}
	var receipts int
	scope, err := newScope(tenant, visibility)
	if err != nil {
		t.Fatal(err)
	}
	if err := withScope(ctx, appDB, scope, &sql.TxOptions{ReadOnly: true}, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT count(*) FROM keel_meta.retrieval_erasure_action_receipts
			WHERE tenant_id=$1 AND visibility_key=$2 AND job_id=$3 AND action_key=$4`,
			string(tenant), visibility, request.ID, ErasureActionDerivedIndex).Scan(&receipts)
	}); err != nil || receipts != 1 {
		t.Fatalf("derived-index receipt count=%d err=%v", receipts, err)
	}
}

func testErasureExecutors(order *[]string) map[string]ErasureActionExecutor {
	result := make(map[string]ErasureActionExecutor, len(erasureActionOrder))
	for _, action := range erasureActionOrder {
		action := action
		result[action] = testErasureExecutor(func(_ context.Context, _ ErasureJob, _, _ string) (ErasureActionExecution, error) {
			*order = append(*order, action)
			if action == ErasureActionCacheRevocation || action == ErasureActionQueuedWorkRevocation || action == ErasureActionBackupExpiry {
				outcome := completeTestErasureAction(action)
				outcome.Disposition = ErasureReceiptNotApplicable
				outcome.Reason = "synthetic action-plan fixture has no mounted provider"
				return outcome, nil
			}
			return completeTestErasureAction(action), nil
		})
	}
	return result
}

func completeTestErasureAction(action string) ErasureActionExecution {
	return ErasureActionExecution{Disposition: ErasureReceiptComplete, ActorID: uuid.New(), ReceiptSHA256: sha256.Sum256([]byte("synthetic evidence:" + action))}
}

type receiptWritingSupplierEraser struct {
	repository *Repository
	order      *[]string
	failFirst  bool
	calls      int
	actorID    uuid.UUID
	worker     string
	epoch      int64
}

type receiptWritingDerivedIndexEraser struct {
	repository     *Repository
	order          *[]string
	progressPasses int
	calls          int
	actorID        uuid.UUID
	worker         string
	epoch          int64
}

func (e *receiptWritingDerivedIndexEraser) CleanupClaimed(ctx context.Context, tenant tenancy.TenantID, visibility, worker string, jobID uuid.UUID, epoch int64) (bool, time.Duration, error) {
	e.calls++
	e.worker, e.epoch = worker, epoch
	if e.order != nil {
		*e.order = append(*e.order, ErasureActionDerivedIndex)
	}
	if e.calls <= e.progressPasses {
		return true, MinErasureProgressDelay, nil
	}
	if e.repository == nil {
		return false, 0, nil
	}
	_, err := e.repository.RecordErasureActionReceipt(ctx, tenant, visibility, worker, jobID, epoch,
		ErasureActionDerivedIndex, ErasureReceiptComplete, e.actorID, "", sha256.Sum256([]byte("synthetic derived-index cleanup evidence")))
	return false, 0, err
}

func (e *receiptWritingSupplierEraser) EraseClaimed(ctx context.Context, tenant tenancy.TenantID, visibility, worker string, jobID uuid.UUID, epoch int64) error {
	e.calls++
	e.worker, e.epoch = worker, epoch
	if e.order != nil {
		*e.order = append(*e.order, ErasureActionSupplierSourceObject)
	}
	if e.failFirst && e.calls == 1 {
		return errors.New("synthetic partial provider success")
	}
	if e.repository == nil {
		return nil
	}
	_, err := e.repository.RecordErasureActionReceipt(ctx, tenant, visibility, worker, jobID, epoch,
		ErasureActionSupplierSourceObject, ErasureReceiptComplete, e.actorID, "", sha256.Sum256([]byte("synthetic supplier delete evidence")))
	return err
}
