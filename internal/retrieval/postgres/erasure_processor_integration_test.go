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
	deleteAttempts := 0
	executors[ErasureActionSupplierSourceObject] = testErasureExecutor(func(_ context.Context, _ ErasureJob, _, _ string) (ErasureActionExecution, error) {
		order = append(order, ErasureActionSupplierSourceObject)
		deleteAttempts++
		if deleteAttempts == 1 {
			return ErasureActionExecution{}, errors.New("synthetic partial provider success")
		}
		return completeTestErasureAction(ErasureActionSupplierSourceObject), nil
	})
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
	if deleteAttempts != 2 || order[2] != ErasureActionSupplierSourceObject || len(order) != 7 {
		t.Fatalf("partial success was repeated incorrectly: attempts=%d order=%v", deleteAttempts, order)
	}
	if order[3] != ErasureActionDerivedIndex || order[4] != ErasureActionCacheRevocation ||
		order[5] != ErasureActionQueuedWorkRevocation || order[6] != ErasureActionBackupExpiry {
		t.Fatalf("retry did not resume in manifest order: %v", order)
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
