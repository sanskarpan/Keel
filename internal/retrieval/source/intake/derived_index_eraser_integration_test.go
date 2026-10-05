package intake

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
	"github.com/sanskarpan/keel/internal/retrieval/contracts"
	"github.com/sanskarpan/keel/internal/retrieval/index"
	retrievalpostgres "github.com/sanskarpan/keel/internal/retrieval/postgres"
)

func TestPostgreSQLDerivedIndexEraserRecordsReceiptUnderClearance(t *testing.T) {
	appDB := openErasureTestDB(t, "KEEL_TEST_DATABASE_URL")
	indexerDB := openErasureTestDB(t, "KEEL_TEST_RETRIEVAL_INDEXER_DATABASE_URL")
	app, err := retrievalpostgres.New(appDB)
	if err != nil {
		t.Fatal(err)
	}
	worker, err := retrievalpostgres.New(indexerDB)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	tenant := tenancy.TenantID(uuid.NewString())
	visibility := "derived-action:" + strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	hasher, err := index.NewHMACTermHasher(string(tenant), "derived-action-v1", []byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := contracts.Tokenize("unpublished source content for derived cleanup")
	if err != nil {
		t.Fatal(err)
	}
	documentVersionID := uuid.New()
	chunk, err := index.PrepareChunk(documentVersionID, contracts.Chunk{Ordinal: 0,
		Text: "unpublished source content for derived cleanup", StartByte: 0,
		EndByte: len("unpublished source content for derived cleanup"), TokenCount: len(tokens)}, hasher)
	if err != nil {
		t.Fatal(err)
	}
	spec := index.BuildSpec{ID: uuid.New(), AnalyzerID: contracts.AnalyzerID, ChunkerID: contracts.ChunkerID,
		TermKeyID: hasher.KeyID(), ManifestDigest: sha256.Sum256([]byte("synthetic manifest")), ExpectedChunks: 1}
	if err := worker.BeginBuild(ctx, tenant, visibility, spec); err != nil {
		t.Fatal(err)
	}
	if err := worker.StageBatch(ctx, tenant, visibility, spec.ID, []index.Chunk{chunk}); err != nil {
		t.Fatal(err)
	}
	if _, err := worker.Finalize(ctx, tenant, visibility, spec.ID); err != nil {
		t.Fatal(err)
	}
	request, err := app.WithdrawSource(ctx, tenant, visibility, uuid.New(), documentVersionID, uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	hold := &testDerivedIndexHoldAuthority{actorID: uuid.New(), deny: true}
	eraser, err := NewDerivedIndexEraser(worker, hold)
	if err != nil {
		t.Fatal(err)
	}
	derivedExecutor, err := retrievalpostgres.NewDerivedIndexCleanupExecutor(eraser)
	if err != nil {
		t.Fatal(err)
	}
	executors := make(map[string]retrievalpostgres.ErasureActionExecutor, 6)
	for _, action := range []string{retrievalpostgres.ErasureActionLegalHoldCheck,
		retrievalpostgres.ErasureActionSupplierSourceObject, retrievalpostgres.ErasureActionDerivedIndex,
		retrievalpostgres.ErasureActionCacheRevocation, retrievalpostgres.ErasureActionQueuedWorkRevocation,
		retrievalpostgres.ErasureActionBackupExpiry} {
		action := action
		executors[action] = retrievalpostgres.ErasureActionExecutorFunc(func(context.Context, retrievalpostgres.ErasureJob, string, string) (retrievalpostgres.ErasureActionExecution, error) {
			if action == retrievalpostgres.ErasureActionDerivedIndex {
				return retrievalpostgres.ErasureActionExecution{}, errors.New("derived executor placeholder was not replaced")
			}
			disposition := retrievalpostgres.ErasureReceiptComplete
			reason := ""
			if action == retrievalpostgres.ErasureActionCacheRevocation || action == retrievalpostgres.ErasureActionQueuedWorkRevocation {
				disposition = retrievalpostgres.ErasureReceiptNotApplicable
				reason = "integration fixture has no mounted provider"
			}
			return retrievalpostgres.ErasureActionExecution{Disposition: disposition, ActorID: uuid.New(), Reason: reason,
				ReceiptSHA256: sha256.Sum256([]byte("synthetic evidence:" + action))}, nil
		})
	}
	executors[retrievalpostgres.ErasureActionDerivedIndex] = derivedExecutor
	processor, err := retrievalpostgres.NewErasureActionProcessor(worker, "derived-index-worker", time.Minute, time.Second, executors)
	if err != nil {
		t.Fatal(err)
	}
	job, claimed, err := processor.ProcessOne(ctx, tenant, visibility)
	if !claimed || !errors.Is(err, retrievalpostgres.ErrErasureActionFailed) || job.State != "cleanup_pending" {
		t.Fatalf("hold denial must leave job retryable: job=%+v claimed=%t err=%v", job, claimed, err)
	}
	if hold.acquires != 1 || hold.releases != 0 {
		t.Fatalf("denied hold decision unexpectedly released a permit: %+v", hold)
	}
	if delay := time.Until(job.AvailableAt); delay > 0 {
		time.Sleep(delay + 25*time.Millisecond)
	}
	hold.deny = false
	completed, claimed, err := processor.ProcessOne(ctx, tenant, visibility)
	if err != nil || !claimed || completed.ID != request.ID || completed.State != "complete" {
		t.Fatalf("processor result after hold release=%+v claimed=%t err=%v", completed, claimed, err)
	}
	if hold.acquires != 2 || hold.releases != 1 || hold.lastFence.JobID != request.ID || hold.lastFence.DocumentVersionID != documentVersionID {
		t.Fatalf("hold authority did not cover the exact source receipt: %+v", hold)
	}
}

type testDerivedIndexHoldAuthority struct {
	actorID   uuid.UUID
	acquires  int
	releases  int
	lastFence ErasureFence
	deny      bool
}

func (a *testDerivedIndexHoldAuthority) AcquireClearance(_ context.Context, fence ErasureFence) (HoldClearance, error) {
	a.acquires++
	a.lastFence = fence
	if a.deny {
		return HoldClearance{}, errors.New("synthetic active legal hold")
	}
	return HoldClearance{DecisionActorID: a.actorID, EvidenceSHA256: sha256.Sum256([]byte("synthetic serialized hold decision")), Release: func() error {
		a.releases++
		return nil
	}}, nil
}

func openErasureTestDB(t *testing.T, envKey string) *sql.DB {
	t.Helper()
	rawURL := os.Getenv(envKey)
	if rawURL == "" {
		t.Skip("set app and retrieval indexer PostgreSQL URLs to run erasure integration tests")
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("pgx", parsed.String())
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(6)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		t.Fatalf("connect PostgreSQL test role %s: %v", envKey, err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}
