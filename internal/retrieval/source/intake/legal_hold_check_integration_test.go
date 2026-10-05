package intake

import (
	"context"
	"crypto/sha256"
	"errors"
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

func TestPostgreSQLLegalHoldCheckBlocksActiveAndUnknownBeforeDestruction(t *testing.T) {
	for _, decision := range []string{LegalHoldActive, "unknown"} {
		t.Run(decision, func(t *testing.T) {
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
			visibility := "hold-check:" + strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
			hasher, err := index.NewHMACTermHasher(string(tenant), "hold-check-v1", []byte(strings.Repeat("q", 32)))
			if err != nil {
				t.Fatal(err)
			}
			text := "legal hold check integration source"
			tokens, err := contracts.Tokenize(text)
			if err != nil {
				t.Fatal(err)
			}
			documentVersionID := uuid.New()
			chunk, err := index.PrepareChunk(documentVersionID, contracts.Chunk{Ordinal: 0, Text: text,
				StartByte: 0, EndByte: len(text), TokenCount: len(tokens)}, hasher)
			if err != nil {
				t.Fatal(err)
			}
			spec := index.BuildSpec{ID: uuid.New(), AnalyzerID: contracts.AnalyzerID, ChunkerID: contracts.ChunkerID,
				TermKeyID: hasher.KeyID(), ManifestDigest: sha256.Sum256([]byte("hold-check manifest")), ExpectedChunks: 1}
			if err := worker.BeginBuild(ctx, tenant, visibility, spec); err != nil {
				t.Fatal(err)
			}
			if err := worker.StageBatch(ctx, tenant, visibility, spec.ID, []index.Chunk{chunk}); err != nil {
				t.Fatal(err)
			}
			if _, err := worker.Finalize(ctx, tenant, visibility, spec.ID); err != nil {
				t.Fatal(err)
			}
			if _, err := app.WithdrawSource(ctx, tenant, visibility, uuid.New(), documentVersionID, uuid.New()); err != nil {
				t.Fatal(err)
			}
			authority := &testLegalHoldAuthority{actorID: uuid.New(), evidence: sha256.Sum256([]byte("synthetic hold evidence")), decision: decision}
			check, err := NewLegalHoldCheckExecutor(worker, authority)
			if err != nil {
				t.Fatal(err)
			}
			destructiveCalls := 0
			executors := make(map[string]retrievalpostgres.ErasureActionExecutor, 6)
			for _, action := range []string{retrievalpostgres.ErasureActionLegalHoldCheck,
				retrievalpostgres.ErasureActionSupplierSourceObject, retrievalpostgres.ErasureActionDerivedIndex,
				retrievalpostgres.ErasureActionCacheRevocation, retrievalpostgres.ErasureActionQueuedWorkRevocation,
				retrievalpostgres.ErasureActionBackupExpiry} {
				action := action
				executors[action] = retrievalpostgres.ErasureActionExecutorFunc(func(context.Context, retrievalpostgres.ErasureJob, string, string) (retrievalpostgres.ErasureActionExecution, error) {
					if action == retrievalpostgres.ErasureActionLegalHoldCheck {
						return retrievalpostgres.ErasureActionExecution{}, errors.New("placeholder legal-hold executor ran")
					}
					destructiveCalls++
					return retrievalpostgres.ErasureActionExecution{Disposition: retrievalpostgres.ErasureReceiptComplete,
						ActorID: uuid.New(), ReceiptSHA256: sha256.Sum256([]byte("synthetic action:" + action))}, nil
				})
			}
			executors[retrievalpostgres.ErasureActionLegalHoldCheck] = check
			processor, err := retrievalpostgres.NewErasureActionProcessor(worker, "hold-check-worker", time.Minute, time.Second, executors)
			if err != nil {
				t.Fatal(err)
			}
			job, claimed, err := processor.ProcessOne(ctx, tenant, visibility)
			wantCode := "legal_hold_unknown"
			if decision == LegalHoldActive {
				wantCode = "legal_hold_active"
			}
			if err != nil || !claimed || job.State != "blocked" || !job.LastErrorCode.Valid || job.LastErrorCode.String != wantCode {
				t.Fatalf("legal-hold decision did not block durably: job=%+v claimed=%t err=%v", job, claimed, err)
			}
			if destructiveCalls != 0 {
				t.Fatalf("destructive actions ran despite %s hold decision", decision)
			}
		})
	}
}

type testLegalHoldAuthority struct {
	actorID  uuid.UUID
	evidence [32]byte
	decision string
}

func (a *testLegalHoldAuthority) AcquireClearance(_ context.Context, _ ErasureFence) (HoldClearance, error) {
	if a.decision == LegalHoldActive {
		return HoldClearance{}, &LegalHoldDecisionError{Decision: LegalHoldActive}
	}
	if a.decision == "unknown" {
		return HoldClearance{}, errors.New("synthetic hold authority unavailable")
	}
	return HoldClearance{DecisionActorID: a.actorID, EvidenceSHA256: a.evidence, Release: func() error { return nil }}, nil
}
