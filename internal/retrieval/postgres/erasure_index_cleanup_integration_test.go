package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
	"github.com/sanskarpan/keel/internal/retrieval/index"
)

func TestPostgreSQLUnpublishedDerivedErasureIsBoundedAndRetainsPublishedCorpus(t *testing.T) {
	appDB, indexerDB, adminDB := retrievalTestDBsWithAdmin(t)
	app, err := New(appDB)
	if err != nil {
		t.Fatal(err)
	}
	indexer, err := New(indexerDB)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	tenant := tenancy.TenantID(uuid.NewString())
	visibility := "erasure-index:" + strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	hasher, err := index.NewHMACTermHasher(string(tenant), "erasure-index-v1", []byte(strings.Repeat("i", 32)))
	if err != nil {
		t.Fatal(err)
	}
	documentVersionID := uuid.New()
	chunk := preparedChunk(t, hasher, documentVersionID, "withdrawn source with several index terms")
	publishedBuild := buildSpec(uuid.New(), hasher.KeyID(), 1)
	createReadyBuild(t, indexer, tenant, visibility, publishedBuild, chunk)
	if generation, err := indexer.Publish(ctx, tenant, visibility, publishedBuild.ID, 0); err != nil || generation != 1 {
		t.Fatalf("publish source corpus: generation=%d err=%v", generation, err)
	}

	manifest := vectorFixtureManifest(t)
	registerVectorTestModel(t, adminDB, manifest)
	vectorBuild, err := indexer.BeginVectorBuild(ctx, tenant, visibility, VectorBuildSpec{ID: uuid.New(), Model: manifest})
	if err != nil {
		t.Fatal(err)
	}
	if err := indexer.StageVectorBatch(ctx, tenant, visibility, vectorBuild.ID,
		[]VectorChunk{{ChunkID: chunk.ID, ModelInputTokens: 5, Values: []float32{1, 0, 0}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := indexer.FinalizeVectorBuild(ctx, tenant, visibility, vectorBuild.ID); err != nil {
		t.Fatal(err)
	}

	stagingBuild := buildSpec(uuid.New(), hasher.KeyID(), 1)
	createReadyBuild(t, indexer, tenant, visibility, stagingBuild, chunk)
	job, err := app.WithdrawSource(ctx, tenant, visibility, uuid.New(), documentVersionID, uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	claim, claimed, err := indexer.ClaimErasureJob(ctx, tenant, visibility, "index-eraser", time.Minute)
	if err != nil || !claimed || claim.ID != job.ID {
		t.Fatalf("claim=%+v claimed=%t err=%v", claim, claimed, err)
	}
	if _, err := indexer.CleanupUnpublishedErasureIndexBatch(ctx, tenant, visibility, "index-eraser", job.ID,
		claim.LeaseEpoch, 1); !errors.Is(err, ErrErasureLegalHoldUncleared) {
		t.Fatalf("derived rows were touched before legal-hold clearance: %v", err)
	}
	if _, err := indexer.RecordErasureActionReceipt(ctx, tenant, visibility, "index-eraser", job.ID,
		claim.LeaseEpoch, ErasureActionLegalHoldCheck, ErasureReceiptComplete, uuid.New(), "",
		sha256.Sum256([]byte("synthetic hold-clearance evidence"))); err != nil {
		t.Fatalf("record synthetic hold-clearance receipt: %v", err)
	}
	if _, err := indexer.CleanupUnpublishedErasureIndexBatch(ctx, tenant, visibility, "other-eraser", job.ID,
		claim.LeaseEpoch, 1); !errors.Is(err, ErrErasureLeaseLost) {
		t.Fatalf("cleanup accepted a non-owner worker: %v", err)
	}
	if _, err := indexer.CleanupUnpublishedErasureIndexBatch(ctx, tenant, visibility, "index-eraser", job.ID,
		claim.LeaseEpoch, MaxErasureIndexBatchRows+1); err == nil {
		t.Fatal("oversized cleanup batch was accepted")
	}
	if _, err := indexer.CleanupUnpublishedErasureIndexBatch(ctx, tenancy.TenantID(uuid.NewString()), visibility, "index-eraser", job.ID,
		claim.LeaseEpoch, 1); !errors.Is(err, ErrErasureLeaseLost) {
		t.Fatalf("cross-tenant cleanup was accepted: %v", err)
	}
	removeFailureTrigger := installErasureCleanupFailureTrigger(t, adminDB, string(tenant), stagingBuild.ID)
	t.Cleanup(removeFailureTrigger)
	if _, err := indexer.CleanupUnpublishedErasureIndexBatch(ctx, tenant, visibility, "index-eraser", job.ID,
		claim.LeaseEpoch, 2); err == nil {
		t.Fatal("injected posting deletion failure did not abort cleanup")
	}
	if got := buildState(t, indexerDB, tenant, visibility, stagingBuild.ID); got != "ready" {
		t.Fatalf("failed cleanup transaction left staging build in %q instead of rolling back", got)
	}
	var vectorStateAfterRollback string
	var vectorRowsAfterRollback int
	if err := withScope(ctx, indexerDB, scope{tenant: tenant, visibility: visibility}, nil, func(tx *sql.Tx) error {
		if err := tx.QueryRowContext(ctx, `SELECT state FROM keel_meta.retrieval_vector_builds WHERE tenant_id=$1 AND vector_build_id=$2`,
			string(tenant), vectorBuild.ID).Scan(&vectorStateAfterRollback); err != nil {
			return err
		}
		return tx.QueryRowContext(ctx, `SELECT count(*) FROM keel_meta.retrieval_vector_chunks WHERE tenant_id=$1 AND vector_build_id=$2`,
			string(tenant), vectorBuild.ID).Scan(&vectorRowsAfterRollback)
	}); err != nil {
		t.Fatal(err)
	}
	if vectorStateAfterRollback != "ready" || vectorRowsAfterRollback != 1 {
		t.Fatalf("rollback lost vector work: state=%s rows=%d", vectorStateAfterRollback, vectorRowsAfterRollback)
	}
	removeFailureTrigger()

	var last ErasureIndexCleanupBatch
	for attempt := 0; attempt < 32; attempt++ {
		last, err = indexer.CleanupUnpublishedErasureIndexBatch(ctx, tenant, visibility, "index-eraser", job.ID,
			claim.LeaseEpoch, 1)
		if err != nil {
			t.Fatalf("cleanup pass %d: %v", attempt, err)
		}
		if last.RowsDeleted > 1 {
			t.Fatalf("cleanup exceeded row budget: %+v", last)
		}
		if !last.RemainingUnpublished {
			break
		}
	}
	if last.RemainingUnpublished || !last.RetainedPublishedBuilds || last.ReadyForReceipt() {
		t.Fatalf("cleanup result must retain the published corpus and refuse its receipt: %+v", last)
	}
	if got := buildState(t, indexerDB, tenant, visibility, publishedBuild.ID); got != "published" {
		t.Fatalf("published corpus was changed to %q", got)
	}
	if got := buildState(t, indexerDB, tenant, visibility, stagingBuild.ID); got != "failed" {
		t.Fatalf("unpublished corpus was not fenced failed: %q", got)
	}
	var vectorState string
	var vectorRows int
	if err := withScope(ctx, indexerDB, scope{tenant: tenant, visibility: visibility}, nil, func(tx *sql.Tx) error {
		if err := tx.QueryRowContext(ctx, `SELECT state FROM keel_meta.retrieval_vector_builds
			WHERE tenant_id=$1 AND vector_build_id=$2`, string(tenant), vectorBuild.ID).Scan(&vectorState); err != nil {
			return err
		}
		return tx.QueryRowContext(ctx, `SELECT count(*) FROM keel_meta.retrieval_vector_chunks
			WHERE tenant_id=$1 AND vector_build_id=$2`, string(tenant), vectorBuild.ID).Scan(&vectorRows)
	}); err != nil {
		t.Fatal(err)
	}
	if vectorState != "failed" || vectorRows != 0 {
		t.Fatalf("unpublished vector cleanup state=%s rows=%d", vectorState, vectorRows)
	}
	var stagingChunks, stagingPostings, stagingStats int
	if err := withScope(ctx, indexerDB, scope{tenant: tenant, visibility: visibility}, nil, func(tx *sql.Tx) error {
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM keel_meta.retrieval_chunks WHERE tenant_id=$1 AND build_id=$2`, string(tenant), stagingBuild.ID).Scan(&stagingChunks); err != nil {
			return err
		}
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM keel_meta.retrieval_term_postings WHERE tenant_id=$1 AND build_id=$2`, string(tenant), stagingBuild.ID).Scan(&stagingPostings); err != nil {
			return err
		}
		return tx.QueryRowContext(ctx, `SELECT count(*) FROM keel_meta.retrieval_term_statistics WHERE tenant_id=$1 AND build_id=$2`, string(tenant), stagingBuild.ID).Scan(&stagingStats)
	}); err != nil {
		t.Fatal(err)
	}
	if stagingChunks != 0 || stagingPostings != 0 || stagingStats != 0 {
		t.Fatalf("unpublished build retained rows: chunks=%d postings=%d statistics=%d", stagingChunks, stagingPostings, stagingStats)
	}
}

func installErasureCleanupFailureTrigger(t *testing.T, admin *sql.DB, tenant string, build uuid.UUID) func() {
	t.Helper()
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")
	function := "k3test_cleanup_fail_" + suffix
	trigger := "k3test_cleanup_posting_fail_" + suffix
	install := func(create bool) {
		conn, err := admin.Conn(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if _, err := conn.ExecContext(context.Background(), `SET ROLE keel_schema_owner`); err != nil {
			t.Fatal(err)
		}
		defer func() { _, _ = conn.ExecContext(context.Background(), `RESET ROLE`) }()
		if create {
			body := fmt.Sprintf(`CREATE FUNCTION keel_meta.%s() RETURNS trigger LANGUAGE plpgsql AS $fn$
				BEGIN IF OLD.tenant_id='%s'::uuid AND OLD.build_id='%s'::uuid THEN
					RAISE EXCEPTION 'injected derived-index cleanup failure'; END IF; RETURN OLD; END $fn$`, function, tenant, build)
			if _, err := conn.ExecContext(context.Background(), body); err != nil {
				t.Fatal(err)
			}
			if _, err := conn.ExecContext(context.Background(), fmt.Sprintf(`CREATE TRIGGER %s BEFORE DELETE ON keel_meta.retrieval_term_postings FOR EACH ROW EXECUTE FUNCTION keel_meta.%s()`, trigger, function)); err != nil {
				t.Fatal(err)
			}
			return
		}
		if _, err := conn.ExecContext(context.Background(), fmt.Sprintf(`DROP TRIGGER IF EXISTS %s ON keel_meta.retrieval_term_postings`, trigger)); err != nil {
			t.Fatal(err)
		}
		if _, err := conn.ExecContext(context.Background(), fmt.Sprintf(`DROP FUNCTION IF EXISTS keel_meta.%s()`, function)); err != nil {
			t.Fatal(err)
		}
	}
	install(true)
	return func() { install(false) }
}
