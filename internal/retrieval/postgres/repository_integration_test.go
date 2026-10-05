package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"math"
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
)

func TestPostgreSQLTenantVisibilityScopedLexicalPublication(t *testing.T) {
	appDB, indexerDB := retrievalTestDBs(t)
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
	otherTenant := tenancy.TenantID(uuid.NewString())
	visibility := "finance-" + strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	hasher, err := index.NewHMACTermHasher(string(tenant), "key-v1", []byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	chunks := []index.Chunk{preparedChunk(t, hasher, uuid.New(), "invoice invoice total"), preparedChunk(t, hasher, uuid.New(), "payment schedule window")}
	buildID := uuid.New()
	spec := buildSpec(buildID, hasher.KeyID(), len(chunks))
	if err := indexer.BeginBuild(ctx, tenant, visibility, spec); err != nil {
		t.Fatal(err)
	}
	wrongTenantHasher, err := index.NewHMACTermHasher(string(otherTenant), "key-v1", []byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	wrongChunk := preparedChunk(t, wrongTenantHasher, uuid.New(), "cross tenant private term")
	if err := indexer.StageBatch(ctx, tenant, visibility, buildID, []index.Chunk{wrongChunk}); err == nil {
		t.Fatal("cross-tenant term IDs were accepted into this build")
	}
	if err := indexer.StageBatch(ctx, tenant, visibility, buildID, chunks); err != nil {
		t.Fatal(err)
	}
	if _, err := app.ActiveBuild(ctx, tenant, visibility); !errors.Is(err, ErrNoActiveBuild) {
		t.Fatalf("staged corpus became active: %v", err)
	}
	if _, err := indexer.Finalize(ctx, tenant, visibility, buildID); err != nil {
		t.Fatal(err)
	}
	if _, err := app.ActiveBuild(ctx, tenant, visibility); !errors.Is(err, ErrNoActiveBuild) {
		t.Fatalf("ready corpus became active before publication: %v", err)
	}
	generation, err := indexer.Publish(ctx, tenant, visibility, buildID, 0)
	if err != nil || generation != 1 {
		t.Fatalf("publish generation=%d err=%v", generation, err)
	}
	active, err := app.ActiveBuild(ctx, tenant, visibility)
	if err != nil {
		t.Fatal(err)
	}
	if active.ID != buildID || active.State != "published" || active.Generation != 1 || active.ChunkCount != 2 || active.TotalTokenCount != 6 {
		t.Fatalf("unexpected active corpus: %+v", active)
	}
	otherVisibility := "restricted-" + strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	otherBuildID := uuid.New()
	otherChunk := preparedChunk(t, hasher, uuid.New(), "invoice invoice invoice invoice")
	createReadyBuild(t, indexer, tenant, otherVisibility, buildSpec(otherBuildID, hasher.KeyID(), 1), otherChunk)
	if generation, err := indexer.Publish(ctx, tenant, otherVisibility, otherBuildID, 0); err != nil || generation != 1 {
		t.Fatalf("publish independent visibility corpus generation=%d err=%v", generation, err)
	}
	invoice := hasher.ID("invoice")
	results, err := app.SearchScores(ctx, tenant, visibility, hasher.KeyID(), []index.TermID{invoice}, 5, 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(results.Candidates) != 1 || results.Candidates[0].DocumentVersionID != chunks[0].DocumentVersionID || results.Candidates[0].Score <= 0 {
		t.Fatalf("unexpected lexical results: %+v", results)
	}
	// Independent BM25 calculation for the two-chunk finance corpus: invoice
	// occurs twice in one three-token chunk, N=2, df=1, and avg length=3.
	wantScore := math.Log(1+(2.0-1.0+.5)/(1.0+.5)) * (2.0 * 2.2 / (2.0 + 1.2))
	if math.Abs(results.Candidates[0].Score-wantScore) > 1e-12 {
		t.Fatalf("BM25 score=%0.15f, independently calculated score=%0.15f", results.Candidates[0].Score, wantScore)
	}
	cohortResults, err := app.SearchScores(ctx, tenant, otherVisibility, hasher.KeyID(), []index.TermID{invoice}, 5, 20)
	if err != nil || len(cohortResults.Candidates) != 1 || cohortResults.Candidates[0].DocumentVersionID != otherChunk.DocumentVersionID || cohortResults.Candidates[0].ChunkID == results.Candidates[0].ChunkID {
		t.Fatalf("visibility cohort received another corpus's candidates: results=%+v err=%v", cohortResults, err)
	}
	if _, err := app.SearchScores(ctx, tenant, visibility, hasher.KeyID()+"-wrong", []index.TermID{invoice}, 5, 20); !errors.Is(err, ErrTermKeyMismatch) {
		t.Fatalf("wrong term key was accepted: %v", err)
	}
	if _, err := app.SearchScores(ctx, tenant, visibility, hasher.KeyID(), []index.TermID{invoice, hasher.ID("total")}, 5, 1); !errors.Is(err, ErrPostingBudgetExceeded) {
		t.Fatalf("posting budget overflow did not fail closed: %v", err)
	}
	if _, err := app.ActiveBuild(ctx, otherTenant, visibility); !errors.Is(err, ErrNoActiveBuild) {
		t.Fatalf("another tenant read a corpus: %v", err)
	}
	if active, err := app.ActiveBuild(ctx, tenant, otherVisibility); err != nil || active.ID != otherBuildID {
		t.Fatalf("visibility cohort read wrong corpus: active=%+v err=%v", active, err)
	}
	withdrawalID := uuid.New()
	withdrawalActor := uuid.New()
	job, err := app.WithdrawSource(ctx, tenant, visibility, withdrawalActor, chunks[0].DocumentVersionID, withdrawalID)
	if err != nil || job.State != "fenced" || job.EligibilityGeneration != 2 || job.RequestedBy != withdrawalActor {
		t.Fatalf("withdrawal did not atomically fence and enqueue erasure: job=%+v err=%v", job, err)
	}
	replayed, err := app.WithdrawSource(ctx, tenant, visibility, withdrawalActor, chunks[0].DocumentVersionID, withdrawalID)
	if err != nil || replayed.ID != job.ID || replayed.State != "fenced" {
		t.Fatalf("replayed withdrawal was not idempotent: job=%+v err=%v", replayed, err)
	}
	persistedJob, err := app.ErasureJob(ctx, tenant, visibility, withdrawalID)
	if err != nil || persistedJob.DocumentVersionID != chunks[0].DocumentVersionID || persistedJob.RequestedBy != withdrawalActor || persistedJob.State != "fenced" {
		t.Fatalf("durable erasure state mismatch: job=%+v err=%v", persistedJob, err)
	}
	withdrawnResults, err := app.SearchScores(ctx, tenant, visibility, hasher.KeyID(), []index.TermID{invoice}, 5, 20)
	if err != nil || len(withdrawnResults.Candidates) != 0 {
		t.Fatalf("query returned withdrawn source: results=%+v err=%v", withdrawnResults, err)
	}
	staleBuildID := uuid.New()
	if err := indexer.BeginBuild(ctx, tenant, visibility, buildSpec(staleBuildID, hasher.KeyID(), 1)); err != nil {
		t.Fatal(err)
	}
	if err := indexer.StageBatch(ctx, tenant, visibility, staleBuildID, []index.Chunk{chunks[0]}); err == nil {
		t.Fatal("withdrawn source version was reintroduced into a build")
	}
	if err := withScope(ctx, indexerDB, scope{tenant: tenant, visibility: visibility}, nil, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `DELETE FROM keel_meta.retrieval_chunks WHERE tenant_id=$1 AND build_id=$2`, string(tenant), buildID)
		return err
	}); err == nil {
		t.Fatal("indexer changed published chunks")
	}
}

func TestPostgreSQLPublicationFailureRollsBackAndGenerationFences(t *testing.T) {
	appDB, indexerDB, adminDB := retrievalTestDBsWithAdmin(t)
	app, _ := New(appDB)
	indexer, _ := New(indexerDB)
	ctx := context.Background()
	tenant := tenancy.TenantID(uuid.NewString())
	visibility := "ops-" + strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	hasher, err := index.NewHMACTermHasher(string(tenant), "key-v1", []byte(strings.Repeat("p", 32)))
	if err != nil {
		t.Fatal(err)
	}
	first := uuid.New()
	createReadyBuild(t, indexer, tenant, visibility, buildSpec(first, hasher.KeyID(), 1), preparedChunk(t, hasher, uuid.New(), "maintenance window"))
	fault, err := installPublicationFailureTrigger(t, adminDB, string(tenant))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := indexer.Publish(ctx, tenant, visibility, first, 0); err == nil {
		t.Fatal("injected publication failure was ignored")
	}
	if err := removePublicationFailureTrigger(t, adminDB, fault); err != nil {
		t.Fatal(err)
	}
	if _, err := app.ActiveBuild(ctx, tenant, visibility); !errors.Is(err, ErrNoActiveBuild) {
		t.Fatalf("failed publication changed active head: %v", err)
	}
	state := buildState(t, indexerDB, tenant, visibility, first)
	if state != "ready" {
		t.Fatalf("failed publish changed candidate build state to %q", state)
	}
	if generation, err := indexer.Publish(ctx, tenant, visibility, first, 0); err != nil || generation != 1 {
		t.Fatalf("recovered publish generation=%d err=%v", generation, err)
	}
	second := uuid.New()
	createReadyBuild(t, indexer, tenant, visibility, buildSpec(second, hasher.KeyID(), 1), preparedChunk(t, hasher, uuid.New(), "new maintenance window"))
	if _, err := indexer.Publish(ctx, tenant, visibility, second, 0); !errors.Is(err, ErrGenerationConflict) {
		t.Fatalf("stale generation did not conflict: %v", err)
	}
	active, err := app.ActiveBuild(ctx, tenant, visibility)
	if err != nil || active.ID != first {
		t.Fatalf("stale publisher displaced active build: active=%+v err=%v", active, err)
	}
	if generation, err := indexer.Publish(ctx, tenant, visibility, second, 1); err != nil || generation != 2 {
		t.Fatalf("second publication generation=%d err=%v", generation, err)
	}
	active, err = app.ActiveBuild(ctx, tenant, visibility)
	if err != nil || active.ID != second || active.Generation != 2 {
		t.Fatalf("atomic replacement failed: active=%+v err=%v", active, err)
	}
	if state := buildState(t, indexerDB, tenant, visibility, first); state != "retired" {
		t.Fatalf("prior build state=%q, want retired", state)
	}
}

func TestPostgreSQLRejectsCorruptStagedPostingTotals(t *testing.T) {
	_, indexerDB := retrievalTestDBs(t)
	indexer, _ := New(indexerDB)
	ctx := context.Background()
	tenant := tenancy.TenantID(uuid.NewString())
	visibility := "audit-" + strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	hasher, err := index.NewHMACTermHasher(string(tenant), "key-v1", []byte(strings.Repeat("c", 32)))
	if err != nil {
		t.Fatal(err)
	}
	buildID := uuid.New()
	spec := buildSpec(buildID, hasher.KeyID(), 1)
	if err := indexer.BeginBuild(ctx, tenant, visibility, spec); err != nil {
		t.Fatal(err)
	}
	badTerm := hasher.ID("only-one-term")
	chunkID, documentVersion := uuid.New(), uuid.New()
	digest := sha256.Sum256([]byte("invalid synthetic chunk"))
	err = withScope(ctx, indexerDB, scope{tenant: tenant, visibility: visibility}, nil, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO keel_meta.retrieval_chunks (tenant_id,build_id,visibility_key,chunk_id,document_version_id,chunk_ordinal,source_start_byte,source_end_byte,token_count,content_sha256) VALUES ($1,$2,$3,$4,$5,0,0,20,2,$6)`, string(tenant), buildID, visibility, chunkID, documentVersion, digest[:]); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO keel_meta.retrieval_term_postings (tenant_id,build_id,visibility_key,term_key_id,term_id,chunk_id,term_frequency) VALUES ($1,$2,$3,$4,$5,$6,1)`, string(tenant), buildID, visibility, hasher.KeyID(), badTerm[:], chunkID)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := indexer.Finalize(ctx, tenant, visibility, buildID); err == nil {
		t.Fatal("posting totals inconsistent with chunk length were finalized")
	}
	if state := buildState(t, indexerDB, tenant, visibility, buildID); state != "building" {
		t.Fatalf("failed finalization left state %q", state)
	}
}

func retrievalTestDBs(t *testing.T) (*sql.DB, *sql.DB) {
	t.Helper()
	appURL := os.Getenv("KEEL_TEST_DATABASE_URL")
	indexerURL := os.Getenv("KEEL_TEST_RETRIEVAL_INDEXER_DATABASE_URL")
	if appURL == "" || indexerURL == "" {
		t.Skip("set app and retrieval indexer PostgreSQL URLs to run retrieval integration tests")
	}
	return openRetrievalDB(t, appURL), openRetrievalDB(t, indexerURL)
}
func retrievalTestDBsWithAdmin(t *testing.T) (*sql.DB, *sql.DB, *sql.DB) {
	t.Helper()
	app, indexer := retrievalTestDBs(t)
	adminURL := os.Getenv("KEEL_TEST_ADMIN_DATABASE_URL")
	if adminURL == "" {
		t.Skip("set KEEL_TEST_ADMIN_DATABASE_URL to run publication fault-injection test")
	}
	return app, indexer, openRetrievalDB(t, adminURL)
}
func openRetrievalDB(t *testing.T, rawURL string) *sql.DB {
	t.Helper()
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
		t.Fatalf("connect PostgreSQL test role: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}
func buildSpec(id uuid.UUID, keyID string, chunks int) index.BuildSpec {
	return index.BuildSpec{ID: id, AnalyzerID: contracts.AnalyzerID, ChunkerID: contracts.ChunkerID, TermKeyID: keyID, ManifestDigest: sha256.Sum256([]byte("synthetic manifest")), ExpectedChunks: chunks}
}
func preparedChunk(t *testing.T, hasher index.TermHasher, docVersion uuid.UUID, text string) index.Chunk {
	t.Helper()
	tokens, err := contracts.Tokenize(text)
	if err != nil {
		t.Fatal(err)
	}
	chunk := contracts.Chunk{Ordinal: 0, Text: text, StartByte: 0, EndByte: len(text), TokenCount: len(tokens)}
	prepared, err := index.PrepareChunk(docVersion, chunk, hasher)
	if err != nil {
		t.Fatal(err)
	}
	return prepared
}
func createReadyBuild(t *testing.T, repo *Repository, tenant tenancy.TenantID, visibility string, spec index.BuildSpec, chunk index.Chunk) {
	t.Helper()
	ctx := context.Background()
	if err := repo.BeginBuild(ctx, tenant, visibility, spec); err != nil {
		t.Fatal(err)
	}
	if err := repo.StageBatch(ctx, tenant, visibility, spec.ID, []index.Chunk{chunk}); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Finalize(ctx, tenant, visibility, spec.ID); err != nil {
		t.Fatal(err)
	}
}
func buildState(t *testing.T, db *sql.DB, tenant tenancy.TenantID, visibility string, build uuid.UUID) string {
	t.Helper()
	var state string
	if err := withScope(context.Background(), db, scope{tenant: tenant, visibility: visibility}, nil, func(tx *sql.Tx) error {
		return tx.QueryRow(`SELECT state FROM keel_meta.retrieval_corpus_builds WHERE tenant_id=$1 AND build_id=$2`, string(tenant), build).Scan(&state)
	}); err != nil {
		t.Fatal(err)
	}
	return state
}

type faultTrigger struct{ trigger, function string }

func installPublicationFailureTrigger(t *testing.T, admin *sql.DB, tenant string) (*faultTrigger, error) {
	t.Helper()
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")
	function := "k3test_fail_" + suffix
	trigger := "k3test_head_fail_" + suffix
	conn, err := admin.Conn(context.Background())
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if _, err = conn.ExecContext(context.Background(), `SET ROLE keel_schema_owner`); err != nil {
		return nil, err
	}
	defer func() { _, _ = conn.ExecContext(context.Background(), `RESET ROLE`) }()
	body := fmt.Sprintf(`CREATE FUNCTION keel_meta.%s() RETURNS trigger LANGUAGE plpgsql AS $fn$ BEGIN IF NEW.tenant_id='%s'::uuid THEN RAISE EXCEPTION 'injected retrieval publication failure'; END IF; RETURN NEW; END $fn$`, function, tenant)
	if _, err = conn.ExecContext(context.Background(), body); err != nil {
		return nil, err
	}
	if _, err = conn.ExecContext(context.Background(), fmt.Sprintf(`CREATE TRIGGER %s BEFORE UPDATE ON keel_meta.retrieval_corpus_heads FOR EACH ROW EXECUTE FUNCTION keel_meta.%s()`, trigger, function)); err != nil {
		_, _ = conn.ExecContext(context.Background(), fmt.Sprintf(`DROP FUNCTION keel_meta.%s()`, function))
		return nil, err
	}
	fault := &faultTrigger{trigger: trigger, function: function}
	t.Cleanup(func() { _ = removeFaultTrigger(admin, trigger, function) })
	return fault, nil
}
func removePublicationFailureTrigger(t *testing.T, admin *sql.DB, fault *faultTrigger) error {
	t.Helper()
	return removeFaultTrigger(admin, fault.trigger, fault.function)
}
func removeFaultTrigger(admin *sql.DB, trigger, function string) error {
	conn, err := admin.Conn(context.Background())
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err = conn.ExecContext(context.Background(), `SET ROLE keel_schema_owner`); err != nil {
		return err
	}
	defer func() { _, _ = conn.ExecContext(context.Background(), `RESET ROLE`) }()
	if _, err = conn.ExecContext(context.Background(), fmt.Sprintf(`DROP TRIGGER IF EXISTS %s ON keel_meta.retrieval_corpus_heads`, trigger)); err != nil {
		return err
	}
	_, err = conn.ExecContext(context.Background(), fmt.Sprintf(`DROP FUNCTION IF EXISTS keel_meta.%s()`, function))
	return err
}
