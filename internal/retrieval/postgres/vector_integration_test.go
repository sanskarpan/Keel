package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
	"github.com/sanskarpan/keel/internal/retrieval/contracts"
	"github.com/sanskarpan/keel/internal/retrieval/index"
	"github.com/sanskarpan/keel/internal/retrieval/vector"
)

func TestPostgreSQLVectorPublicationExactAndBoundedHNSW(t *testing.T) {
	appDB, indexerDB, adminDB := retrievalTestDBsWithAdmin(t)
	app, _ := New(appDB)
	indexer, _ := New(indexerDB)
	ctx := context.Background()
	manifest := vectorFixtureManifest(t)
	registerVectorTestModel(t, adminDB, manifest)
	tenant := tenancy.TenantID(uuid.NewString())
	visibility := "research-" + strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	texts := []string{"alpha source one", "alpha source two", "alpha source three", "alpha source four", "alpha source five"}
	lexBuild, chunks := createVectorSourceCorpus(t, indexer, tenant, visibility, texts)
	values := [][]float32{{1, 0, 0}, {.8, .6, 0}, {0, 1, 0}, {0, 1, 0}, {-1, 0, 0}}
	vectorBuild, err := indexer.BeginVectorBuild(ctx, tenant, visibility, VectorBuildSpec{ID: uuid.New(), Model: manifest})
	if err != nil {
		t.Fatal(err)
	}
	if err := indexer.StageVectorBatch(ctx, tenant, visibility, vectorBuild.ID, []VectorChunk{{ChunkID: chunks[0].ID, ModelInputTokens: manifest.MaxInputTokens + 1, Values: values[0]}}); err == nil {
		t.Fatal("embedding input token bound overflow was accepted")
	}
	if err := indexer.StageVectorBatch(ctx, tenant, visibility, vectorBuild.ID, []VectorChunk{{ChunkID: chunks[0].ID, ModelInputTokens: 3, Values: []float32{1, 0}}}); err == nil {
		t.Fatal("embedding dimension mismatch was accepted")
	}
	inputs := make([]VectorChunk, len(chunks))
	for i := range chunks {
		inputs[i] = VectorChunk{ChunkID: chunks[i].ID, ModelInputTokens: 3, Values: values[i]}
	}
	if err := indexer.StageVectorBatch(ctx, tenant, visibility, vectorBuild.ID, inputs); err != nil {
		t.Fatal(err)
	}
	if _, err := indexer.FinalizeVectorBuild(ctx, tenant, visibility, vectorBuild.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := app.ActiveVectorBuild(ctx, tenant, visibility, manifest.ID, manifest.Revision); !errors.Is(err, ErrNoActiveVectorBuild) {
		t.Fatalf("ready vectors became visible before publication: %v", err)
	}
	if generation, err := indexer.PublishVectorBuild(ctx, tenant, visibility, vectorBuild.ID, 0); err != nil || generation != 1 {
		t.Fatalf("publish generation=%d err=%v", generation, err)
	}
	active, err := app.ActiveVectorBuild(ctx, tenant, visibility, manifest.ID, manifest.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if active.CorpusBuildID != lexBuild || active.Generation != 1 || active.VectorCount != len(chunks) {
		t.Fatalf("wrong active vector build: %+v", active)
	}
	query := []float32{1, 0, 0}
	exact, err := app.SearchVectorExact(ctx, tenant, visibility, manifest.ID, manifest.Revision, query, 4, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(exact.Candidates) != 4 || exact.Candidates[0].ChunkID != chunks[0].ID || exact.Candidates[0].Score != 1 ||
		exact.Candidates[2].CosineDistance != 1 || exact.Candidates[3].CosineDistance != 1 ||
		exact.Candidates[2].ChunkID.String() > exact.Candidates[3].ChunkID.String() {
		t.Fatalf("unexpected exact vector order/score: %+v", exact.Candidates)
	}
	if _, err := app.SearchVectorExact(ctx, tenant, visibility, manifest.ID, manifest.Revision, query, 3, 3); !errors.Is(err, ErrVectorBudgetExceeded) {
		t.Fatalf("exact candidate budget did not fail closed: %v", err)
	}
	ann, err := app.SearchVectorHNSW(ctx, tenant, visibility, manifest.ID, manifest.Revision, query, HNSWOptions{TopK: 2, CandidateLimit: 4, MaxScanTuples: 100, EFSearch: 20, MaxExactFallbackCandidates: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(ann.Candidates) != 2 || ann.Candidates[0].ChunkID != chunks[0].ID || ann.Candidates[1].ChunkID != chunks[1].ID || ann.Candidates[0].CosineDistance > 1e-6 {
		t.Fatalf("unexpected HNSW results: %+v", ann)
	}
	fallback, err := app.SearchVectorHNSW(ctx, tenant, visibility, manifest.ID, manifest.Revision, query, HNSWOptions{TopK: 4, CandidateLimit: 2, MaxScanTuples: 100, EFSearch: 20, MaxExactFallbackCandidates: 10})
	if err != nil {
		t.Fatal(err)
	}
	if !fallback.Fallback || fallback.Degraded || len(fallback.Candidates) != 4 {
		t.Fatalf("underfilled ANN did not use bounded exact fallback: %+v", fallback)
	}
	degraded, err := app.SearchVectorHNSW(ctx, tenant, visibility, manifest.ID, manifest.Revision, query, HNSWOptions{TopK: 4, CandidateLimit: 2, MaxScanTuples: 100, EFSearch: 20, MaxExactFallbackCandidates: 1})
	if err != nil {
		t.Fatal(err)
	}
	if !degraded.Degraded || degraded.Fallback || len(degraded.Candidates) >= 4 {
		t.Fatalf("over-budget fallback did not report underfill: %+v", degraded)
	}
	otherVisibility := "private-" + strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	otherLexBuild, otherChunks := createVectorSourceCorpus(t, indexer, tenant, otherVisibility, []string{"private cohort vector source"})
	otherVisibilityBuild, err := indexer.BeginVectorBuild(ctx, tenant, otherVisibility, VectorBuildSpec{ID: uuid.New(), Model: manifest})
	if err != nil {
		t.Fatal(err)
	}
	if err := indexer.StageVectorBatch(ctx, tenant, otherVisibility, otherVisibilityBuild.ID, []VectorChunk{{ChunkID: otherChunks[0].ID, ModelInputTokens: 4, Values: []float32{0, 0, 1}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := indexer.FinalizeVectorBuild(ctx, tenant, otherVisibility, otherVisibilityBuild.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := indexer.PublishVectorBuild(ctx, tenant, otherVisibility, otherVisibilityBuild.ID, 0); err != nil {
		t.Fatal(err)
	}
	otherResults, err := app.SearchVectorExact(ctx, tenant, otherVisibility, manifest.ID, manifest.Revision, []float32{0, 0, 1}, 1, 10)
	if err != nil || len(otherResults.Candidates) != 1 || otherResults.Build.CorpusBuildID != otherLexBuild || otherResults.Candidates[0].DocumentVersionID != otherChunks[0].DocumentVersionID {
		t.Fatalf("visibility cohort read another vector corpus: results=%+v err=%v", otherResults, err)
	}
	underfilledCorpus, err := app.SearchVectorHNSW(ctx, tenant, otherVisibility, manifest.ID, manifest.Revision, []float32{0, 0, 1}, HNSWOptions{TopK: 4, CandidateLimit: 2, MaxScanTuples: 20, EFSearch: 20, MaxExactFallbackCandidates: 10})
	if err != nil || !underfilledCorpus.Fallback || !underfilledCorpus.Degraded || len(underfilledCorpus.Candidates) != 1 {
		t.Fatalf("exact fallback did not report corpus underfill: results=%+v err=%v", underfilledCorpus, err)
	}
	financeAgain, err := app.SearchVectorExact(ctx, tenant, visibility, manifest.ID, manifest.Revision, query, 1, 10)
	if err != nil || len(financeAgain.Candidates) != 1 || financeAgain.Candidates[0].ChunkID != chunks[0].ID {
		t.Fatalf("vector cohorts influenced each other's result scope: results=%+v err=%v", financeAgain, err)
	}
	otherManifest := manifest
	otherManifest.ID = "keel.test-unit-vector-alt.v1"
	otherManifest.ArtifactSHA256 = strings.Repeat("b", 64)
	registerVectorTestModel(t, adminDB, otherManifest)
	otherModelBuild, err := indexer.BeginVectorBuild(ctx, tenant, visibility, VectorBuildSpec{ID: uuid.New(), Model: otherManifest})
	if err != nil {
		t.Fatal(err)
	}
	otherModelVectors := make([]VectorChunk, len(chunks))
	for i := range chunks {
		otherModelVectors[i] = VectorChunk{ChunkID: chunks[i].ID, ModelInputTokens: 3, Values: []float32{0, 1, 0}}
	}
	if err := indexer.StageVectorBatch(ctx, tenant, visibility, otherModelBuild.ID, otherModelVectors); err != nil {
		t.Fatal(err)
	}
	if _, err := indexer.FinalizeVectorBuild(ctx, tenant, visibility, otherModelBuild.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := indexer.PublishVectorBuild(ctx, tenant, visibility, otherModelBuild.ID, 0); err != nil {
		t.Fatal(err)
	}
	modelIsolated, err := app.SearchVectorExact(ctx, tenant, visibility, otherManifest.ID, otherManifest.Revision, []float32{0, 1, 0}, 1, 10)
	if err != nil || len(modelIsolated.Candidates) != 1 || modelIsolated.Build.ID != otherModelBuild.ID {
		t.Fatalf("model identity received another model's vectors: results=%+v err=%v", modelIsolated, err)
	}
	if _, err := app.SearchVectorExact(ctx, tenancy.TenantID(uuid.NewString()), visibility, manifest.ID, manifest.Revision, query, 2, 10); !errors.Is(err, ErrNoActiveVectorBuild) {
		t.Fatalf("another tenant read vector build: %v", err)
	}
	if _, err := app.WithdrawSource(ctx, tenant, visibility, uuid.New(), chunks[0].DocumentVersionID, uuid.New()); err != nil {
		t.Fatalf("withdraw vector source: %v", err)
	}
	postWithdrawal, err := app.SearchVectorExact(ctx, tenant, visibility, manifest.ID, manifest.Revision, query, 5, 10)
	if err != nil || len(postWithdrawal.Candidates) != 4 {
		t.Fatalf("vector search did not suppress withdrawn source: candidates=%+v err=%v", postWithdrawal.Candidates, err)
	}
	for _, candidate := range postWithdrawal.Candidates {
		if candidate.DocumentVersionID == chunks[0].DocumentVersionID {
			t.Fatal("vector search returned a withdrawn document version")
		}
	}
	assertVectorHNSWPlan(t, appDB, tenant, visibility, active, manifest, query)
	if err := withScope(ctx, indexerDB, scope{tenant: tenant, visibility: visibility}, nil, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `DELETE FROM keel_meta.retrieval_vector_chunks WHERE tenant_id=$1 AND vector_build_id=$2`, string(tenant), vectorBuild.ID)
		return err
	}); err == nil {
		t.Fatal("indexer changed published vectors")
	}
	newCorpusID := uuid.New()
	if err := indexer.BeginBuild(ctx, tenant, visibility, buildSpec(newCorpusID, "term-key-v1", 1)); err != nil {
		t.Fatal(err)
	}
	hasher, err := index.NewHMACTermHasher(string(tenant), "term-key-v1", []byte(strings.Repeat("z", 32)))
	if err != nil {
		t.Fatal(err)
	}
	newChunk := preparedChunk(t, hasher, uuid.New(), "replacement lexical source")
	if err := indexer.StageBatch(ctx, tenant, visibility, newCorpusID, []index.Chunk{newChunk}); err != nil {
		t.Fatal(err)
	}
	if _, err := indexer.Finalize(ctx, tenant, visibility, newCorpusID); err != nil {
		t.Fatal(err)
	}
	if _, err := indexer.Publish(ctx, tenant, visibility, newCorpusID, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := app.SearchVectorExact(ctx, tenant, visibility, manifest.ID, manifest.Revision, query, 1, 10); !errors.Is(err, ErrNoActiveVectorBuild) {
		t.Fatalf("vector from a retired lexical corpus remained active: %v", err)
	}
}

func TestPostgreSQLVectorBuildIsFencedToPublishedCorpusGeneration(t *testing.T) {
	_, indexerDB, adminDB := retrievalTestDBsWithAdmin(t)
	indexer, _ := New(indexerDB)
	ctx := context.Background()
	manifest := vectorFixtureManifest(t)
	registerVectorTestModel(t, adminDB, manifest)
	tenant := tenancy.TenantID(uuid.NewString())
	visibility := "vector-fence-" + strings.ReplaceAll(uuid.NewString(), "-", "")[:10]
	_, chunks := createVectorSourceCorpus(t, indexer, tenant, visibility, []string{"source corpus generation one"})
	build, err := indexer.BeginVectorBuild(ctx, tenant, visibility, VectorBuildSpec{ID: uuid.New(), Model: manifest})
	if err != nil {
		t.Fatal(err)
	}
	if err := indexer.StageVectorBatch(ctx, tenant, visibility, build.ID, []VectorChunk{{ChunkID: chunks[0].ID, ModelInputTokens: 4, Values: []float32{0, 1, 0}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := indexer.FinalizeVectorBuild(ctx, tenant, visibility, build.ID); err != nil {
		t.Fatal(err)
	}
	newCorpusID := uuid.New()
	spec := buildSpec(newCorpusID, "term-key-v1", 1)
	if err := indexer.BeginBuild(ctx, tenant, visibility, spec); err != nil {
		t.Fatal(err)
	}
	hasher, err := index.NewHMACTermHasher(string(tenant), spec.TermKeyID, []byte(strings.Repeat("z", 32)))
	if err != nil {
		t.Fatal(err)
	}
	chunk := preparedChunk(t, hasher, uuid.New(), "replacement corpus generation")
	if err := indexer.StageBatch(ctx, tenant, visibility, newCorpusID, []index.Chunk{chunk}); err != nil {
		t.Fatal(err)
	}
	if _, err := indexer.Finalize(ctx, tenant, visibility, newCorpusID); err != nil {
		t.Fatal(err)
	}
	if _, err := indexer.Publish(ctx, tenant, visibility, newCorpusID, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := indexer.PublishVectorBuild(ctx, tenant, visibility, build.ID, 0); !errors.Is(err, ErrVectorCorpusStale) {
		t.Fatalf("stale vector corpus generation published: %v", err)
	}
}

func vectorFixtureManifest(t *testing.T) vector.Manifest {
	t.Helper()
	m := vector.Manifest{ID: "keel.test-unit-vector.v1", Revision: "fixture-v1", Provider: "synthetic-fixture", ArtifactSHA256: strings.Repeat("a", 64), TokenizerID: "keel.test-tokenizer.v1", AnalyzerID: contracts.AnalyzerID, MaxInputTokens: 128, Dimensions: 3, Distance: "cosine", Normalization: "unit_l2"}
	if err := m.Validate(); err != nil {
		t.Fatal(err)
	}
	return m
}

func registerVectorTestModel(t *testing.T, admin *sql.DB, m vector.Manifest) {
	t.Helper()
	digest, err := m.Digest()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	conn, err := admin.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, `SET ROLE keel_schema_owner`); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = conn.ExecContext(context.Background(), `RESET ROLE`) }()
	_, err = conn.ExecContext(ctx, `INSERT INTO keel_meta.retrieval_model_manifests(model_id,model_revision,provider_id,artifact_sha256,tokenizer_id,analyzer_id,max_input_tokens,dimensions,distance_metric,normalization,manifest_sha256)
		VALUES($1,$2,$3,decode($4,'hex'),$5,$6,$7,$8,$9,$10,$11) ON CONFLICT(model_id,model_revision) DO NOTHING`, m.ID, m.Revision, m.Provider, m.ArtifactSHA256, m.TokenizerID, m.AnalyzerID, m.MaxInputTokens, m.Dimensions, m.Distance, m.Normalization, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	var registered []byte
	if err := conn.QueryRowContext(ctx, `SELECT manifest_sha256 FROM keel_meta.retrieval_model_manifests WHERE model_id=$1 AND model_revision=$2`, m.ID, m.Revision).Scan(&registered); err != nil {
		t.Fatal(err)
	}
	if len(registered) != 32 || !strings.EqualFold(fmt.Sprintf("%x", registered), fmt.Sprintf("%x", digest)) {
		t.Fatal("synthetic model fixture ID is already registered with a different manifest")
	}
	var indexName string
	if err := conn.QueryRowContext(ctx, `SELECT keel_meta.provision_retrieval_hnsw_index($1,$2)::text`, m.ID, m.Revision).Scan(&indexName); err != nil {
		t.Fatalf("provision model-specific HNSW index: %v", err)
	}
	if indexName == "" {
		t.Fatal("HNSW index was not provisioned")
	}
}

func createVectorSourceCorpus(t *testing.T, r *Repository, tenant tenancy.TenantID, visibility string, texts []string) (uuid.UUID, []index.Chunk) {
	t.Helper()
	ctx := context.Background()
	hasher, err := index.NewHMACTermHasher(string(tenant), "term-key-v1", []byte(strings.Repeat("z", 32)))
	if err != nil {
		t.Fatal(err)
	}
	buildID := uuid.New()
	if err := r.BeginBuild(ctx, tenant, visibility, buildSpec(buildID, hasher.KeyID(), len(texts))); err != nil {
		t.Fatal(err)
	}
	chunks := make([]index.Chunk, len(texts))
	for i, text := range texts {
		chunks[i] = preparedChunk(t, hasher, uuid.New(), text)
		chunks[i].Ordinal = i
	}
	if err := r.StageBatch(ctx, tenant, visibility, buildID, chunks); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Finalize(ctx, tenant, visibility, buildID); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Publish(ctx, tenant, visibility, buildID, 0); err != nil {
		t.Fatal(err)
	}
	return buildID, chunks
}

func assertVectorHNSWPlan(t *testing.T, db *sql.DB, tenant tenancy.TenantID, visibility string, b VectorBuild, m vector.Manifest, query []float32) {
	t.Helper()
	ctx := context.Background()
	s, err := newScope(tenant, visibility)
	if err != nil {
		t.Fatal(err)
	}
	literal := formatVector(query)
	sqlText := fmt.Sprintf(`EXPLAIN SELECT chunk_id FROM keel_meta.retrieval_vector_chunks WHERE tenant_id=$1 AND visibility_key=$2 AND vector_build_id=$3 AND model_id='%s' AND model_revision='%s' ORDER BY embedding::halfvec(%d) <=> $4::halfvec(%d) LIMIT 2`, m.ID, m.Revision, m.Dimensions, m.Dimensions)
	err = withScope(ctx, db, s, &sql.TxOptions{ReadOnly: true}, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `SET LOCAL enable_seqscan=off`); err != nil {
			return err
		}
		rows, err := tx.QueryContext(ctx, sqlText, string(tenant), visibility, b.ID, literal)
		if err != nil {
			return err
		}
		defer rows.Close()
		var plan strings.Builder
		for rows.Next() {
			var line string
			if err := rows.Scan(&line); err != nil {
				return err
			}
			plan.WriteString(line)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		if !strings.Contains(plan.String(), b.HNSWIndexName) {
			return fmt.Errorf("query plan did not use model HNSW index %s: %s", b.HNSWIndexName, plan.String())
		}
		return nil
	})
	if err != nil {
		t.Fatalf("verify model-specific HNSW plan: %v", err)
	}
}
