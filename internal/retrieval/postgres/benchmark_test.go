package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"math"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
	"github.com/sanskarpan/keel/internal/retrieval/contracts"
	"github.com/sanskarpan/keel/internal/retrieval/index"
)

func BenchmarkPostgreSQLSearchScoresTenantSkew(b *testing.B) {
	appDSN, indexerDSN := os.Getenv("KEEL_TEST_DATABASE_URL"), os.Getenv("KEEL_TEST_RETRIEVAL_INDEXER_DATABASE_URL")
	if appDSN == "" || indexerDSN == "" {
		b.Skip("set the app and retrieval-indexer test DSNs to run the PostgreSQL retrieval benchmark")
	}
	for _, size := range []int{100, 5000} {
		b.Run(fmt.Sprintf("eligible_chunks_%d", size), func(b *testing.B) {
			appDB := openRetrievalBenchmarkDB(b, appDSN)
			indexerDB := openRetrievalBenchmarkDB(b, indexerDSN)
			app, _ := New(appDB)
			indexer, _ := New(indexerDB)
			tenant := tenancy.TenantID(uuid.NewString())
			visibility := "bench-" + strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
			hasher, err := index.NewHMACTermHasher(string(tenant), "bench-key-v1", []byte(strings.Repeat("b", 32)))
			if err != nil {
				b.Fatal(err)
			}
			buildID := uuid.New()
			ctx := context.Background()
			if err := indexer.BeginBuild(ctx, tenant, visibility, buildSpec(buildID, hasher.KeyID(), size)); err != nil {
				b.Fatal(err)
			}
			for first := 0; first < size; first += MaxChunksPerBatch {
				last := min(first+MaxChunksPerBatch, size)
				chunks := make([]index.Chunk, 0, last-first)
				for ordinal := first; ordinal < last; ordinal++ {
					text := fmt.Sprintf("common retrieval workload marker%05d", ordinal)
					tokens, err := contracts.Tokenize(text)
					if err != nil {
						b.Fatal(err)
					}
					chunk, err := index.PrepareChunk(uuid.New(), contracts.Chunk{Ordinal: ordinal, Text: text, StartByte: 0, EndByte: len(text), TokenCount: len(tokens)}, hasher)
					if err != nil {
						b.Fatal(err)
					}
					chunks = append(chunks, chunk)
				}
				if err := indexer.StageBatch(ctx, tenant, visibility, buildID, chunks); err != nil {
					b.Fatal(err)
				}
			}
			if _, err := indexer.Finalize(ctx, tenant, visibility, buildID); err != nil {
				b.Fatal(err)
			}
			if _, err := indexer.Publish(ctx, tenant, visibility, buildID, 0); err != nil {
				b.Fatal(err)
			}
			common := hasher.ID("common")
			marker := hasher.ID("marker00000")
			rares, err := app.SearchScores(ctx, tenant, visibility, hasher.KeyID(), []index.TermID{marker}, 5, size)
			if err != nil || len(rares.Candidates) != 1 || rares.Candidates[0].Score <= 0 {
				b.Fatalf("rare-term reference query failed: candidates=%+v err=%v", rares.Candidates, err)
			}
			b.Logf("server=%s tenant_chunks=%d cohort_count=1 common_postings=%d rare_recall@5=1/1 rare_query_terms=1 rare_top_k=5 common_query_terms=1 common_top_k=10 posting_budget=%d", retrievalServerVersion(b, appDB), size, size, size)
			b.ReportAllocs()
			b.ResetTimer()
			durations := make([]time.Duration, 0, b.N)
			for i := 0; i < b.N; i++ {
				started := time.Now()
				result, err := app.SearchScores(ctx, tenant, visibility, hasher.KeyID(), []index.TermID{common}, 10, size)
				durations = append(durations, time.Since(started))
				if err != nil || len(result.Candidates) != 10 || result.PostingRows != size {
					b.Fatalf("common-term query violated result/posting contract: candidates=%d postings=%d err=%v", len(result.Candidates), result.PostingRows, err)
				}
			}
			b.StopTimer()
			sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
			b.ReportMetric(float64(durations[(len(durations)-1)/2].Microseconds()), "p50-us/op")
			p95 := (95*len(durations)+99)/100 - 1
			b.ReportMetric(float64(durations[p95].Microseconds()), "p95-us/op")
			b.ReportMetric(float64(size), "postings/op")
		})
	}
}

func TestPostgreSQLLexicalPlanUsesPostingTermIdentity(t *testing.T) {
	appDB, indexerDB, adminDB := retrievalTestDBsWithAdmin(t)
	indexer, _ := New(indexerDB)
	tenant := tenancy.TenantID(uuid.NewString())
	visibility := "plan-" + strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	hasher, err := index.NewHMACTermHasher(string(tenant), "plan-key-v1", []byte(strings.Repeat("p", 32)))
	if err != nil {
		t.Fatal(err)
	}
	buildID := uuid.New()
	const corpusSize = 2000
	if err := indexer.BeginBuild(context.Background(), tenant, visibility, buildSpec(buildID, hasher.KeyID(), corpusSize)); err != nil {
		t.Fatal(err)
	}
	for first := 0; first < corpusSize; first += MaxChunksPerBatch {
		last := min(first+MaxChunksPerBatch, corpusSize)
		chunks := make([]index.Chunk, 0, last-first)
		for ordinal := first; ordinal < last; ordinal++ {
			text := fmt.Sprintf("common retrieval workload marker%05d", ordinal)
			tokens, err := contracts.Tokenize(text)
			if err != nil {
				t.Fatal(err)
			}
			chunk, err := index.PrepareChunk(uuid.New(), contracts.Chunk{Ordinal: ordinal, Text: text, StartByte: 0, EndByte: len(text), TokenCount: len(tokens)}, hasher)
			if err != nil {
				t.Fatal(err)
			}
			chunks = append(chunks, chunk)
		}
		if err := indexer.StageBatch(context.Background(), tenant, visibility, buildID, chunks); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := indexer.Finalize(context.Background(), tenant, visibility, buildID); err != nil {
		t.Fatal(err)
	}
	if _, err := indexer.Publish(context.Background(), tenant, visibility, buildID, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := adminDB.ExecContext(context.Background(), `ANALYZE keel_meta.retrieval_term_postings,keel_meta.retrieval_term_statistics,keel_meta.retrieval_chunks`); err != nil {
		t.Fatal(err)
	}
	term := hasher.ID("marker00000")
	var plan []byte
	err = withScope(context.Background(), appDB, scope{tenant: tenant, visibility: visibility}, &sql.TxOptions{ReadOnly: true}, func(tx *sql.Tx) error {
		return tx.QueryRowContext(context.Background(), `EXPLAIN (FORMAT JSON)
			SELECT c.chunk_id,c.document_version_id,c.chunk_ordinal,c.source_start_byte,c.source_end_byte,c.content_sha256,c.token_count,p.term_id,p.term_frequency,st.document_frequency
			FROM keel_meta.retrieval_chunks c JOIN keel_meta.retrieval_term_postings p ON p.tenant_id=c.tenant_id AND p.build_id=c.build_id AND p.chunk_id=c.chunk_id
			JOIN keel_meta.retrieval_term_statistics st ON st.tenant_id=p.tenant_id AND st.build_id=p.build_id AND st.term_id=p.term_id
			JOIN keel_meta.retrieval_source_eligibility e ON e.tenant_id=c.tenant_id AND e.visibility_key=c.visibility_key AND e.document_version_id=c.document_version_id AND e.state='active'
			WHERE c.tenant_id=$1 AND c.visibility_key=$2 AND c.build_id=$3 AND p.term_key_id=$4 AND p.term_id=$5
			ORDER BY c.chunk_id,p.term_id LIMIT 6`, string(tenant), visibility, buildID, hasher.KeyID(), term[:]).Scan(&plan)
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(plan), "retrieval_term_postings_pkey") {
		t.Fatalf("selective term query plan did not use the tenant/build/term posting index: %s", plan)
	}
	t.Logf("selective retrieval EXPLAIN JSON (non-owner app role): %s", plan)
}

func TestPostgreSQLBM25MatchesIndependentReferenceAcrossLengthsAndFrequencies(t *testing.T) {
	appDB, indexerDB := retrievalTestDBs(t)
	app, _ := New(appDB)
	indexer, _ := New(indexerDB)
	tenant := tenancy.TenantID(uuid.NewString())
	visibility := "bm25-ref-" + strings.ReplaceAll(uuid.NewString(), "-", "")[:10]
	hasher, err := index.NewHMACTermHasher(string(tenant), "bm25-ref-key-v1", []byte(strings.Repeat("r", 32)))
	if err != nil {
		t.Fatal(err)
	}
	sources := []struct {
		text string
		tf   int
	}{
		{text: "common common alpha", tf: 2},
		{text: "common beta", tf: 1},
		{text: "common common common gamma", tf: 3},
		{text: "delta epsilon", tf: 0},
		{text: "common tie", tf: 1},
		{text: "common tie", tf: 1},
	}
	buildID := uuid.New()
	if err := indexer.BeginBuild(context.Background(), tenant, visibility, buildSpec(buildID, hasher.KeyID(), len(sources))); err != nil {
		t.Fatal(err)
	}
	chunks := make([]index.Chunk, 0, len(sources))
	versions := make([]uuid.UUID, len(sources))
	chunkIDs := make([]uuid.UUID, len(sources))
	lengths := make([]int, len(sources))
	for i, source := range sources {
		version := uuid.New()
		versions[i] = version
		tokens, err := contracts.Tokenize(source.text)
		if err != nil {
			t.Fatal(err)
		}
		lengths[i] = len(tokens)
		chunk, err := index.PrepareChunk(version, contracts.Chunk{Ordinal: 0, Text: source.text, StartByte: 0, EndByte: len(source.text), TokenCount: len(tokens)}, hasher)
		if err != nil {
			t.Fatal(err)
		}
		if source.text == "common tie" {
			chunk.ID = uuid.MustParse(fmt.Sprintf("00000000-0000-0000-0000-%012d", i))
		}
		chunkIDs[i] = chunk.ID
		chunks = append(chunks, chunk)
	}
	if err := indexer.StageBatch(context.Background(), tenant, visibility, buildID, chunks); err != nil {
		t.Fatal(err)
	}
	if _, err := indexer.Finalize(context.Background(), tenant, visibility, buildID); err != nil {
		t.Fatal(err)
	}
	if _, err := indexer.Publish(context.Background(), tenant, visibility, buildID, 0); err != nil {
		t.Fatal(err)
	}
	result, err := app.SearchScores(context.Background(), tenant, visibility, hasher.KeyID(), []index.TermID{hasher.ID("common")}, 10, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Candidates) != 5 {
		t.Fatalf("got %d common-term candidates, want 5", len(result.Candidates))
	}
	const corpusCount = 6
	const documentFrequency = 5
	const averageLength = float64(15) / corpusCount
	want := make(map[uuid.UUID]float64, len(sources))
	reference := make([]Result, 0, documentFrequency)
	for i, source := range sources {
		if source.tf == 0 {
			continue
		}
		idf := math.Log1p((float64(corpusCount-documentFrequency) + 0.5) / (float64(documentFrequency) + 0.5))
		lengthNorm := float64(source.tf) + 1.2*(1-0.75+0.75*float64(lengths[i])/averageLength)
		score := idf * float64(source.tf) * 2.2 / lengthNorm
		want[versions[i]] = score
		reference = append(reference, Result{DocumentVersionID: versions[i], ChunkID: chunkIDs[i], Score: score})
	}
	sort.Slice(reference, func(i, j int) bool {
		if reference[i].Score == reference[j].Score {
			return reference[i].ChunkID.String() < reference[j].ChunkID.String()
		}
		return reference[i].Score > reference[j].Score
	})
	for i, candidate := range result.Candidates {
		expected, ok := want[candidate.DocumentVersionID]
		if !ok || math.Abs(candidate.Score-expected) > 1e-12 {
			t.Fatalf("candidate %d score mismatch: candidate=%+v want=%0.15f", i, candidate, expected)
		}
		if candidate.ChunkID != reference[i].ChunkID || candidate.DocumentVersionID != reference[i].DocumentVersionID {
			t.Fatalf("candidate %d differs from independently ranked BM25 reference: got=%+v want=%+v", i, candidate, reference[i])
		}
	}
	repeated, err := app.SearchScores(context.Background(), tenant, visibility, hasher.KeyID(), []index.TermID{hasher.ID("common")}, 10, 100)
	if err != nil || len(repeated.Candidates) != len(result.Candidates) {
		t.Fatalf("repeated reference query failed: candidates=%d err=%v", len(repeated.Candidates), err)
	}
	for i := range result.Candidates {
		if repeated.Candidates[i].ChunkID != result.Candidates[i].ChunkID {
			t.Fatalf("BM25 ordering changed across identical queries at rank %d: first=%+v repeated=%+v", i, result.Candidates[i], repeated.Candidates[i])
		}
	}
}

func openRetrievalBenchmarkDB(b *testing.B, dsn string) *sql.DB {
	b.Helper()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		b.Fatal(err)
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = db.Close() })
	return db
}

func retrievalServerVersion(b *testing.B, db *sql.DB) string {
	b.Helper()
	var version string
	if err := db.QueryRow(`SELECT current_setting('server_version')`).Scan(&version); err != nil {
		b.Fatal(err)
	}
	return version
}
