// Package postgres persists encrypted-term, tenant/cohort-local BM25 indexes.
package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"

	"github.com/google/uuid"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
	"github.com/sanskarpan/keel/internal/retrieval/index"
)

const (
	MaxChunksPerBatch   = 1000
	MaxPostingsPerBatch = 100000
	MaxQueryTerms       = 64
	MaxQueryPostingRows = 100000
)

var termKeyIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]{1,159}$`)

var (
	ErrNoActiveBuild         = errors.New("no active retrieval corpus build")
	ErrBuildNotReady         = errors.New("retrieval corpus build is not ready")
	ErrBuildNotBuilding      = errors.New("retrieval corpus build is not building")
	ErrGenerationConflict    = errors.New("retrieval corpus publication generation conflict")
	ErrPostingBudgetExceeded = errors.New("retrieval query posting budget exceeded")
	ErrTermKeyMismatch       = errors.New("retrieval query term-key identity mismatch")
)

type Repository struct{ db *sql.DB }

func New(db *sql.DB) (*Repository, error) {
	if db == nil {
		return nil, errors.New("database is required")
	}
	return &Repository{db: db}, nil
}

type scope struct {
	tenant     tenancy.TenantID
	visibility string
}

func newScope(tenant tenancy.TenantID, visibility string) (scope, error) {
	parsedTenant, err := tenancy.ParseTenantID(string(tenant))
	if err != nil {
		return scope{}, err
	}
	canonicalTenant, err := uuid.Parse(string(parsedTenant))
	if err != nil {
		return scope{}, err
	}
	v, err := index.ParseVisibilityKey(visibility)
	if err != nil {
		return scope{}, err
	}
	return scope{tenant: tenancy.TenantID(canonicalTenant.String()), visibility: v}, nil
}
func withScope(ctx context.Context, db *sql.DB, s scope, options *sql.TxOptions, work func(*sql.Tx) error) error {
	return tenancy.WithTenantTx(ctx, db, s.tenant, options, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `SELECT set_config('keel.visibility_key',$1,true)`, s.visibility); err != nil {
			return fmt.Errorf("set retrieval visibility scope: %w", err)
		}
		return work(tx)
	})
}

func (r *Repository) BeginBuild(ctx context.Context, tenant tenancy.TenantID, visibility string, spec index.BuildSpec) error {
	s, err := newScope(tenant, visibility)
	if err != nil {
		return err
	}
	if err := index.ValidateBuildSpec(spec, spec.TermKeyID); err != nil {
		return err
	}
	return withScope(ctx, r.db, s, nil, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO keel_meta.retrieval_corpus_heads (tenant_id,visibility_key) VALUES ($1,$2) ON CONFLICT DO NOTHING`, string(s.tenant), s.visibility); err != nil {
			return fmt.Errorf("initialize retrieval corpus head: %w", err)
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO keel_meta.retrieval_corpus_builds
			(tenant_id,build_id,visibility_key,analyzer_id,chunker_id,term_key_id,manifest_sha256,expected_chunk_count)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, string(s.tenant), spec.ID, s.visibility, spec.AnalyzerID, spec.ChunkerID, spec.TermKeyID, spec.ManifestDigest[:], spec.ExpectedChunks)
		if err != nil {
			return fmt.Errorf("create retrieval corpus build: %w", err)
		}
		return nil
	})
}

func (r *Repository) StageBatch(ctx context.Context, tenant tenancy.TenantID, visibility string, buildID uuid.UUID, chunks []index.Chunk) error {
	s, err := newScope(tenant, visibility)
	if err != nil {
		return err
	}
	if buildID == uuid.Nil {
		return errors.New("build ID is required")
	}
	if len(chunks) == 0 || len(chunks) > MaxChunksPerBatch {
		return fmt.Errorf("chunk batch size must be in [1,%d]", MaxChunksPerBatch)
	}
	postingRows := 0
	seenChunks := map[uuid.UUID]bool{}
	seenOrdinals := map[string]bool{}
	for _, chunk := range chunks {
		if err := index.ValidateChunk(chunk); err != nil {
			return err
		}
		if seenChunks[chunk.ID] {
			return errors.New("duplicate chunk ID in batch")
		}
		seenChunks[chunk.ID] = true
		ordinal := chunk.DocumentVersionID.String() + ":" + fmt.Sprint(chunk.Ordinal)
		if seenOrdinals[ordinal] {
			return errors.New("duplicate document chunk ordinal in batch")
		}
		seenOrdinals[ordinal] = true
		postingRows += len(chunk.Terms)
	}
	if postingRows > MaxPostingsPerBatch {
		return fmt.Errorf("posting batch exceeds %d rows", MaxPostingsPerBatch)
	}
	return withScope(ctx, r.db, s, nil, func(tx *sql.Tx) error {
		var state, termKeyID string
		if err := tx.QueryRowContext(ctx, `SELECT state,term_key_id FROM keel_meta.retrieval_corpus_builds WHERE tenant_id=$1 AND build_id=$2 AND visibility_key=$3`, string(s.tenant), buildID, s.visibility).Scan(&state, &termKeyID); err != nil {
			return err
		}
		if state != "building" {
			return ErrBuildNotBuilding
		}
		for _, chunk := range chunks {
			if chunk.TermTenantID != string(s.tenant) || chunk.TermKeyID != termKeyID {
				return errors.New("chunk term IDs do not match the authorized tenant and build key")
			}
			_, err := tx.ExecContext(ctx, `INSERT INTO keel_meta.retrieval_chunks
				(tenant_id,build_id,visibility_key,chunk_id,document_version_id,chunk_ordinal,source_start_byte,source_end_byte,token_count,content_sha256)
				VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, string(s.tenant), buildID, s.visibility, chunk.ID, chunk.DocumentVersionID, chunk.Ordinal, chunk.StartByte, chunk.EndByte, chunk.TokenCount, chunk.ContentDigest[:])
			if err != nil {
				return fmt.Errorf("insert retrieval chunk: %w", err)
			}
			for _, term := range chunk.Terms {
				_, err = tx.ExecContext(ctx, `INSERT INTO keel_meta.retrieval_term_postings
					(tenant_id,build_id,visibility_key,term_key_id,term_id,chunk_id,term_frequency) VALUES ($1,$2,$3,$4,$5,$6,$7)`, string(s.tenant), buildID, s.visibility, termKeyID, term.Term[:], chunk.ID, term.Frequency)
				if err != nil {
					return fmt.Errorf("insert retrieval term posting: %w", err)
				}
			}
		}
		return nil
	})
}

func (r *Repository) Finalize(ctx context.Context, tenant tenancy.TenantID, visibility string, buildID uuid.UUID) (index.Build, error) {
	s, err := newScope(tenant, visibility)
	if err != nil {
		return index.Build{}, err
	}
	if buildID == uuid.Nil {
		return index.Build{}, errors.New("build ID is required")
	}
	var build index.Build
	err = withScope(ctx, r.db, s, nil, func(tx *sql.Tx) error {
		var state string
		if err := tx.QueryRowContext(ctx, `SELECT state FROM keel_meta.retrieval_corpus_builds WHERE tenant_id=$1 AND build_id=$2 AND visibility_key=$3 FOR UPDATE`, string(s.tenant), buildID, s.visibility).Scan(&state); err != nil {
			return err
		}
		if state != "building" {
			return ErrBuildNotBuilding
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO keel_meta.retrieval_term_statistics
			(tenant_id,build_id,visibility_key,term_key_id,term_id,document_frequency)
			SELECT p.tenant_id,p.build_id,p.visibility_key,p.term_key_id,p.term_id,count(DISTINCT p.chunk_id)::integer
			FROM keel_meta.retrieval_term_postings p WHERE p.tenant_id=$1 AND p.build_id=$2 AND p.visibility_key=$3
			GROUP BY p.tenant_id,p.build_id,p.visibility_key,p.term_key_id,p.term_id`, string(s.tenant), buildID, s.visibility); err != nil {
			return fmt.Errorf("build retrieval term statistics: %w", err)
		}
		if err := tx.QueryRowContext(ctx, `SELECT count(*),coalesce(sum(token_count),0) FROM keel_meta.retrieval_chunks WHERE tenant_id=$1 AND build_id=$2 AND visibility_key=$3`, string(s.tenant), buildID, s.visibility).Scan(&build.ChunkCount, &build.TotalTokenCount); err != nil {
			return err
		}
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM keel_meta.retrieval_term_statistics WHERE tenant_id=$1 AND build_id=$2 AND visibility_key=$3`, string(s.tenant), buildID, s.visibility).Scan(&build.TermCount); err != nil {
			return err
		}
		var manifestDigest []byte
		if err := tx.QueryRowContext(ctx, `UPDATE keel_meta.retrieval_corpus_builds SET state='ready',chunk_count=$3,total_token_count=$4,term_count=$5,ready_at=clock_timestamp(),updated_at=clock_timestamp()
			WHERE tenant_id=$1 AND build_id=$2 RETURNING analyzer_id,chunker_id,term_key_id,manifest_sha256,expected_chunk_count`, string(s.tenant), buildID, build.ChunkCount, build.TotalTokenCount, build.TermCount).Scan(&build.AnalyzerID, &build.ChunkerID, &build.TermKeyID, &manifestDigest, &build.ExpectedChunks); err != nil {
			return fmt.Errorf("validate and finalize retrieval build: %w", err)
		}
		if len(manifestDigest) != 32 {
			return errors.New("retrieval manifest digest has invalid length")
		}
		copy(build.ManifestDigest[:], manifestDigest)
		build.ID = buildID
		build.Visibility = s.visibility
		build.State = "ready"
		return nil
	})
	return build, err
}

func (r *Repository) Publish(ctx context.Context, tenant tenancy.TenantID, visibility string, buildID uuid.UUID, expectedGeneration int64) (int64, error) {
	s, err := newScope(tenant, visibility)
	if err != nil {
		return 0, err
	}
	if buildID == uuid.Nil || expectedGeneration < 0 {
		return 0, errors.New("build ID and nonnegative expected generation are required")
	}
	var next int64
	err = withScope(ctx, r.db, s, nil, func(tx *sql.Tx) error {
		var state string
		if err := tx.QueryRowContext(ctx, `SELECT state FROM keel_meta.retrieval_corpus_builds WHERE tenant_id=$1 AND build_id=$2 AND visibility_key=$3 FOR UPDATE`, string(s.tenant), buildID, s.visibility).Scan(&state); err != nil {
			return err
		}
		if state != "ready" {
			return ErrBuildNotReady
		}
		rows, err := tx.QueryContext(ctx, `SELECT DISTINCT document_version_id FROM keel_meta.retrieval_chunks
			WHERE tenant_id=$1 AND build_id=$2 AND visibility_key=$3 ORDER BY document_version_id`, string(s.tenant), buildID, s.visibility)
		if err != nil {
			return fmt.Errorf("read source versions before publication: %w", err)
		}
		var sourceIDs []uuid.UUID
		for rows.Next() {
			var sourceID uuid.UUID
			if err := rows.Scan(&sourceID); err != nil {
				_ = rows.Close()
				return err
			}
			sourceIDs = append(sourceIDs, sourceID)
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return err
		}
		if err := rows.Close(); err != nil {
			return err
		}
		if err := lockEligibleSources(ctx, tx, s, sourceIDs); err != nil {
			return fmt.Errorf("refuse stale retrieval publication: %w", err)
		}
		var old sql.NullString
		var generation int64
		if err := tx.QueryRowContext(ctx, `SELECT active_build_id::text,generation FROM keel_meta.retrieval_corpus_heads WHERE tenant_id=$1 AND visibility_key=$2 FOR UPDATE`, string(s.tenant), s.visibility).Scan(&old, &generation); err != nil {
			return err
		}
		if generation != expectedGeneration {
			return ErrGenerationConflict
		}
		next = generation + 1
		if _, err := tx.ExecContext(ctx, `UPDATE keel_meta.retrieval_corpus_heads SET active_build_id=$3,generation=$4,updated_at=clock_timestamp() WHERE tenant_id=$1 AND visibility_key=$2`, string(s.tenant), s.visibility, buildID, next); err != nil {
			return fmt.Errorf("switch retrieval corpus head: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE keel_meta.retrieval_corpus_builds SET state='published',published_at=clock_timestamp(),updated_at=clock_timestamp() WHERE tenant_id=$1 AND build_id=$2`, string(s.tenant), buildID); err != nil {
			return fmt.Errorf("mark retrieval build published: %w", err)
		}
		if old.Valid {
			oldID, parseErr := uuid.Parse(old.String)
			if parseErr != nil {
				return fmt.Errorf("parse previous retrieval build ID: %w", parseErr)
			}
			if _, err := tx.ExecContext(ctx, `UPDATE keel_meta.retrieval_corpus_builds SET state='retired',updated_at=clock_timestamp() WHERE tenant_id=$1 AND build_id=$2`, string(s.tenant), oldID); err != nil {
				return fmt.Errorf("retire previous retrieval build: %w", err)
			}
		}
		return nil
	})
	return next, err
}

func (r *Repository) ActiveBuild(ctx context.Context, tenant tenancy.TenantID, visibility string) (index.Build, error) {
	s, err := newScope(tenant, visibility)
	if err != nil {
		return index.Build{}, err
	}
	var build index.Build
	err = withScope(ctx, r.db, s, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead}, func(tx *sql.Tx) error {
		err := scanBuild(tx.QueryRowContext(ctx, `SELECT b.build_id,b.visibility_key,b.analyzer_id,b.chunker_id,b.term_key_id,b.manifest_sha256,b.expected_chunk_count,b.chunk_count,b.total_token_count,b.term_count,b.state,h.generation
			FROM keel_meta.retrieval_corpus_heads h JOIN keel_meta.retrieval_corpus_builds b ON b.tenant_id=h.tenant_id AND b.build_id=h.active_build_id
			WHERE h.tenant_id=$1 AND h.visibility_key=$2 AND b.state='published'`, string(s.tenant), s.visibility), &build)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNoActiveBuild
		}
		return err
	})
	return build, err
}

type Result struct {
	ChunkID           uuid.UUID
	DocumentVersionID uuid.UUID
	Ordinal           int
	StartByte         int
	EndByte           int
	ContentDigest     [32]byte
	Score             float64
}
type SearchResult struct {
	Build       index.Build
	Candidates  []Result
	PostingRows int
}

// SearchScores returns only citation metadata and bounded BM25 scores; source
// text stays in the encrypted source system. Exceeding the posting budget
// fails closed and returns no partial ranking.
func (r *Repository) SearchScores(ctx context.Context, tenant tenancy.TenantID, visibility, termKeyID string, queryTerms []index.TermID, topK, maxPostingRows int) (SearchResult, error) {
	s, err := newScope(tenant, visibility)
	if err != nil {
		return SearchResult{}, err
	}
	if !stableTermKeyID(termKeyID) {
		return SearchResult{}, errors.New("term key ID is required")
	}
	if topK < 1 || topK > 100 {
		return SearchResult{}, errors.New("topK must be in [1,100]")
	}
	if maxPostingRows < 1 || maxPostingRows > MaxQueryPostingRows {
		return SearchResult{}, fmt.Errorf("posting row budget must be in [1,%d]", MaxQueryPostingRows)
	}
	terms := uniqueTerms(queryTerms)
	if len(terms) == 0 || len(terms) > MaxQueryTerms {
		return SearchResult{}, fmt.Errorf("query must contain [1,%d] unique terms", MaxQueryTerms)
	}
	result := SearchResult{}
	// Source row locks require a read-write PostgreSQL transaction. The app
	// database role still has only SELECT plus its guarded withdrawal columns.
	err = withScope(ctx, r.db, s, &sql.TxOptions{Isolation: sql.LevelRepeatableRead}, func(tx *sql.Tx) error {
		if err := scanBuild(tx.QueryRowContext(ctx, `SELECT b.build_id,b.visibility_key,b.analyzer_id,b.chunker_id,b.term_key_id,b.manifest_sha256,b.expected_chunk_count,b.chunk_count,b.total_token_count,b.term_count,b.state,h.generation
			FROM keel_meta.retrieval_corpus_heads h JOIN keel_meta.retrieval_corpus_builds b ON b.tenant_id=h.tenant_id AND b.build_id=h.active_build_id
			WHERE h.tenant_id=$1 AND h.visibility_key=$2 AND b.state='published'`, string(s.tenant), s.visibility), &result.Build); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrNoActiveBuild
			}
			return err
		}
		if result.Build.TermKeyID != termKeyID {
			return ErrTermKeyMismatch
		}
		args := []any{string(s.tenant), s.visibility, result.Build.ID, termKeyID}
		placeholders := make([]string, 0, len(terms))
		for i, term := range terms {
			args = append(args, term[:])
			placeholders = append(placeholders, fmt.Sprintf("$%d", i+5))
		}
		args = append(args, maxPostingRows+1)
		limitArg := fmt.Sprintf("$%d", len(args))
		query := `SELECT c.chunk_id,c.document_version_id,c.chunk_ordinal,c.source_start_byte,c.source_end_byte,c.content_sha256,c.token_count,p.term_frequency,st.document_frequency
			FROM keel_meta.retrieval_chunks c JOIN keel_meta.retrieval_term_postings p ON p.tenant_id=c.tenant_id AND p.build_id=c.build_id AND p.chunk_id=c.chunk_id
			JOIN keel_meta.retrieval_term_statistics st ON st.tenant_id=p.tenant_id AND st.build_id=p.build_id AND st.term_id=p.term_id
			JOIN keel_meta.retrieval_source_eligibility e ON e.tenant_id=c.tenant_id AND e.visibility_key=c.visibility_key AND e.document_version_id=c.document_version_id AND e.state='active'
			WHERE c.tenant_id=$1 AND c.visibility_key=$2 AND c.build_id=$3 AND p.term_key_id=$4 AND p.term_id IN (` + strings.Join(placeholders, ",") + `)
			ORDER BY c.chunk_id,p.term_id LIMIT ` + limitArg
		rows, err := tx.QueryContext(ctx, query, args...)
		if err != nil {
			return fmt.Errorf("read bounded retrieval postings: %w", err)
		}
		averageLength := float64(result.Build.TotalTokenCount) / float64(result.Build.ChunkCount)
		var current Result
		var currentChunk uuid.UUID
		hasCurrent := false
		for rows.Next() {
			var chunkID, docID uuid.UUID
			var ordinal, start, end, length, tf, df int
			var digest []byte
			if err := rows.Scan(&chunkID, &docID, &ordinal, &start, &end, &digest, &length, &tf, &df); err != nil {
				_ = rows.Close()
				return err
			}
			result.PostingRows++
			if result.PostingRows > maxPostingRows {
				_ = rows.Close()
				return ErrPostingBudgetExceeded
			}
			if len(digest) != 32 {
				_ = rows.Close()
				return errors.New("retrieval index contains malformed content digest")
			}
			if !hasCurrent || chunkID != currentChunk {
				if hasCurrent {
					result.Candidates = append(result.Candidates, current)
				}
				var d [32]byte
				copy(d[:], digest)
				currentChunk = chunkID
				current = Result{ChunkID: chunkID, DocumentVersionID: docID, Ordinal: ordinal, StartByte: start, EndByte: end, ContentDigest: d}
				hasCurrent = true
			}
			id := math.Log1p((float64(result.Build.ChunkCount-df) + .5) / (float64(df) + .5))
			lengthNorm := float64(tf) + 1.2*(1-.75+.75*float64(length)/averageLength)
			current.Score += id * float64(tf) * 2.2 / lengthNorm
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return err
		}
		if err := rows.Close(); err != nil {
			return err
		}
		if hasCurrent {
			result.Candidates = append(result.Candidates, current)
		}
		sort.Slice(result.Candidates, func(i, j int) bool {
			if result.Candidates[i].Score == result.Candidates[j].Score {
				return result.Candidates[i].ChunkID.String() < result.Candidates[j].ChunkID.String()
			}
			return result.Candidates[i].Score > result.Candidates[j].Score
		})
		if len(result.Candidates) > topK {
			result.Candidates = result.Candidates[:topK]
		}
		ids := make([]uuid.UUID, 0, len(result.Candidates))
		for _, candidate := range result.Candidates {
			ids = append(ids, candidate.DocumentVersionID)
		}
		return lockEligibleSources(ctx, tx, s, ids)
	})
	if err != nil {
		return SearchResult{}, err
	}
	return result, nil
}

// lockEligibleSources defines the query/revocation race: a query that locks an
// active source first is ordered before a concurrent withdrawal; a withdrawal
// that commits first makes this repeatable-read transaction fail to acquire a
// current lock (serialization failure) or return no candidates. Callers must
// retry serialization failures before exposing any result.
func lockEligibleSources(ctx context.Context, tx *sql.Tx, s scope, ids []uuid.UUID) error {
	seen := make(map[uuid.UUID]struct{}, len(ids))
	for _, id := range ids {
		if id == uuid.Nil {
			return errors.New("retrieval candidate has an empty source version")
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		var state string
		err := tx.QueryRowContext(ctx, `SELECT state FROM keel_meta.retrieval_source_eligibility
			WHERE tenant_id=$1 AND visibility_key=$2 AND document_version_id=$3 FOR SHARE`, string(s.tenant), s.visibility, id).Scan(&state)
		if errors.Is(err, sql.ErrNoRows) || (err == nil && state != "active") {
			return errors.New("retrieval source was withdrawn during query")
		}
		if err != nil {
			return fmt.Errorf("lock current retrieval source eligibility: %w", err)
		}
	}
	return nil
}

type rowScanner interface{ Scan(...any) error }

func scanBuild(row rowScanner, build *index.Build) error {
	var digest []byte
	if err := row.Scan(&build.ID, &build.Visibility, &build.AnalyzerID, &build.ChunkerID, &build.TermKeyID, &digest, &build.ExpectedChunks, &build.ChunkCount, &build.TotalTokenCount, &build.TermCount, &build.State, &build.Generation); err != nil {
		return err
	}
	if len(digest) != 32 {
		return errors.New("retrieval manifest digest has invalid length")
	}
	copy(build.ManifestDigest[:], digest)
	return nil
}

func uniqueTerms(in []index.TermID) []index.TermID {
	seen := map[index.TermID]bool{}
	out := make([]index.TermID, 0, len(in))
	for _, term := range in {
		if term == ([32]byte{}) || seen[term] {
			continue
		}
		seen[term] = true
		out = append(out, term)
	}
	return out
}
func stableTermKeyID(v string) bool {
	return termKeyIDPattern.MatchString(v)
}
