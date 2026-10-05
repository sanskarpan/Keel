package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
	"github.com/sanskarpan/keel/internal/retrieval/vector"
)

const (
	MaxVectorBatch           = 512
	MaxVectorBatchBytes      = 32 << 20
	MaxVectorTopK            = 100
	MaxExactVectorCandidates = 100000
	MaxHNSWScanTuples        = 20000
	MaxHNSWCandidateLimit    = 10000
	MaxHNSWEFSearch          = 500
	VectorSearchTimeout      = 2 * time.Second
)

var (
	ErrNoActiveVectorBuild  = errors.New("no active retrieval vector build for this corpus")
	ErrVectorBuildNotReady  = errors.New("retrieval vector build is not ready")
	ErrVectorBuildNotBuild  = errors.New("retrieval vector build is not building")
	ErrVectorGeneration     = errors.New("retrieval vector publication generation conflict")
	ErrVectorBudgetExceeded = errors.New("retrieval vector candidate budget exceeded")
	ErrVectorCorpusStale    = errors.New("retrieval vector build belongs to a stale lexical corpus generation")
	ErrHNSWUnavailable      = errors.New("HNSW index is not provisioned for this immutable model identity")
)

type VectorBuildSpec struct {
	ID    uuid.UUID
	Model vector.Manifest
}

type VectorBuild struct {
	ID               uuid.UUID
	Visibility       string
	CorpusBuildID    uuid.UUID
	CorpusGeneration int64
	Model            vector.Manifest
	ManifestDigest   [32]byte
	ExpectedChunks   int
	VectorCount      int
	State            string
	Generation       int64
	HNSWIndexName    string
}

type VectorChunk struct {
	ChunkID          uuid.UUID
	ModelInputTokens int
	Values           []float32
}

type VectorCandidate struct {
	ChunkID           uuid.UUID
	DocumentVersionID uuid.UUID
	Ordinal           int
	StartByte         int
	EndByte           int
	ContentDigest     [32]byte
	CosineDistance    float64
	Score             float64
}

type VectorSearchResult struct {
	Build          VectorBuild
	Candidates     []VectorCandidate
	CandidateCount int
	Fallback       bool
	Degraded       bool
}

type HNSWOptions struct {
	TopK                       int
	CandidateLimit             int
	MaxScanTuples              int
	EFSearch                   int
	MaxExactFallbackCandidates int
}

func (r *Repository) BeginVectorBuild(ctx context.Context, tenant tenancy.TenantID, visibility string, spec VectorBuildSpec) (VectorBuild, error) {
	s, err := newScope(tenant, visibility)
	if err != nil {
		return VectorBuild{}, err
	}
	if spec.ID == uuid.Nil {
		return VectorBuild{}, errors.New("vector build ID is required")
	}
	digest, err := spec.Model.Digest()
	if err != nil {
		return VectorBuild{}, err
	}
	var build VectorBuild
	err = withScope(ctx, r.db, s, nil, func(tx *sql.Tx) error {
		if err := verifyRegisteredModel(ctx, tx, spec.Model, digest, &build.HNSWIndexName); err != nil {
			return err
		}
		var corpusAnalyzer string
		if err := tx.QueryRowContext(ctx, `SELECT h.active_build_id,h.generation,b.chunk_count,b.state,b.analyzer_id
			FROM keel_meta.retrieval_corpus_heads h JOIN keel_meta.retrieval_corpus_builds b
			 ON b.tenant_id=h.tenant_id AND b.build_id=h.active_build_id AND b.visibility_key=h.visibility_key
			WHERE h.tenant_id=$1 AND h.visibility_key=$2 FOR SHARE OF h,b`, string(s.tenant), s.visibility).
			Scan(&build.CorpusBuildID, &build.CorpusGeneration, &build.ExpectedChunks, &build.State, &corpusAnalyzer); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrNoActiveBuild
			}
			return err
		}
		if build.State != "published" {
			return ErrNoActiveBuild
		}
		if corpusAnalyzer != spec.Model.AnalyzerID {
			return errors.New("embedding model analyzer identity does not match the active source corpus")
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO keel_meta.retrieval_vector_heads (tenant_id,visibility_key,model_id,model_revision)
			VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING`, string(s.tenant), s.visibility, spec.Model.ID, spec.Model.Revision); err != nil {
			return fmt.Errorf("initialize vector head: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO keel_meta.retrieval_vector_builds
			(tenant_id,vector_build_id,visibility_key,corpus_build_id,corpus_generation,model_id,model_revision,manifest_sha256,expected_chunk_count)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`, string(s.tenant), spec.ID, s.visibility, build.CorpusBuildID, build.CorpusGeneration, spec.Model.ID, spec.Model.Revision, digest[:], build.ExpectedChunks); err != nil {
			return fmt.Errorf("create vector build: %w", err)
		}
		build.ID = spec.ID
		build.Visibility = s.visibility
		build.Model = spec.Model
		build.ManifestDigest = digest
		build.State = "building"
		return nil
	})
	return build, err
}

func (r *Repository) StageVectorBatch(ctx context.Context, tenant tenancy.TenantID, visibility string, vectorBuildID uuid.UUID, chunks []VectorChunk) error {
	s, err := newScope(tenant, visibility)
	if err != nil {
		return err
	}
	if vectorBuildID == uuid.Nil {
		return errors.New("vector build ID is required")
	}
	if len(chunks) == 0 || len(chunks) > MaxVectorBatch {
		return fmt.Errorf("vector batch size must be in [1,%d]", MaxVectorBatch)
	}
	seen := map[uuid.UUID]bool{}
	byteCount := 0
	for _, chunk := range chunks {
		if chunk.ChunkID == uuid.Nil || seen[chunk.ChunkID] {
			return errors.New("vector chunk IDs must be present and unique")
		}
		seen[chunk.ChunkID] = true
		byteCount += len(chunk.Values) * 4
		if byteCount > MaxVectorBatchBytes {
			return fmt.Errorf("vector batch exceeds %d bytes", MaxVectorBatchBytes)
		}
	}
	return withScope(ctx, r.db, s, nil, func(tx *sql.Tx) error {
		var state, modelID, revision string
		var dimensions, maxInputTokens int
		err := tx.QueryRowContext(ctx, `SELECT b.state,m.model_id,m.model_revision,m.dimensions,m.max_input_tokens
			FROM keel_meta.retrieval_vector_builds b JOIN keel_meta.retrieval_model_manifests m
			 ON m.model_id=b.model_id AND m.model_revision=b.model_revision AND m.manifest_sha256=b.manifest_sha256
			WHERE b.tenant_id=$1 AND b.vector_build_id=$2 AND b.visibility_key=$3`, string(s.tenant), vectorBuildID, s.visibility).Scan(&state, &modelID, &revision, &dimensions, &maxInputTokens)
		if err != nil {
			return err
		}
		if state != "building" {
			return ErrVectorBuildNotBuild
		}
		for _, chunk := range chunks {
			if chunk.ModelInputTokens < 1 || chunk.ModelInputTokens > maxInputTokens {
				return errors.New("embedding input token count exceeds immutable model manifest bound")
			}
			if err := vector.ValidateVector(chunk.Values, dimensions); err != nil {
				return err
			}
			literal := formatVector(chunk.Values)
			_, err = tx.ExecContext(ctx, `INSERT INTO keel_meta.retrieval_vector_chunks
				(tenant_id,vector_build_id,visibility_key,corpus_build_id,model_id,model_revision,chunk_id,model_input_tokens,embedding)
				SELECT b.tenant_id,b.vector_build_id,b.visibility_key,b.corpus_build_id,b.model_id,b.model_revision,$4,$5,$6::vector
				FROM keel_meta.retrieval_vector_builds b WHERE b.tenant_id=$1 AND b.vector_build_id=$2 AND b.visibility_key=$3`, string(s.tenant), vectorBuildID, s.visibility, chunk.ChunkID, chunk.ModelInputTokens, literal)
			if err != nil {
				return fmt.Errorf("stage retrieval vector: %w", err)
			}
		}
		return nil
	})
}

func (r *Repository) FinalizeVectorBuild(ctx context.Context, tenant tenancy.TenantID, visibility string, vectorBuildID uuid.UUID) (VectorBuild, error) {
	s, err := newScope(tenant, visibility)
	if err != nil {
		return VectorBuild{}, err
	}
	if vectorBuildID == uuid.Nil {
		return VectorBuild{}, errors.New("vector build ID is required")
	}
	var b VectorBuild
	err = withScope(ctx, r.db, s, nil, func(tx *sql.Tx) error {
		if err := tx.QueryRowContext(ctx, `SELECT b.state FROM keel_meta.retrieval_vector_builds b WHERE b.tenant_id=$1 AND b.vector_build_id=$2 AND b.visibility_key=$3 FOR UPDATE`, string(s.tenant), vectorBuildID, s.visibility).Scan(&b.State); err != nil {
			return err
		}
		if b.State != "building" {
			return ErrVectorBuildNotBuild
		}
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM keel_meta.retrieval_vector_chunks WHERE tenant_id=$1 AND vector_build_id=$2 AND visibility_key=$3`, string(s.tenant), vectorBuildID, s.visibility).Scan(&b.VectorCount); err != nil {
			return err
		}
		var digest []byte
		if err := tx.QueryRowContext(ctx, `UPDATE keel_meta.retrieval_vector_builds SET state='ready',vector_count=$3,ready_at=clock_timestamp(),updated_at=clock_timestamp()
			WHERE tenant_id=$1 AND vector_build_id=$2 RETURNING visibility_key,corpus_build_id,corpus_generation,expected_chunk_count,model_id,model_revision,manifest_sha256`, string(s.tenant), vectorBuildID, b.VectorCount).
			Scan(&b.Visibility, &b.CorpusBuildID, &b.CorpusGeneration, &b.ExpectedChunks, &b.Model.ID, &b.Model.Revision, &digest); err != nil {
			return fmt.Errorf("finalize vector build: %w", err)
		}
		if len(digest) != 32 {
			return errors.New("vector manifest digest has invalid length")
		}
		copy(b.ManifestDigest[:], digest)
		b.ID = vectorBuildID
		b.State = "ready"
		return loadManifest(ctx, tx, b.Model.ID, b.Model.Revision, b.ManifestDigest, &b.Model, &b.HNSWIndexName)
	})
	return b, err
}

func (r *Repository) PublishVectorBuild(ctx context.Context, tenant tenancy.TenantID, visibility string, vectorBuildID uuid.UUID, expectedGeneration int64) (int64, error) {
	s, err := newScope(tenant, visibility)
	if err != nil {
		return 0, err
	}
	if vectorBuildID == uuid.Nil || expectedGeneration < 0 {
		return 0, errors.New("vector build ID and nonnegative generation are required")
	}
	var next int64
	err = withScope(ctx, r.db, s, nil, func(tx *sql.Tx) error {
		var state, modelID, revision string
		var corpusID uuid.UUID
		var corpusGeneration int64
		if err := tx.QueryRowContext(ctx, `SELECT state,model_id,model_revision,corpus_build_id,corpus_generation FROM keel_meta.retrieval_vector_builds
			WHERE tenant_id=$1 AND vector_build_id=$2 AND visibility_key=$3 FOR UPDATE`, string(s.tenant), vectorBuildID, s.visibility).Scan(&state, &modelID, &revision, &corpusID, &corpusGeneration); err != nil {
			return err
		}
		if state != "ready" {
			return ErrVectorBuildNotReady
		}
		rows, err := tx.QueryContext(ctx, `SELECT DISTINCT document_version_id FROM keel_meta.retrieval_chunks
			WHERE tenant_id=$1 AND build_id=$2 AND visibility_key=$3 ORDER BY document_version_id`, string(s.tenant), corpusID, s.visibility)
		if err != nil {
			return fmt.Errorf("read source versions before vector publication: %w", err)
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
			return fmt.Errorf("refuse stale vector publication: %w", err)
		}
		var old sql.NullString
		var generation int64
		if err := tx.QueryRowContext(ctx, `SELECT active_vector_build_id::text,generation FROM keel_meta.retrieval_vector_heads
			WHERE tenant_id=$1 AND visibility_key=$2 AND model_id=$3 AND model_revision=$4 FOR UPDATE`, string(s.tenant), s.visibility, modelID, revision).Scan(&old, &generation); err != nil {
			return err
		}
		if generation != expectedGeneration {
			return ErrVectorGeneration
		}
		var activeCorpus uuid.UUID
		var activeCorpusGeneration int64
		if err := tx.QueryRowContext(ctx, `SELECT active_build_id,generation FROM keel_meta.retrieval_corpus_heads WHERE tenant_id=$1 AND visibility_key=$2 FOR SHARE`, string(s.tenant), s.visibility).Scan(&activeCorpus, &activeCorpusGeneration); err != nil {
			return err
		}
		if activeCorpus != corpusID || activeCorpusGeneration != corpusGeneration {
			return ErrVectorCorpusStale
		}
		next = generation + 1
		if _, err := tx.ExecContext(ctx, `UPDATE keel_meta.retrieval_vector_heads SET active_vector_build_id=$5,generation=$6,updated_at=clock_timestamp()
			WHERE tenant_id=$1 AND visibility_key=$2 AND model_id=$3 AND model_revision=$4`, string(s.tenant), s.visibility, modelID, revision, vectorBuildID, next); err != nil {
			return fmt.Errorf("switch vector head: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE keel_meta.retrieval_vector_builds SET state='published',published_at=clock_timestamp(),updated_at=clock_timestamp() WHERE tenant_id=$1 AND vector_build_id=$2`, string(s.tenant), vectorBuildID); err != nil {
			return fmt.Errorf("mark vector build published: %w", err)
		}
		if old.Valid {
			oldID, err := uuid.Parse(old.String)
			if err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `UPDATE keel_meta.retrieval_vector_builds SET state='retired',updated_at=clock_timestamp() WHERE tenant_id=$1 AND vector_build_id=$2`, string(s.tenant), oldID); err != nil {
				return fmt.Errorf("retire previous vector build: %w", err)
			}
		}
		return nil
	})
	return next, err
}

func (r *Repository) ActiveVectorBuild(ctx context.Context, tenant tenancy.TenantID, visibility, modelID, revision string) (VectorBuild, error) {
	s, err := newScope(tenant, visibility)
	if err != nil {
		return VectorBuild{}, err
	}
	if !stableTermKeyID(modelID) || !stableTermKeyID(revision) {
		return VectorBuild{}, errors.New("stable model ID and revision are required")
	}
	var b VectorBuild
	err = withScope(ctx, r.db, s, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead}, func(tx *sql.Tx) error { return readActiveVectorBuild(ctx, tx, s, modelID, revision, &b) })
	return b, err
}

func (r *Repository) SearchVectorExact(ctx context.Context, tenant tenancy.TenantID, visibility, modelID, revision string, query []float32, topK, maxCandidates int) (VectorSearchResult, error) {
	if topK < 1 || topK > MaxVectorTopK {
		return VectorSearchResult{}, fmt.Errorf("topK must be in [1,%d]", MaxVectorTopK)
	}
	if maxCandidates < 1 || maxCandidates > MaxExactVectorCandidates {
		return VectorSearchResult{}, fmt.Errorf("exact candidate budget must be in [1,%d]", MaxExactVectorCandidates)
	}
	return r.searchVector(ctx, tenant, visibility, modelID, revision, query, topK, maxCandidates, false, HNSWOptions{})
}

func (r *Repository) SearchVectorHNSW(ctx context.Context, tenant tenancy.TenantID, visibility, modelID, revision string, query []float32, options HNSWOptions) (VectorSearchResult, error) {
	if options.TopK < 1 || options.TopK > MaxVectorTopK || options.CandidateLimit < 1 || options.CandidateLimit > MaxHNSWCandidateLimit ||
		options.MaxScanTuples < options.CandidateLimit || options.MaxScanTuples > MaxHNSWScanTuples || options.EFSearch < options.TopK || options.EFSearch > MaxHNSWEFSearch ||
		options.MaxExactFallbackCandidates < 0 || options.MaxExactFallbackCandidates > MaxExactVectorCandidates {
		return VectorSearchResult{}, errors.New("HNSW and exact-fallback options exceed supported bounds")
	}
	return r.searchVector(ctx, tenant, visibility, modelID, revision, query, options.TopK, options.CandidateLimit, true, options)
}

func (r *Repository) searchVector(ctx context.Context, tenant tenancy.TenantID, visibility, modelID, revision string, query []float32, topK, budget int, hnsw bool, options HNSWOptions) (VectorSearchResult, error) {
	if ctx == nil {
		return VectorSearchResult{}, errors.New("vector search context is required")
	}
	s, err := newScope(tenant, visibility)
	if err != nil {
		return VectorSearchResult{}, err
	}
	if !stableTermKeyID(modelID) || !stableTermKeyID(revision) {
		return VectorSearchResult{}, errors.New("stable model ID and revision are required")
	}
	workCtx, cancel := context.WithTimeout(ctx, VectorSearchTimeout)
	defer cancel()
	result := VectorSearchResult{}
	// Source row locks require a read-write PostgreSQL transaction. The app
	// database role still has only SELECT plus its guarded withdrawal columns.
	err = withScope(workCtx, r.db, s, &sql.TxOptions{Isolation: sql.LevelRepeatableRead}, func(tx *sql.Tx) error {
		if err := readActiveVectorBuild(workCtx, tx, s, modelID, revision, &result.Build); err != nil {
			return err
		}
		if err := vector.ValidateVector(query, result.Build.Model.Dimensions); err != nil {
			return err
		}
		if hnsw && result.Build.HNSWIndexName == "" {
			return ErrHNSWUnavailable
		}
		if hnsw {
			var indexReady bool
			if err := tx.QueryRowContext(workCtx, `SELECT EXISTS (
				SELECT 1 FROM pg_catalog.pg_index i
				WHERE i.indexrelid=pg_catalog.to_regclass('keel_meta.'||pg_catalog.quote_ident($1))
				  AND i.indisvalid AND i.indisready)`, result.Build.HNSWIndexName).Scan(&indexReady); err != nil {
				return err
			}
			if !indexReady {
				return ErrHNSWUnavailable
			}
		}
		var candidates []VectorCandidate
		if hnsw {
			for name, value := range map[string]string{"hnsw.ef_search": strconv.Itoa(options.EFSearch), "hnsw.iterative_scan": "strict_order", "hnsw.max_scan_tuples": strconv.Itoa(options.MaxScanTuples), "hnsw.scan_mem_multiplier": "2"} {
				if _, err := tx.ExecContext(workCtx, `SELECT set_config($1,$2,true)`, name, value); err != nil {
					return fmt.Errorf("bound pgvector HNSW setting %s: %w", name, err)
				}
			}
			var err error
			candidates, err = readHNSWCandidates(workCtx, tx, s, result.Build, query, options.CandidateLimit)
			if err != nil {
				return err
			}
			result.CandidateCount = len(candidates)
			if len(candidates) < topK && options.MaxExactFallbackCandidates > 0 {
				var eligible int
				if err := tx.QueryRowContext(workCtx, `SELECT count(*) FROM keel_meta.retrieval_vector_chunks WHERE tenant_id=$1 AND visibility_key=$2 AND vector_build_id=$3`, string(s.tenant), s.visibility, result.Build.ID).Scan(&eligible); err != nil {
					return err
				}
				if eligible <= options.MaxExactFallbackCandidates {
					candidates, err = readExactVectorCandidates(workCtx, tx, s, result.Build, query, eligible)
					if err != nil {
						return err
					}
					result.Fallback = true
					result.Degraded = len(candidates) < topK
				} else {
					result.Degraded = true
				}
			} else if len(candidates) < topK {
				result.Degraded = true
			}
		} else {
			var eligible int
			if err := tx.QueryRowContext(workCtx, `SELECT count(*) FROM keel_meta.retrieval_vector_chunks WHERE tenant_id=$1 AND visibility_key=$2 AND vector_build_id=$3`, string(s.tenant), s.visibility, result.Build.ID).Scan(&eligible); err != nil {
				return err
			}
			if eligible > budget {
				return ErrVectorBudgetExceeded
			}
			candidates, err = readExactVectorCandidates(workCtx, tx, s, result.Build, query, eligible)
			if err != nil {
				return err
			}
			result.CandidateCount = eligible
		}
		result.Candidates = sortVectorCandidates(candidates, topK)
		ids := make([]uuid.UUID, 0, len(result.Candidates))
		for _, candidate := range result.Candidates {
			ids = append(ids, candidate.DocumentVersionID)
		}
		return lockEligibleSources(workCtx, tx, s, ids)
	})
	if err != nil {
		return VectorSearchResult{}, err
	}
	return result, nil
}

func readActiveVectorBuild(ctx context.Context, tx *sql.Tx, s scope, modelID, revision string, b *VectorBuild) error {
	var digest []byte
	err := tx.QueryRowContext(ctx, `SELECT b.vector_build_id,b.visibility_key,b.corpus_build_id,b.corpus_generation,b.model_id,b.model_revision,b.manifest_sha256,b.expected_chunk_count,b.vector_count,b.state,h.generation
		FROM keel_meta.retrieval_vector_heads h JOIN keel_meta.retrieval_vector_builds b ON b.tenant_id=h.tenant_id AND b.vector_build_id=h.active_vector_build_id
		JOIN keel_meta.retrieval_corpus_heads ch ON ch.tenant_id=b.tenant_id AND ch.visibility_key=b.visibility_key AND ch.active_build_id=b.corpus_build_id AND ch.generation=b.corpus_generation
		WHERE h.tenant_id=$1 AND h.visibility_key=$2 AND h.model_id=$3 AND h.model_revision=$4 AND b.state='published'`, string(s.tenant), s.visibility, modelID, revision).
		Scan(&b.ID, &b.Visibility, &b.CorpusBuildID, &b.CorpusGeneration, &b.Model.ID, &b.Model.Revision, &digest, &b.ExpectedChunks, &b.VectorCount, &b.State, &b.Generation)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNoActiveVectorBuild
	}
	if err != nil {
		return err
	}
	if len(digest) != 32 {
		return errors.New("vector manifest digest has invalid length")
	}
	copy(b.ManifestDigest[:], digest)
	return loadManifest(ctx, tx, b.Model.ID, b.Model.Revision, b.ManifestDigest, &b.Model, &b.HNSWIndexName)
}

func readExactVectorCandidates(ctx context.Context, tx *sql.Tx, s scope, b VectorBuild, query []float32, limit int) ([]VectorCandidate, error) {
	if limit == 0 {
		return []VectorCandidate{}, nil
	}
	literal := formatVector(query)
	rows, err := tx.QueryContext(ctx, `SELECT v.chunk_id,c.document_version_id,c.chunk_ordinal,c.source_start_byte,c.source_end_byte,c.content_sha256,(v.embedding <=> $4::vector)::float8
		FROM keel_meta.retrieval_vector_chunks v JOIN keel_meta.retrieval_chunks c ON c.tenant_id=v.tenant_id AND c.build_id=v.corpus_build_id AND c.chunk_id=v.chunk_id
		JOIN keel_meta.retrieval_source_eligibility e ON e.tenant_id=c.tenant_id AND e.visibility_key=c.visibility_key AND e.document_version_id=c.document_version_id AND e.state='active'
		WHERE v.tenant_id=$1 AND v.visibility_key=$2 AND v.vector_build_id=$3 ORDER BY v.embedding <=> $4::vector,v.chunk_id LIMIT $5`, string(s.tenant), s.visibility, b.ID, literal, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]VectorCandidate, 0, limit)
	for rows.Next() {
		var c VectorCandidate
		var digest []byte
		if err := rows.Scan(&c.ChunkID, &c.DocumentVersionID, &c.Ordinal, &c.StartByte, &c.EndByte, &digest, &c.CosineDistance); err != nil {
			return nil, err
		}
		if len(digest) != 32 {
			return nil, errors.New("vector citation digest has invalid length")
		}
		copy(c.ContentDigest[:], digest)
		c.Score = 1 - c.CosineDistance
		out = append(out, c)
	}
	return out, rows.Err()
}

func readHNSWCandidates(ctx context.Context, tx *sql.Tx, s scope, b VectorBuild, query []float32, limit int) ([]VectorCandidate, error) {
	// IDs are immutable, strictly validated literals so PostgreSQL can prove
	// that the model-specific partial HNSW index predicate is satisfied.
	modelID, revision := b.Model.ID, b.Model.Revision
	if !stableTermKeyID(modelID) || !stableTermKeyID(revision) {
		return nil, errors.New("unsafe vector model identity")
	}
	dims := b.Model.Dimensions
	literal := formatVector(query)
	sqlText := fmt.Sprintf(`SELECT v.chunk_id,c.document_version_id,c.chunk_ordinal,c.source_start_byte,c.source_end_byte,c.content_sha256,v.embedding::text
		FROM keel_meta.retrieval_vector_chunks v JOIN keel_meta.retrieval_chunks c ON c.tenant_id=v.tenant_id AND c.build_id=v.corpus_build_id AND c.chunk_id=v.chunk_id
		JOIN keel_meta.retrieval_source_eligibility e ON e.tenant_id=c.tenant_id AND e.visibility_key=c.visibility_key AND e.document_version_id=c.document_version_id AND e.state='active'
		WHERE v.tenant_id=$1 AND v.visibility_key=$2 AND v.vector_build_id=$3 AND v.model_id='%s' AND v.model_revision='%s'
		ORDER BY v.embedding::halfvec(%d) <=> $4::halfvec(%d) LIMIT $5`, modelID, revision, dims, dims)
	rows, err := tx.QueryContext(ctx, sqlText, string(s.tenant), s.visibility, b.ID, literal, limit)
	if err != nil {
		return nil, fmt.Errorf("bounded HNSW candidate scan: %w", err)
	}
	defer rows.Close()
	var out []VectorCandidate
	for rows.Next() {
		var c VectorCandidate
		var digest []byte
		var encoded string
		if err := rows.Scan(&c.ChunkID, &c.DocumentVersionID, &c.Ordinal, &c.StartByte, &c.EndByte, &digest, &encoded); err != nil {
			return nil, err
		}
		if len(digest) != 32 {
			return nil, errors.New("vector citation digest has invalid length")
		}
		copy(c.ContentDigest[:], digest)
		values, err := parseVector(encoded, dims)
		if err != nil {
			return nil, err
		}
		distance, err := vector.CosineDistance(values, query)
		if err != nil {
			return nil, err
		}
		c.CosineDistance = distance
		c.Score = 1 - distance
		out = append(out, c)
	}
	return out, rows.Err()
}

func sortVectorCandidates(candidates []VectorCandidate, topK int) []VectorCandidate {
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].CosineDistance == candidates[j].CosineDistance {
			return candidates[i].ChunkID.String() < candidates[j].ChunkID.String()
		}
		return candidates[i].CosineDistance < candidates[j].CosineDistance
	})
	if len(candidates) > topK {
		candidates = candidates[:topK]
	}
	return candidates
}

func verifyRegisteredModel(ctx context.Context, tx *sql.Tx, m vector.Manifest, digest [32]byte, indexName *string) error {
	var stored vector.Manifest
	var storedDigest []byte
	var hnswName sql.NullString
	var err error
	err = tx.QueryRowContext(ctx, `SELECT model_id,model_revision,provider_id,encode(artifact_sha256,'hex'),tokenizer_id,analyzer_id,max_input_tokens,dimensions,distance_metric,normalization,manifest_sha256,hnsw_index_name::text
		FROM keel_meta.retrieval_model_manifests WHERE model_id=$1 AND model_revision=$2`, m.ID, m.Revision).
		Scan(&stored.ID, &stored.Revision, &stored.Provider, &stored.ArtifactSHA256, &stored.TokenizerID, &stored.AnalyzerID, &stored.MaxInputTokens, &stored.Dimensions, &stored.Distance, &stored.Normalization, &storedDigest, &hnswName)
	if err != nil {
		return fmt.Errorf("load immutable embedding model manifest: %w", err)
	}
	if len(storedDigest) != 32 {
		return errors.New("registered model manifest digest has invalid length")
	}
	var got [32]byte
	copy(got[:], storedDigest)
	if got != digest || stored != m {
		return errors.New("requested embedding identity differs from the registered immutable manifest")
	}
	*indexName = ""
	if hnswName.Valid {
		*indexName = hnswName.String
	}
	return nil
}

func loadManifest(ctx context.Context, tx *sql.Tx, id, revision string, digest [32]byte, m *vector.Manifest, indexName *string) error {
	var storedDigest []byte
	var hnswName sql.NullString
	err := tx.QueryRowContext(ctx, `SELECT model_id,model_revision,provider_id,encode(artifact_sha256,'hex'),tokenizer_id,analyzer_id,max_input_tokens,dimensions,distance_metric,normalization,manifest_sha256,hnsw_index_name::text
		FROM keel_meta.retrieval_model_manifests WHERE model_id=$1 AND model_revision=$2`, id, revision).
		Scan(&m.ID, &m.Revision, &m.Provider, &m.ArtifactSHA256, &m.TokenizerID, &m.AnalyzerID, &m.MaxInputTokens, &m.Dimensions, &m.Distance, &m.Normalization, &storedDigest, &hnswName)
	if err != nil {
		return err
	}
	if len(storedDigest) != 32 {
		return errors.New("registered model manifest digest has invalid length")
	}
	var got [32]byte
	copy(got[:], storedDigest)
	if got != digest {
		return errors.New("stored vector build manifest digest no longer matches its immutable model")
	}
	*indexName = ""
	if hnswName.Valid {
		*indexName = hnswName.String
	}
	return m.Validate()
}

func formatVector(values []float32) string {
	parts := make([]string, len(values))
	for i, v := range values {
		parts[i] = strconv.FormatFloat(float64(v), 'g', -1, 32)
	}
	return "[" + strings.Join(parts, ",") + "]"
}
func parseVector(encoded string, dimensions int) ([]float32, error) {
	if len(encoded) < 2 || encoded[0] != '[' || encoded[len(encoded)-1] != ']' {
		return nil, errors.New("stored vector has invalid PostgreSQL text representation")
	}
	parts := strings.Split(encoded[1:len(encoded)-1], ",")
	if len(parts) != dimensions {
		return nil, errors.New("stored vector dimension differs from manifest")
	}
	out := make([]float32, len(parts))
	for i, part := range parts {
		v, err := strconv.ParseFloat(part, 32)
		if err != nil || math.IsNaN(v) || math.IsInf(v, 0) {
			return nil, errors.New("stored vector contains a non-finite value")
		}
		out[i] = float32(v)
	}
	if err := vector.ValidateVector(out, dimensions); err != nil {
		return nil, err
	}
	return out, nil
}
