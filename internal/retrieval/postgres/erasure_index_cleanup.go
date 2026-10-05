package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

var ErrErasureLegalHoldUncleared = errors.New("legal-hold clearance is required before destructive erasure actions")

const MaxErasureIndexBatchRows = 500

// ErasureIndexCleanupBatch reports progress for one bounded, retry-safe pass.
// Published and retired corpus rows are never changed; their presence keeps
// the derived-index action pending until an approved retention path handles it.
type ErasureIndexCleanupBatch struct {
	RowsDeleted             int64
	RemainingUnpublished    bool
	RetainedPublishedBuilds bool
}

func (result ErasureIndexCleanupBatch) ReadyForReceipt() bool {
	return !result.RemainingUnpublished && !result.RetainedPublishedBuilds
}

// CleanupUnpublishedErasureIndexBatch removes only rows in builds that were
// never published. It uses deletion itself as its durable cursor, so replay
// after a crash resumes at the remaining rows. Each call deletes at most
// batchLimit derived rows across vectors, postings, term statistics and chunks.
func (r *Repository) CleanupUnpublishedErasureIndexBatch(ctx context.Context, tenant tenancy.TenantID, visibility,
	workerID string, jobID uuid.UUID, epoch int64, batchLimit int) (ErasureIndexCleanupBatch, error) {
	if err := validateErasureWorkerRepository(r, ctx); err != nil {
		return ErasureIndexCleanupBatch{}, err
	}
	s, err := newScope(tenant, visibility)
	if err != nil {
		return ErasureIndexCleanupBatch{}, err
	}
	if !erasureWorkerIDPattern.MatchString(workerID) || jobID == uuid.Nil || epoch < 1 || batchLimit < 1 || batchLimit > MaxErasureIndexBatchRows {
		return ErasureIndexCleanupBatch{}, errors.New("derived-index cleanup lease or batch size is invalid")
	}
	var result ErasureIndexCleanupBatch
	err = withScope(ctx, r.db, s, nil, func(tx *sql.Tx) error {
		var documentVersionID uuid.UUID
		err := tx.QueryRowContext(ctx, `SELECT j.document_version_id
			FROM keel_meta.retrieval_erasure_jobs j
			JOIN keel_meta.retrieval_source_eligibility e
			  ON e.tenant_id=j.tenant_id AND e.visibility_key=j.visibility_key AND e.document_version_id=j.document_version_id
			WHERE j.tenant_id=$1 AND j.visibility_key=$2 AND j.job_id=$3 AND j.state='cleanup_pending'
			  AND j.lease_owner=$4 AND j.lease_epoch=$5 AND j.lease_until>clock_timestamp()
			  AND e.state='withdrawn' AND e.generation=j.eligibility_generation
			FOR UPDATE OF j`, string(s.tenant), s.visibility, jobID, workerID, epoch).
			Scan(&documentVersionID)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrErasureLeaseLost
		}
		if err != nil {
			return fmt.Errorf("lock source fence for derived-index cleanup: %w", err)
		}
		var holdClear bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS (
			SELECT 1 FROM keel_meta.retrieval_erasure_action_receipts r
			WHERE r.tenant_id=$1 AND r.visibility_key=$2 AND r.job_id=$3 AND r.action_key='legal_hold_check'
			  AND r.disposition='complete' AND r.lease_epoch<=$4
		)`, string(s.tenant), s.visibility, jobID, epoch).Scan(&holdClear); err != nil {
			return fmt.Errorf("read legal-hold decision before derived cleanup: %w", err)
		}
		if !holdClear {
			return ErrErasureLegalHoldUncleared
		}

		remaining := batchLimit
		// A vector build can contain withdrawn-source embeddings even when its
		// published lexical corpus must remain immutable. Fail only an unpublished
		// vector manifest, then remove that source's rows before touching chunks.
		var vectorBuildID uuid.UUID
		var vectorState string
		err = tx.QueryRowContext(ctx, `SELECT b.vector_build_id,b.state
			FROM keel_meta.retrieval_vector_builds b
			JOIN keel_meta.retrieval_vector_chunks v
			  ON v.tenant_id=b.tenant_id AND v.vector_build_id=b.vector_build_id AND v.visibility_key=b.visibility_key
			JOIN keel_meta.retrieval_chunks c
			  ON c.tenant_id=v.tenant_id AND c.build_id=v.corpus_build_id AND c.chunk_id=v.chunk_id
			WHERE b.tenant_id=$1 AND b.visibility_key=$2 AND c.document_version_id=$3
			  AND b.state IN ('building','ready','failed')
			ORDER BY b.vector_build_id LIMIT 1 FOR UPDATE OF b`, string(s.tenant), s.visibility, documentVersionID).
			Scan(&vectorBuildID, &vectorState)
		if err == nil {
			if vectorState != "failed" {
				if _, err := tx.ExecContext(ctx, `UPDATE keel_meta.retrieval_vector_builds
					SET state='failed',updated_at=clock_timestamp()
					WHERE tenant_id=$1 AND vector_build_id=$2 AND state IN ('building','ready')`, string(s.tenant), vectorBuildID); err != nil {
					return fmt.Errorf("fail unpublished vector build before cleanup: %w", err)
				}
			}
			deleted, err := deleteErasureVectorRows(ctx, tx, s, vectorBuildID, documentVersionID, remaining)
			if err != nil {
				return err
			}
			result.RowsDeleted += deleted
			remaining -= int(deleted)
		} else if !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("find unpublished vector rows for source: %w", err)
		}

		if remaining > 0 {
			var corpusBuildID uuid.UUID
			var corpusState string
			err = tx.QueryRowContext(ctx, `SELECT b.build_id,b.state
				FROM keel_meta.retrieval_corpus_builds b
				JOIN keel_meta.retrieval_chunks c ON c.tenant_id=b.tenant_id AND c.build_id=b.build_id
				WHERE b.tenant_id=$1 AND b.visibility_key=$2 AND c.document_version_id=$3
				  AND b.state IN ('building','ready','failed')
				ORDER BY b.build_id LIMIT 1 FOR UPDATE OF b`, string(s.tenant), s.visibility, documentVersionID).
				Scan(&corpusBuildID, &corpusState)
			if err == nil {
				if corpusState != "failed" {
					if _, err := tx.ExecContext(ctx, `UPDATE keel_meta.retrieval_corpus_builds
						SET state='failed',updated_at=clock_timestamp()
						WHERE tenant_id=$1 AND build_id=$2 AND state IN ('building','ready')`, string(s.tenant), corpusBuildID); err != nil {
						return fmt.Errorf("fail unpublished corpus build before cleanup: %w", err)
					}
				}
				deleted, err := deleteErasureCorpusRows(ctx, tx, s, corpusBuildID, documentVersionID, remaining)
				if err != nil {
					return err
				}
				result.RowsDeleted += deleted
			} else if !errors.Is(err, sql.ErrNoRows) {
				return fmt.Errorf("find unpublished corpus rows for source: %w", err)
			}
		}

		if err := tx.QueryRowContext(ctx, `SELECT EXISTS (
				SELECT 1 FROM keel_meta.retrieval_chunks c
				JOIN keel_meta.retrieval_corpus_builds b ON b.tenant_id=c.tenant_id AND b.build_id=c.build_id
				WHERE c.tenant_id=$1 AND c.visibility_key=$2 AND c.document_version_id=$3 AND b.state IN ('building','ready','failed')
			) OR EXISTS (
				SELECT 1 FROM keel_meta.retrieval_vector_chunks v
				JOIN keel_meta.retrieval_vector_builds b ON b.tenant_id=v.tenant_id AND b.vector_build_id=v.vector_build_id
				JOIN keel_meta.retrieval_chunks c ON c.tenant_id=v.tenant_id AND c.build_id=v.corpus_build_id AND c.chunk_id=v.chunk_id
				WHERE v.tenant_id=$1 AND v.visibility_key=$2 AND c.document_version_id=$3 AND b.state IN ('building','ready','failed')
			)`, string(s.tenant), s.visibility, documentVersionID).Scan(&result.RemainingUnpublished); err != nil {
			return fmt.Errorf("check remaining unpublished derived rows: %w", err)
		}
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS (
			SELECT 1 FROM keel_meta.retrieval_chunks c
			JOIN keel_meta.retrieval_corpus_builds b ON b.tenant_id=c.tenant_id AND b.build_id=c.build_id
			WHERE c.tenant_id=$1 AND c.visibility_key=$2 AND c.document_version_id=$3 AND b.state IN ('published','retired')
		)`, string(s.tenant), s.visibility, documentVersionID).Scan(&result.RetainedPublishedBuilds); err != nil {
			return fmt.Errorf("check retained published source rows: %w", err)
		}
		return nil
	})
	return result, err
}

func deleteErasureVectorRows(ctx context.Context, tx *sql.Tx, s scope, buildID, documentVersionID uuid.UUID, limit int) (int64, error) {
	if limit <= 0 {
		return 0, nil
	}
	result, err := tx.ExecContext(ctx, `WITH candidates AS (
		SELECT v.ctid FROM keel_meta.retrieval_vector_chunks v
		JOIN keel_meta.retrieval_chunks c ON c.tenant_id=v.tenant_id AND c.build_id=v.corpus_build_id AND c.chunk_id=v.chunk_id
		WHERE v.tenant_id=$1 AND v.visibility_key=$2 AND v.vector_build_id=$3 AND c.document_version_id=$4
		ORDER BY c.chunk_id LIMIT $5
	)
	DELETE FROM keel_meta.retrieval_vector_chunks v USING candidates x WHERE v.ctid=x.ctid`,
		string(s.tenant), s.visibility, buildID, documentVersionID, limit)
	if err != nil {
		return 0, fmt.Errorf("delete bounded unpublished vector rows: %w", err)
	}
	return result.RowsAffected()
}

func deleteErasureCorpusRows(ctx context.Context, tx *sql.Tx, s scope, buildID, documentVersionID uuid.UUID, limit int) (int64, error) {
	var total int64
	remaining := limit
	deletes := []struct {
		label string
		query string
	}{
		{"source term postings", `WITH candidates AS (
			SELECT p.ctid FROM keel_meta.retrieval_term_postings p
			JOIN keel_meta.retrieval_chunks c ON c.tenant_id=p.tenant_id AND c.build_id=p.build_id AND c.chunk_id=p.chunk_id
			WHERE p.tenant_id=$1 AND p.visibility_key=$2 AND p.build_id=$3 AND c.document_version_id=$4
			ORDER BY p.term_id,p.chunk_id LIMIT $5
		)
		DELETE FROM keel_meta.retrieval_term_postings p USING candidates x WHERE p.ctid=x.ctid`},
		{"failed-build term statistics", `WITH candidates AS (
			SELECT s.ctid FROM keel_meta.retrieval_term_statistics s
			WHERE s.tenant_id=$1 AND s.visibility_key=$2 AND s.build_id=$3
			ORDER BY s.term_id LIMIT $4
		)
		DELETE FROM keel_meta.retrieval_term_statistics s USING candidates x WHERE s.ctid=x.ctid`},
		{"unreferenced source chunks", `WITH candidates AS (
			SELECT c.ctid FROM keel_meta.retrieval_chunks c
			WHERE c.tenant_id=$1 AND c.visibility_key=$2 AND c.build_id=$3 AND c.document_version_id=$4
			  AND NOT EXISTS (SELECT 1 FROM keel_meta.retrieval_term_postings p
			    WHERE p.tenant_id=c.tenant_id AND p.build_id=c.build_id AND p.chunk_id=c.chunk_id)
			  AND NOT EXISTS (SELECT 1 FROM keel_meta.retrieval_vector_chunks v
			    WHERE v.tenant_id=c.tenant_id AND v.corpus_build_id=c.build_id AND v.chunk_id=c.chunk_id)
			ORDER BY c.chunk_id LIMIT $5
		)
		DELETE FROM keel_meta.retrieval_chunks c USING candidates x WHERE c.ctid=x.ctid`},
	}
	for i, deletion := range deletes {
		if remaining <= 0 {
			break
		}
		args := []any{string(s.tenant), s.visibility, buildID, documentVersionID, remaining}
		if i == 1 {
			args = []any{string(s.tenant), s.visibility, buildID, remaining}
		}
		result, err := tx.ExecContext(ctx, deletion.query, args...)
		if err != nil {
			return 0, fmt.Errorf("delete bounded %s: %w", deletion.label, err)
		}
		count, err := result.RowsAffected()
		if err != nil {
			return 0, fmt.Errorf("count deleted %s: %w", deletion.label, err)
		}
		total += count
		remaining -= int(count)
	}
	return total, nil
}
