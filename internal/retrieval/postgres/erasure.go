package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

var ErrSourceNotRegistered = errors.New("retrieval source version is not registered in this cohort")

// ErasureJob is a durable request to suppress one immutable source version.
// Its lease state records cleanup orchestration; complete is only valid after
// the caller has finished its configured actions. The repository itself does
// not claim physical or backup erasure.
type ErasureJob struct {
	ID                    uuid.UUID
	RequestedBy           uuid.UUID
	DocumentVersionID     uuid.UUID
	EligibilityGeneration int64
	State                 string
	RequestedAt           string
	AttemptCount          int
	LastErrorCode         sql.NullString
	AvailableAt           time.Time
	LeaseOwner            sql.NullString
	LeaseEpoch            int64
	LeaseUntil            sql.NullTime
	BlockedAt             sql.NullTime
	CompletedAt           sql.NullTime
}

// WithdrawSource atomically installs a monotonic query-time tombstone and a
// durable idempotent erasure request. The app role cannot reactivate a source.
func (r *Repository) WithdrawSource(ctx context.Context, tenant tenancy.TenantID, visibility string, requestedBy, documentVersionID, jobID uuid.UUID) (ErasureJob, error) {
	s, err := newScope(tenant, visibility)
	if err != nil {
		return ErasureJob{}, err
	}
	if requestedBy == uuid.Nil || documentVersionID == uuid.Nil || jobID == uuid.Nil {
		return ErasureJob{}, errors.New("request actor, document version and erasure job IDs are required")
	}
	var job ErasureJob
	err = withScope(ctx, r.db, s, nil, func(tx *sql.Tx) error {
		var state string
		var generation int64
		if err := tx.QueryRowContext(ctx, `SELECT state,generation FROM keel_meta.retrieval_source_eligibility
			WHERE tenant_id=$1 AND visibility_key=$2 AND document_version_id=$3 FOR UPDATE`, string(s.tenant), s.visibility, documentVersionID).
			Scan(&state, &generation); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrSourceNotRegistered
			}
			return fmt.Errorf("lock source eligibility for withdrawal: %w", err)
		}
		if state == "active" {
			if err := tx.QueryRowContext(ctx, `UPDATE keel_meta.retrieval_source_eligibility
				SET state='withdrawn',generation=generation+1,changed_at=clock_timestamp()
				WHERE tenant_id=$1 AND visibility_key=$2 AND document_version_id=$3
				RETURNING generation`, string(s.tenant), s.visibility, documentVersionID).Scan(&generation); err != nil {
				return fmt.Errorf("install source withdrawal fence: %w", err)
			}
		} else if state != "withdrawn" {
			return errors.New("unknown source eligibility state")
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO keel_meta.retrieval_erasure_jobs
			(tenant_id,visibility_key,job_id,requested_by,document_version_id,eligibility_generation)
			VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING`, string(s.tenant), s.visibility, jobID, requestedBy, documentVersionID, generation)
		if err != nil {
			return fmt.Errorf("persist source erasure job: %w", err)
		}
		if err := tx.QueryRowContext(ctx, `SELECT job_id,requested_by,document_version_id,eligibility_generation,state,requested_at::text,attempt_count,last_error_code,
			available_at,lease_owner,lease_epoch,lease_until,blocked_at,completed_at
			FROM keel_meta.retrieval_erasure_jobs WHERE tenant_id=$1 AND visibility_key=$2 AND job_id=$3`, string(s.tenant), s.visibility, jobID).
			Scan(&job.ID, &job.RequestedBy, &job.DocumentVersionID, &job.EligibilityGeneration, &job.State, &job.RequestedAt, &job.AttemptCount, &job.LastErrorCode,
				&job.AvailableAt, &job.LeaseOwner, &job.LeaseEpoch, &job.LeaseUntil, &job.BlockedAt, &job.CompletedAt); err != nil {
			return fmt.Errorf("read durable source erasure job: %w", err)
		}
		if job.RequestedBy != requestedBy || job.DocumentVersionID != documentVersionID || job.EligibilityGeneration != generation {
			return errors.New("erasure job ID already belongs to a different source fence")
		}
		return nil
	})
	return job, err
}

// ErasureJob returns the tenant/cohort-scoped durable state for a request.
func (r *Repository) ErasureJob(ctx context.Context, tenant tenancy.TenantID, visibility string, jobID uuid.UUID) (ErasureJob, error) {
	s, err := newScope(tenant, visibility)
	if err != nil {
		return ErasureJob{}, err
	}
	if jobID == uuid.Nil {
		return ErasureJob{}, errors.New("erasure job ID is required")
	}
	var job ErasureJob
	err = withScope(ctx, r.db, s, &sql.TxOptions{ReadOnly: true}, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT job_id,requested_by,document_version_id,eligibility_generation,state,requested_at::text,attempt_count,last_error_code,
			available_at,lease_owner,lease_epoch,lease_until,blocked_at,completed_at
			FROM keel_meta.retrieval_erasure_jobs WHERE tenant_id=$1 AND visibility_key=$2 AND job_id=$3`, string(s.tenant), s.visibility, jobID).
			Scan(&job.ID, &job.RequestedBy, &job.DocumentVersionID, &job.EligibilityGeneration, &job.State, &job.RequestedAt, &job.AttemptCount, &job.LastErrorCode,
				&job.AvailableAt, &job.LeaseOwner, &job.LeaseEpoch, &job.LeaseUntil, &job.BlockedAt, &job.CompletedAt)
	})
	return job, err
}
