package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

const (
	MaxErasureAttempts      = 12
	MinErasureLease         = time.Second
	MaxErasureLease         = 15 * time.Minute
	MaxErasureBackoff       = 24 * time.Hour
	MinErasureProgressDelay = time.Second
	MaxErasureProgressDelay = 15 * time.Minute
)

var (
	ErrErasureLeaseLost     = errors.New("retrieval erasure job lease is no longer current")
	erasureWorkerIDPattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]{1,63}$`)
	erasureErrorCodePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_]{0,63}$`)
)

// ClaimErasureJob leases the next due job in one authorized tenant/cohort.
// The caller must supply each scope from trusted server context; RLS prevents
// a worker from enumerating or claiming another tenant's jobs.
func (r *Repository) ClaimErasureJob(ctx context.Context, tenant tenancy.TenantID, visibility, workerID string, lease time.Duration) (ErasureJob, bool, error) {
	if err := validateErasureWorkerRepository(r, ctx); err != nil {
		return ErasureJob{}, false, err
	}
	s, err := newScope(tenant, visibility)
	if err != nil {
		return ErasureJob{}, false, err
	}
	if !erasureWorkerIDPattern.MatchString(workerID) || lease < MinErasureLease || lease > MaxErasureLease {
		return ErasureJob{}, false, errors.New("erasure worker identity or lease duration is invalid")
	}
	var job ErasureJob
	claimed := false
	err = withScope(ctx, r.db, s, nil, func(tx *sql.Tx) error {
		// A worker crash on the final permitted attempt must become an observable
		// terminal poison state after its lease expires rather than stay pending.
		_, err := tx.ExecContext(ctx, `UPDATE keel_meta.retrieval_erasure_jobs
			SET state='blocked',last_error_code='attempts_exhausted',blocked_at=clock_timestamp(),
				lease_owner=NULL,lease_until=NULL,updated_at=clock_timestamp()
			WHERE tenant_id=$1 AND visibility_key=$2 AND state='cleanup_pending'
			  AND attempt_count >= $3 AND available_at <= clock_timestamp()
			  AND (lease_until IS NULL OR lease_until <= clock_timestamp())`, string(s.tenant), s.visibility, MaxErasureAttempts)
		if err != nil {
			return fmt.Errorf("block exhausted retrieval erasure jobs: %w", err)
		}
		err = tx.QueryRowContext(ctx, `WITH candidate AS (
			SELECT tenant_id,visibility_key,job_id
			FROM keel_meta.retrieval_erasure_jobs
		 WHERE tenant_id=$1 AND visibility_key=$2 AND state IN ('fenced','cleanup_pending')
			  AND available_at <= clock_timestamp() AND attempt_count < $3
			  AND (lease_until IS NULL OR lease_until <= clock_timestamp())
			ORDER BY available_at,requested_at,job_id
			LIMIT 1 FOR UPDATE SKIP LOCKED
		)
		UPDATE keel_meta.retrieval_erasure_jobs AS job
		SET state='cleanup_pending',lease_owner=$4,lease_epoch=job.lease_epoch+1,
			lease_until=clock_timestamp()+($5::bigint * interval '1 microsecond'),
			attempt_count=job.attempt_count+1,last_error_code=NULL,updated_at=clock_timestamp()
		FROM candidate
		WHERE job.tenant_id=candidate.tenant_id AND job.visibility_key=candidate.visibility_key AND job.job_id=candidate.job_id
		RETURNING job.job_id,job.requested_by,job.document_version_id,job.eligibility_generation,job.state,job.requested_at::text,
			job.attempt_count,job.last_error_code,job.available_at,job.lease_owner,job.lease_epoch,job.lease_until,job.blocked_at,job.completed_at`,
			string(s.tenant), s.visibility, MaxErasureAttempts, workerID, lease.Microseconds()).
			Scan(&job.ID, &job.RequestedBy, &job.DocumentVersionID, &job.EligibilityGeneration, &job.State, &job.RequestedAt,
				&job.AttemptCount, &job.LastErrorCode, &job.AvailableAt, &job.LeaseOwner, &job.LeaseEpoch,
				&job.LeaseUntil, &job.BlockedAt, &job.CompletedAt)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("claim retrieval erasure job: %w", err)
		}
		claimed = true
		return nil
	})
	if err != nil {
		return ErasureJob{}, false, err
	}
	return job, claimed, nil
}

// YieldErasureJob releases a live claim after a successful bounded action pass
// that needs another lease to continue. The claim increment is refunded from
// the failure budget, while the lease epoch remains monotonic for fencing.
func (r *Repository) YieldErasureJob(ctx context.Context, tenant tenancy.TenantID, visibility, workerID string,
	jobID uuid.UUID, epoch int64, delay time.Duration) (ErasureJob, error) {
	if err := validateErasureWorkerRepository(r, ctx); err != nil {
		return ErasureJob{}, err
	}
	s, err := newScope(tenant, visibility)
	if err != nil {
		return ErasureJob{}, err
	}
	if !erasureWorkerIDPattern.MatchString(workerID) || jobID == uuid.Nil || epoch < 1 ||
		delay < MinErasureProgressDelay || delay > MaxErasureProgressDelay {
		return ErasureJob{}, errors.New("erasure progress yield identity or delay is invalid")
	}
	var job ErasureJob
	err = withScope(ctx, r.db, s, nil, func(tx *sql.Tx) error {
		err := tx.QueryRowContext(ctx, `UPDATE keel_meta.retrieval_erasure_jobs
			SET state='cleanup_pending',available_at=clock_timestamp()+($6::bigint * interval '1 microsecond'),
				attempt_count=GREATEST(attempt_count-1,0),last_error_code=NULL,
				lease_owner=NULL,lease_until=NULL,updated_at=clock_timestamp()
			WHERE tenant_id=$1 AND visibility_key=$2 AND job_id=$3 AND state='cleanup_pending'
			  AND lease_owner=$4 AND lease_epoch=$5 AND lease_until>clock_timestamp()
			RETURNING `+erasureJobColumns, string(s.tenant), s.visibility, jobID, workerID, epoch, delay.Microseconds()).
			Scan(erasureJobDestinations(&job)...)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrErasureLeaseLost
		}
		if err != nil {
			return fmt.Errorf("yield retrieval erasure job after progress: %w", err)
		}
		return nil
	})
	return job, err
}

// RenewErasureJobLease extends a live claim without changing its fencing epoch.
func (r *Repository) RenewErasureJobLease(ctx context.Context, tenant tenancy.TenantID, visibility, workerID string, jobID uuid.UUID, epoch int64, lease time.Duration) (ErasureJob, error) {
	return r.updateErasureLease(ctx, tenant, visibility, workerID, jobID, epoch, lease, `
		UPDATE keel_meta.retrieval_erasure_jobs SET lease_until=clock_timestamp()+($6::bigint * interval '1 microsecond'),updated_at=clock_timestamp()
		WHERE tenant_id=$1 AND visibility_key=$2 AND job_id=$3 AND state='cleanup_pending'
		  AND lease_owner=$4 AND lease_epoch=$5 AND lease_until>clock_timestamp()
		RETURNING `+erasureJobColumns)
}

// CompleteErasureJob records completion only for the current live lease. A
// cleanup processor must call this after every configured cleanup action has
// completed idempotently; it does not itself delete source or index data.
func (r *Repository) CompleteErasureJob(ctx context.Context, tenant tenancy.TenantID, visibility, workerID string, jobID uuid.UUID, epoch int64) (ErasureJob, error) {
	if err := validateErasureWorkerRepository(r, ctx); err != nil {
		return ErasureJob{}, err
	}
	s, err := newScope(tenant, visibility)
	if err != nil {
		return ErasureJob{}, err
	}
	if !erasureWorkerIDPattern.MatchString(workerID) || jobID == uuid.Nil || epoch < 1 {
		return ErasureJob{}, errors.New("erasure job lease identity is invalid")
	}
	var job ErasureJob
	err = withScope(ctx, r.db, s, nil, func(tx *sql.Tx) error {
		err := tx.QueryRowContext(ctx, `UPDATE keel_meta.retrieval_erasure_jobs
			SET state='complete',lease_owner=NULL,lease_until=NULL,last_error_code=NULL,
				completed_at=clock_timestamp(),updated_at=clock_timestamp()
			WHERE tenant_id=$1 AND visibility_key=$2 AND job_id=$3 AND state='cleanup_pending'
			  AND lease_owner=$4 AND lease_epoch=$5 AND lease_until>clock_timestamp()
			RETURNING `+erasureJobColumns, string(s.tenant), s.visibility, jobID, workerID, epoch).Scan(erasureJobDestinations(&job)...)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrErasureLeaseLost
		}
		if err != nil {
			if strings.Contains(err.Error(), "until every required action has a receipt") ||
				strings.Contains(err.Error(), "without an action manifest") {
				return ErrErasureActionManifestIncomplete
			}
			return fmt.Errorf("complete retrieval erasure job: %w", err)
		}
		return nil
	})
	return job, err
}

// RetryErasureJob releases a live claim with bounded delay. The twelfth
// unsuccessful attempt transitions to blocked for operator recovery.
func (r *Repository) RetryErasureJob(ctx context.Context, tenant tenancy.TenantID, visibility, workerID string, jobID uuid.UUID, epoch int64, code string, backoff time.Duration) (ErasureJob, error) {
	if err := validateErasureWorkerRepository(r, ctx); err != nil {
		return ErasureJob{}, err
	}
	s, err := newScope(tenant, visibility)
	if err != nil {
		return ErasureJob{}, err
	}
	if !erasureWorkerIDPattern.MatchString(workerID) || jobID == uuid.Nil || epoch < 1 ||
		!erasureErrorCodePattern.MatchString(code) || code == "attempts_exhausted" || backoff < time.Second || backoff > MaxErasureBackoff {
		return ErasureJob{}, errors.New("erasure retry identity, error code or backoff is invalid")
	}
	var job ErasureJob
	err = withScope(ctx, r.db, s, nil, func(tx *sql.Tx) error {
		err := tx.QueryRowContext(ctx, `UPDATE keel_meta.retrieval_erasure_jobs
			SET state=CASE WHEN attempt_count >= $6 THEN 'blocked' ELSE 'cleanup_pending' END,
				available_at=CASE WHEN attempt_count >= $6 THEN available_at ELSE clock_timestamp()+($7::bigint * interval '1 microsecond') END,
				last_error_code=CASE WHEN attempt_count >= $6 THEN 'attempts_exhausted' ELSE $8 END,
				blocked_at=CASE WHEN attempt_count >= $6 THEN clock_timestamp() ELSE NULL END,
				lease_owner=NULL,lease_until=NULL,updated_at=clock_timestamp()
			WHERE tenant_id=$1 AND visibility_key=$2 AND job_id=$3 AND state='cleanup_pending'
			  AND lease_owner=$4 AND lease_epoch=$5 AND lease_until>clock_timestamp()
			RETURNING `+erasureJobColumns, string(s.tenant), s.visibility, jobID, workerID, epoch,
			MaxErasureAttempts, backoff.Microseconds(), code).Scan(erasureJobDestinations(&job)...)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrErasureLeaseLost
		}
		if err != nil {
			return fmt.Errorf("schedule retrieval erasure retry: %w", err)
		}
		return nil
	})
	return job, err
}

// BlockErasureJob records a non-retryable or policy-blocked cleanup failure.
func (r *Repository) BlockErasureJob(ctx context.Context, tenant tenancy.TenantID, visibility, workerID string, jobID uuid.UUID, epoch int64, code string) (ErasureJob, error) {
	if err := validateErasureWorkerRepository(r, ctx); err != nil {
		return ErasureJob{}, err
	}
	s, err := newScope(tenant, visibility)
	if err != nil {
		return ErasureJob{}, err
	}
	if !erasureWorkerIDPattern.MatchString(workerID) || jobID == uuid.Nil || epoch < 1 ||
		!erasureErrorCodePattern.MatchString(code) || code == "attempts_exhausted" {
		return ErasureJob{}, errors.New("erasure block identity or error code is invalid")
	}
	var job ErasureJob
	err = withScope(ctx, r.db, s, nil, func(tx *sql.Tx) error {
		err := tx.QueryRowContext(ctx, `UPDATE keel_meta.retrieval_erasure_jobs
			SET state='blocked',lease_owner=NULL,lease_until=NULL,last_error_code=$6,
				blocked_at=clock_timestamp(),updated_at=clock_timestamp()
			WHERE tenant_id=$1 AND visibility_key=$2 AND job_id=$3 AND state='cleanup_pending'
			  AND lease_owner=$4 AND lease_epoch=$5 AND lease_until>clock_timestamp()
			RETURNING `+erasureJobColumns, string(s.tenant), s.visibility, jobID, workerID, epoch, code).Scan(erasureJobDestinations(&job)...)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrErasureLeaseLost
		}
		if err != nil {
			return fmt.Errorf("block retrieval erasure job: %w", err)
		}
		return nil
	})
	return job, err
}

const erasureJobColumns = `job_id,requested_by,document_version_id,eligibility_generation,state,requested_at::text,
	attempt_count,last_error_code,available_at,lease_owner,lease_epoch,lease_until,blocked_at,completed_at`

func erasureJobDestinations(job *ErasureJob) []any {
	return []any{&job.ID, &job.RequestedBy, &job.DocumentVersionID, &job.EligibilityGeneration, &job.State,
		&job.RequestedAt, &job.AttemptCount, &job.LastErrorCode, &job.AvailableAt, &job.LeaseOwner,
		&job.LeaseEpoch, &job.LeaseUntil, &job.BlockedAt, &job.CompletedAt}
}

func (r *Repository) updateErasureLease(ctx context.Context, tenant tenancy.TenantID, visibility, workerID string, jobID uuid.UUID, epoch int64, lease time.Duration, query string) (ErasureJob, error) {
	if err := validateErasureWorkerRepository(r, ctx); err != nil {
		return ErasureJob{}, err
	}
	s, err := newScope(tenant, visibility)
	if err != nil {
		return ErasureJob{}, err
	}
	if !erasureWorkerIDPattern.MatchString(workerID) || jobID == uuid.Nil || epoch < 1 || lease < MinErasureLease || lease > MaxErasureLease {
		return ErasureJob{}, errors.New("erasure lease identity or duration is invalid")
	}
	var job ErasureJob
	err = withScope(ctx, r.db, s, nil, func(tx *sql.Tx) error {
		err := tx.QueryRowContext(ctx, query, string(s.tenant), s.visibility, jobID, workerID, epoch, lease.Microseconds()).Scan(erasureJobDestinations(&job)...)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrErasureLeaseLost
		}
		if err != nil {
			return fmt.Errorf("renew retrieval erasure lease: %w", err)
		}
		return nil
	})
	return job, err
}

func validateErasureWorkerRepository(r *Repository, ctx context.Context) error {
	if ctx == nil {
		return errors.New("erasure worker context is required")
	}
	if r == nil || r.db == nil {
		return errors.New("retrieval repository is unavailable")
	}
	return nil
}
