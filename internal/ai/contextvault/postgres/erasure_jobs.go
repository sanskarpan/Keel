package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

const (
	MaxErasureJobFailures = 12
	MinErasureJobLease    = time.Second
	MaxErasureJobLease    = 15 * time.Minute
	MinErasureJobBackoff  = time.Second
	MaxErasureJobBackoff  = 24 * time.Hour
)

var (
	ErrErasureJobLeaseLost = errors.New("context erasure job lease is no longer current")
	erasureJobWorkerID     = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]{1,63}$`)
	erasureJobErrorCode    = regexp.MustCompile(`^[a-z0-9][a-z0-9_]{0,63}$`)
)

// ErasureJob contains scheduling metadata only. It never contains vault envelope fields.
type ErasureJob struct {
	TenantID   tenancy.TenantID
	RecordID   string
	Version    uint64
	ExpiresAt  time.Time
	State      string
	LeaseEpoch int64
	Attempt    int
	Failures   int
	WorkerID   string
}

// ErasureWorkerStore exposes only claim, atomic process, and bounded retry functions. Its
// connection must use the dedicated worker capability, which cannot directly read ciphertext.
type ErasureWorkerStore struct{ db *sql.DB }

func NewErasureWorkerStore(db *sql.DB) (*ErasureWorkerStore, error) {
	if db == nil {
		return nil, errors.New("context erasure worker database is required")
	}
	return &ErasureWorkerStore{db: db}, nil
}

// Claim leases at most one due job for the explicitly supplied tenant scope.
func (s *ErasureWorkerStore) Claim(ctx context.Context, tenant tenancy.TenantID, workerID string, lease time.Duration) (ErasureJob, bool, error) {
	if s == nil || s.db == nil || ctx == nil || !validErasureWorkerID(workerID) ||
		lease < MinErasureJobLease || lease > MaxErasureJobLease {
		return ErasureJob{}, false, ErrInvalid
	}
	canonicalTenant, err := tenancy.ParseTenantID(string(tenant))
	if err != nil {
		return ErasureJob{}, false, ErrInvalid
	}
	var job ErasureJob
	job.WorkerID = workerID
	err = tenancy.WithTenantTx(ctx, s.db, canonicalTenant, nil, func(tx *sql.Tx) error {
		var claimed bool
		var err error
		job, claimed, err = s.ClaimTx(ctx, tx, canonicalTenant, workerID, lease)
		if err == nil && !claimed {
			return sql.ErrNoRows
		}
		return err
	})
	if errors.Is(err, sql.ErrNoRows) {
		return ErasureJob{}, false, nil
	}
	if err != nil {
		return ErasureJob{}, false, fmt.Errorf("claim context erasure job: %w", err)
	}
	if !sameUUID(string(job.TenantID), string(canonicalTenant)) {
		return ErasureJob{}, false, ErrInvalid
	}
	job.State = "leased"
	return job, true, nil
}

// ClaimTx composes a bounded tenant-scoped claim with a caller transaction.
func (s *ErasureWorkerStore) ClaimTx(ctx context.Context, tx *sql.Tx, tenant tenancy.TenantID, workerID string, lease time.Duration) (ErasureJob, bool, error) {
	if s == nil || tx == nil || ctx == nil || !validErasureWorkerID(workerID) ||
		lease < MinErasureJobLease || lease > MaxErasureJobLease {
		return ErasureJob{}, false, ErrInvalid
	}
	canonicalTenant, err := tenancy.ParseTenantID(string(tenant))
	if err != nil {
		return ErasureJob{}, false, ErrInvalid
	}
	job := ErasureJob{WorkerID: workerID}
	err = tx.QueryRowContext(ctx, `SELECT tenant_id::text,record_id::text,version,expires_at,lease_epoch,attempt_count,failure_count
		FROM keel_meta.claim_context_vault_erasure_job($1,$2)`, workerID, int(lease.Milliseconds())).Scan(
		&job.TenantID, &job.RecordID, &job.Version, &job.ExpiresAt, &job.LeaseEpoch, &job.Attempt, &job.Failures)
	if errors.Is(err, sql.ErrNoRows) {
		return ErasureJob{}, false, nil
	}
	if err != nil {
		return ErasureJob{}, false, fmt.Errorf("claim context erasure job: %w", err)
	}
	if !sameUUID(string(job.TenantID), string(canonicalTenant)) {
		return ErasureJob{}, false, ErrInvalid
	}
	job.State = "leased"
	return job, true, nil
}

// Process atomically inserts the tombstone, removes the expired ciphertext, and completes
// the current fenced job. A repeated result after an independently completed deletion is safe.
func (s *ErasureWorkerStore) Process(ctx context.Context, tenant tenancy.TenantID, job ErasureJob) (bool, error) {
	if s == nil || s.db == nil || ctx == nil || !sameUUID(string(tenant), string(job.TenantID)) ||
		!validErasureWorkerID(job.WorkerID) || job.Version == 0 || job.Version > maxVersion || job.LeaseEpoch < 1 || !validRecordID(job.RecordID) {
		return false, ErrInvalid
	}
	var deleted bool
	err := tenancy.WithTenantTx(ctx, s.db, tenant, nil, func(tx *sql.Tx) error {
		var err error
		deleted, err = s.ProcessTx(ctx, tx, tenant, job)
		return err
	})
	if isContextErasureLeaseLost(err) {
		return false, ErrErasureJobLeaseLost
	}
	if err != nil {
		return false, fmt.Errorf("process context erasure job: %w", err)
	}
	return deleted, nil
}

// ProcessTx composes the atomic tombstone/deletion/job-completion transition with a caller transaction.
func (s *ErasureWorkerStore) ProcessTx(ctx context.Context, tx *sql.Tx, tenant tenancy.TenantID, job ErasureJob) (bool, error) {
	if s == nil || tx == nil || ctx == nil || !sameUUID(string(tenant), string(job.TenantID)) ||
		!validErasureWorkerID(job.WorkerID) || job.Version == 0 || job.Version > maxVersion ||
		job.LeaseEpoch < 1 || !validRecordID(job.RecordID) {
		return false, ErrInvalid
	}
	var deleted bool
	err := tx.QueryRowContext(ctx, `SELECT keel_meta.process_context_vault_erasure_job($1,$2,$3,$4)`,
		job.RecordID, int64(job.Version), job.WorkerID, job.LeaseEpoch).Scan(&deleted)
	if isContextErasureLeaseLost(err) {
		return false, ErrErasureJobLeaseLost
	}
	if err != nil {
		return false, fmt.Errorf("process context erasure job: %w", err)
	}
	return deleted, nil
}

// Retry releases a current claim with a bounded delay and content-free error classification.
func (s *ErasureWorkerStore) Retry(ctx context.Context, tenant tenancy.TenantID, job ErasureJob, code string, backoff time.Duration) (string, error) {
	if s == nil || s.db == nil || ctx == nil || !sameUUID(string(tenant), string(job.TenantID)) ||
		!validErasureWorkerID(job.WorkerID) || job.Version == 0 || job.Version > maxVersion || job.LeaseEpoch < 1 || !validRecordID(job.RecordID) ||
		!erasureJobErrorCode.MatchString(code) || code == "attempts_exhausted" ||
		backoff < MinErasureJobBackoff || backoff > MaxErasureJobBackoff {
		return "", ErrInvalid
	}
	var state string
	err := tenancy.WithTenantTx(ctx, s.db, tenant, nil, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT keel_meta.retry_context_vault_erasure_job($1,$2,$3,$4,$5,$6)`,
			job.RecordID, int64(job.Version), job.WorkerID, job.LeaseEpoch, code, int(backoff.Milliseconds())).Scan(&state)
	})
	if isContextErasureLeaseLost(err) {
		return "", ErrErasureJobLeaseLost
	}
	if err != nil {
		return "", fmt.Errorf("retry context erasure job: %w", err)
	}
	return state, nil
}

func validErasureWorkerID(value string) bool {
	return erasureJobWorkerID.MatchString(value)
}

func validRecordID(value string) bool {
	_, err := tenancy.ParseTenantID(value)
	return err == nil
}

func isContextErasureLeaseLost(err error) bool {
	if err == nil {
		return false
	}
	var postgresErr *pgconn.PgError
	if errors.As(err, &postgresErr) {
		return postgresErr.Message == "context erasure lease is no longer current"
	}
	return strings.Contains(err.Error(), "context erasure lease is no longer current")
}
