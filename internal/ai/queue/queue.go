// Package queue provides a durable, tenant-scoped AI job queue. It grants no
// provider access and stores no prompt or response content.
package queue

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sanskarpan/keel/internal/ai/budget"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

var (
	ErrQueueUnavailable = errors.New("AI execution profile or durable reservation is unavailable")
	ErrQueueFull        = errors.New("AI execution queue is at capacity")
	ErrQueueConflict    = errors.New("AI inference already has a conflicting queue record")
	ErrLeaseLost        = errors.New("AI job lease is no longer current")
	ErrConcurrencyCap   = errors.New("AI provider concurrency cap is reached")
	queueProvider       = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,79}$`)
	queueModel          = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,119}$`)
	queueWorker         = regexp.MustCompile(`^[A-Za-z0-9._~-]{1,120}$`)
	queuePrincipal      = regexp.MustCompile(`^principal:[A-Za-z0-9._~-]{1,120}$`)
)

const MaxLease = 30 * time.Second

type Repository struct {
	budget   *budget.Repository
	workerDB *sql.DB
}

func NewRepository(budgets *budget.Repository, workerDB *sql.DB) (*Repository, error) {
	if budgets == nil || workerDB == nil {
		return nil, errors.New("AI queue requires budget admission and a separate worker database")
	}
	return &Repository{budget: budgets, workerDB: workerDB}, nil
}

type JobSpec struct {
	Admission       budget.Admission
	ProviderID      string
	ModelID         string
	MaxOutputTokens int
}

type EnqueueResult struct {
	InferenceID string
	Replayed    bool
}

func (r *Repository) Enqueue(ctx context.Context, spec JobSpec) (EnqueueResult, error) {
	if !validSpec(spec) {
		return EnqueueResult{}, ErrQueueUnavailable
	}
	a := spec.Admission
	policyHash, _ := hex.DecodeString(a.Quote.PolicyDigest())
	principalHash := sha256.Sum256([]byte(a.PrincipalBinding))
	result := EnqueueResult{InferenceID: a.InferenceID}
	_, err := r.budget.AdmitWith(ctx, a, func(tx *sql.Tx, admitted budget.AdmissionResult) error {
		if err := lockProfile(tx, ctx, a.Tenant, spec.ProviderID, spec.ModelID); err != nil {
			return err
		}
		var configuredHash []byte
		var maxTokens, queueDepth int
		var enabled bool
		if err := tx.QueryRowContext(ctx, `SELECT policy_sha256,max_output_tokens,max_queue_depth,enabled
			FROM keel_meta.ai_execution_profiles WHERE tenant_id=$1 AND provider_id=$2 AND model_id=$3`,
			string(a.Tenant), spec.ProviderID, spec.ModelID).Scan(&configuredHash, &maxTokens, &queueDepth, &enabled); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrQueueUnavailable
			}
			return err
		}
		if !enabled || !equalHash(configuredHash, policyHash) || spec.MaxOutputTokens > maxTokens {
			return ErrQueueUnavailable
		}
		var priorProvider, priorModel, priorAttempt, priorPeriod string
		var priorPolicy, priorPrincipal []byte
		var priorTokens int
		err := tx.QueryRowContext(ctx, `SELECT attempt_id::text,period_id::text,provider_id,model_id,policy_sha256,principal_sha256,max_output_tokens
			FROM keel_meta.ai_jobs WHERE tenant_id=$1 AND inference_id=$2`, string(a.Tenant), a.InferenceID).
			Scan(&priorAttempt, &priorPeriod, &priorProvider, &priorModel, &priorPolicy, &priorPrincipal, &priorTokens)
		if err == nil {
			if priorAttempt != a.AttemptID || priorPeriod != a.PeriodID || priorProvider != spec.ProviderID || priorModel != spec.ModelID ||
				!equalHash(priorPolicy, policyHash) || !equalHash(priorPrincipal, principalHash[:]) || priorTokens != spec.MaxOutputTokens {
				return ErrQueueConflict
			}
			result.Replayed = true
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		var queued int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM keel_meta.ai_jobs
			WHERE tenant_id=$1 AND provider_id=$2 AND model_id=$3 AND state='queued'`,
			string(a.Tenant), spec.ProviderID, spec.ModelID).Scan(&queued); err != nil {
			return err
		}
		if queued >= queueDepth {
			return ErrQueueFull
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO keel_meta.ai_job_fairness(tenant_id,provider_id,model_id,principal_sha256)
			VALUES($1,$2,$3,$4) ON CONFLICT(tenant_id,provider_id,model_id,principal_sha256) DO NOTHING`, string(a.Tenant), spec.ProviderID, spec.ModelID, principalHash[:]); err != nil {
			return err
		}
		insert, err := tx.ExecContext(ctx, `INSERT INTO keel_meta.ai_jobs
			(tenant_id,inference_id,attempt_id,period_id,scope,provider_id,model_id,policy_sha256,principal_sha256,max_output_tokens)
			VALUES($1,$2,$3,$4,'inference',$5,$6,$7,$8,$9)`,
			string(a.Tenant), a.InferenceID, a.AttemptID, admitted.PeriodID, spec.ProviderID, spec.ModelID, policyHash, principalHash[:], spec.MaxOutputTokens)
		if err != nil {
			return err
		}
		rows, err := insert.RowsAffected()
		if err != nil {
			return err
		}
		if rows != 1 {
			return ErrQueueUnavailable
		}
		return nil
	})
	if err != nil {
		return EnqueueResult{}, mapQueueError(err)
	}
	return result, nil
}

type Lease struct {
	Tenant          tenancy.TenantID
	InferenceID     string
	AttemptID       string
	ProviderID      string
	ModelID         string
	WorkerID        string
	Epoch           int64
	AttemptCount    int
	MaxOutputTokens int
	LeaseUntil      time.Time
	AttemptDeadline time.Time
}

// ClaimNext performs a fair principal-level round-robin among due jobs for the
// selected provider/model. An expired provider lease is never silently replayed:
// it may represent an accepted billable request and remains concurrency-held
// until the unknown outcome is reconciled.
func (r *Repository) ClaimNext(ctx context.Context, tenant tenancy.TenantID, provider, model, worker string, lease time.Duration) (Lease, bool, error) {
	if !validIdentity(tenant, provider, model) || !queueWorker.MatchString(worker) || lease < time.Millisecond {
		return Lease{}, false, ErrQueueUnavailable
	}
	if lease > MaxLease {
		lease = MaxLease
	}
	var claimed Lease
	found := false
	err := tenancy.WithTenantTx(ctx, r.workerDB, tenant, nil, func(tx *sql.Tx) error {
		row := tx.QueryRowContext(ctx, `SELECT inference_id::text,attempt_id::text,lease_epoch,attempt_count,max_output_tokens,lease_until,attempt_deadline_at
			FROM keel_meta.claim_ai_job($1,$2,$3,$4,$5)`, string(tenant), provider, model, worker, lease.Milliseconds())
		if err := row.Scan(&claimed.InferenceID, &claimed.AttemptID, &claimed.Epoch, &claimed.AttemptCount,
			&claimed.MaxOutputTokens, &claimed.LeaseUntil, &claimed.AttemptDeadline); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil
			}
			return err
		}
		claimed.Tenant, claimed.ProviderID, claimed.ModelID, claimed.WorkerID = tenant, provider, model, worker
		found = true
		return nil
	})
	if err != nil {
		return Lease{}, false, mapQueueError(err)
	}
	return claimed, found, nil
}

// Renew extends only the current, still-live lease and never past the immutable
// attempt deadline. Workers must use AttemptDeadline as the provider context cap.
func (r *Repository) Renew(ctx context.Context, lease Lease, extension time.Duration) (Lease, error) {
	if !validLease(lease) || extension < time.Millisecond {
		return Lease{}, ErrLeaseLost
	}
	if extension > MaxLease {
		extension = MaxLease
	}
	renewed := lease
	err := tenancy.WithTenantTx(ctx, r.workerDB, lease.Tenant, nil, func(tx *sql.Tx) error {
		var until time.Time
		err := tx.QueryRowContext(ctx, `SELECT keel_meta.renew_ai_job_lease($1,$2,$3,$4,$5)`,
			string(lease.Tenant), lease.InferenceID, lease.WorkerID, lease.Epoch, extension.Milliseconds()).Scan(&until)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrLeaseLost
		}
		if err != nil {
			return err
		}
		renewed.LeaseUntil = until
		return nil
	})
	if err != nil {
		return Lease{}, mapQueueError(err)
	}
	return renewed, nil
}

func validSpec(spec JobSpec) bool {
	a := spec.Admission
	if !validIdentity(a.Tenant, spec.ProviderID, spec.ModelID) || uuid.Validate(a.InferenceID) != nil ||
		uuid.Validate(a.AttemptID) != nil || uuid.Validate(a.PeriodID) != nil || uuid.Validate(a.ReservationID) != nil ||
		spec.MaxOutputTokens < 1 || spec.MaxOutputTokens > 131072 || !queuePrincipal.MatchString(a.PrincipalBinding) ||
		!validDigest(a.Quote.PolicyDigest()) || !validDigest(a.RequestDigest) || a.Quote.ProviderID() != spec.ProviderID ||
		a.Quote.ModelID() != spec.ModelID || a.PeriodStart.IsZero() || !a.PeriodEnd.After(a.PeriodStart) {
		return false
	}
	return true
}

func validLease(l Lease) bool {
	return validIdentity(l.Tenant, l.ProviderID, l.ModelID) && uuid.Validate(l.InferenceID) == nil &&
		uuid.Validate(l.AttemptID) == nil && queueWorker.MatchString(l.WorkerID) && l.Epoch > 0
}

func validIdentity(tenant tenancy.TenantID, provider, model string) bool {
	return uuid.Validate(string(tenant)) == nil && queueProvider.MatchString(provider) && queueModel.MatchString(model)
}

func validDigest(s string) bool {
	if len(s) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

func equalHash(a, b []byte) bool {
	return len(a) == sha256.Size && len(b) == sha256.Size && string(a) == string(b)
}

func lockProfile(tx *sql.Tx, ctx context.Context, tenant tenancy.TenantID, provider, model string) error {
	// A transaction advisory lock serializes queue-depth admission and provider
	// concurrency claims without granting either runtime role profile mutation.
	key := string(tenant) + "|" + provider + "|" + model
	_, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, key)
	return err
}

func mapQueueError(err error) error {
	switch {
	case errors.Is(err, ErrQueueUnavailable), errors.Is(err, ErrQueueFull), errors.Is(err, ErrQueueConflict), errors.Is(err, ErrLeaseLost):
		return err
	case strings.Contains(strings.ToLower(err.Error()), "ai execution queue is at capacity"):
		return ErrQueueFull
	case strings.Contains(strings.ToLower(err.Error()), "ai job lease is no longer current"):
		return ErrLeaseLost
	default:
		return fmt.Errorf("AI queue transaction: %w", err)
	}
}
