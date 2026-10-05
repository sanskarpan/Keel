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

var (
	ErrErasureActionFailed       = errors.New("retrieval erasure action failed and was rescheduled")
	ErrErasureOutcomeInvalid     = errors.New("retrieval erasure action returned an invalid outcome")
	ErrErasureReceiptWriteFailed = errors.New("retrieval erasure action receipt could not be recorded")
	ErrErasurePolicyBlocked      = errors.New("retrieval erasure action is blocked by policy")
)

// ErasureActionBlockError marks an action result that must enter the durable
// blocked state instead of consuming the transient failure budget. Its code
// is constrained to the same content-free vocabulary stored by PostgreSQL.
type ErasureActionBlockError struct{ code string }

func NewErasureActionBlockError(code string) (*ErasureActionBlockError, error) {
	if !erasureErrorCodePattern.MatchString(code) || code == "attempts_exhausted" {
		return nil, errors.New("erasure policy block code is invalid")
	}
	return &ErasureActionBlockError{code: code}, nil
}

func (e *ErasureActionBlockError) Error() string { return ErrErasurePolicyBlocked.Error() }

func (e *ErasureActionBlockError) Unwrap() error { return ErrErasurePolicyBlocked }

func (e *ErasureActionBlockError) Code() string {
	if e == nil {
		return ""
	}
	return e.code
}

const MaxErasureActionDuration = 30 * time.Minute

var erasureActionOrder = [...]string{
	ErasureActionLegalHoldCheck,
	ErasureActionSupplierSourceObject,
	ErasureActionDerivedIndex,
	ErasureActionCacheRevocation,
	ErasureActionQueuedWorkRevocation,
	ErasureActionBackupExpiry,
}

// ErasureActionExecution is an executor's content-free evidence for one
// manifest action. Executors must be idempotent: a process may crash after a
// provider action succeeds but before its receipt commits.
type ErasureActionExecution struct {
	Disposition   string
	ActorID       uuid.UUID
	Reason        string
	ReceiptSHA256 [32]byte
	// Progress yields the live job lease without writing this action's receipt.
	// It is reserved for successful bounded work such as one derived-index batch.
	Progress bool
	// ProgressDelay is required with Progress and is bounded by the repository.
	ProgressDelay time.Duration
}

// ErasureActionExecutor runs one action for the current tenant/cohort job
// lease. It must stop on context cancellation and make external effects
// idempotent because a provider may complete just before a lease is lost.
// Before destructive effects it must verify the current owner/lease epoch and
// independently obtain current legal-hold clearance; the earlier
// legal_hold_check receipt only enforces manifest order.
type ErasureActionExecutor interface {
	Execute(context.Context, ErasureJob, string, string) (ErasureActionExecution, error)
}

type ErasureActionExecutorFunc func(context.Context, ErasureJob, string, string) (ErasureActionExecution, error)

func (f ErasureActionExecutorFunc) Execute(ctx context.Context, job ErasureJob, tenant, visibility string) (ErasureActionExecution, error) {
	if f == nil {
		return ErasureActionExecution{}, errors.New("erasure action executor function is nil")
	}
	return f(ctx, job, tenant, visibility)
}

// ErasureActionProcessor claims one job, executes its immutable manifest in
// legal-hold-first order, records idempotent receipts, and completes only after
// PostgreSQL accepts the fully satisfied manifest. A missing executor stops
// construction, so unconfigured actions cannot be silently skipped.
type ErasureActionProcessor struct {
	repository *Repository
	workerID   string
	lease      time.Duration
	backoff    time.Duration
	executors  map[string]ErasureActionExecutor
}

func NewErasureActionProcessor(repository *Repository, workerID string, lease, backoff time.Duration, executors map[string]ErasureActionExecutor) (*ErasureActionProcessor, error) {
	if repository == nil || !erasureWorkerIDPattern.MatchString(workerID) ||
		lease < MinErasureLease || lease > MaxErasureLease || backoff < time.Second || backoff > MaxErasureBackoff {
		return nil, errors.New("erasure processor repository, worker identity, lease or backoff is invalid")
	}
	if len(executors) != len(erasureActionOrder) {
		return nil, errors.New("erasure processor requires an executor for every manifest action")
	}
	copyExecutors := make(map[string]ErasureActionExecutor, len(executors))
	for _, action := range erasureActionOrder {
		executor := executors[action]
		if executor == nil {
			return nil, fmt.Errorf("erasure processor has no executor for %s", action)
		}
		copyExecutors[action] = executor
	}
	for action := range executors {
		if !validErasureAction(action) {
			return nil, fmt.Errorf("erasure processor has an unknown action executor %q", action)
		}
	}
	return &ErasureActionProcessor{repository: repository, workerID: workerID, lease: lease, backoff: backoff, executors: copyExecutors}, nil
}

// ProcessOne leases at most one due job. It returns claimed=false when no work
// is due. A successful bounded action may yield the lease with claimed=true and
// no error while leaving the job pending. Handler and receipt errors consume
// the bounded failure budget; exhausted jobs transition to the durable blocked state.
func (p *ErasureActionProcessor) ProcessOne(ctx context.Context, tenant tenancy.TenantID, visibility string) (job ErasureJob, claimed bool, err error) {
	if ctx == nil || p == nil || p.repository == nil {
		return ErasureJob{}, false, errors.New("erasure processor context is required")
	}
	job, claimed, err = p.repository.ClaimErasureJob(ctx, tenant, visibility, p.workerID, p.lease)
	if err != nil || !claimed {
		return job, claimed, err
	}
	claimedJob := job
	for _, action := range erasureActionOrder {
		recorded, checkErr := p.hasReceipt(ctx, tenant, visibility, job.ID, action)
		if checkErr != nil {
			return p.retry(ctx, tenant, visibility, job, "action_failed")
		}
		if recorded {
			continue
		}
		result, actionErr := p.executeUnderLease(ctx, tenant, visibility, job, action)
		if actionErr != nil {
			var policyBlock *ErasureActionBlockError
			if errors.As(actionErr, &policyBlock) {
				blocked, blockErr := p.repository.BlockErasureJob(ctx, tenant, visibility, p.workerID, job.ID, job.LeaseEpoch, policyBlock.Code())
				if blockErr != nil {
					return job, true, fmt.Errorf("persist policy-blocked retrieval erasure job: %w", blockErr)
				}
				return blocked, true, nil
			}
			return p.retry(ctx, tenant, visibility, job, "action_failed")
		}
		// Some actions (for example, supplier object erasure) must keep a
		// provider permit until their receipt is committed, so the executor
		// writes that receipt itself. Observe it before asking for a second
		// outcome or insert; this also makes response-loss replay idempotent.
		recorded, checkErr = p.hasReceipt(ctx, tenant, visibility, job.ID, action)
		if checkErr != nil {
			return p.retry(ctx, tenant, visibility, job, "receipt_check_failed")
		}
		if recorded {
			if result.Progress {
				return p.retry(ctx, tenant, visibility, job, "action_outcome_invalid")
			}
			continue
		}
		if result.Progress {
			if action != ErasureActionDerivedIndex || result.Disposition != "" || result.ActorID != uuid.Nil ||
				result.Reason != "" || result.ReceiptSHA256 != ([32]byte{}) ||
				result.ProgressDelay < MinErasureProgressDelay || result.ProgressDelay > MaxErasureProgressDelay {
				return p.retry(ctx, tenant, visibility, job, "action_outcome_invalid")
			}
			yielded, yieldErr := p.repository.YieldErasureJob(ctx, tenant, visibility, p.workerID, job.ID, job.LeaseEpoch, result.ProgressDelay)
			if yieldErr != nil {
				return job, true, fmt.Errorf("yield retrieval erasure progress: %w", yieldErr)
			}
			return yielded, true, nil
		}
		if err := validateErasureExecution(action, result); err != nil {
			return p.retry(ctx, tenant, visibility, job, "action_outcome_invalid")
		}
		if _, err := p.repository.RecordErasureActionReceipt(ctx, tenant, visibility, p.workerID, job.ID, job.LeaseEpoch,
			action, result.Disposition, result.ActorID, result.Reason, result.ReceiptSHA256); err != nil {
			return p.retry(ctx, tenant, visibility, job, "receipt_write_failed")
		}
	}
	job, err = p.repository.CompleteErasureJob(ctx, tenant, visibility, p.workerID, job.ID, job.LeaseEpoch)
	if err != nil {
		return p.retry(ctx, tenant, visibility, claimedJob, "completion_refused")
	}
	return job, true, nil
}

// ReadErasureBacklog exposes only bounded scope-local counts for the runtime's
// low-cardinality backlog gauges.
func (p *ErasureActionProcessor) ReadErasureBacklog(ctx context.Context, tenant tenancy.TenantID, visibility string) (ErasureBacklog, error) {
	if p == nil || p.repository == nil {
		return ErasureBacklog{}, errors.New("erasure processor repository is required")
	}
	return p.repository.ReadErasureBacklog(ctx, tenant, visibility)
}

// executeUnderLease renews the current fencing epoch while an injected handler
// runs and bounds a single action so a wedged provider cannot hold the job
// forever. Losing the database lease cancels the handler immediately.
func (p *ErasureActionProcessor) executeUnderLease(ctx context.Context, tenant tenancy.TenantID, visibility string,
	job ErasureJob, action string) (ErasureActionExecution, error) {
	actionCtx, cancel := context.WithTimeout(ctx, MaxErasureActionDuration)
	renewCtx, renewCancel := context.WithTimeout(actionCtx, erasureLeaseRenewalTimeout(p.lease))
	if _, err := p.repository.RenewErasureJobLease(renewCtx, tenant, visibility, p.workerID, job.ID, job.LeaseEpoch, p.lease); err != nil {
		renewCancel()
		cancel()
		return ErasureActionExecution{}, fmt.Errorf("verify live retrieval erasure lease before action: %w", err)
	}
	renewCancel()
	done := make(chan error, 1)
	interval := p.lease / 3
	if interval < MinErasureLease/3 {
		interval = MinErasureLease / 3
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-actionCtx.Done():
				done <- nil
				return
			case <-ticker.C:
				renewCtx, renewCancel := context.WithTimeout(actionCtx, erasureLeaseRenewalTimeout(p.lease))
				_, err := p.repository.RenewErasureJobLease(renewCtx, tenant, visibility, p.workerID, job.ID, job.LeaseEpoch, p.lease)
				renewCancel()
				if err != nil {
					if actionCtx.Err() != nil {
						done <- nil
					} else {
						done <- fmt.Errorf("renew retrieval erasure lease: %w", err)
						cancel()
					}
					return
				}
			}
		}
	}()
	result, actionErr := p.executors[action].Execute(actionCtx, job, string(tenant), visibility)
	cancel()
	leaseErr := <-done
	if leaseErr != nil {
		return ErasureActionExecution{}, leaseErr
	}
	return result, actionErr
}

func erasureLeaseRenewalTimeout(lease time.Duration) time.Duration {
	timeout := lease / 4
	if timeout < 100*time.Millisecond {
		return 100 * time.Millisecond
	}
	return timeout
}

func validateErasureExecution(action string, result ErasureActionExecution) error {
	if result.ActorID == uuid.Nil || result.ReceiptSHA256 == ([32]byte{}) ||
		(result.Disposition != ErasureReceiptComplete && result.Disposition != ErasureReceiptNotApplicable) {
		return ErrErasureOutcomeInvalid
	}
	if result.Disposition == ErasureReceiptComplete && result.Reason != "" {
		return ErrErasureOutcomeInvalid
	}
	if result.Disposition == ErasureReceiptNotApplicable &&
		(action == ErasureActionLegalHoldCheck || len(result.Reason) == 0 || len(result.Reason) > 512) {
		return ErrErasureOutcomeInvalid
	}
	return nil
}

func (p *ErasureActionProcessor) hasReceipt(ctx context.Context, tenant tenancy.TenantID, visibility string, jobID uuid.UUID, action string) (bool, error) {
	s, err := newScope(tenant, visibility)
	if err != nil {
		return false, err
	}
	var exists bool
	err = withScope(ctx, p.repository.db, s, &sql.TxOptions{ReadOnly: true}, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT EXISTS (
			SELECT 1 FROM keel_meta.retrieval_erasure_action_receipts
			WHERE tenant_id=$1 AND visibility_key=$2 AND job_id=$3 AND action_key=$4
		)`, string(s.tenant), s.visibility, jobID, action).Scan(&exists)
	})
	return exists, err
}

func (p *ErasureActionProcessor) retry(ctx context.Context, tenant tenancy.TenantID, visibility string, job ErasureJob, code string) (ErasureJob, bool, error) {
	retried, err := p.repository.RetryErasureJob(ctx, tenant, visibility, p.workerID, job.ID, job.LeaseEpoch, code, p.backoff)
	if err != nil {
		return job, true, fmt.Errorf("%w: retry lease could not be persisted", ErrErasureActionFailed)
	}
	return retried, true, ErrErasureActionFailed
}
