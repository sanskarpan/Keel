// Package erasureworker runs the context-vault erasure queue for one explicitly authorized tenant.
package erasureworker

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/sanskarpan/keel/internal/ai/contextvault/postgres"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

var (
	ErrJobRetryScheduled = errors.New("context erasure failure was durably rescheduled")
	workerIdentity       = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]{1,63}$`)
)

// Repository is the lease-fenced database boundary used by Processor.
type Repository interface {
	Claim(context.Context, tenancy.TenantID, string, time.Duration) (postgres.ErasureJob, bool, error)
	Process(context.Context, tenancy.TenantID, postgres.ErasureJob) (bool, error)
	Retry(context.Context, tenancy.TenantID, postgres.ErasureJob, string, time.Duration) (string, error)
}

// Processor claims and processes at most one due job per poll.
type Processor struct {
	repository  Repository
	workerID    string
	lease       time.Duration
	baseBackoff time.Duration
}

func NewProcessor(repository Repository, workerID string, lease, baseBackoff time.Duration) (*Processor, error) {
	if repository == nil || !workerIdentity.MatchString(workerID) ||
		lease < postgres.MinErasureJobLease || lease > postgres.MaxErasureJobLease ||
		baseBackoff < postgres.MinErasureJobBackoff || baseBackoff > postgres.MaxErasureJobBackoff {
		return nil, errors.New("context erasure repository, worker identity, lease or retry delay is invalid")
	}
	return &Processor{repository: repository, workerID: workerID, lease: lease, baseBackoff: baseBackoff}, nil
}

// ProcessOne claims at most one due item; transient failures are recorded using a bounded
// exponential delay and a fixed content-free error code.
func (p *Processor) ProcessOne(ctx context.Context, tenant tenancy.TenantID) (postgres.ErasureJob, bool, error) {
	if ctx == nil || p == nil || p.repository == nil {
		return postgres.ErasureJob{}, false, errors.New("context erasure processor and context are required")
	}
	job, claimed, err := p.repository.Claim(ctx, tenant, p.workerID, p.lease)
	if err != nil || !claimed {
		return job, claimed, err
	}
	job.WorkerID = p.workerID
	_, err = p.repository.Process(ctx, tenant, job)
	if err == nil {
		job.State = "complete"
		return job, true, nil
	}
	if errors.Is(err, postgres.ErrErasureJobLeaseLost) {
		return job, true, err
	}
	state, retryErr := p.repository.Retry(ctx, tenant, job, "delete_failed", retryDelay(p.baseBackoff, job.Failures+1))
	if retryErr != nil {
		return job, true, fmt.Errorf("persist context erasure retry: %w", retryErr)
	}
	job.State = state
	return job, true, ErrJobRetryScheduled
}

func retryDelay(base time.Duration, failure int) time.Duration {
	if failure < 1 {
		failure = 1
	}
	delay := base
	for n := 1; n < failure && delay < postgres.MaxErasureJobBackoff; n++ {
		if delay > postgres.MaxErasureJobBackoff/2 {
			return postgres.MaxErasureJobBackoff
		}
		delay *= 2
	}
	if delay > postgres.MaxErasureJobBackoff {
		return postgres.MaxErasureJobBackoff
	}
	return delay
}
