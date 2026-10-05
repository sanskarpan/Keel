// Package erasureworker provides a bounded polling runtime for the K3.5
// manifest processor. It deliberately receives authorized tenant/cohort scopes
// from its caller; it does not discover tenants or infer authorization.
package erasureworker

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"time"

	"github.com/google/uuid"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
	"github.com/sanskarpan/keel/internal/retrieval/index"
	"github.com/sanskarpan/keel/internal/retrieval/postgres"
)

const (
	MinPollInterval     = time.Second
	MaxPollInterval     = 30 * time.Second
	MaxIdlePollInterval = time.Minute
)

// Scope must be created from trusted server-side authorization state. Do not
// construct it from request headers, job payloads, or user supplied config.
type Scope struct {
	Tenant        tenancy.TenantID
	VisibilityKey string
}

// Processor is the single-scope action processor. ProcessOne claims no more
// than one due job, keeping the runtime's per-scope work bounded.
type Processor interface {
	ProcessOne(context.Context, tenancy.TenantID, string) (postgres.ErasureJob, bool, error)
}

// Observation omits scope IDs so an observer can export low-cardinality worker
// metrics without tenant or visibility labels.
type Observation struct {
	ScopeCount int
	Claimed    int
	Completed  int
	Blocked    int
	Pending    int
	Errors     int
}

type Observer interface {
	ObserveErasurePoll(Observation)
}

// ErrorHandler receives aggregated scope errors without the corresponding
// tenant/cohort IDs. Callers should redact provider-specific error details
// before exporting them to logs or telemetry.
type ErrorHandler func(error)

type Runtime struct {
	processor Processor
	scope     Scope
	interval  time.Duration
	observer  Observer
	onError   ErrorHandler
}

// New validates one trusted scope. The caller must supply a scope already
// authorized for this worker identity. Run one instance per tenant/cohort so a
// slow provider action in one scope cannot delay unrelated scopes.
func New(processor Processor, input Scope, pollInterval time.Duration, observer Observer, onError ErrorHandler) (*Runtime, error) {
	if processor == nil || observer == nil || onError == nil {
		return nil, errors.New("erasure action processor, observer and error handler are required")
	}
	if pollInterval < MinPollInterval || pollInterval > MaxPollInterval {
		return nil, errors.New("erasure worker poll interval is outside the supported bounds")
	}
	tenant, err := tenancy.ParseTenantID(string(input.Tenant))
	if err != nil {
		return nil, fmt.Errorf("erasure worker scope has invalid tenant identity: %w", err)
	}
	parsedTenant, err := uuid.Parse(string(tenant))
	if err != nil {
		return nil, fmt.Errorf("erasure worker scope has invalid tenant identity: %w", err)
	}
	visibility, err := index.ParseVisibilityKey(input.VisibilityKey)
	if err != nil {
		return nil, fmt.Errorf("erasure worker scope has invalid visibility key: %w", err)
	}
	return &Runtime{processor: processor, scope: Scope{Tenant: tenancy.TenantID(parsedTenant.String()), VisibilityKey: visibility}, interval: pollInterval, observer: observer, onError: onError}, nil
}

// PollOnce performs one processor attempt against the configured tenant/cohort.
func (r *Runtime) PollOnce(ctx context.Context) (Observation, error) {
	if ctx == nil || r == nil || r.processor == nil {
		return Observation{}, errors.New("erasure worker runtime and context are required")
	}
	observation := Observation{ScopeCount: 1}
	job, claimed, err := r.processor.ProcessOne(ctx, r.scope.Tenant, r.scope.VisibilityKey)
	if claimed {
		observation.Claimed++
		switch job.State {
		case "complete":
			observation.Completed++
		case "blocked":
			observation.Blocked++
		case "cleanup_pending", "fenced":
			observation.Pending++
		}
	}
	if err != nil {
		observation.Errors++
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return observation, ctxErr
	}
	return observation, err
}

// Run polls until cancellation. Rounds with no claimed job use exponential
// idle backoff with jitter to limit database load and avoid synchronized
// replicas. Active work returns to the configured poll interval.
func (r *Runtime) Run(ctx context.Context) error {
	if ctx == nil || r == nil || r.processor == nil {
		return errors.New("erasure worker runtime and context are required")
	}
	idleInterval := r.interval
	for {
		if err := ctx.Err(); err != nil {
			return nil
		}
		observation, pollErr := r.PollOnce(ctx)
		if err := ctx.Err(); err != nil {
			return nil
		}
		if pollErr != nil {
			r.onError(pollErr)
		}
		r.observer.ObserveErasurePoll(observation)
		delay := r.interval
		if observation.Claimed == 0 {
			delay = idleInterval
			idleInterval *= 2
			if idleInterval > MaxIdlePollInterval {
				idleInterval = MaxIdlePollInterval
			}
		} else {
			idleInterval = r.interval
		}
		jitter := delay / 5
		if jitter > 0 {
			delay += time.Duration(rand.Int64N(int64(jitter)))
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}
