package erasureworker

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"time"

	"github.com/sanskarpan/keel/internal/ai/contextvault/postgres"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

const (
	MinPollInterval     = time.Second
	MaxPollInterval     = 30 * time.Second
	MaxIdlePollInterval = time.Minute
)

// Scope is provisioned by trusted server configuration, never from request or job data.
type Scope struct{ Tenant tenancy.TenantID }

type ProcessorAPI interface {
	ProcessOne(context.Context, tenancy.TenantID) (postgres.ErasureJob, bool, error)
}

type Observation struct {
	Claimed   int
	Completed int
	Held      int
	Blocked   int
	Pending   int
	Errors    int
}

type Observer interface{ ObserveContextErasurePoll(Observation) }
type ErrorHandler func(error)

type Runtime struct {
	processor ProcessorAPI
	scope     Scope
	interval  time.Duration
	observer  Observer
	onError   ErrorHandler
}

// New creates one runtime for one explicitly provisioned tenant scope.
func New(processor ProcessorAPI, scope Scope, pollInterval time.Duration, observer Observer, onError ErrorHandler) (*Runtime, error) {
	if processor == nil || observer == nil || onError == nil {
		return nil, errors.New("context erasure processor, observer and error handler are required")
	}
	if pollInterval < MinPollInterval || pollInterval > MaxPollInterval {
		return nil, errors.New("context erasure polling interval is outside the supported bounds")
	}
	tenant, err := tenancy.ParseTenantID(string(scope.Tenant))
	if err != nil {
		return nil, fmt.Errorf("context erasure scope has invalid tenant identity: %w", err)
	}
	return &Runtime{processor: processor, scope: Scope{Tenant: tenant}, interval: pollInterval, observer: observer, onError: onError}, nil
}

func (r *Runtime) PollOnce(ctx context.Context) (Observation, error) {
	if ctx == nil || r == nil || r.processor == nil {
		return Observation{}, errors.New("context erasure runtime and context are required")
	}
	observation := Observation{}
	job, claimed, err := r.processor.ProcessOne(ctx, r.scope.Tenant)
	if claimed {
		observation.Claimed++
		switch job.State {
		case "complete":
			observation.Completed++
		case "held":
			observation.Held++
		case "blocked":
			observation.Blocked++
		case "pending", "leased":
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

// Run uses bounded polling and exponential idle backoff with jitter. It handles
// one preauthorized tenant scope and never discovers tenants from the database.
func (r *Runtime) Run(ctx context.Context) error {
	if ctx == nil || r == nil || r.processor == nil {
		return errors.New("context erasure runtime and context are required")
	}
	idle := r.interval
	for {
		if ctx.Err() != nil {
			return nil
		}
		observation, err := r.PollOnce(ctx)
		if ctx.Err() != nil {
			return nil
		}
		if err != nil {
			r.onError(err)
		}
		r.observer.ObserveContextErasurePoll(observation)
		delay := r.interval
		if observation.Claimed == 0 {
			delay = idle
			idle *= 2
			if idle > MaxIdlePollInterval {
				idle = MaxIdlePollInterval
			}
		} else {
			idle = r.interval
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
