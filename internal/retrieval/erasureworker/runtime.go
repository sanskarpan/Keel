// Package erasureworker provides a bounded polling runtime for the K3.5
// manifest processor. It deliberately receives authorized tenant/cohort scopes
// from its caller; it does not discover tenants or infer authorization.
package erasureworker

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
	"github.com/sanskarpan/keel/internal/retrieval/index"
	"github.com/sanskarpan/keel/internal/retrieval/postgres"
)

const (
	MinPollInterval = 100 * time.Millisecond
	MaxPollInterval = time.Minute
	MaxScopes       = 1000
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
	scopes    []Scope
	interval  time.Duration
	observer  Observer
	onError   ErrorHandler
}

// New validates and copies a bounded set of trusted scopes. The caller must
// supply scopes already authorized for this worker identity.
func New(processor Processor, scopes []Scope, pollInterval time.Duration, observer Observer, onError ErrorHandler) (*Runtime, error) {
	if processor == nil {
		return nil, errors.New("erasure action processor is required")
	}
	if len(scopes) == 0 || len(scopes) > MaxScopes {
		return nil, fmt.Errorf("erasure worker requires between 1 and %d authorized scopes", MaxScopes)
	}
	if pollInterval < MinPollInterval || pollInterval > MaxPollInterval {
		return nil, errors.New("erasure worker poll interval is outside the supported bounds")
	}
	copyScopes := make([]Scope, 0, len(scopes))
	seen := make(map[Scope]struct{}, len(scopes))
	for _, input := range scopes {
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
		scope := Scope{Tenant: tenancy.TenantID(parsedTenant.String()), VisibilityKey: visibility}
		if _, exists := seen[scope]; exists {
			return nil, errors.New("erasure worker scopes contain a duplicate tenant/cohort")
		}
		seen[scope] = struct{}{}
		copyScopes = append(copyScopes, scope)
	}
	return &Runtime{processor: processor, scopes: copyScopes, interval: pollInterval, observer: observer, onError: onError}, nil
}

// PollOnce performs one bounded round: at most one job per configured scope.
// Errors in one scope do not prevent other authorized scopes from progressing.
func (r *Runtime) PollOnce(ctx context.Context) (Observation, error) {
	if ctx == nil || r == nil || r.processor == nil {
		return Observation{}, errors.New("erasure worker runtime and context are required")
	}
	observation := Observation{ScopeCount: len(r.scopes)}
	var failures []error
	for _, scope := range r.scopes {
		if err := ctx.Err(); err != nil {
			break
		}
		_, claimed, err := r.processor.ProcessOne(ctx, scope.Tenant, scope.VisibilityKey)
		if claimed {
			observation.Claimed++
		}
		if err != nil {
			observation.Errors++
			failures = append(failures, err)
		}
	}
	if err := ctx.Err(); err != nil {
		return observation, err
	}
	return observation, errors.Join(failures...)
}

// Run polls until cancellation. Each round is bounded and followed by the
// configured interval, including after errors or active work, so one backlog
// cannot create a hot loop that monopolizes CPU or the database.
func (r *Runtime) Run(ctx context.Context) error {
	if ctx == nil || r == nil || r.processor == nil {
		return errors.New("erasure worker runtime and context are required")
	}
	for {
		if err := ctx.Err(); err != nil {
			return nil
		}
		observation, pollErr := r.PollOnce(ctx)
		if err := ctx.Err(); err != nil {
			return nil
		}
		if pollErr != nil && r.onError != nil {
			r.onError(pollErr)
		}
		if r.observer != nil {
			r.observer.ObserveErasurePoll(observation)
		}
		timer := time.NewTimer(r.interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}
