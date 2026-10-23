// Package worker runs the single-tenant webhook delivery loop: lease, breaker admission, endpoint
// resolution, payload fetch, one signed attempt, durable recording and breaker observation.
package worker

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/sanskarpan/keel/internal/delivery/webhook"
	"github.com/sanskarpan/keel/internal/delivery/webhook/postgres"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

const (
	// DefaultBatch is the number of due deliveries one loop iteration leases.
	DefaultBatch = 20
	// MaxBatch bounds one loop iteration.
	MaxBatch = 100
	// DefaultLeaseDuration outlives a bounded attempt and its recording.
	DefaultLeaseDuration = 60 * time.Second

	minLeaseDuration = 5 * time.Second
	maxLeaseDuration = 300 * time.Second
	minDefer         = 5 * time.Second
	zeroTenant       = "00000000-0000-0000-0000-000000000000"
)

// Store is the durable webhook delivery surface the loop needs. *postgres.Store implements it.
type Store interface {
	Lease(ctx context.Context, tenant tenancy.TenantID, limit int, leaseFor time.Duration) ([]postgres.Lease, error)
	Endpoint(ctx context.Context, tenant tenancy.TenantID, endpointID string, subscriptionVersion uint32) (webhook.Endpoint, error)
	Breaker(ctx context.Context, tenant tenancy.TenantID, endpointID string) (postgres.BreakerSnapshot, error)
	SaveBreaker(ctx context.Context, tenant tenancy.TenantID, endpointID string, expectedVersion int64, state webhook.BreakerState) (postgres.BreakerSnapshot, error)
	RecordAttempt(ctx context.Context, lease postgres.Lease, result postgres.AttemptResult) (postgres.DeliveryState, error)
}

// PayloadSource returns the exact event bytes to sign. It must be tenant-scoped by the caller and
// must not derive the tenant from the delivery identity.
type PayloadSource interface {
	Payload(ctx context.Context, delivery webhook.Delivery) ([]byte, error)
}

// Sender signs and performs one attempt. *webhook.Executor implements it.
type Sender interface {
	Execute(ctx context.Context, request webhook.AttemptRequest) (webhook.AttemptResult, error)
}

// Report counts the dispositions of one loop iteration.
type Report struct {
	Leased         int
	Delivered      int
	RetryScheduled int
	Exhausted      int
	Failed         int
	Deferred       int
	Skipped        int
}

// Runner executes one batch of due deliveries. It is immutable after construction and safe for
// sequential reuse across tenants; concurrent use is safe when the Store and Sender are.
type Runner struct {
	store    Store
	payloads PayloadSource
	sender   Sender
	schedule *webhook.Scheduler
	breaker  webhook.BreakerPolicy
	now      func() time.Time
	leaseFor time.Duration
}

// Option adjusts bounded runner behavior. Options are applied by New.
type Option func(*Runner) error

// WithLeaseDuration sets the fence duration of one batch. It must be a whole number of seconds
// between 5 and 300.
func WithLeaseDuration(duration time.Duration) Option {
	return func(runner *Runner) error {
		seconds := int(duration / time.Second)
		if seconds < 5 || seconds > 300 || duration != time.Duration(seconds)*time.Second {
			return webhook.ErrInvalidAttempt
		}
		runner.leaseFor = duration
		return nil
	}
}

// WithClock injects the loop clock. It must return a non-zero time.
func WithClock(now func() time.Time) Option {
	return func(runner *Runner) error {
		if now == nil {
			return webhook.ErrInvalidAttempt
		}
		runner.now = now
		return nil
	}
}

// New validates the loop dependencies and defaults.
func New(store Store, payloads PayloadSource, sender Sender, schedule *webhook.Scheduler, breaker webhook.BreakerPolicy, options ...Option) (*Runner, error) {
	if store == nil {
		return nil, errors.New("webhook worker store is required")
	}
	if payloads == nil {
		return nil, errors.New("webhook worker payload source is required")
	}
	if sender == nil {
		return nil, errors.New("webhook worker sender is required")
	}
	if schedule == nil {
		return nil, errors.New("webhook worker retry scheduler is required")
	}
	if err := breaker.Validate(); err != nil {
		return nil, err
	}
	runner := &Runner{
		store:    store,
		payloads: payloads,
		sender:   sender,
		schedule: schedule,
		breaker:  breaker,
		now:      time.Now,
		leaseFor: DefaultLeaseDuration,
	}
	for _, option := range options {
		if option == nil {
			return nil, webhook.ErrInvalidAttempt
		}
		if err := option(runner); err != nil {
			return nil, err
		}
	}
	return runner, nil
}

// Run leases and processes up to batch due deliveries for one trusted tenant. A per-delivery error
// does not abort the rest of the batch; the errors are joined. Processing stops early only when the
// context is done.
func (r *Runner) Run(ctx context.Context, tenant tenancy.TenantID, batch int) (Report, error) {
	var report Report
	if r == nil || r.store == nil || r.payloads == nil || r.sender == nil || r.schedule == nil || r.now == nil {
		return report, errors.New("webhook worker is not configured")
	}
	if ctx == nil {
		return report, errors.New("webhook worker context is required")
	}
	if err := validateTenant(tenant); err != nil {
		return report, err
	}
	if batch < 1 || batch > MaxBatch {
		return report, webhook.ErrInvalidAttempt
	}

	leases, err := r.store.Lease(ctx, tenant, batch, r.leaseFor)
	if err != nil {
		return report, err
	}
	report.Leased = len(leases)
	var failures []error
	for _, lease := range leases {
		if err := ctx.Err(); err != nil {
			failures = append(failures, err)
			break
		}
		disposition, err := r.attempt(ctx, tenant, lease)
		switch disposition {
		case dispositionDelivered:
			report.Delivered++
		case dispositionRetry:
			report.RetryScheduled++
		case dispositionExhausted:
			report.Exhausted++
		case dispositionFailed:
			report.Failed++
		case dispositionDeferred:
			report.Deferred++
		default:
			report.Skipped++
		}
		if err != nil {
			failures = append(failures, fmt.Errorf("webhook delivery %s attempt %d: %w",
				lease.Delivery.ID, lease.AttemptNumber, err))
		}
	}
	return report, errors.Join(failures...)
}

type disposition int

const (
	dispositionSkipped disposition = iota
	dispositionDelivered
	dispositionRetry
	dispositionExhausted
	dispositionFailed
	dispositionDeferred
)

func (r *Runner) attempt(ctx context.Context, tenant tenancy.TenantID, lease postgres.Lease) (disposition, error) {
	if err := lease.Validate(); err != nil {
		return dispositionSkipped, err
	}
	endpointID := lease.Delivery.Identity.EndpointID
	now := r.now().UTC()
	if now.IsZero() {
		return dispositionSkipped, errors.New("webhook worker clock is invalid")
	}

	snapshot, err := r.store.Breaker(ctx, tenant, endpointID)
	if err != nil {
		return dispositionSkipped, err
	}
	state, allowed, err := r.breaker.Allow(now, snapshot.State)
	if err != nil {
		return dispositionSkipped, err
	}
	version := snapshot.Version
	if state != snapshot.State {
		saved, saveErr := r.store.SaveBreaker(ctx, tenant, endpointID, version, state)
		if saveErr != nil {
			return dispositionSkipped, saveErr
		}
		version = saved.Version
	}
	if !allowed {
		next, nextErr := r.deferUntil(now, lease, state)
		if nextErr != nil {
			return dispositionSkipped, nextErr
		}
		recorded, recordErr := r.store.RecordAttempt(ctx, lease, postgres.AttemptResult{
			Outcome:       webhook.OutcomeRetryable,
			NextAttemptAt: next,
		})
		if recordErr != nil {
			return dispositionSkipped, recordErr
		}
		if recorded.State == webhook.StatePending {
			return dispositionDeferred, nil
		}
		return dispositionFromState(recorded.State), nil
	}

	endpoint, err := r.store.Endpoint(ctx, tenant, endpointID,
		lease.Delivery.Identity.SubscriptionVersion)
	if err != nil {
		if errors.Is(err, webhook.ErrEndpointUnavailable) {
			return r.finish(ctx, tenant, lease, now, state, version, webhook.AttemptResult{
				Outcome: webhook.OutcomePermanent,
			})
		}
		return dispositionSkipped, err
	}

	payload, err := r.payloads.Payload(ctx, lease.Delivery)
	if err != nil && ctx.Err() != nil {
		return dispositionSkipped, ctx.Err()
	}
	if err != nil || len(payload) == 0 || len(payload) > webhook.MaxAttemptBodyBytes {
		if err == nil || errors.Is(err, webhook.ErrInvalidDelivery) {
			return r.finish(ctx, tenant, lease, now, state, version, webhook.AttemptResult{
				Outcome: webhook.OutcomePermanent,
			})
		}
		return r.finish(ctx, tenant, lease, now, state, version, webhook.AttemptResult{
			Outcome: webhook.OutcomeRetryable,
		})
	}

	result, err := r.sender.Execute(ctx, webhook.AttemptRequest{
		Delivery:      lease.Delivery,
		Endpoint:      endpoint,
		AttemptID:     lease.AttemptID,
		AttemptNumber: lease.AttemptNumber,
		Body:          payload,
		Now:           now,
	})
	if err != nil {
		return dispositionSkipped, err
	}
	return r.finish(ctx, tenant, lease, now, state, version, result)
}

func (r *Runner) finish(ctx context.Context, tenant tenancy.TenantID, lease postgres.Lease, now time.Time, state webhook.BreakerState, version int64, result webhook.AttemptResult) (disposition, error) {
	attempt := postgres.AttemptResult{
		Outcome:    result.Outcome,
		HTTPStatus: result.HTTPStatus,
		Latency:    result.Latency,
	}
	if result.Outcome == webhook.OutcomeRetryable {
		next, exhausted, err := r.schedule.Next(lease.FirstAttemptAt, now, lease.AttemptNumber)
		if err != nil {
			return dispositionSkipped, err
		}
		if !exhausted {
			attempt.NextAttemptAt = &next
		}
	}

	recorded, err := r.store.RecordAttempt(ctx, lease, attempt)
	if err != nil {
		return dispositionSkipped, err
	}
	disposition := dispositionFromState(recorded.State)

	observed, observeErr := r.breaker.Observe(now, state, result.Outcome)
	if observeErr != nil {
		return disposition, observeErr
	}
	if observed == state {
		return disposition, nil
	}
	if _, saveErr := r.store.SaveBreaker(ctx, tenant, lease.Delivery.Identity.EndpointID, version, observed); saveErr != nil {
		return disposition, saveErr
	}
	return disposition, nil
}

func dispositionFromState(state webhook.DeliveryState) disposition {
	switch state {
	case webhook.StateDelivered:
		return dispositionDelivered
	case webhook.StatePending:
		return dispositionRetry
	case webhook.StateExhausted:
		return dispositionExhausted
	case webhook.StateFailed:
		return dispositionFailed
	default:
		return dispositionSkipped
	}
}

func (r *Runner) deferUntil(now time.Time, lease postgres.Lease, state webhook.BreakerState) (*time.Time, error) {
	next, exhausted, err := r.schedule.Next(lease.FirstAttemptAt, now, lease.AttemptNumber)
	if err != nil {
		return nil, err
	}
	if exhausted {
		return nil, nil
	}
	earliest := now.Add(minDefer).UTC()
	if next.Before(earliest) {
		next = earliest
	}
	if until := state.OpenUntil(); until.After(next) {
		next = until.Add(time.Second).UTC()
	}
	return &next, nil
}

func validateTenant(tenant tenancy.TenantID) error {
	if string(tenant) == "" || string(tenant) == zeroTenant {
		return webhook.ErrInvalidDelivery
	}
	if _, err := tenancy.ParseTenantID(string(tenant)); err != nil {
		return webhook.ErrInvalidDelivery
	}
	return nil
}
