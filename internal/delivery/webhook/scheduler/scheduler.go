// Package scheduler discovers tenants with due webhook deliveries and runs the single-tenant
// delivery loop for each one. It is deliberately sequential per process: replicas coordinate
// through the delivery lease and epoch fence.
package scheduler

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/sanskarpan/keel/internal/delivery/webhook"
	"github.com/sanskarpan/keel/internal/delivery/webhook/worker"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

const (
	// DefaultInterval is the pause between tenant discovery passes.
	DefaultInterval = time.Second
	// DefaultTenantLimit is the number of due tenants one pass evaluates.
	DefaultTenantLimit = 100
	// MaxTenantLimit bounds one discovery pass.
	MaxTenantLimit = 1000

	minInterval = 100 * time.Millisecond
	maxInterval = time.Minute
)

// TenantSource returns tenants with due or expired deliveries. It carries no delivery content.
type TenantSource interface {
	DueTenants(ctx context.Context, limit int) ([]webhook.DueTenant, error)
}

// Runner processes one batch for one trusted tenant. *worker.Runner implements it.
type Runner interface {
	Run(ctx context.Context, tenant tenancy.TenantID, batch int) (worker.Report, error)
}

// PassObservation describes one discovery pass without tenant or delivery identifiers.
type PassObservation struct {
	Tenants         int
	DueDeliveries   int64
	OldestDue       time.Duration
	DiscoveryFailed bool
}

// TenantObservation describes one tenant batch without the tenant identifier.
type TenantObservation struct {
	Report worker.Report
	Failed bool
}

// Observer receives content-free scheduler observations. Implementations must not retain tenant,
// endpoint, event, URL or error strings.
type Observer interface {
	ObservePass(PassObservation)
	ObserveTenant(TenantObservation)
}

// Report aggregates one scheduler pass.
type Report struct {
	Tenants        int
	Leased         int
	Delivered      int
	RetryScheduled int
	Exhausted      int
	Failed         int
	Deferred       int
	Skipped        int
	Failures       int
}

func (r *Report) add(tenant worker.Report) {
	r.Tenants++
	r.Leased += tenant.Leased
	r.Delivered += tenant.Delivered
	r.RetryScheduled += tenant.RetryScheduled
	r.Exhausted += tenant.Exhausted
	r.Failed += tenant.Failed
	r.Deferred += tenant.Deferred
	r.Skipped += tenant.Skipped
}

// Scheduler polls tenant discovery and runs one worker batch per tenant.
type Scheduler struct {
	source   TenantSource
	runner   Runner
	limit    int
	batch    int
	interval time.Duration
	observer Observer
	reporter PassReporter
	lastPoll atomic.Int64
}

// PassReporter receives content-free aggregate results after each RunOnce. Implementations must not
// add tenant, endpoint, delivery, URL, payload, key or error strings.
type PassReporter func(Report, bool)

// Option adjusts bounded scheduler behavior.
type Option func(*Scheduler) error

// WithTenantLimit bounds how many due tenants one pass evaluates.
func WithTenantLimit(limit int) Option {
	return func(s *Scheduler) error {
		if limit < 1 || limit > MaxTenantLimit {
			return errors.New("webhook scheduler tenant limit is invalid")
		}
		s.limit = limit
		return nil
	}
}

// WithBatch bounds the deliveries leased for one tenant in one pass.
func WithBatch(batch int) Option {
	return func(s *Scheduler) error {
		if batch < 1 || batch > worker.MaxBatch {
			return errors.New("webhook scheduler batch is invalid")
		}
		s.batch = batch
		return nil
	}
}

// WithInterval sets the pause between discovery passes.
func WithInterval(interval time.Duration) Option {
	return func(s *Scheduler) error {
		if interval < minInterval || interval > maxInterval {
			return errors.New("webhook scheduler interval is invalid")
		}
		s.interval = interval
		return nil
	}
}

// WithObserver records content-free pass and tenant observations. A nil observer is rejected.
func WithObserver(observer Observer) Option {
	return func(s *Scheduler) error {
		if observer == nil {
			return errors.New("webhook scheduler observer is invalid")
		}
		s.observer = observer
		return nil
	}
}

// WithReporter records one content-free aggregate result per pass. A nil reporter is rejected.
func WithReporter(reporter PassReporter) Option {
	return func(s *Scheduler) error {
		if reporter == nil {
			return errors.New("webhook scheduler reporter is invalid")
		}
		s.reporter = reporter
		return nil
	}
}

// New validates the scheduler dependencies and defaults.
func New(source TenantSource, runner Runner, options ...Option) (*Scheduler, error) {
	if source == nil {
		return nil, errors.New("webhook scheduler tenant source is required")
	}
	if runner == nil {
		return nil, errors.New("webhook scheduler runner is required")
	}
	s := &Scheduler{
		source:   source,
		runner:   runner,
		limit:    DefaultTenantLimit,
		batch:    worker.DefaultBatch,
		interval: DefaultInterval,
	}
	for _, option := range options {
		if option == nil {
			return nil, errors.New("webhook scheduler option is invalid")
		}
		if err := option(s); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// RunOnce discovers due tenants and processes one batch for each. A per-tenant failure does not
// stop the remaining tenants; the joined errors are returned with the report.
func (s *Scheduler) RunOnce(ctx context.Context) (Report, error) {
	var report Report
	if s == nil || s.source == nil || s.runner == nil {
		return report, errors.New("webhook scheduler is not configured")
	}
	if ctx == nil {
		return report, errors.New("webhook scheduler context is required")
	}
	tenants, err := s.source.DueTenants(ctx, s.limit)
	if err != nil {
		if s.observer != nil {
			s.observer.ObservePass(PassObservation{DiscoveryFailed: true})
		}
		return report, fmt.Errorf("discover webhook delivery tenants: %w", err)
	}
	now := time.Now()
	s.lastPoll.Store(now.UnixNano())
	var dueDeliveries int64
	var oldest time.Time
	for _, tenant := range tenants {
		dueDeliveries += tenant.DueCount
		if oldest.IsZero() || tenant.DueAt.Before(oldest) {
			oldest = tenant.DueAt
		}
	}
	oldestAge := time.Duration(0)
	if !oldest.IsZero() {
		oldestAge = now.Sub(oldest)
		if oldestAge < 0 {
			oldestAge = 0
		}
	}
	if s.observer != nil {
		s.observer.ObservePass(PassObservation{
			Tenants:       len(tenants),
			DueDeliveries: dueDeliveries,
			OldestDue:     oldestAge,
		})
	}
	var failures []error
	for _, dueTenant := range tenants {
		if err := ctx.Err(); err != nil {
			failures = append(failures, err)
			break
		}
		result, err := s.runner.Run(ctx, dueTenant.Tenant, s.batch)
		report.add(result)
		if err != nil {
			report.Failures++
			failures = append(failures, err)
		}
		if s.observer != nil {
			s.observer.ObserveTenant(TenantObservation{Report: result, Failed: err != nil})
		}
	}
	return report, errors.Join(failures...)
}

// LastPoll reports when tenant discovery last succeeded. A zero time means no pass has completed.
func (s *Scheduler) LastPoll() time.Time {
	if s == nil {
		return time.Time{}
	}
	nanos := s.lastPoll.Load()
	if nanos <= 0 {
		return time.Time{}
	}
	return time.Unix(0, nanos).UTC()
}

// Run polls until the context is cancelled. Discovery and per-tenant failures are retried on the
// next pass; cancellation is the normal shutdown path.
func (s *Scheduler) Run(ctx context.Context) error {
	if s == nil || s.source == nil || s.runner == nil {
		return errors.New("webhook scheduler is not configured")
	}
	if ctx == nil {
		return errors.New("webhook scheduler context is required")
	}
	for {
		report, err := s.RunOnce(ctx)
		if s.reporter != nil {
			s.reporter(report, err != nil)
		}
		if err != nil && ctx.Err() != nil {
			return nil
		}
		timer := time.NewTimer(s.interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}
