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

// TenantSource returns tenants with due or expired deliveries. It returns tenant IDs only.
type TenantSource interface {
	DueTenants(ctx context.Context, limit int) ([]tenancy.TenantID, error)
}

// Runner processes one batch for one trusted tenant. *worker.Runner implements it.
type Runner interface {
	Run(ctx context.Context, tenant tenancy.TenantID, batch int) (worker.Report, error)
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
	lastPoll atomic.Int64
}

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
		return report, fmt.Errorf("discover webhook delivery tenants: %w", err)
	}
	s.lastPoll.Store(time.Now().UnixNano())
	var failures []error
	for _, tenant := range tenants {
		if err := ctx.Err(); err != nil {
			failures = append(failures, err)
			break
		}
		result, err := s.runner.Run(ctx, tenant, s.batch)
		report.add(result)
		if err != nil {
			report.Failures++
			failures = append(failures, err)
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
		if _, err := s.RunOnce(ctx); err != nil && ctx.Err() != nil {
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
