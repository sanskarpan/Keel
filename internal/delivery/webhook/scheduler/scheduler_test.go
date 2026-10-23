package scheduler

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/sanskarpan/keel/internal/delivery/webhook/worker"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

func schedulerTenant(t *testing.T, raw string) tenancy.TenantID {
	t.Helper()
	tenant, err := tenancy.ParseTenantID(raw)
	if err != nil {
		t.Fatal(err)
	}
	return tenant
}

type recordingSource struct {
	mu      sync.Mutex
	tenants []tenancy.TenantID
	err     error
	limits  []int
	called  chan struct{}
}

func (s *recordingSource) DueTenants(ctx context.Context, limit int) ([]tenancy.TenantID, error) {
	s.mu.Lock()
	s.limits = append(s.limits, limit)
	tenants, err := append([]tenancy.TenantID(nil), s.tenants...), s.err
	s.mu.Unlock()
	if s.called != nil {
		select {
		case s.called <- struct{}{}:
		default:
		}
	}
	return tenants, err
}

type runnerCall struct {
	tenant tenancy.TenantID
	batch  int
}

type recordingRunner struct {
	mu      sync.Mutex
	calls   []runnerCall
	reports map[string]worker.Report
	errors  map[string]error
}

func (r *recordingRunner) Run(ctx context.Context, tenant tenancy.TenantID, batch int) (worker.Report, error) {
	r.mu.Lock()
	r.calls = append(r.calls, runnerCall{tenant: tenant, batch: batch})
	report := r.reports[string(tenant)]
	err := r.errors[string(tenant)]
	r.mu.Unlock()
	return report, err
}

func TestSchedulerRunOnceProcessesEveryDueTenant(t *testing.T) {
	first := schedulerTenant(t, "11111111-1111-4111-8111-111111111111")
	second := schedulerTenant(t, "22222222-2222-4222-8222-222222222222")
	source := &recordingSource{tenants: []tenancy.TenantID{first, second}}
	runner := &recordingRunner{
		reports: map[string]worker.Report{
			string(first):  {Leased: 2, Delivered: 1, RetryScheduled: 1},
			string(second): {Leased: 1, Failed: 1},
		},
		errors: map[string]error{string(second): errors.New("tenant failed")},
	}
	s, err := New(source, runner, WithTenantLimit(10), WithBatch(3))
	if err != nil {
		t.Fatal(err)
	}

	report, err := s.RunOnce(context.Background())
	if err == nil {
		t.Fatal("expected the per-tenant failure to be reported")
	}
	if report.Tenants != 2 || report.Leased != 3 || report.Delivered != 1 ||
		report.RetryScheduled != 1 || report.Failed != 1 || report.Failures != 1 {
		t.Fatalf("unexpected report: %+v", report)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("runner calls = %d, want 2", len(runner.calls))
	}
	for _, call := range runner.calls {
		if call.batch != 3 {
			t.Fatalf("batch = %d, want 3", call.batch)
		}
	}
	if len(source.limits) != 1 || source.limits[0] != 10 {
		t.Fatalf("source limits = %v, want [10]", source.limits)
	}
}

func TestSchedulerRunOnceReturnsDiscoveryError(t *testing.T) {
	source := &recordingSource{err: errors.New("database unavailable")}
	runner := &recordingRunner{}
	s, err := New(source, runner)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.RunOnce(context.Background()); err == nil {
		t.Fatal("expected discovery error")
	}
	if len(runner.calls) != 0 {
		t.Fatalf("runner was called %d times after a discovery error", len(runner.calls))
	}
}

func TestSchedulerRunStopsOnCancellation(t *testing.T) {
	source := &recordingSource{called: make(chan struct{}, 1)}
	s, err := New(source, &recordingRunner{}, WithInterval(100*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	select {
	case <-source.called:
	case <-time.After(2 * time.Second):
		t.Fatal("scheduler did not poll")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("scheduler did not stop")
	}
}

func TestSchedulerRunOnceRejectsCancelledContextBeforeWork(t *testing.T) {
	source := &recordingSource{tenants: []tenancy.TenantID{
		schedulerTenant(t, "11111111-1111-4111-8111-111111111111"),
	}}
	runner := &recordingRunner{}
	s, err := New(source, runner)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.RunOnce(ctx); err == nil {
		t.Fatal("expected cancellation error")
	}
	if len(runner.calls) != 0 {
		t.Fatalf("runner was called %d times with a cancelled context", len(runner.calls))
	}
}

func TestSchedulerConfigurationBounds(t *testing.T) {
	source := &recordingSource{}
	runner := &recordingRunner{}
	if _, err := New(nil, runner); err == nil {
		t.Fatal("nil source accepted")
	}
	if _, err := New(source, nil); err == nil {
		t.Fatal("nil runner accepted")
	}
	for _, option := range []Option{
		WithTenantLimit(0),
		WithTenantLimit(MaxTenantLimit + 1),
		WithBatch(0),
		WithBatch(worker.MaxBatch + 1),
		WithInterval(0),
		WithInterval(2 * time.Minute),
		nil,
	} {
		if _, err := New(source, runner, option); err == nil {
			t.Fatalf("invalid option accepted: %v", option)
		}
	}
	if _, err := New(source, runner, WithTenantLimit(MaxTenantLimit), WithBatch(worker.MaxBatch), WithInterval(time.Minute)); err != nil {
		t.Fatalf("valid bounds rejected: %v", err)
	}
}

func TestSchedulerLastPollTracksSuccessfulDiscovery(t *testing.T) {
	source := &recordingSource{tenants: []tenancy.TenantID{
		schedulerTenant(t, "11111111-1111-4111-8111-111111111111"),
	}}
	s, err := New(source, &recordingRunner{})
	if err != nil {
		t.Fatal(err)
	}
	if !s.LastPoll().IsZero() {
		t.Fatal("fresh scheduler reports a poll")
	}
	started := time.Now().Add(-time.Second)
	if _, err := s.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	last := s.LastPoll()
	if last.IsZero() || last.Before(started) || last.After(time.Now().Add(time.Second)) {
		t.Fatalf("last poll = %v", last)
	}
}
