package ratelimit

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestDegradedWindowStatusRefreshContinuesAfterTransientError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	metrics := NewDegradedMetrics()
	secondCall := make(chan struct{})
	var calls atomic.Uint32
	done := make(chan error, 1)
	go func() {
		done <- runDegradedWindowStatusRefresh(ctx, 5*time.Millisecond, 2*time.Millisecond, func(context.Context) error {
			if calls.Add(1) == 1 {
				return errors.New("synthetic database interruption")
			}
			select {
			case <-secondCall:
			default:
				close(secondCall)
			}
			return nil
		}, metrics.recordWindowStatusRefreshError)
	}()

	select {
	case <-secondCall:
	case <-time.After(time.Second):
		t.Fatal("refresh loop did not retry after a transient error")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("refresh loop returned an error on cancellation: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("refresh loop did not stop after cancellation")
	}
	if calls.Load() < 2 {
		t.Fatalf("refresh loop made %d calls, want at least two", calls.Load())
	}
	if got := metrics.PrometheusMetrics(); !strings.Contains(got, "keel_rate_limit_degraded_window_status_refresh_errors_total 1\n") {
		t.Fatalf("refresh error counter missing or incorrect: %s", got)
	}
}

func TestDegradedWindowStatusRefreshBoundsEachQuery(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	metrics := NewDegradedMetrics()
	queryCanceled := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- runDegradedWindowStatusRefresh(ctx, 50*time.Millisecond, 5*time.Millisecond, func(callCtx context.Context) error {
			<-callCtx.Done()
			close(queryCanceled)
			return callCtx.Err()
		}, metrics.recordWindowStatusRefreshError)
	}()

	select {
	case <-queryCanceled:
	case <-time.After(time.Second):
		t.Fatal("refresh query context was not bounded by its timeout")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("refresh loop returned an error on cancellation: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("refresh loop did not stop after cancellation")
	}
	if got := metrics.PrometheusMetrics(); !strings.Contains(got, "keel_rate_limit_degraded_window_status_refresh_errors_total 1\n") {
		t.Fatalf("timeout was not counted as a refresh error: %s", got)
	}
}

func TestDegradedWindowStatusRefreshDoesNotCountShutdownCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	metrics := NewDegradedMetrics()
	done := make(chan error, 1)
	go func() {
		done <- runDegradedWindowStatusRefresh(ctx, time.Second, time.Second, func(callCtx context.Context) error {
			cancel()
			<-callCtx.Done()
			return callCtx.Err()
		}, metrics.recordWindowStatusRefreshError)
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("refresh loop returned an error on cancellation: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("refresh loop did not stop after cancellation")
	}
	if got := metrics.PrometheusMetrics(); !strings.Contains(got, "keel_rate_limit_degraded_window_status_refresh_errors_total 0\n") {
		t.Fatalf("expected graceful cancellation to avoid incrementing refresh errors: %s", got)
	}
}

func TestDegradedWindowStatusObservedReadinessSignal(t *testing.T) {
	metrics := NewDegradedMetrics()
	now := time.Date(2026, time.October, 7, 12, 0, 0, 0, time.UTC)
	if metrics.WindowStatusObserved() {
		t.Fatal("new metrics reported an unobserved status as ready")
	}
	if metrics.WindowStatusFresh(now, 15*time.Second) {
		t.Fatal("new metrics reported an unobserved status as fresh")
	}
	metrics.setWindowStatusAt(DegradedWindowStatus{ObservedAt: now}, now)
	if !metrics.WindowStatusObserved() {
		t.Fatal("successful status snapshot did not open the readiness signal")
	}
	for _, tc := range []struct {
		name string
		now  time.Time
		age  time.Duration
		want bool
	}{
		{name: "fresh within threshold", now: now.Add(15 * time.Second), age: 15 * time.Second, want: true},
		{name: "stale beyond threshold", now: now.Add(15*time.Second + time.Nanosecond), age: 15 * time.Second},
		{name: "clock moved backwards", now: now.Add(-time.Second), age: 15 * time.Second},
		{name: "invalid threshold", now: now, age: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := metrics.WindowStatusFresh(tc.now, tc.age); got != tc.want {
				t.Fatalf("WindowStatusFresh() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestDegradedWindowStatusRefreshAgeMetric(t *testing.T) {
	metrics := NewDegradedMetrics()
	if got := metrics.PrometheusMetrics(); !strings.Contains(got, "keel_rate_limit_degraded_window_status_refresh_age_seconds -1\n") {
		t.Fatalf("missing no-snapshot refresh age sentinel: %s", got)
	}
	metrics.setWindowStatus(DegradedWindowStatus{ObservedAt: time.Now().UTC()})
	if got := metrics.PrometheusMetrics(); !strings.Contains(got, "keel_rate_limit_degraded_window_status_refresh_age_seconds 0.") {
		t.Fatalf("missing refresh age gauge after a successful snapshot: %s", got)
	}
}

func TestDegradedWindowStatusRefreshRejectsInvalidConfiguration(t *testing.T) {
	for name, args := range map[string]struct {
		ctx          context.Context
		interval     time.Duration
		queryTimeout time.Duration
		observe      func(context.Context) error
		onError      func()
	}{
		"nil context":                  {nil, time.Second, time.Second, func(context.Context) error { return nil }, func() {}},
		"nil observer":                 {context.Background(), time.Second, time.Second, nil, func() {}},
		"nil error callback":           {context.Background(), time.Second, time.Second, func(context.Context) error { return nil }, nil},
		"nonpositive interval":         {context.Background(), 0, time.Second, func(context.Context) error { return nil }, func() {}},
		"nonpositive timeout":          {context.Background(), time.Second, 0, func(context.Context) error { return nil }, func() {}},
		"timeout longer than interval": {context.Background(), time.Second, 2 * time.Second, func(context.Context) error { return nil }, func() {}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := runDegradedWindowStatusRefresh(args.ctx, args.interval, args.queryTimeout, args.observe, args.onError); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("invalid refresh configuration returned %v, want ErrInvalidConfig", err)
			}
		})
	}
}
