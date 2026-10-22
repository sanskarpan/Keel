package webhook

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestRetryPolicyBackoff(t *testing.T) {
	policy := DefaultRetryPolicy()
	cases := []struct {
		retry int
		want  time.Duration
	}{
		{0, 5 * time.Second},
		{1, 10 * time.Second},
		{2, 20 * time.Second},
		{4, 80 * time.Second},
		{10, 5120 * time.Second},
		{12, 20480 * time.Second},
		{13, 6 * time.Hour},
		{20, 6 * time.Hour},
		{21, 6 * time.Hour},
	}
	for _, tc := range cases {
		got, err := policy.Backoff(tc.retry)
		if err != nil {
			t.Fatalf("Backoff(%d) error = %v", tc.retry, err)
		}
		if got != tc.want {
			t.Fatalf("Backoff(%d) = %v, want %v", tc.retry, got, tc.want)
		}
	}
	if _, err := policy.Backoff(-1); !errors.Is(err, ErrInvalidAttempt) {
		t.Fatalf("Backoff(-1) error = %v, want ErrInvalidAttempt", err)
	}
}

func TestRetryPolicyValidate(t *testing.T) {
	valid := DefaultRetryPolicy()
	if err := valid.Validate(); err != nil {
		t.Fatalf("default policy invalid: %v", err)
	}
	cases := map[string]RetryPolicy{
		"no attempts":    {MaxAttempts: 0, Window: time.Hour, Base: time.Second, Cap: time.Minute},
		"too many":       {MaxAttempts: 101, Window: time.Hour, Base: time.Second, Cap: time.Minute},
		"zero window":    {MaxAttempts: 1, Window: 0, Base: time.Second, Cap: time.Minute},
		"long window":    {MaxAttempts: 1, Window: 8 * 24 * time.Hour, Base: time.Second, Cap: time.Minute},
		"zero base":      {MaxAttempts: 1, Window: time.Hour, Base: 0, Cap: time.Minute},
		"long base":      {MaxAttempts: 1, Window: time.Hour, Base: 2 * time.Hour, Cap: 3 * time.Hour},
		"cap below base": {MaxAttempts: 1, Window: time.Hour, Base: time.Minute, Cap: time.Second},
		"long cap":       {MaxAttempts: 1, Window: time.Hour, Base: time.Second, Cap: 13 * time.Hour},
	}
	for name, policy := range cases {
		if err := policy.Validate(); !errors.Is(err, ErrInvalidRetryPolicy) {
			t.Fatalf("%s: Validate() error = %v, want ErrInvalidRetryPolicy", name, err)
		}
	}
}

func TestSchedulerDelayIsFullJitter(t *testing.T) {
	policy := DefaultRetryPolicy()
	scheduler, err := NewSchedulerWithRand(policy, func() float64 { return 0.5 })
	if err != nil {
		t.Fatalf("NewSchedulerWithRand() error = %v", err)
	}
	got, err := scheduler.Delay(0)
	if err != nil {
		t.Fatalf("Delay(0) error = %v", err)
	}
	if got != 2500*time.Millisecond {
		t.Fatalf("Delay(0) = %v, want 2.5s", got)
	}
	capped, err := scheduler.Delay(30)
	if err != nil {
		t.Fatalf("Delay(30) error = %v", err)
	}
	if capped != 3*time.Hour {
		t.Fatalf("Delay(30) = %v, want half of the 6h cap", capped)
	}

	zero, err := NewSchedulerWithRand(policy, func() float64 { return 0 })
	if err != nil {
		t.Fatalf("NewSchedulerWithRand() error = %v", err)
	}
	if delay, err := zero.Delay(3); err != nil || delay != 0 {
		t.Fatalf("Delay with zero jitter = %v, %v", delay, err)
	}

	for _, jitter := range []float64{-0.1, 1, 1.5} {
		value := jitter
		bad, err := NewSchedulerWithRand(policy, func() float64 { return value })
		if err != nil {
			t.Fatalf("NewSchedulerWithRand() error = %v", err)
		}
		if _, err := bad.Delay(0); !errors.Is(err, ErrInvalidAttempt) {
			t.Fatalf("jitter %v: Delay() error = %v, want ErrInvalidAttempt", value, err)
		}
	}
	if _, err := NewSchedulerWithRand(policy, nil); !errors.Is(err, ErrInvalidRetryPolicy) {
		t.Fatalf("nil rand error = %v, want ErrInvalidRetryPolicy", err)
	}
	if _, err := NewScheduler(RetryPolicy{}); !errors.Is(err, ErrInvalidRetryPolicy) {
		t.Fatalf("invalid policy error = %v, want ErrInvalidRetryPolicy", err)
	}
	if delay, err := NewScheduler(policy); err != nil {
		t.Fatalf("NewScheduler() error = %v", err)
	} else if _, err := delay.Delay(1); err != nil {
		t.Fatalf("Delay() with package random source error = %v", err)
	}
}

func TestSchedulerNext(t *testing.T) {
	policy := DefaultRetryPolicy()
	scheduler, err := NewSchedulerWithRand(policy, func() float64 { return 0.5 })
	if err != nil {
		t.Fatalf("NewSchedulerWithRand() error = %v", err)
	}
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)

	next, exhausted, err := scheduler.Next(now, now, 1)
	if err != nil || exhausted {
		t.Fatalf("Next(attempts=1) = %v, %v, %v", next, exhausted, err)
	}
	if want := now.Add(2500 * time.Millisecond); !next.Equal(want) {
		t.Fatalf("Next(attempts=1) = %v, want %v", next, want)
	}

	if _, exhausted, err := scheduler.Next(now, now, 12); err != nil || !exhausted {
		t.Fatalf("Next(attempts=12) exhausted = %v, %v, want true", exhausted, err)
	}
	if _, exhausted, err := scheduler.Next(now.Add(-24*time.Hour), now, 2); err != nil || !exhausted {
		t.Fatalf("Next(expired window) exhausted = %v, %v, want true", exhausted, err)
	}
	if _, _, err := scheduler.Next(now, now, 0); !errors.Is(err, ErrInvalidAttempt) {
		t.Fatalf("Next(attempts=0) error = %v, want ErrInvalidAttempt", err)
	}
	if next, exhausted, err := scheduler.Next(time.Time{}, now, 2); err != nil || exhausted {
		t.Fatalf("Next(zero first attempt) = %v, %v, %v", next, exhausted, err)
	}
	if _, _, err := (*Scheduler)(nil).Next(now, now, 1); !errors.Is(err, ErrInvalidRetryPolicy) {
		t.Fatalf("nil scheduler error = %v, want ErrInvalidRetryPolicy", err)
	}
}

func TestClassifyStatus(t *testing.T) {
	cases := []struct {
		status int
		want   Outcome
	}{
		{200, OutcomeDelivered},
		{204, OutcomeDelivered},
		{299, OutcomeDelivered},
		{408, OutcomeRetryable},
		{425, OutcomeRetryable},
		{429, OutcomeRetryable},
		{500, OutcomeRetryable},
		{503, OutcomeRetryable},
		{599, OutcomeRetryable},
		{301, OutcomePermanent},
		{400, OutcomePermanent},
		{404, OutcomePermanent},
		{422, OutcomePermanent},
		{100, OutcomePermanent},
		{199, OutcomePermanent},
	}
	for _, tc := range cases {
		got, err := ClassifyStatus(tc.status)
		if err != nil {
			t.Fatalf("ClassifyStatus(%d) error = %v", tc.status, err)
		}
		if got != tc.want {
			t.Fatalf("ClassifyStatus(%d) = %q, want %q", tc.status, got, tc.want)
		}
	}
	for _, status := range []int{0, 99, 600, -1} {
		if _, err := ClassifyStatus(status); !errors.Is(err, ErrInvalidAttempt) {
			t.Fatalf("ClassifyStatus(%d) error = %v, want ErrInvalidAttempt", status, err)
		}
	}
}

func TestClassifyError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want Outcome
	}{
		{"egress denial", ErrEgressDenied, OutcomePermanent},
		{"wrapped denial", &net.OpError{Op: "dial", Err: ErrEgressDenied}, OutcomePermanent},
		{"invalid delivery", ErrInvalidDelivery, OutcomePermanent},
		{"invalid keyring", ErrInvalidKeyring, OutcomePermanent},
		{"resolver failure", ErrEgressUnavailable, OutcomeRetryable},
		{"timeout", context.DeadlineExceeded, OutcomeRetryable},
		{"connection refused", errors.New("connection refused"), OutcomeRetryable},
	}
	for _, tc := range cases {
		if got := ClassifyError(tc.err); got != tc.want {
			t.Fatalf("%s: ClassifyError() = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestOutcomeValid(t *testing.T) {
	for _, outcome := range []Outcome{OutcomeDelivered, OutcomeRetryable, OutcomePermanent} {
		if !outcome.Valid() {
			t.Fatalf("Outcome(%q).Valid() = false", outcome)
		}
	}
	for _, outcome := range []Outcome{"", "sent", "unknown"} {
		if outcome.Valid() {
			t.Fatalf("Outcome(%q).Valid() = true", outcome)
		}
	}
}
