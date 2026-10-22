package webhook

import (
	"errors"
	"testing"
	"time"
)

func TestBreakerPolicyValidate(t *testing.T) {
	if err := DefaultBreakerPolicy().Validate(); err != nil {
		t.Fatalf("default breaker policy invalid: %v", err)
	}
	cases := map[string]BreakerPolicy{
		"zero threshold":  {FailureThreshold: 0, OpenFor: time.Second, MaxOpenFor: time.Minute, ProbesPerHalfOpen: 1},
		"large threshold": {FailureThreshold: 101, OpenFor: time.Second, MaxOpenFor: time.Minute, ProbesPerHalfOpen: 1},
		"short cooldown":  {FailureThreshold: 1, OpenFor: 0, MaxOpenFor: time.Minute, ProbesPerHalfOpen: 1},
		"long cooldown":   {FailureThreshold: 1, OpenFor: 2 * time.Hour, MaxOpenFor: 3 * time.Hour, ProbesPerHalfOpen: 1},
		"cap below base":  {FailureThreshold: 1, OpenFor: time.Minute, MaxOpenFor: time.Second, ProbesPerHalfOpen: 1},
		"long cap":        {FailureThreshold: 1, OpenFor: time.Second, MaxOpenFor: 25 * time.Hour, ProbesPerHalfOpen: 1},
		"no probes":       {FailureThreshold: 1, OpenFor: time.Second, MaxOpenFor: time.Minute, ProbesPerHalfOpen: 0},
		"many probes":     {FailureThreshold: 1, OpenFor: time.Second, MaxOpenFor: time.Minute, ProbesPerHalfOpen: 11},
	}
	for name, policy := range cases {
		if err := policy.Validate(); !errors.Is(err, ErrInvalidBreakerPolicy) {
			t.Fatalf("%s: Validate() error = %v, want ErrInvalidBreakerPolicy", name, err)
		}
	}
}

func TestBreakerClosedOpensAfterConsecutiveFailures(t *testing.T) {
	policy := DefaultBreakerPolicy()
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	state := BreakerState{}

	allowed, ok, err := policy.Allow(now, state)
	if err != nil || !ok || allowed.Status != BreakerClosed {
		t.Fatalf("closed breaker did not allow: %+v, %v, %v", allowed, ok, err)
	}
	for failure := 1; failure < policy.FailureThreshold; failure++ {
		state, err = policy.Observe(now, state, OutcomeRetryable)
		if err != nil {
			t.Fatalf("Observe failure %d: %v", failure, err)
		}
		if state.Status != BreakerClosed || state.Failures != failure {
			t.Fatalf("after %d failures = %+v, want closed with %d failures", failure, state, failure)
		}
		if _, ok, _ := policy.Allow(now, state); !ok {
			t.Fatalf("breaker denied before reaching the threshold")
		}
	}
	state, err = policy.Observe(now, state, OutcomeRetryable)
	if err != nil {
		t.Fatalf("Observe threshold: %v", err)
	}
	if state.Status != BreakerOpen || state.OpenFor != policy.OpenFor || state.Failures != 0 {
		t.Fatalf("unexpected open state: %+v", state)
	}
	if !state.OpenUntil().Equal(now.Add(policy.OpenFor)) {
		t.Fatalf("OpenUntil() = %s, want %s", state.OpenUntil(), now.Add(policy.OpenFor))
	}
	if _, ok, err := policy.Allow(now, state); err != nil || ok {
		t.Fatalf("open breaker allowed before cooldown: %v, %v", ok, err)
	}
	if _, ok, _ := policy.Allow(now.Add(policy.OpenFor-time.Second), state); ok {
		t.Fatal("open breaker allowed one second before cooldown")
	}
}

func TestBreakerIgnoresOutcomesWhileOpen(t *testing.T) {
	policy := DefaultBreakerPolicy()
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	open := BreakerState{Status: BreakerOpen, OpenedAt: now, OpenFor: policy.OpenFor}
	for _, outcome := range []Outcome{OutcomeDelivered, OutcomePermanent, OutcomeRetryable} {
		state, err := policy.Observe(now.Add(time.Second), open, outcome)
		if err != nil {
			t.Fatalf("Observe(%q): %v", outcome, err)
		}
		if state != open {
			t.Fatalf("outcome %q changed an open breaker: %+v", outcome, state)
		}
	}
}

func TestBreakerHalfOpenProbe(t *testing.T) {
	policy := DefaultBreakerPolicy()
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	open := BreakerState{Status: BreakerOpen, OpenedAt: now, OpenFor: policy.OpenFor}

	state, ok, err := policy.Allow(now.Add(policy.OpenFor), open)
	if err != nil || !ok {
		t.Fatalf("probe at cooldown end = %v, %v", ok, err)
	}
	if state.Status != BreakerHalfOpen || state.Probes != 1 {
		t.Fatalf("unexpected half-open state: %+v", state)
	}
	if _, ok, _ := policy.Allow(now.Add(policy.OpenFor), state); ok {
		t.Fatal("half-open breaker allowed a second concurrent probe")
	}

	failed, err := policy.Observe(now.Add(policy.OpenFor), state, OutcomeRetryable)
	if err != nil {
		t.Fatalf("Observe failed probe: %v", err)
	}
	if failed.Status != BreakerOpen || failed.OpenFor != 2*policy.OpenFor {
		t.Fatalf("failed probe did not reopen with a doubled cooldown: %+v", failed)
	}

	probe := failed.OpenedAt.Add(failed.OpenFor)
	state, ok, err = policy.Allow(probe, failed)
	if err != nil || !ok {
		t.Fatalf("second probe = %v, %v", ok, err)
	}
	healthy, err := policy.Observe(probe, state, OutcomeDelivered)
	if err != nil {
		t.Fatalf("Observe delivered probe: %v", err)
	}
	if healthy.Status != BreakerClosed || healthy.Failures != 0 || healthy.OpenFor != 0 || healthy.Probes != 0 {
		t.Fatalf("delivered probe did not close and reset: %+v", healthy)
	}
}

func TestBreakerCooldownEscalatesAndCaps(t *testing.T) {
	policy := DefaultBreakerPolicy()
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	state, err := policy.Observe(now, BreakerState{}, OutcomeRetryable)
	for failure := 0; failure < policy.FailureThreshold-1; failure++ {
		state, err = policy.Observe(now, state, OutcomeRetryable)
		if err != nil {
			t.Fatalf("trip breaker: %v", err)
		}
	}
	if state.Status != BreakerOpen || state.OpenFor != policy.OpenFor {
		t.Fatalf("unexpected first trip: %+v", state)
	}
	want := []time.Duration{60 * time.Second, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute, 10 * time.Minute, 10 * time.Minute}
	for index, cooldown := range want {
		probe := state.OpenedAt.Add(state.OpenFor)
		probeState, ok, err := policy.Allow(probe, state)
		if err != nil || !ok {
			t.Fatalf("probe %d = %v, %v", index, ok, err)
		}
		state, err = policy.Observe(probe, probeState, OutcomeRetryable)
		if err != nil {
			t.Fatalf("observe probe %d: %v", index, err)
		}
		if state.Status != BreakerOpen || state.OpenFor != cooldown {
			t.Fatalf("probe %d cooldown = %v, want %v (%+v)", index, state.OpenFor, cooldown, state)
		}
	}
}

func TestBreakerReachableOutcomeResetsClosed(t *testing.T) {
	policy := DefaultBreakerPolicy()
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	for _, outcome := range []Outcome{OutcomeDelivered, OutcomePermanent} {
		state := BreakerState{Status: BreakerClosed, Failures: policy.FailureThreshold - 1}
		reset, err := policy.Observe(now, state, outcome)
		if err != nil {
			t.Fatalf("Observe(%q): %v", outcome, err)
		}
		if reset.Status != BreakerClosed || reset.Failures != 0 {
			t.Fatalf("outcome %q did not reset the breaker: %+v", outcome, reset)
		}
	}
}

func TestBreakerProbesPerHalfOpen(t *testing.T) {
	policy := DefaultBreakerPolicy()
	policy.ProbesPerHalfOpen = 2
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	state := BreakerState{Status: BreakerOpen, OpenedAt: now, OpenFor: policy.OpenFor}

	state, ok, err := policy.Allow(now.Add(policy.OpenFor), state)
	if err != nil || !ok || state.Probes != 1 {
		t.Fatalf("first probe = %+v, %v, %v", state, ok, err)
	}
	state, ok, err = policy.Allow(now.Add(policy.OpenFor), state)
	if err != nil || !ok || state.Probes != 2 {
		t.Fatalf("second probe = %+v, %v, %v", state, ok, err)
	}
	if _, ok, _ := policy.Allow(now.Add(policy.OpenFor), state); ok {
		t.Fatal("half-open breaker exceeded its probe budget")
	}
}

func TestBreakerRejectsInvalidState(t *testing.T) {
	policy := DefaultBreakerPolicy()
	now := time.Now()
	cases := []BreakerState{
		{Status: BreakerOpen},
		{Status: BreakerOpen, OpenedAt: now},
		{Status: BreakerOpen, OpenedAt: now, OpenFor: time.Minute, Failures: 1},
		{Status: BreakerClosed, OpenedAt: now, OpenFor: time.Minute},
		{Status: BreakerHalfOpen, OpenFor: time.Minute},
		{Status: "bogus"},
	}
	for index, state := range cases {
		if _, _, err := policy.Allow(now, state); !errors.Is(err, ErrInvalidBreakerState) {
			t.Fatalf("case %d: Allow() error = %v, want ErrInvalidBreakerState", index, err)
		}
		if _, err := policy.Observe(now, state, OutcomeDelivered); !errors.Is(err, ErrInvalidBreakerState) {
			t.Fatalf("case %d: Observe() error = %v, want ErrInvalidBreakerState", index, err)
		}
	}
	if _, err := policy.Observe(now, BreakerState{}, "sent"); !errors.Is(err, ErrInvalidAttempt) {
		t.Fatalf("invalid outcome error = %v, want ErrInvalidAttempt", err)
	}
	if _, _, err := (BreakerPolicy{}).Allow(now, BreakerState{}); !errors.Is(err, ErrInvalidBreakerPolicy) {
		t.Fatalf("invalid policy error = %v, want ErrInvalidBreakerPolicy", err)
	}
}

func TestBreakerZeroStateIsClosed(t *testing.T) {
	state, ok, err := DefaultBreakerPolicy().Allow(time.Now(), BreakerState{})
	if err != nil || !ok || state.Status != BreakerClosed {
		t.Fatalf("zero state = %+v, %v, %v", state, ok, err)
	}
	if !state.OpenUntil().IsZero() {
		t.Fatalf("closed breaker reported OpenUntil %s", state.OpenUntil())
	}
}
