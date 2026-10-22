package webhook

import (
	"errors"
	"time"
)

const (
	// DefaultBreakerFailures is the consecutive retryable failure count that opens a breaker.
	DefaultBreakerFailures = 5
	// DefaultBreakerOpenFor is the first cooldown of an open endpoint.
	DefaultBreakerOpenFor = 30 * time.Second
	// DefaultBreakerMaxOpenFor caps the cooldown after repeated failed probes.
	DefaultBreakerMaxOpenFor = 10 * time.Minute
	// DefaultBreakerProbes is the number of concurrent probes a half-open breaker allows.
	DefaultBreakerProbes = 1
)

// ErrInvalidBreakerPolicy means the threshold, cooldown or probe bound is not usable.
var ErrInvalidBreakerPolicy = errors.New("webhook breaker policy is invalid")

// ErrInvalidBreakerState means the stored breaker state violates its own invariants.
var ErrInvalidBreakerState = errors.New("webhook breaker state is invalid")

// BreakerStatus is the availability state of one endpoint.
type BreakerStatus string

const (
	// BreakerClosed admits attempts and counts consecutive retryable failures.
	BreakerClosed BreakerStatus = "closed"
	// BreakerOpen denies attempts until its cooldown elapses.
	BreakerOpen BreakerStatus = "open"
	// BreakerHalfOpen admits a bounded probe after the cooldown.
	BreakerHalfOpen BreakerStatus = "half_open"
)

// BreakerState is the pure, persistable state of one endpoint breaker. The zero value is a closed
// breaker with no failures, so a new endpoint needs no initialization.
type BreakerState struct {
	Status   BreakerStatus
	Failures int
	OpenedAt time.Time
	OpenFor  time.Duration
	Probes   int
}

// BreakerPolicy bounds per-endpoint circuit breaking. Only retryable outcomes count as failures:
// a delivered or permanent response proves the endpoint is reachable, so it resets the breaker
// even when the specific request was rejected.
type BreakerPolicy struct {
	FailureThreshold  int
	OpenFor           time.Duration
	MaxOpenFor        time.Duration
	ProbesPerHalfOpen int
}

// DefaultBreakerPolicy returns five consecutive failures, a 30-second first cooldown capped at ten
// minutes, and one half-open probe.
func DefaultBreakerPolicy() BreakerPolicy {
	return BreakerPolicy{
		FailureThreshold:  DefaultBreakerFailures,
		OpenFor:           DefaultBreakerOpenFor,
		MaxOpenFor:        DefaultBreakerMaxOpenFor,
		ProbesPerHalfOpen: DefaultBreakerProbes,
	}
}

// Validate checks the bounded breaker policy.
func (p BreakerPolicy) Validate() error {
	if p.FailureThreshold < 1 || p.FailureThreshold > 100 {
		return ErrInvalidBreakerPolicy
	}
	if p.OpenFor < time.Second || p.OpenFor > time.Hour {
		return ErrInvalidBreakerPolicy
	}
	if p.MaxOpenFor < p.OpenFor || p.MaxOpenFor > 24*time.Hour {
		return ErrInvalidBreakerPolicy
	}
	if p.ProbesPerHalfOpen < 1 || p.ProbesPerHalfOpen > 10 {
		return ErrInvalidBreakerPolicy
	}
	return nil
}

// Allow decides whether one attempt may start at now and returns the state after any cooldown
// transition. The caller must record the returned state even when the decision is deny, because an
// elapsed cooldown moves the breaker to half-open.
func (p BreakerPolicy) Allow(now time.Time, state BreakerState) (BreakerState, bool, error) {
	if err := p.Validate(); err != nil {
		return BreakerState{}, false, err
	}
	if err := state.validate(); err != nil {
		return BreakerState{}, false, err
	}
	state = normalizeBreakerState(state)
	switch state.Status {
	case BreakerClosed:
		return state, true, nil
	case BreakerOpen:
		if now.Before(state.OpenedAt.Add(state.OpenFor)) {
			return state, false, nil
		}
		state.Status = BreakerHalfOpen
		state.Probes = 1
		return state, true, nil
	case BreakerHalfOpen:
		if state.Probes >= p.ProbesPerHalfOpen {
			return state, false, nil
		}
		state.Probes++
		return state, true, nil
	default:
		return BreakerState{}, false, ErrInvalidBreakerState
	}
}

// Observe records the outcome of one attempt. A retryable failure counts toward opening from
// closed, reopens a failed half-open probe with a doubled cooldown, and is ignored while open.
// Delivered and permanent outcomes close the breaker and clear the cooldown escalation.
func (p BreakerPolicy) Observe(now time.Time, state BreakerState, outcome Outcome) (BreakerState, error) {
	if err := p.Validate(); err != nil {
		return BreakerState{}, err
	}
	if err := state.validate(); err != nil {
		return BreakerState{}, err
	}
	state = normalizeBreakerState(state)
	if !outcome.Valid() {
		return BreakerState{}, ErrInvalidAttempt
	}
	if state.Status == BreakerOpen {
		return state, nil
	}
	if outcome != OutcomeRetryable {
		return BreakerState{Status: BreakerClosed}, nil
	}
	switch state.Status {
	case BreakerClosed:
		state.Failures++
		if state.Failures < p.FailureThreshold {
			return state, nil
		}
		return p.open(now, p.OpenFor), nil
	case BreakerHalfOpen:
		cooldown := state.OpenFor
		if cooldown == 0 {
			cooldown = p.OpenFor
		}
		if cooldown < p.MaxOpenFor {
			cooldown *= 2
			if cooldown > p.MaxOpenFor || cooldown <= 0 {
				cooldown = p.MaxOpenFor
			}
		}
		return p.open(now, cooldown), nil
	default:
		return BreakerState{}, ErrInvalidBreakerState
	}
}

// OpenUntil reports the cooldown end while the breaker is open. It is zero otherwise.
func (s BreakerState) OpenUntil() time.Time {
	if s.Status != BreakerOpen {
		return time.Time{}
	}
	return s.OpenedAt.Add(s.OpenFor)
}

func (p BreakerPolicy) open(now time.Time, cooldown time.Duration) BreakerState {
	return BreakerState{
		Status:   BreakerOpen,
		OpenedAt: now.UTC(),
		OpenFor:  cooldown,
	}
}

func normalizeBreakerState(state BreakerState) BreakerState {
	if state.Status == "" {
		state.Status = BreakerClosed
	}
	return state
}

func (s BreakerState) validate() error {
	switch s.Status {
	case "":
		if s.Failures != 0 || s.Probes != 0 || !s.OpenedAt.IsZero() || s.OpenFor != 0 {
			return ErrInvalidBreakerState
		}
		return nil
	case BreakerClosed:
		if s.Probes != 0 || !s.OpenedAt.IsZero() || s.OpenFor != 0 {
			return ErrInvalidBreakerState
		}
		return nil
	case BreakerOpen:
		if s.Failures != 0 || s.Probes != 0 || s.OpenedAt.IsZero() || s.OpenFor <= 0 {
			return ErrInvalidBreakerState
		}
		return nil
	case BreakerHalfOpen:
		if s.Failures != 0 || s.OpenedAt.IsZero() || s.OpenFor <= 0 || s.Probes < 0 {
			return ErrInvalidBreakerState
		}
		return nil
	default:
		return ErrInvalidBreakerState
	}
}
