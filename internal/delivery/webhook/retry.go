package webhook

import (
	"errors"
	"math"
	"math/rand"
	"time"
)

const (
	// DefaultMaxAttempts is the documented attempt ceiling per delivery.
	DefaultMaxAttempts = 12
	// DefaultRetryWindow bounds the time in which retries are allowed.
	DefaultRetryWindow = 24 * time.Hour
	// DefaultRetryBase is the uncapped first-retry delay.
	DefaultRetryBase = 5 * time.Second
	// DefaultRetryCap bounds a single retry delay.
	DefaultRetryCap = 6 * time.Hour
)

var (
	// ErrInvalidRetryPolicy means the attempt, window, base or cap bound is not usable.
	ErrInvalidRetryPolicy = errors.New("webhook retry policy is invalid")
	// ErrInvalidAttempt means an attempt number or observation is out of range.
	ErrInvalidAttempt = errors.New("webhook attempt is invalid")
)

// RetryPolicy bounds retry scheduling. The retry delay is full-jitter uniform in
// [0, min(Cap, Base*2^retry)] where retry 0 is the first retry after the initial attempt.
type RetryPolicy struct {
	MaxAttempts int
	Window      time.Duration
	Base        time.Duration
	Cap         time.Duration
}

// DefaultRetryPolicy returns min(6h, 5s*2^retry), at most 12 attempts within 24 hours.
func DefaultRetryPolicy() RetryPolicy {
	return RetryPolicy{
		MaxAttempts: DefaultMaxAttempts,
		Window:      DefaultRetryWindow,
		Base:        DefaultRetryBase,
		Cap:         DefaultRetryCap,
	}
}

// Validate checks that the policy is bounded and internally consistent.
func (p RetryPolicy) Validate() error {
	if p.MaxAttempts < 1 || p.MaxAttempts > 100 {
		return ErrInvalidRetryPolicy
	}
	if p.Window <= 0 || p.Window > 7*24*time.Hour {
		return ErrInvalidRetryPolicy
	}
	if p.Base <= 0 || p.Base > time.Hour {
		return ErrInvalidRetryPolicy
	}
	if p.Cap < p.Base || p.Cap > 12*time.Hour {
		return ErrInvalidRetryPolicy
	}
	return nil
}

// Backoff returns the uncapped-by-jitter ceiling for one retry. Retry 0 is the first retry after
// the initial attempt. A retry index large enough to overflow saturates at Cap.
func (p RetryPolicy) Backoff(retry int) (time.Duration, error) {
	if err := p.Validate(); err != nil {
		return 0, err
	}
	if retry < 0 {
		return 0, ErrInvalidAttempt
	}
	if retry > 20 {
		return p.Cap, nil
	}
	ceiling := float64(p.Base) * math.Pow(2, float64(retry))
	if ceiling >= float64(p.Cap) {
		return p.Cap, nil
	}
	return time.Duration(ceiling), nil
}

// Scheduler applies a retry policy with full jitter. It is safe for concurrent use because it uses
// the package-level random source; tests inject a deterministic source.
type Scheduler struct {
	policy RetryPolicy
	random func() float64
}

// NewScheduler validates the policy and returns a scheduler with a full-jitter random source.
func NewScheduler(policy RetryPolicy) (*Scheduler, error) {
	return NewSchedulerWithRand(policy, rand.Float64)
}

// NewSchedulerWithRand is NewScheduler with an injected jitter source returning [0,1). A source
// that returns anything outside that range is rejected.
func NewSchedulerWithRand(policy RetryPolicy, random func() float64) (*Scheduler, error) {
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	if random == nil {
		return nil, ErrInvalidRetryPolicy
	}
	return &Scheduler{policy: policy, random: random}, nil
}

// Delay returns the jittered delay for one retry.
func (s *Scheduler) Delay(retry int) (time.Duration, error) {
	if s == nil {
		return 0, ErrInvalidRetryPolicy
	}
	ceiling, err := s.policy.Backoff(retry)
	if err != nil {
		return 0, err
	}
	jitter := s.random()
	if math.IsNaN(jitter) || jitter < 0 || jitter >= 1 {
		return 0, ErrInvalidAttempt
	}
	return time.Duration(jitter * float64(ceiling)), nil
}

// Next decides the next attempt time for a retryable failure. attempts is the number of attempts
// already started. It reports exhausted when the attempt ceiling or the retry window is reached;
// an exhausted delivery must be recorded as such with no next attempt time.
func (s *Scheduler) Next(firstAttempt, now time.Time, attempts int) (time.Time, bool, error) {
	if s == nil {
		return time.Time{}, false, ErrInvalidRetryPolicy
	}
	if attempts < 1 {
		return time.Time{}, false, ErrInvalidAttempt
	}
	if attempts >= s.policy.MaxAttempts {
		return time.Time{}, true, nil
	}
	if !firstAttempt.IsZero() && now.Sub(firstAttempt) >= s.policy.Window {
		return time.Time{}, true, nil
	}
	delay, err := s.Delay(attempts - 1)
	if err != nil {
		return time.Time{}, false, err
	}
	return now.Add(delay).UTC(), false, nil
}

// Outcome is the durable classification of one delivery attempt.
type Outcome string

const (
	// OutcomeDelivered means the receiver accepted the attempt.
	OutcomeDelivered Outcome = "delivered"
	// OutcomeRetryable means another attempt may succeed.
	OutcomeRetryable Outcome = "retryable"
	// OutcomePermanent means retrying the same destination cannot succeed.
	OutcomePermanent Outcome = "permanent"
)

// Valid reports whether the outcome is one of the three recorded classes.
func (o Outcome) Valid() bool {
	return o == OutcomeDelivered || o == OutcomeRetryable || o == OutcomePermanent
}

// MaxResponseStatus bounds the HTTP status an attempt may record.
const MaxResponseStatus = 599

// ClassifyStatus maps an HTTP status to an attempt outcome. Only 2xx is delivered. 408, 425, 429
// and 5xx are retryable; other 4xx, unexpected 1xx and unexpected 3xx are permanent.
func ClassifyStatus(status int) (Outcome, error) {
	if status < 100 || status > MaxResponseStatus {
		return "", ErrInvalidAttempt
	}
	switch {
	case status >= 200 && status <= 299:
		return OutcomeDelivered, nil
	case status == 408, status == 425, status == 429:
		return OutcomeRetryable, nil
	case status >= 400 && status <= 499:
		return OutcomePermanent, nil
	case status >= 500 && status <= 599:
		return OutcomeRetryable, nil
	default:
		return OutcomePermanent, nil
	}
}

// ClassifyError maps a transport error to an attempt outcome. A policy denial is permanent because
// retrying the same destination cannot help; every other transport or timeout failure is retryable.
func ClassifyError(err error) Outcome {
	if errors.Is(err, ErrEgressDenied) || errors.Is(err, ErrInvalidDelivery) ||
		errors.Is(err, ErrInvalidKeyring) {
		return OutcomePermanent
	}
	return OutcomeRetryable
}
