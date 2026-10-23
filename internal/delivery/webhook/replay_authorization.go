package webhook

import (
	"errors"
	"time"
)

const maxReplayAuthorizationAttempts = 100

var (
	// ErrReplayUnauthorized means the caller does not hold the operator replay capability.
	ErrReplayUnauthorized = errors.New("webhook replay authorization is not permitted")
	// ErrReplayNotEligible means the delivery state, endpoint revision or key reference cannot be replayed.
	ErrReplayNotEligible = errors.New("webhook replay delivery is not eligible")
	// ErrReplayNotFound means the delivery does not exist inside the authorized tenant.
	ErrReplayNotFound = errors.New("webhook replay delivery was not found")
)

// ReplayAuthorization is the immutable audit outcome of one authorized replay requeue. It carries
// only the transition identity and prior budget values, never a URL, secret or receiver content.
type ReplayAuthorization struct {
	ReplayID        string
	DeliveryID      string
	RequestedBy     string
	Reason          string
	RequestedAt     time.Time
	PriorState      DeliveryState
	PriorAttempts   int
	PriorFinishedAt time.Time
	PriorLeaseEpoch int64
	AuthorizedAt    time.Time
	Created         bool
}

// Validate checks that the stored transition describes a bounded failed or exhausted delivery.
func (a ReplayAuthorization) Validate() error {
	if err := ValidateReplayID(a.ReplayID); err != nil {
		return err
	}
	if err := ValidateReplayDeliveryID(a.DeliveryID); err != nil {
		return err
	}
	if !replayActorPattern.MatchString(a.RequestedBy) {
		return ErrInvalidReplay
	}
	if err := validateReplayReason(a.Reason); err != nil {
		return err
	}
	if a.PriorState != StateFailed && a.PriorState != StateExhausted {
		return ErrReplayNotEligible
	}
	if a.PriorAttempts < 1 || a.PriorAttempts > maxReplayAuthorizationAttempts {
		return ErrReplayNotEligible
	}
	if a.PriorLeaseEpoch < 0 {
		return ErrReplayNotEligible
	}
	if a.PriorFinishedAt.IsZero() || a.RequestedAt.IsZero() || a.AuthorizedAt.IsZero() {
		return ErrReplayNotEligible
	}
	return nil
}
