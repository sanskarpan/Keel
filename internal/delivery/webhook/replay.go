package webhook

import "errors"

const (
	// MaxReplayBatch is the number of deliveries one manual replay request may select.
	MaxReplayBatch = 500
	// MaxReplayCandidates bounds the candidate set an operator call may evaluate.
	MaxReplayCandidates = 5000
)

// ErrInvalidReplay means the request bound, candidate set or selection is not usable.
var ErrInvalidReplay = errors.New("webhook replay request is invalid")

// ErrReplayTooLarge means more deliveries were eligible than the request may replay. Nothing is
// selected in that case; the operator must narrow the batch instead of relying on silent truncation.
var ErrReplayTooLarge = errors.New("webhook replay selection exceeds the cap")

// EndpointStatus is the live registration state a replay must recheck.
type EndpointStatus string

const (
	// EndpointActive means the endpoint may receive new attempts.
	EndpointActive EndpointStatus = "active"
	// EndpointInactive means the endpoint was disabled or unsubscribed.
	EndpointInactive EndpointStatus = "inactive"
	// EndpointUnknown means the caller could not resolve the endpoint; replay fails closed.
	EndpointUnknown EndpointStatus = "unknown"
)

// EndpointEligibility is the live endpoint and signing configuration a replay must recheck. The
// caller must resolve it from the current registry and keyring, never from the replay request.
type EndpointEligibility struct {
	Status              EndpointStatus
	SubscriptionVersion uint32
	SignatureKeyReady   bool
}

// ReplayCandidate is one delivery an operator asked to replay plus the current state needed to
// decide. Replayed reports whether the delivery already has a replay record for this endpoint
// revision; a replayable delivery must not have one.
type ReplayCandidate struct {
	Delivery Delivery
	State    DeliveryState
	Attempts int
	Replayed bool
	Endpoint EndpointEligibility
}

// ReplaySkipReason is the stable, content-free reason a candidate was not selected.
type ReplaySkipReason string

const (
	// ReplaySkipDelivered means the delivery already reached a receiver.
	ReplaySkipDelivered ReplaySkipReason = "already_delivered"
	// ReplaySkipNotReplayable means the delivery is not in a terminal failure state.
	ReplaySkipNotReplayable ReplaySkipReason = "not_replayable"
	// ReplaySkipAlreadyReplayed means a replay record already exists.
	ReplaySkipAlreadyReplayed ReplaySkipReason = "already_replayed"
	// ReplaySkipEndpointInactive means the endpoint is disabled or unsubscribed.
	ReplaySkipEndpointInactive ReplaySkipReason = "endpoint_inactive"
	// ReplaySkipEndpointUnknown means the endpoint could not be resolved.
	ReplaySkipEndpointUnknown ReplaySkipReason = "endpoint_unknown"
	// ReplaySkipSubscriptionMismatch means the delivery targets a stale subscription revision.
	ReplaySkipSubscriptionMismatch ReplaySkipReason = "subscription_mismatch"
	// ReplaySkipSignatureUnavailable means no usable signing key is configured.
	ReplaySkipSignatureUnavailable ReplaySkipReason = "signature_unavailable"
	// ReplaySkipNoAttempts means no attempt was ever recorded for the delivery.
	ReplaySkipNoAttempts ReplaySkipReason = "no_attempts"
	// ReplaySkipInvalidDelivery means the delivery identity does not satisfy the wire contract.
	ReplaySkipInvalidDelivery ReplaySkipReason = "invalid_delivery"
	// ReplaySkipDuplicate means the same delivery was presented more than once in one request.
	ReplaySkipDuplicate ReplaySkipReason = "duplicate"
)

// Valid reports whether the skip reason is one of the recorded reasons.
func (r ReplaySkipReason) Valid() bool {
	switch r {
	case ReplaySkipDelivered, ReplaySkipNotReplayable, ReplaySkipAlreadyReplayed,
		ReplaySkipEndpointInactive, ReplaySkipEndpointUnknown, ReplaySkipSubscriptionMismatch,
		ReplaySkipSignatureUnavailable, ReplaySkipNoAttempts, ReplaySkipInvalidDelivery,
		ReplaySkipDuplicate:
		return true
	default:
		return false
	}
}

// ReplaySkip records why one candidate was left out. It carries no URL, secret or receiver content.
type ReplaySkip struct {
	DeliveryID string
	Reason     ReplaySkipReason
}

// ReplaySelection is the deduplicated, ordered result of one eligible selection.
type ReplaySelection struct {
	Deliveries []Delivery
	Skipped    []ReplaySkip
}

// SelectReplay evaluates candidates in input order and selects the eligible deliveries. Only
// exhausted or failed deliveries with at least one recorded attempt, an active endpoint at the same
// subscription revision, a ready signing key and no earlier replay are eligible. A requested limit
// of 1-500 is mandatory; if more candidates are eligible than the limit, the whole selection fails
// with ErrReplayTooLarge so the caller cannot silently replay a truncated batch.
func SelectReplay(candidates []ReplayCandidate, limit int) (ReplaySelection, error) {
	if limit < 1 || limit > MaxReplayBatch {
		return ReplaySelection{}, ErrInvalidReplay
	}
	if len(candidates) > MaxReplayCandidates {
		return ReplaySelection{}, ErrInvalidReplay
	}
	selection := ReplaySelection{}
	seen := make(map[string]struct{}, len(candidates))
	eligible := 0
	for _, candidate := range candidates {
		if reason, skip := replaySkipReason(candidate, seen); skip {
			selection.Skipped = append(selection.Skipped, ReplaySkip{
				DeliveryID: candidate.Delivery.ID,
				Reason:     reason,
			})
			continue
		}
		eligible++
		if eligible > limit {
			return ReplaySelection{}, ErrReplayTooLarge
		}
		selection.Deliveries = append(selection.Deliveries, candidate.Delivery)
	}
	return selection, nil
}

func replaySkipReason(candidate ReplayCandidate, seen map[string]struct{}) (ReplaySkipReason, bool) {
	if err := candidate.Delivery.Validate(); err != nil {
		return ReplaySkipInvalidDelivery, true
	}
	if _, duplicate := seen[candidate.Delivery.ID]; duplicate {
		return ReplaySkipDuplicate, true
	}
	seen[candidate.Delivery.ID] = struct{}{}
	if candidate.State == StateDelivered {
		return ReplaySkipDelivered, true
	}
	if candidate.State != StateExhausted && candidate.State != StateFailed {
		return ReplaySkipNotReplayable, true
	}
	if candidate.Attempts < 1 {
		return ReplaySkipNoAttempts, true
	}
	if candidate.Replayed {
		return ReplaySkipAlreadyReplayed, true
	}
	switch candidate.Endpoint.Status {
	case EndpointActive:
	case EndpointInactive:
		return ReplaySkipEndpointInactive, true
	default:
		return ReplaySkipEndpointUnknown, true
	}
	if candidate.Endpoint.SubscriptionVersion != candidate.Delivery.Identity.SubscriptionVersion {
		return ReplaySkipSubscriptionMismatch, true
	}
	if !candidate.Endpoint.SignatureKeyReady {
		return ReplaySkipSignatureUnavailable, true
	}
	return "", false
}
