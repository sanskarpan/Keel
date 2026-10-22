package webhook

// DeliveryState is the durable scheduling state of one logical delivery.
type DeliveryState string

const (
	// StatePending means the delivery is waiting for its next attempt time.
	StatePending DeliveryState = "pending"
	// StateInFlight means a worker holds a lease on the next attempt.
	StateInFlight DeliveryState = "in_flight"
	// StateDelivered means a receiver accepted an attempt; the delivery is terminal.
	StateDelivered DeliveryState = "delivered"
	// StateFailed means a non-retryable attempt failed; the delivery is terminal.
	StateFailed DeliveryState = "failed"
	// StateExhausted means the attempt ceiling or retry window ran out; the delivery is terminal.
	StateExhausted DeliveryState = "exhausted"
)

// Valid reports whether the state is one of the recorded states.
func (s DeliveryState) Valid() bool {
	switch s {
	case StatePending, StateInFlight, StateDelivered, StateFailed, StateExhausted:
		return true
	default:
		return false
	}
}

// Terminal reports whether no further attempt may be scheduled.
func (s DeliveryState) Terminal() bool {
	return s == StateDelivered || s == StateFailed || s == StateExhausted
}
