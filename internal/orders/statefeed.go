package orders

import "time"

// StateFeedUpdate is the allowlisted durable state event exposed to SSE clients.
type StateFeedUpdate struct {
	Sequence    uint64 `json:"sequence"`
	EventID     string `json:"event_id"`
	AggregateID string `json:"aggregate_id"`
	Version     uint64 `json:"version"`
	Kind        string `json:"kind"`
	Status      Status `json:"status"`
}

// StateFeedBatch is a bounded page plus retention and high-water marks from one DB snapshot.
type StateFeedBatch struct {
	Updates []StateFeedUpdate
	Oldest  uint64
	Latest  uint64
}

// StateStreamSnapshot is a privacy-safe order head and its durable stream cursor from one DB snapshot.
type StateStreamSnapshot struct {
	OrderID   string    `json:"order_id"`
	Version   uint64    `json:"version"`
	Status    Status    `json:"status"`
	UpdatedAt time.Time `json:"updated_at"`
	Cursor    uint64    `json:"cursor"`
}
