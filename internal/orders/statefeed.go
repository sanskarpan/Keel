package orders

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
