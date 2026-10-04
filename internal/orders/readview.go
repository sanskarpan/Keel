package orders

import (
	"errors"
	"time"
)

var ErrNotFound = errors.New("order not found")

// ReadView combines the authoritative command snapshot with an independently advancing
// projection watermark. Snapshot status/version remain authoritative for command reads.
type ReadView struct {
	Snapshot            Snapshot
	ProjectionWatermark uint64
	UpdatedAt           time.Time
}

// HistoryEvent is the safe history projection exposed by order read APIs. It deliberately
// omits event payloads, actor/tenant references, evidence digests, and trace/correlation IDs.
type HistoryEvent struct {
	EventID    string    `json:"event_id"`
	Version    uint64    `json:"version"`
	Type       EventType `json:"type"`
	OccurredAt time.Time `json:"occurred_at"`
}

type HistoryPage struct {
	Items    []HistoryEvent
	HasMore  bool
	NextFrom uint64 // Exclusive upper bound for the next descending page.
}
