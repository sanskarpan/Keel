package postgres

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/sanskarpan/keel/internal/orders"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

// ReadOrder reads command authority and projector progress from one repeatable-read snapshot.
// A missing projection is normal lag and is represented as watermark zero.
func (r *Repository) ReadOrder(ctx context.Context, tenant tenancy.TenantID, orderID string) (view orders.ReadView, err error) {
	err = tenancy.WithTenantTx(ctx, r.db, tenant, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead}, func(tx *sql.Tx) error {
		var readErr error
		view, readErr = readOrderInTx(ctx, tx, tenant, orderID)
		return readErr
	})
	return view, err
}

// ReadOrderStateStreamSnapshot returns the authorized order head and durable feed high-water
// mark from one repeatable-read transaction, so reconnect snapshots cannot skip later updates.
func (r *Repository) ReadOrderStateStreamSnapshot(ctx context.Context, tenant tenancy.TenantID, orderID string) (snapshot orders.StateStreamSnapshot, err error) {
	err = tenancy.WithTenantTx(ctx, r.db, tenant, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead}, func(tx *sql.Tx) error {
		view, err := readOrderInTx(ctx, tx, tenant, orderID)
		if err != nil {
			return err
		}
		var cursor int64
		err = tx.QueryRowContext(ctx, `SELECT last_sequence FROM keel_meta.state_feed_counters WHERE tenant_id=$1`, string(tenant)).Scan(&cursor)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if cursor < 0 {
			return ErrCorruptState
		}
		snapshot = orders.StateStreamSnapshot{OrderID: view.Snapshot.OrderID, Version: view.Snapshot.Version,
			Status: view.Snapshot.Status, UpdatedAt: view.UpdatedAt.UTC(), Cursor: uint64(cursor)}
		return nil
	})
	return snapshot, err
}

// ReadStateUpdates returns a bounded tenant sequence page and retention bounds from one
// repeatable-read snapshot. The caller receives typed allowlisted fields, never raw JSON.
func (r *Repository) ReadStateUpdates(ctx context.Context, tenant tenancy.TenantID, after uint64, limit int) (batch orders.StateFeedBatch, err error) {
	if limit < 1 || limit > 100 {
		return orders.StateFeedBatch{}, errors.New("state feed page limit must be in [1,100]")
	}
	if after > uint64(^uint64(0)>>1) {
		return orders.StateFeedBatch{}, errors.New("state feed cursor exceeds database sequence range")
	}
	err = tenancy.WithTenantTx(ctx, r.db, tenant, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead}, func(tx *sql.Tx) error {
		var oldest sql.NullInt64
		var latest int64
		if err := tx.QueryRowContext(ctx, `SELECT
			(SELECT min(sequence) FROM keel_meta.state_updates WHERE tenant_id=$1),
			COALESCE((SELECT last_sequence FROM keel_meta.state_feed_counters WHERE tenant_id=$1),0)`, string(tenant)).Scan(&oldest, &latest); err != nil {
			return err
		}
		if latest < 0 || oldest.Valid && oldest.Int64 <= 0 {
			return ErrCorruptState
		}
		batch.Latest = uint64(latest)
		if oldest.Valid {
			batch.Oldest = uint64(oldest.Int64)
			if batch.Oldest > batch.Latest {
				return ErrCorruptState
			}
		} else if latest > 0 {
			// All entries may have expired; expose the first missing sequence so the
			// stream can request a snapshot instead of silently appearing current.
			batch.Oldest = batch.Latest + 1
		}
		rows, err := tx.QueryContext(ctx, `SELECT sequence,event_id,aggregate_id,aggregate_version,update_kind,safe_payload->>'status'
			FROM keel_meta.state_updates WHERE tenant_id=$1 AND sequence>$2
			ORDER BY sequence LIMIT $3`, string(tenant), int64(after), limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		batch.Updates = make([]orders.StateFeedUpdate, 0, limit)
		for rows.Next() {
			var sequence, version int64
			var update orders.StateFeedUpdate
			var status string
			if err := rows.Scan(&sequence, &update.EventID, &update.AggregateID, &version, &update.Kind, &status); err != nil {
				return err
			}
			if sequence <= 0 || uint64(sequence) > batch.Latest || version <= 0 || update.Kind != "order.changed" || !validFeedStatus(orders.Status(status)) {
				return ErrCorruptState
			}
			update.Sequence = uint64(sequence)
			update.Version = uint64(version)
			update.Status = orders.Status(status)
			batch.Updates = append(batch.Updates, update)
		}
		return rows.Err()
	})
	return batch, err
}

func validFeedStatus(status orders.Status) bool {
	switch status {
	case orders.Draft, orders.Submitted, orders.Verifying, orders.Approved, orders.Rejected, orders.Canceled:
		return true
	default:
		return false
	}
}

// ReadOrderWithHistory returns the detail view and its first history page from one database
// snapshot, so concurrent commands cannot produce a timeline newer than its displayed head.
func (r *Repository) ReadOrderWithHistory(ctx context.Context, tenant tenancy.TenantID, orderID string, beforeVersion uint64, limit int) (view orders.ReadView, page orders.HistoryPage, err error) {
	if limit < 1 || limit > 100 {
		return orders.ReadView{}, orders.HistoryPage{}, errors.New("history page limit must be in [1,100]")
	}
	err = tenancy.WithTenantTx(ctx, r.db, tenant, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead}, func(tx *sql.Tx) error {
		var readErr error
		view, readErr = readOrderInTx(ctx, tx, tenant, orderID)
		if readErr != nil {
			return readErr
		}
		page, readErr = pageEventsInTx(ctx, tx, tenant, orderID, view.Snapshot.Version, beforeVersion, limit)
		return readErr
	})
	return view, page, err
}

func readOrderInTx(ctx context.Context, tx *sql.Tx, tenant tenancy.TenantID, orderID string) (orders.ReadView, error) {
	snapshot, err := loadSnapshot(ctx, tx, tenant, orderID, false)
	if err != nil {
		return orders.ReadView{}, err
	}
	var updatedAt time.Time
	if err := tx.QueryRowContext(ctx, `SELECT updated_at FROM keel_meta.order_heads WHERE tenant_id=$1 AND order_id=$2`, string(tenant), orderID).Scan(&updatedAt); err != nil {
		return orders.ReadView{}, err
	}
	var watermark int64
	var projectedStatus sql.NullString
	err = tx.QueryRowContext(ctx, `SELECT applied_version,status FROM keel_meta.order_projections WHERE tenant_id=$1 AND aggregate_id=$2`, string(tenant), orderID).Scan(&watermark, &projectedStatus)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return orders.ReadView{}, err
	}
	if watermark < 0 || uint64(watermark) > snapshot.Version || (watermark == 0 && projectedStatus.Valid) || (watermark > 0 && !projectedStatus.Valid) || (uint64(watermark) == snapshot.Version && projectedStatus.String != string(snapshot.Status)) {
		return orders.ReadView{}, fmt.Errorf("%w: projection conflicts with authoritative order state", ErrCorruptState)
	}
	return orders.ReadView{Snapshot: snapshot, ProjectionWatermark: uint64(watermark), UpdatedAt: updatedAt.UTC()}, nil
}

// PageEvents returns an integrity-checked descending page from immutable aggregate history.
// beforeVersion is exclusive; zero starts at the authoritative command head.
func (r *Repository) PageEvents(ctx context.Context, tenant tenancy.TenantID, orderID string, beforeVersion uint64, limit int) (page orders.HistoryPage, err error) {
	if limit < 1 || limit > 100 {
		return orders.HistoryPage{}, errors.New("history page limit must be in [1,100]")
	}
	err = tenancy.WithTenantTx(ctx, r.db, tenant, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead}, func(tx *sql.Tx) error {
		snapshot, err := loadSnapshot(ctx, tx, tenant, orderID, false)
		if err != nil {
			return err
		}
		page, err = pageEventsInTx(ctx, tx, tenant, orderID, snapshot.Version, beforeVersion, limit)
		return err
	})
	return page, err
}

func pageEventsInTx(ctx context.Context, tx *sql.Tx, tenant tenancy.TenantID, orderID string, headVersion, beforeVersion uint64, limit int) (orders.HistoryPage, error) {
	if headVersion >= uint64(^uint64(0)>>1) {
		return orders.HistoryPage{}, fmt.Errorf("%w: order version is outside database history range", ErrCorruptState)
	}
	upper := beforeVersion
	if upper == 0 {
		upper = headVersion + 1
	}
	if upper < 2 || upper > headVersion+1 {
		return orders.HistoryPage{}, errors.New("history cursor is outside the order version range")
	}
	rows, err := tx.QueryContext(ctx, `SELECT aggregate_version,event_id::text,event_type,occurred_at,event_data,event_hash
		FROM keel_meta.order_events WHERE tenant_id=$1 AND order_id=$2 AND aggregate_version<$3
		ORDER BY aggregate_version DESC LIMIT $4`, string(tenant), orderID, int64(upper), limit+1)
	if err != nil {
		return orders.HistoryPage{}, err
	}
	defer rows.Close()
	items := make([]orders.HistoryEvent, 0, limit+1)
	expected := upper - 1
	for rows.Next() {
		var version int64
		var eventID, eventType string
		var occurredAt time.Time
		var raw, storedHash []byte
		if err := rows.Scan(&version, &eventID, &eventType, &occurredAt, &raw, &storedHash); err != nil {
			return orders.HistoryPage{}, err
		}
		var event orders.Event
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&event); err != nil {
			return orders.HistoryPage{}, fmt.Errorf("%w: decode history event", ErrCorruptState)
		}
		canonical, err := json.Marshal(event)
		if err != nil || !bytes.Equal(digest(canonical), storedHash) || version < 1 || uint64(version) != expected || event.Version != expected || eventID != event.Metadata.EventID || eventType != string(event.Type) || !occurredAt.Equal(event.Metadata.OccurredAt) || event.Metadata.TenantID != string(tenant) || event.Metadata.OrderID != orderID {
			return orders.HistoryPage{}, fmt.Errorf("%w: history event integrity check failed", ErrCorruptState)
		}
		items = append(items, orders.HistoryEvent{EventID: eventID, Version: uint64(version), Type: event.Type, OccurredAt: occurredAt.UTC()})
		expected--
	}
	if err := rows.Err(); err != nil {
		return orders.HistoryPage{}, err
	}
	if err := rows.Close(); err != nil {
		return orders.HistoryPage{}, err
	}
	hasMore := len(items) > limit
	if hasMore {
		items = items[:limit]
	} else if expected != 0 {
		return orders.HistoryPage{}, fmt.Errorf("%w: event history has a version gap", ErrCorruptState)
	}
	if len(items) == 0 {
		return orders.HistoryPage{}, fmt.Errorf("%w: event history is empty", ErrCorruptState)
	}
	page := orders.HistoryPage{Items: items, HasMore: hasMore}
	if hasMore {
		page.NextFrom = items[len(items)-1].Version
	}
	return page, nil
}
