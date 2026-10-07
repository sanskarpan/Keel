package postgres

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/sanskarpan/keel/internal/orders"
	"github.com/sanskarpan/keel/internal/orders/outbox"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
	"github.com/sanskarpan/keel/internal/platform/tracecontext"
)

const maxOutboxRepairHistory = 10_000

type repairEnvelope struct {
	SchemaVersion    int              `json:"schema_version"`
	EventID          string           `json:"event_id"`
	TenantID         string           `json:"tenant_id"`
	AggregateID      string           `json:"aggregate_id"`
	AggregateVersion uint64           `json:"aggregate_version"`
	EventType        orders.EventType `json:"event_type"`
	OccurredAt       time.Time        `json:"occurred_at"`
	Traceparent      string           `json:"traceparent,omitempty"`
}

func (r *Repository) ListBlocked(ctx context.Context, tenant tenancy.TenantID, aggregateID string) ([]outbox.BlockedEvent, error) {
	blocked := make([]outbox.BlockedEvent, 0, 1)
	err := tenancy.WithTenantTx(ctx, r.db, tenant, &sql.TxOptions{ReadOnly: true}, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT d.tenant_id::text,d.aggregate_id::text,d.event_id::text,
			d.aggregate_version,d.last_error_code,d.attempt_count
			FROM keel_meta.outbox_publish_heads h
			JOIN keel_meta.outbox_delivery d ON d.tenant_id=h.tenant_id AND d.aggregate_id=h.aggregate_id AND d.aggregate_version=h.next_version
			WHERE h.tenant_id=$1 AND h.aggregate_id=$2 AND d.delivery_state='blocked'
			ORDER BY d.aggregate_version`, string(tenant), aggregateID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var item outbox.BlockedEvent
			if err := rows.Scan(&item.TenantID, &item.AggregateID, &item.EventID, &item.Version, &item.ErrorCode, &item.AttemptCount); err != nil {
				return err
			}
			blocked = append(blocked, item)
		}
		return rows.Err()
	})
	return blocked, err
}

func (r *Repository) RepairBlocked(ctx context.Context, tenant tenancy.TenantID, aggregateID string, identity outbox.RepairIdentity, request outbox.RepairRequest) error {
	if identity.TenantID != tenant || identity.ActorRef == "" || identity.RequestID == "" {
		return outbox.ErrRepairUnauthorized
	}
	if request.ExpectedVersion < 1 || request.ExpectedAttemptCount < 0 {
		return outbox.ErrRepairInvalid
	}
	return tenancy.WithTenantTx(ctx, r.db, tenant, nil, func(tx *sql.Tx) error {
		var nextVersion int64
		var claimOwner, errorCode sql.NullString
		var leaseExpires sql.NullTime
		var state string
		var eventID, eventType string
		var schemaVersion, attempts int
		var rawEnvelope, rawEvent, eventHash []byte
		var indexedEventID, indexedAggregateID, indexedEventType string
		var indexedVersion int64
		var occurredAt time.Time
		err := tx.QueryRowContext(ctx, `SELECT h.next_version,h.claim_owner,h.lease_expires_at,
			d.delivery_state,d.last_error_code,d.attempt_count,d.event_id::text,o.event_type,o.schema_version,o.safe_envelope,
			e.event_id::text,e.order_id::text,e.aggregate_version,e.event_type,e.event_data,e.event_hash,e.occurred_at
			FROM keel_meta.outbox_publish_heads h
			JOIN keel_meta.outbox_delivery d ON d.tenant_id=h.tenant_id AND d.aggregate_id=h.aggregate_id AND d.aggregate_version=h.next_version
			JOIN keel_meta.event_outbox o ON o.tenant_id=d.tenant_id AND o.event_id=d.event_id
			JOIN keel_meta.order_events e ON e.tenant_id=o.tenant_id AND e.event_id=o.event_id
			WHERE h.tenant_id=$1 AND h.aggregate_id=$2 AND d.event_id=$3
			FOR UPDATE OF d`, string(tenant), aggregateID, request.EventID).Scan(
			&nextVersion, &claimOwner, &leaseExpires, &state, &errorCode, &attempts, &eventID, &eventType,
			&schemaVersion, &rawEnvelope, &indexedEventID, &indexedAggregateID, &indexedVersion, &indexedEventType,
			&rawEvent, &eventHash, &occurredAt)
		if errors.Is(err, sql.ErrNoRows) {
			return outbox.ErrRepairNotFound
		}
		if err != nil {
			return err
		}
		if state != "blocked" || !errorCode.Valid || errorCode.String != request.ExpectedErrorCode ||
			attempts != request.ExpectedAttemptCount || nextVersion != request.ExpectedVersion ||
			indexedVersion != nextVersion || eventID != request.EventID || indexedEventID != eventID ||
			indexedAggregateID != aggregateID || indexedEventType != eventType || claimOwner.Valid || leaseExpires.Valid {
			return outbox.ErrRepairStale
		}
		if schemaVersion != 1 && schemaVersion != 2 {
			return fmt.Errorf("%w: unsupported canonical outbox schema", ErrCorruptState)
		}
		if err := validateRepairStream(tenant, aggregateID, request.ExpectedVersion, eventID, eventType,
			rawEnvelope, rawEvent, eventHash, occurredAt); err != nil {
			return err
		}
		var earlierUnpublished, laterPublished int
		if err := tx.QueryRowContext(ctx, `SELECT
			(SELECT count(*) FROM keel_meta.outbox_delivery WHERE tenant_id=$1 AND aggregate_id=$2 AND aggregate_version<$3 AND delivery_state<>'published'),
			(SELECT count(*) FROM keel_meta.outbox_delivery WHERE tenant_id=$1 AND aggregate_id=$2 AND aggregate_version>$3 AND delivery_state='published')`,
			string(tenant), aggregateID, nextVersion).Scan(&earlierUnpublished, &laterPublished); err != nil {
			return err
		}
		if earlierUnpublished != 0 || laterPublished != 0 {
			return fmt.Errorf("%w: stream ordering invariant is not satisfied", ErrCorruptState)
		}
		if err := verifyStoredAggregateHistory(ctx, tx, tenant, aggregateID, nextVersion, eventID, eventType, occurredAt); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO keel_meta.outbox_repair_audit
			(request_id,tenant_id,aggregate_id,event_id,aggregate_version,actor_ref,reason_code,evidence_ref,prior_error_code,prior_attempt_count)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, identity.RequestID, string(tenant), aggregateID, eventID,
			nextVersion, identity.ActorRef, request.ReasonCode, request.EvidenceRef, errorCode.String, attempts); err != nil {
			return fmt.Errorf("record outbox repair audit: %w", err)
		}
		result, err := tx.ExecContext(ctx, `UPDATE keel_meta.outbox_delivery SET delivery_state='pending',next_attempt_at=clock_timestamp(),updated_at=clock_timestamp()
			WHERE tenant_id=$1 AND aggregate_id=$2 AND event_id=$3 AND aggregate_version=$4 AND delivery_state='blocked'
			AND last_error_code=$5 AND attempt_count=$6`, string(tenant), aggregateID, eventID, nextVersion, errorCode.String, attempts)
		if err != nil {
			return fmt.Errorf("requeue validated outbox event: %w", err)
		}
		rows, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if rows != 1 {
			return outbox.ErrRepairStale
		}
		return nil
	})
}

func verifyStoredAggregateHistory(ctx context.Context, tx *sql.Tx, tenant tenancy.TenantID, aggregateID string, targetVersion int64,
	targetEventID, targetEventType string, targetOccurredAt time.Time) error {
	if targetVersion < 1 || targetVersion > maxOutboxRepairHistory {
		return fmt.Errorf("%w: blocked event version exceeds the repair validation bound", ErrCorruptState)
	}
	rows, err := tx.QueryContext(ctx, `SELECT aggregate_version,event_id::text,event_type,event_data,event_hash,occurred_at
		FROM keel_meta.order_events WHERE tenant_id=$1 AND order_id=$2 ORDER BY aggregate_version`, string(tenant), aggregateID)
	if err != nil {
		return err
	}
	defer rows.Close()
	events := make([]orders.Event, 0, int(targetVersion))
	for rows.Next() {
		var version int64
		var eventID, eventType string
		var raw, storedHash []byte
		var occurredAt time.Time
		if err := rows.Scan(&version, &eventID, &eventType, &raw, &storedHash, &occurredAt); err != nil {
			return err
		}
		if version > maxOutboxRepairHistory {
			return fmt.Errorf("%w: immutable aggregate history exceeds the repair validation bound", ErrCorruptState)
		}
		var event orders.Event
		if err := json.Unmarshal(raw, &event); err != nil {
			return fmt.Errorf("%w: decode canonical event history", ErrCorruptState)
		}
		canonical, err := json.Marshal(event)
		if err != nil || !bytes.Equal(digest(canonical), storedHash) ||
			version < 1 || int64(event.Version) != version || event.Metadata.EventID != eventID ||
			event.Metadata.TenantID != string(tenant) || event.Metadata.OrderID != aggregateID ||
			string(event.Type) != eventType || !event.Metadata.OccurredAt.Equal(occurredAt) {
			return fmt.Errorf("%w: canonical event history integrity check failed", ErrCorruptState)
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if int64(len(events)) < targetVersion || events[targetVersion-1].Metadata.EventID != targetEventID ||
		string(events[targetVersion-1].Type) != targetEventType {
		return fmt.Errorf("%w: blocked event is not at its immutable stream version", ErrCorruptState)
	}
	if !events[targetVersion-1].Metadata.OccurredAt.Equal(targetOccurredAt) {
		return fmt.Errorf("%w: blocked event timestamp differs from immutable source", ErrCorruptState)
	}
	if _, err := orders.Replay(events); err != nil {
		return fmt.Errorf("%w: immutable event history cannot be replayed", ErrCorruptState)
	}
	return nil
}

func validateRepairStream(tenant tenancy.TenantID, aggregateID string, version int64,
	eventID, eventType string, rawEnvelope, rawEvent, eventHash []byte, occurredAt time.Time) error {
	var event orders.Event
	if err := json.Unmarshal(rawEvent, &event); err != nil {
		return fmt.Errorf("%w: decode blocked canonical event", ErrCorruptState)
	}
	canonical, err := json.Marshal(event)
	if err != nil || !bytes.Equal(digest(canonical), eventHash) || event.Metadata.EventID != eventID ||
		event.Metadata.TenantID != string(tenant) || event.Metadata.OrderID != aggregateID ||
		int64(event.Version) != version || string(event.Type) != eventType || !event.Metadata.OccurredAt.Equal(occurredAt) {
		return fmt.Errorf("%w: blocked source event does not match immutable event identity", ErrCorruptState)
	}
	schemaVersion := 1
	if event.Metadata.Traceparent != "" {
		if _, ok := tracecontext.Parse(event.Metadata.Traceparent); !ok {
			return fmt.Errorf("%w: protected event trace context is invalid", ErrCorruptState)
		}
		schemaVersion = 2
	}
	expectedBytes, err := json.Marshal(repairEnvelope{SchemaVersion: schemaVersion, EventID: eventID, TenantID: string(tenant),
		AggregateID: aggregateID, AggregateVersion: event.Version, EventType: event.Type, OccurredAt: event.Metadata.OccurredAt,
		Traceparent: event.Metadata.Traceparent})
	if err != nil {
		return err
	}
	var expected, actual repairEnvelope
	if err := json.Unmarshal(expectedBytes, &expected); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(rawEnvelope))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&actual); err != nil {
		return fmt.Errorf("%w: blocked safe envelope is invalid", ErrCorruptState)
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) || actual.SchemaVersion != expected.SchemaVersion ||
		actual.EventID != expected.EventID || actual.TenantID != expected.TenantID || actual.AggregateID != expected.AggregateID ||
		actual.AggregateVersion != expected.AggregateVersion || actual.EventType != expected.EventType || !actual.OccurredAt.Equal(expected.OccurredAt) ||
		actual.Traceparent != expected.Traceparent {
		return fmt.Errorf("%w: blocked safe envelope does not match canonical event", ErrCorruptState)
	}
	return nil
}
