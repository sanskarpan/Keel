package postgres

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"time"

	"github.com/sanskarpan/keel/internal/orders"
	"github.com/sanskarpan/keel/internal/orders/projector"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

const (
	maxReplayAttempts = 10
	maxReplayChain    = 100
)

var topicNamePattern = regexp.MustCompile(`^keel\.[a-z0-9-]+\.orders\.v1$`)

// Apply atomically validates a broker envelope against immutable PostgreSQL outbox history,
// records the inbox identity and applies or defers the minimal order-status projection.
func (r *Repository) Apply(ctx context.Context, consumerID string, envelope projector.Envelope, envelopeHash [32]byte) (result projector.Result, err error) {
	if !validConsumerID(consumerID) {
		return projector.Result{}, errors.New("projector consumer ID is invalid")
	}
	tenant, err := tenancy.ParseTenantID(envelope.TenantID)
	if err != nil {
		return projector.Result{}, err
	}
	err = tenancy.WithTenantTx(ctx, r.db, tenant, nil, func(tx *sql.Tx) error {
		canonical, canonicalHash, found, err := loadOutboxByIdentity(ctx, tx, envelope.TenantID, envelope.EventID, envelope.AggregateID, envelope.AggregateVersion)
		if err != nil {
			if found && errors.Is(err, ErrCorruptState) {
				if err := blockCorruptCanonicalEvent(ctx, tx, string(tenant), consumerID, envelope, envelopeHash); err != nil {
					return err
				}
				result = projector.Result{Disposition: projector.Quarantined, ReasonCode: "source_event_invalid"}
				return nil
			}
			return err
		}
		if !found {
			result = projector.Result{Disposition: projector.Quarantined, ReasonCode: "source_not_found"}
			return nil
		}
		if canonical != envelope || canonicalHash != envelopeHash {
			if err := insertQuarantine(ctx, tx, envelope, envelopeHash, consumerID, "source_mismatch"); err != nil {
				return err
			}
			result = projector.Result{Disposition: projector.Quarantined, ReasonCode: "source_mismatch"}
			return nil
		}

		if _, err := tx.ExecContext(ctx, `INSERT INTO keel_meta.order_projections (tenant_id,aggregate_id,applied_version,status)
			VALUES ($1,$2,0,NULL) ON CONFLICT (tenant_id,aggregate_id) DO NOTHING`, string(tenant), envelope.AggregateID); err != nil {
			return err
		}
		version, status, err := lockProjection(ctx, tx, string(tenant), envelope.AggregateID)
		if err != nil {
			return err
		}

		inserted, err := insertInbox(ctx, tx, consumerID, envelope, envelopeHash, "broker", "deferred")
		if err != nil {
			return err
		}
		if !inserted {
			duplicate, reason, err := inspectInboxConflict(ctx, tx, consumerID, envelope, envelopeHash)
			if err != nil {
				return err
			}
			if duplicate != "" {
				result = projector.Result{Disposition: projector.Disposition(duplicate)}
				return nil
			}
			if reason == "" {
				reason = "version_conflict"
			}
			if err := insertQuarantine(ctx, tx, envelope, envelopeHash, consumerID, reason); err != nil {
				return err
			}
			result = projector.Result{Disposition: projector.Quarantined, ReasonCode: reason}
			return nil
		}

		if envelope.AggregateVersion <= version {
			if err := markInboxQuarantined(ctx, tx, string(tenant), consumerID, envelope.EventID); err != nil {
				return err
			}
			if err := insertQuarantine(ctx, tx, envelope, envelopeHash, consumerID, "version_conflict"); err != nil {
				return err
			}
			result = projector.Result{Disposition: projector.Quarantined, ReasonCode: "version_conflict"}
			return nil
		}
		if envelope.AggregateVersion > version+1 {
			if err := deferInbox(ctx, tx, string(tenant), consumerID, envelope, version+1); err != nil {
				return err
			}
			result = projector.Result{Disposition: projector.Deferred}
			return nil
		}

		updated, nextStatus, reason := applyStatusTransition(status, envelope.EventType)
		if !updated {
			if err := markInboxQuarantined(ctx, tx, string(tenant), consumerID, envelope.EventID); err != nil {
				return err
			}
			if err := insertQuarantine(ctx, tx, envelope, envelopeHash, consumerID, "invalid_transition"); err != nil {
				return err
			}
			result = projector.Result{Disposition: projector.Quarantined, ReasonCode: reason}
			return nil
		}
		if err := advanceProjection(ctx, tx, string(tenant), envelope.AggregateID, envelope.AggregateVersion, nextStatus); err != nil {
			return err
		}
		if err := markInboxApplied(ctx, tx, string(tenant), consumerID, envelope.EventID); err != nil {
			return err
		}
		result = projector.Result{Disposition: projector.Applied, Applied: 1}
		more, err := drainDeferred(ctx, tx, string(tenant), consumerID, envelope.AggregateID, envelope.AggregateVersion, nextStatus)
		if err != nil {
			return err
		}
		result.Applied += more
		return nil
	})
	return result, err
}

// ReplayGaps reads missing canonical versions from the retained outbox and applies a bounded
// number of contiguous events per tenant transaction. It never trusts the deferred wire bytes.
func (r *Repository) ReplayGaps(ctx context.Context, tenantValue, consumerID string, limit int) (int, error) {
	tenant, err := tenancy.ParseTenantID(tenantValue)
	if err != nil {
		return 0, err
	}
	if !validConsumerID(consumerID) || limit < 1 || limit > 500 {
		return 0, errors.New("projector replay request is invalid")
	}
	applied := 0
	err = tenancy.WithTenantTx(ctx, r.db, tenant, nil, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT p.aggregate_id::text,d.aggregate_version,d.event_id::text
			FROM keel_meta.order_projections AS p
			CROSS JOIN LATERAL (
				SELECT candidate.aggregate_version,candidate.event_id,candidate.next_attempt_at
				FROM keel_meta.deferred_events AS candidate
				WHERE candidate.tenant_id=p.tenant_id AND candidate.consumer_id=$2 AND candidate.aggregate_id=p.aggregate_id
				  AND candidate.state='pending' AND candidate.next_attempt_at<=clock_timestamp()
				ORDER BY candidate.aggregate_version,candidate.next_attempt_at LIMIT 1
			) AS d
		WHERE p.tenant_id=$1
		ORDER BY d.next_attempt_at,p.aggregate_id
		LIMIT $3 FOR UPDATE OF p SKIP LOCKED`, string(tenant), consumerID, limit)
		if err != nil {
			return err
		}
		type gap struct {
			aggregateID string
			version     int64
			eventID     string
		}
		gaps := make([]gap, 0, limit)
		for rows.Next() {
			var item gap
			if err := rows.Scan(&item.aggregateID, &item.version, &item.eventID); err != nil {
				rows.Close()
				return err
			}
			gaps = append(gaps, item)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
		remaining := limit
		for _, item := range gaps {
			if remaining == 0 {
				break
			}
			chainLimit := min(maxReplayChain, remaining)
			count, err := replayOneGap(ctx, tx, string(tenant), consumerID, item.aggregateID, item.version, item.eventID, chainLimit)
			if err != nil {
				return err
			}
			applied += count
			remaining -= count
		}
		return nil
	})
	return applied, err
}

// QuarantineTransport persists only Kafka coordinates, a payload digest and a bounded reason.
// The projector can inspect only stored transport coordinates/hash/reason for idempotent retries.
func (r *Repository) QuarantineTransport(ctx context.Context, topic string, partition int, offset int64, payloadHash [32]byte, reason string) error {
	if !topicNamePattern.MatchString(topic) || partition < 0 || offset < 0 {
		return errors.New("transport quarantine coordinates are invalid")
	}
	if reason != "invalid_record" && reason != "unsupported_schema" && reason != "source_mismatch" {
		return errors.New("transport quarantine reason is not allowlisted")
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, `INSERT INTO keel_meta.transport_quarantine
			(source_topic,partition_id,message_offset,payload_hash,reason_code)
			VALUES ($1,$2,$3,$4,$5) ON CONFLICT (source_topic,partition_id,message_offset) DO NOTHING`,
		topic, partition, offset, payloadHash[:], reason)
	if err != nil {
		return err
	}
	if affected, err := result.RowsAffected(); err != nil {
		return err
	} else if affected == 0 {
		var storedHash []byte
		var storedReason string
		if err := tx.QueryRowContext(ctx, `SELECT payload_hash,reason_code FROM keel_meta.transport_quarantine
			WHERE source_topic=$1 AND partition_id=$2 AND message_offset=$3`, topic, partition, offset).
			Scan(&storedHash, &storedReason); err != nil {
			return err
		}
		if !bytes.Equal(storedHash, payloadHash[:]) || storedReason != reason {
			return errors.New("transport quarantine coordinate conflicts with stored digest or reason")
		}
	}
	return tx.Commit()
}

func loadOutboxByIdentity(ctx context.Context, tx *sql.Tx, tenantID, eventID, aggregateID string, version int64) (projector.Envelope, [32]byte, bool, error) {
	var raw []byte
	var eventType string
	var schemaVersion int
	err := tx.QueryRowContext(ctx, `SELECT safe_envelope,event_type,schema_version FROM keel_meta.event_outbox
		WHERE tenant_id=$1 AND event_id=$2 AND aggregate_id=$3 AND aggregate_version=$4`, tenantID, eventID, aggregateID, version).
		Scan(&raw, &eventType, &schemaVersion)
	if errors.Is(err, sql.ErrNoRows) {
		return projector.Envelope{}, [32]byte{}, false, nil
	}
	if err != nil {
		return projector.Envelope{}, [32]byte{}, false, err
	}
	envelope, digest, err := decodeCanonicalEnvelope(tenantID, raw)
	if err != nil || string(envelope.EventType) != eventType || envelope.SchemaVersion != schemaVersion {
		return envelope, digest, true, fmt.Errorf("%w: canonical outbox envelope is corrupt", ErrCorruptState)
	}
	return envelope, digest, true, nil
}

func decodeCanonicalEnvelope(tenantID string, raw []byte) (projector.Envelope, [32]byte, error) {
	var envelope projector.Envelope
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return projector.Envelope{}, [32]byte{}, err
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return projector.Envelope{}, [32]byte{}, errors.New("canonical envelope has trailing JSON")
	}
	canonical, err := json.Marshal(envelope)
	if err != nil {
		return projector.Envelope{}, [32]byte{}, err
	}
	record := projector.Record{
		Topic: "keel.internal.orders.v1", Partition: 0, Offset: 0,
		Key: []byte(envelope.TenantID + "/" + envelope.AggregateID), Value: canonical,
		Headers: append([]projector.Header{
			{Key: "event_id", Value: []byte(envelope.EventID)},
			{Key: "schema_version", Value: []byte(fmt.Sprint(envelope.SchemaVersion))},
			{Key: "aggregate_version", Value: []byte(fmt.Sprint(envelope.AggregateVersion))},
		}, func() []projector.Header {
			if envelope.Traceparent == "" {
				return nil
			}
			return []projector.Header{{Key: "traceparent", Value: []byte(envelope.Traceparent)}}
		}()...),
	}
	validated, hash, err := projector.Decode(tenantID, record)
	return validated, hash, err
}

func insertInbox(ctx context.Context, tx *sql.Tx, consumerID string, e projector.Envelope, digest [32]byte, source, state string) (bool, error) {
	result, err := tx.ExecContext(ctx, `INSERT INTO keel_meta.event_inbox
		(tenant_id,consumer_id,event_id,aggregate_id,aggregate_version,event_type,envelope_hash,delivery_source,apply_state,applied_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,CASE WHEN $9='applied' THEN clock_timestamp() ELSE NULL END)
		ON CONFLICT DO NOTHING`, e.TenantID, consumerID, e.EventID, e.AggregateID, e.AggregateVersion, string(e.EventType), digest[:], source, state)
	if err != nil {
		return false, err
	}
	rows, err := result.RowsAffected()
	return rows == 1, err
}

func inspectInboxConflict(ctx context.Context, tx *sql.Tx, consumerID string, e projector.Envelope, digest [32]byte) (string, string, error) {
	var aggregateID, eventType, state string
	var version int64
	var storedHash []byte
	err := tx.QueryRowContext(ctx, `SELECT aggregate_id::text,aggregate_version,event_type,envelope_hash,apply_state
		FROM keel_meta.event_inbox WHERE tenant_id=$1 AND consumer_id=$2 AND event_id=$3`, e.TenantID, consumerID, e.EventID).
		Scan(&aggregateID, &version, &eventType, &storedHash, &state)
	if err == nil {
		if aggregateID != e.AggregateID || version != e.AggregateVersion || eventType != string(e.EventType) || !bytes.Equal(storedHash, digest[:]) {
			return "", "event_id_conflict", nil
		}
		switch state {
		case "applied":
			return string(projector.Duplicate), "", nil
		case "deferred":
			return string(projector.Deferred), "", nil
		case "quarantined":
			return string(projector.Quarantined), "", nil
		}
		return "", "event_id_conflict", nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", "", err
	}
	err = tx.QueryRowContext(ctx, `SELECT event_id::text FROM keel_meta.event_inbox
		WHERE tenant_id=$1 AND consumer_id=$2 AND aggregate_id=$3 AND aggregate_version=$4`,
		e.TenantID, consumerID, e.AggregateID, e.AggregateVersion).Scan(new(string))
	if errors.Is(err, sql.ErrNoRows) {
		return "", "version_conflict", nil
	}
	if err != nil {
		return "", "", err
	}
	return "", "version_conflict", nil
}

func insertQuarantine(ctx context.Context, tx *sql.Tx, e projector.Envelope, digest [32]byte, consumerID, reason string) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO keel_meta.event_quarantine
		(tenant_id,consumer_id,event_id,aggregate_id,aggregate_version,envelope_hash,reason_code)
		VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING`,
		e.TenantID, consumerID, e.EventID, e.AggregateID, e.AggregateVersion, digest[:], reason)
	return err
}

func blockCorruptCanonicalEvent(ctx context.Context, tx *sql.Tx, tenantID, consumerID string, e projector.Envelope, digest [32]byte) error {
	if _, err := tx.ExecContext(ctx, `INSERT INTO keel_meta.order_projections (tenant_id,aggregate_id,applied_version,status)
		VALUES ($1,$2,0,NULL) ON CONFLICT (tenant_id,aggregate_id) DO NOTHING`, tenantID, e.AggregateID); err != nil {
		return err
	}
	if _, _, err := lockProjection(ctx, tx, tenantID, e.AggregateID); err != nil {
		return err
	}
	inserted, err := insertInbox(ctx, tx, consumerID, e, digest, "broker", "deferred")
	if err != nil {
		return err
	}
	if !inserted {
		duplicate, reason, err := inspectInboxConflict(ctx, tx, consumerID, e, digest)
		if err != nil {
			return err
		}
		if duplicate == "" && reason != "" {
			return insertQuarantine(ctx, tx, e, digest, consumerID, reason)
		}
	}
	if err := markInboxQuarantined(ctx, tx, tenantID, consumerID, e.EventID); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO keel_meta.deferred_events
		(tenant_id,consumer_id,aggregate_id,aggregate_version,event_id,expected_version,state,last_error_code)
		VALUES ($1,$2,$3,$4,$5,$4,'blocked','source_event_invalid')
		ON CONFLICT (tenant_id,consumer_id,aggregate_id,aggregate_version) DO UPDATE
		SET state='blocked',last_error_code='source_event_invalid',updated_at=clock_timestamp()
		WHERE keel_meta.deferred_events.event_id=EXCLUDED.event_id`, tenantID, consumerID, e.AggregateID, e.AggregateVersion, e.EventID)
	if err != nil {
		return err
	}
	if affected, err := result.RowsAffected(); err != nil {
		return err
	} else if affected != 1 {
		return fmt.Errorf("%w: corrupt canonical event conflicts with existing deferred identity", ErrCorruptState)
	}
	return insertQuarantine(ctx, tx, e, digest, consumerID, "source_event_invalid")
}

func lockProjection(ctx context.Context, tx *sql.Tx, tenantID, aggregateID string) (int64, *orders.Status, error) {
	var version int64
	var rawStatus sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT applied_version,status FROM keel_meta.order_projections
		WHERE tenant_id=$1 AND aggregate_id=$2 FOR UPDATE`, tenantID, aggregateID).Scan(&version, &rawStatus); err != nil {
		return 0, nil, err
	}
	if !rawStatus.Valid {
		return version, nil, nil
	}
	status := orders.Status(rawStatus.String)
	return version, &status, nil
}

func applyStatusTransition(previous *orders.Status, eventType orders.EventType) (bool, orders.Status, string) {
	status, err := projector.NextStatus(previous, eventType)
	if err != nil {
		return false, "", "invalid_transition"
	}
	return true, status, ""
}

func advanceProjection(ctx context.Context, tx *sql.Tx, tenantID, aggregateID string, version int64, status orders.Status) error {
	result, err := tx.ExecContext(ctx, `UPDATE keel_meta.order_projections
		SET applied_version=$1,status=$2,updated_at=clock_timestamp()
		WHERE tenant_id=$3 AND aggregate_id=$4 AND applied_version=$1-1`, version, string(status), tenantID, aggregateID)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return fmt.Errorf("%w: projection head changed while locked", ErrCorruptState)
	}
	return nil
}

func markInboxApplied(ctx context.Context, tx *sql.Tx, tenantID, consumerID, eventID string) error {
	_, err := tx.ExecContext(ctx, `UPDATE keel_meta.event_inbox SET apply_state='applied',applied_at=clock_timestamp()
		WHERE tenant_id=$1 AND consumer_id=$2 AND event_id=$3 AND apply_state IN ('deferred','applied')`, tenantID, consumerID, eventID)
	return err
}

func markInboxQuarantined(ctx context.Context, tx *sql.Tx, tenantID, consumerID, eventID string) error {
	_, err := tx.ExecContext(ctx, `UPDATE keel_meta.event_inbox SET apply_state='quarantined',applied_at=NULL
		WHERE tenant_id=$1 AND consumer_id=$2 AND event_id=$3 AND apply_state<>'applied'`, tenantID, consumerID, eventID)
	return err
}

func deferInbox(ctx context.Context, tx *sql.Tx, tenantID, consumerID string, e projector.Envelope, expected int64) error {
	if _, err := tx.ExecContext(ctx, `UPDATE keel_meta.event_inbox SET apply_state='deferred',applied_at=NULL
		WHERE tenant_id=$1 AND consumer_id=$2 AND event_id=$3`, tenantID, consumerID, e.EventID); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO keel_meta.deferred_events
		(tenant_id,consumer_id,aggregate_id,aggregate_version,event_id,expected_version)
		VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (tenant_id,consumer_id,aggregate_id,aggregate_version)
		DO UPDATE SET expected_version=EXCLUDED.expected_version,next_attempt_at=LEAST(keel_meta.deferred_events.next_attempt_at,clock_timestamp()),updated_at=clock_timestamp()`,
		tenantID, consumerID, e.AggregateID, e.AggregateVersion, e.EventID, expected)
	return err
}

func drainDeferred(ctx context.Context, tx *sql.Tx, tenantID, consumerID, aggregateID string, version int64, status orders.Status) (int, error) {
	applied := 0
	for applied < maxReplayChain {
		var eventID, eventType string
		var nextVersion int64
		var storedHash []byte
		err := tx.QueryRowContext(ctx, `SELECT i.event_id::text,i.event_type,i.aggregate_version,i.envelope_hash
			FROM keel_meta.deferred_events AS d JOIN keel_meta.event_inbox AS i
			ON i.tenant_id=d.tenant_id AND i.consumer_id=d.consumer_id AND i.event_id=d.event_id
			WHERE d.tenant_id=$1 AND d.consumer_id=$2 AND d.aggregate_id=$3 AND d.aggregate_version=$4 AND d.state='pending'
			FOR UPDATE OF d`, tenantID, consumerID, aggregateID, version+1).
			Scan(&eventID, &eventType, &nextVersion, &storedHash)
		if errors.Is(err, sql.ErrNoRows) {
			return applied, nil
		}
		if err != nil {
			return applied, err
		}
		envelope, digest, found, err := loadOutboxByIdentity(ctx, tx, tenantID, eventID, aggregateID, nextVersion)
		if err != nil {
			return applied, err
		}
		if !found || !bytes.Equal(storedHash, digest[:]) || eventType != string(envelope.EventType) {
			if err := blockDeferred(ctx, tx, tenantID, consumerID, aggregateID, nextVersion, eventID, storedHash, "source_event_invalid"); err != nil {
				return applied, err
			}
			return applied, nil
		}
		ok, nextStatus, _ := applyStatusTransition(&status, envelope.EventType)
		if !ok {
			if err := blockDeferred(ctx, tx, tenantID, consumerID, aggregateID, nextVersion, eventID, storedHash, "source_event_invalid"); err != nil {
				return applied, err
			}
			return applied, nil
		}
		if err := advanceProjection(ctx, tx, tenantID, aggregateID, nextVersion, nextStatus); err != nil {
			return applied, err
		}
		if err := markInboxApplied(ctx, tx, tenantID, consumerID, eventID); err != nil {
			return applied, err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM keel_meta.deferred_events
			WHERE tenant_id=$1 AND consumer_id=$2 AND aggregate_id=$3 AND aggregate_version=$4`, tenantID, consumerID, aggregateID, nextVersion); err != nil {
			return applied, err
		}
		version, status = nextVersion, nextStatus
		applied++
	}
	return applied, nil
}

func replayOneGap(ctx context.Context, tx *sql.Tx, tenantID, consumerID, aggregateID string, deferredVersion int64, deferredEventID string, maxEvents int) (int, error) {
	version, status, err := lockProjection(ctx, tx, tenantID, aggregateID)
	if err != nil {
		return 0, err
	}
	var lockedEventID string
	if err := tx.QueryRowContext(ctx, `SELECT event_id::text FROM keel_meta.deferred_events
		WHERE tenant_id=$1 AND consumer_id=$2 AND aggregate_id=$3 AND aggregate_version=$4 AND state='pending' FOR UPDATE`,
		tenantID, consumerID, aggregateID, deferredVersion).Scan(&lockedEventID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, nil
		}
		return 0, err
	}
	if lockedEventID != deferredEventID {
		return 0, fmt.Errorf("%w: deferred event identity changed", ErrCorruptState)
	}
	applied := 0
	for version < deferredVersion && applied < maxEvents {
		nextVersion := version + 1
		envelope, digest, found, err := loadOutboxByVersion(ctx, tx, tenantID, aggregateID, nextVersion)
		if err != nil {
			if errors.Is(err, ErrCorruptState) {
				if err := recordInvalidSource(ctx, tx, tenantID, consumerID, aggregateID, deferredVersion, deferredEventID, digest); err != nil {
					return applied, err
				}
				return applied, nil
			}
			return applied, err
		}
		if !found {
			if err := recordMissingSource(ctx, tx, tenantID, consumerID, aggregateID, deferredVersion, deferredEventID, nextVersion); err != nil {
				return applied, err
			}
			return applied, nil
		}
		if nextVersion == deferredVersion && envelope.EventID != deferredEventID {
			if err := recordInvalidSource(ctx, tx, tenantID, consumerID, aggregateID, deferredVersion, deferredEventID, digest); err != nil {
				return applied, err
			}
			return applied, nil
		}
		var source string
		if err := ensureReplayInbox(ctx, tx, consumerID, envelope, digest, &source); err != nil {
			return applied, err
		}
		if source == "conflict" {
			if err := recordInvalidSource(ctx, tx, tenantID, consumerID, aggregateID, deferredVersion, deferredEventID, digest); err != nil {
				return applied, err
			}
			return applied, nil
		}
		ok, nextStatus, _ := applyStatusTransition(status, envelope.EventType)
		if !ok {
			if err := recordInvalidSource(ctx, tx, tenantID, consumerID, aggregateID, deferredVersion, deferredEventID, digest); err != nil {
				return applied, err
			}
			return applied, nil
		}
		if err := advanceProjection(ctx, tx, tenantID, aggregateID, nextVersion, nextStatus); err != nil {
			return applied, err
		}
		if err := markInboxApplied(ctx, tx, tenantID, consumerID, envelope.EventID); err != nil {
			return applied, err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM keel_meta.deferred_events
			WHERE tenant_id=$1 AND consumer_id=$2 AND aggregate_id=$3 AND aggregate_version=$4`, tenantID, consumerID, aggregateID, nextVersion); err != nil {
			return applied, err
		}
		version, status = nextVersion, &nextStatus
		applied++
	}
	return applied, nil
}

func ensureReplayInbox(ctx context.Context, tx *sql.Tx, consumerID string, e projector.Envelope, digest [32]byte, result *string) error {
	inserted, err := insertInbox(ctx, tx, consumerID, e, digest, "replay", "deferred")
	if err != nil {
		return err
	}
	if inserted {
		*result = "inserted"
		return nil
	}
	var storedHash []byte
	var state string
	err = tx.QueryRowContext(ctx, `SELECT envelope_hash,apply_state FROM keel_meta.event_inbox
		WHERE tenant_id=$1 AND consumer_id=$2 AND event_id=$3`, e.TenantID, consumerID, e.EventID).Scan(&storedHash, &state)
	if errors.Is(err, sql.ErrNoRows) || err == nil && !bytes.Equal(storedHash, digest[:]) {
		*result = "conflict"
		return nil
	}
	if err != nil {
		return err
	}
	if state == "quarantined" {
		*result = "conflict"
		return nil
	}
	*result = state
	return nil
}

func loadOutboxByVersion(ctx context.Context, tx *sql.Tx, tenantID, aggregateID string, version int64) (projector.Envelope, [32]byte, bool, error) {
	var eventID string
	err := tx.QueryRowContext(ctx, `SELECT event_id::text FROM keel_meta.event_outbox
		WHERE tenant_id=$1 AND aggregate_id=$2 AND aggregate_version=$3`, tenantID, aggregateID, version).Scan(&eventID)
	if errors.Is(err, sql.ErrNoRows) {
		return projector.Envelope{}, [32]byte{}, false, nil
	}
	if err != nil {
		return projector.Envelope{}, [32]byte{}, false, err
	}
	return loadOutboxByIdentity(ctx, tx, tenantID, eventID, aggregateID, version)
}

func recordMissingSource(ctx context.Context, tx *sql.Tx, tenantID, consumerID, aggregateID string, deferredVersion int64, deferredEventID string, missingVersion int64) error {
	var retries int
	if err := tx.QueryRowContext(ctx, `SELECT retry_count FROM keel_meta.deferred_events
		WHERE tenant_id=$1 AND consumer_id=$2 AND aggregate_id=$3 AND aggregate_version=$4 FOR UPDATE`,
		tenantID, consumerID, aggregateID, deferredVersion).Scan(&retries); err != nil {
		return err
	}
	retries++
	if retries >= maxReplayAttempts {
		var rawHash []byte
		if err := tx.QueryRowContext(ctx, `SELECT envelope_hash FROM keel_meta.event_inbox
			WHERE tenant_id=$1 AND consumer_id=$2 AND event_id=$3`, tenantID, consumerID, deferredEventID).Scan(&rawHash); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE keel_meta.deferred_events SET retry_count=$1,state='blocked',last_error_code='source_event_missing',updated_at=clock_timestamp()
			WHERE tenant_id=$2 AND consumer_id=$3 AND aggregate_id=$4 AND aggregate_version=$5`, retries, tenantID, consumerID, aggregateID, deferredVersion); err != nil {
			return err
		}
		var envelope projector.Envelope
		if err := tx.QueryRowContext(ctx, `SELECT event_id::text,aggregate_id::text,aggregate_version,event_type
			FROM keel_meta.event_inbox WHERE tenant_id=$1 AND consumer_id=$2 AND event_id=$3`, tenantID, consumerID, deferredEventID).
			Scan(&envelope.EventID, &envelope.AggregateID, &envelope.AggregateVersion, &envelope.EventType); err != nil {
			return err
		}
		if err := markInboxQuarantined(ctx, tx, tenantID, consumerID, deferredEventID); err != nil {
			return err
		}
		return insertQuarantine(ctx, tx, envelope, toDigest(rawHash), consumerID, "source_event_missing")
	}
	delay := retryDelay(retries)
	_, err := tx.ExecContext(ctx, `UPDATE keel_meta.deferred_events SET retry_count=$1,expected_version=$2,
		next_attempt_at=clock_timestamp()+$3::interval,last_error_code='source_event_missing',updated_at=clock_timestamp()
		WHERE tenant_id=$4 AND consumer_id=$5 AND aggregate_id=$6 AND aggregate_version=$7`,
		retries, missingVersion, delay.String(), tenantID, consumerID, aggregateID, deferredVersion)
	return err
}

func recordInvalidSource(ctx context.Context, tx *sql.Tx, tenantID, consumerID, aggregateID string, deferredVersion int64, deferredEventID string, sourceHash [32]byte) error {
	if _, err := tx.ExecContext(ctx, `UPDATE keel_meta.deferred_events SET state='blocked',last_error_code='source_event_invalid',updated_at=clock_timestamp()
		WHERE tenant_id=$1 AND consumer_id=$2 AND aggregate_id=$3 AND aggregate_version=$4`, tenantID, consumerID, aggregateID, deferredVersion); err != nil {
		return err
	}
	var event projector.Envelope
	var inboxHash []byte
	if err := tx.QueryRowContext(ctx, `SELECT event_id::text,aggregate_id::text,aggregate_version,event_type,envelope_hash
		FROM keel_meta.event_inbox WHERE tenant_id=$1 AND consumer_id=$2 AND event_id=$3`, tenantID, consumerID, deferredEventID).
		Scan(&event.EventID, &event.AggregateID, &event.AggregateVersion, &event.EventType, &inboxHash); err != nil {
		return err
	}
	if err := markInboxQuarantined(ctx, tx, tenantID, consumerID, deferredEventID); err != nil {
		return err
	}
	if err := insertQuarantine(ctx, tx, event, toDigest(inboxHash), consumerID, "source_event_invalid"); err != nil {
		return err
	}
	_ = sourceHash
	return nil
}

func blockDeferred(ctx context.Context, tx *sql.Tx, tenantID, consumerID, aggregateID string, version int64, eventID string, digestBytes []byte, reason string) error {
	if reason != "source_event_missing" && reason != "source_event_invalid" {
		return errors.New("deferred block reason is invalid")
	}
	if _, err := tx.ExecContext(ctx, `UPDATE keel_meta.deferred_events SET state='blocked',last_error_code=$1,updated_at=clock_timestamp()
		WHERE tenant_id=$2 AND consumer_id=$3 AND aggregate_id=$4 AND aggregate_version=$5`, reason, tenantID, consumerID, aggregateID, version); err != nil {
		return err
	}
	var envelope projector.Envelope
	if err := tx.QueryRowContext(ctx, `SELECT event_id::text,aggregate_id::text,aggregate_version,event_type
		FROM keel_meta.event_inbox WHERE tenant_id=$1 AND consumer_id=$2 AND event_id=$3`, tenantID, consumerID, eventID).
		Scan(&envelope.EventID, &envelope.AggregateID, &envelope.AggregateVersion, &envelope.EventType); err != nil {
		return err
	}
	if err := markInboxQuarantined(ctx, tx, tenantID, consumerID, eventID); err != nil {
		return err
	}
	return insertQuarantine(ctx, tx, envelope, toDigest(digestBytes), consumerID, reason)
}

func retryDelay(attempt int) time.Duration {
	delay := time.Second
	for index := 1; index < attempt && delay < 15*time.Minute; index++ {
		delay *= 2
	}
	if delay > 15*time.Minute {
		return 15 * time.Minute
	}
	return delay
}

func validConsumerID(value string) bool { return value == projector.DefaultConsumerID }

func toDigest(raw []byte) [32]byte {
	var digest [32]byte
	copy(digest[:], raw)
	return digest
}
