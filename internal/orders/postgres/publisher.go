package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/sanskarpan/keel/internal/orders/outbox"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

var publishOwnerPattern = regexp.MustCompile(`^[A-Za-z0-9._~-]{1,128}$`)

const maxPublishLease = 2 * time.Minute

func (r *Repository) ClaimNext(ctx context.Context, tenantValue, owner string, lease time.Duration) (outbox.Claim, bool, error) {
	tenant, err := tenancy.ParseTenantID(tenantValue)
	if err != nil {
		return outbox.Claim{}, false, err
	}
	if !publishOwnerPattern.MatchString(owner) {
		return outbox.Claim{}, false, errors.New("publish worker ID is invalid")
	}
	if lease <= 0 || lease > maxPublishLease {
		return outbox.Claim{}, false, fmt.Errorf("publish lease must be in (0,%s]", maxPublishLease)
	}
	var claim outbox.Claim
	claimed := false
	err = tenancy.WithTenantTx(ctx, r.db, tenant, nil, func(tx *sql.Tx) error {
		var aggregateID, eventID, eventType string
		var version int64
		var attempts int
		err := tx.QueryRowContext(ctx, `SELECT h.aggregate_id::text,h.next_version,d.event_id::text,d.attempt_count,o.event_type
			FROM keel_meta.outbox_publish_heads AS h
			JOIN keel_meta.outbox_delivery AS d
			  ON d.tenant_id=h.tenant_id AND d.aggregate_id=h.aggregate_id AND d.aggregate_version=h.next_version
			JOIN keel_meta.event_outbox AS o
			  ON o.tenant_id=d.tenant_id AND o.event_id=d.event_id
			WHERE h.tenant_id=$1 AND d.delivery_state='pending'
			  AND d.next_attempt_at<=statement_timestamp()
			  AND (h.claim_owner IS NULL OR h.lease_expires_at<=statement_timestamp())
			ORDER BY d.next_attempt_at,h.aggregate_id
			FOR UPDATE OF h SKIP LOCKED LIMIT 1`, string(tenant)).Scan(&aggregateID, &version, &eventID, &attempts, &eventType)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		var epoch int64
		var expires time.Time
		if err := tx.QueryRowContext(ctx, `UPDATE keel_meta.outbox_publish_heads
			SET claim_owner=$1,lease_epoch=lease_epoch+1,lease_expires_at=clock_timestamp()+$2::interval,updated_at=clock_timestamp()
			WHERE tenant_id=$3 AND aggregate_id=$4 AND next_version=$5
			RETURNING lease_epoch,lease_expires_at`, owner, lease.String(), string(tenant), aggregateID, version).Scan(&epoch, &expires); err != nil {
			return err
		}
		claim = outbox.Claim{
			TenantID: string(tenant), AggregateID: aggregateID, EventID: eventID, EventType: eventType,
			Version: version, Owner: owner, Epoch: epoch, LeaseExpires: expires, AttemptCount: attempts,
		}
		claimed = true
		return nil
	})
	return claim, claimed, err
}

func (r *Repository) LoadClaimed(ctx context.Context, claim outbox.Claim) (outbox.Message, error) {
	tenant, err := tenancy.ParseTenantID(claim.TenantID)
	if err != nil {
		return outbox.Message{}, err
	}
	if !publishOwnerPattern.MatchString(claim.Owner) || claim.Epoch < 1 || claim.Version < 1 || claim.EventID == "" || claim.AggregateID == "" {
		return outbox.Message{}, outbox.ErrLeaseLost
	}
	var message outbox.Message
	err = tenancy.WithTenantTx(ctx, r.db, tenant, &sql.TxOptions{ReadOnly: true}, func(tx *sql.Tx) error {
		var raw []byte
		var eventType string
		var schemaVersion int
		err := tx.QueryRowContext(ctx, `SELECT o.safe_envelope,o.event_type,o.schema_version
			FROM keel_meta.outbox_publish_heads AS h
			JOIN keel_meta.outbox_delivery AS d ON d.tenant_id=h.tenant_id AND d.event_id=$2
			JOIN keel_meta.event_outbox AS o ON o.tenant_id=d.tenant_id AND o.event_id=d.event_id
			WHERE h.tenant_id=$1 AND h.aggregate_id=$3 AND h.next_version=$4
			  AND h.claim_owner=$5 AND h.lease_epoch=$6 AND h.lease_expires_at>clock_timestamp()
			  AND d.aggregate_id=h.aggregate_id AND d.aggregate_version=h.next_version AND d.delivery_state='pending'`,
			string(tenant), claim.EventID, claim.AggregateID, claim.Version, claim.Owner, claim.Epoch).Scan(&raw, &eventType, &schemaVersion)
		if errors.Is(err, sql.ErrNoRows) {
			return outbox.ErrLeaseLost
		}
		if err != nil {
			return err
		}
		envelope, _, err := decodeCanonicalEnvelope(string(tenant), raw)
		if err != nil {
			return fmt.Errorf("%w: %w: decode safe outbox envelope", ErrCorruptState, outbox.ErrPoisonEnvelope)
		}
		if envelope.SchemaVersion != schemaVersion || envelope.EventID != claim.EventID || envelope.TenantID != string(tenant) ||
			envelope.AggregateID != claim.AggregateID || envelope.AggregateVersion != claim.Version || string(envelope.EventType) != eventType ||
			eventType != claim.EventType || envelope.OccurredAt.IsZero() {
			return fmt.Errorf("%w: %w: safe outbox envelope identity mismatch", ErrCorruptState, outbox.ErrPoisonEnvelope)
		}
		message = outbox.Message{
			SchemaVersion: envelope.SchemaVersion, TenantID: envelope.TenantID, AggregateID: envelope.AggregateID,
			AggregateVersion: envelope.AggregateVersion, EventID: envelope.EventID, EventType: string(envelope.EventType), Traceparent: envelope.Traceparent,
			Payload: append([]byte(nil), raw...),
		}
		return nil
	})
	return message, err
}

// BlockPoison durably blocks an aggregate at a corrupt event version. It releases the lease
// but deliberately does not advance the head; an operator repair must preserve stream order.
func (r *Repository) BlockPoison(ctx context.Context, claim outbox.Claim) error {
	tenant, err := tenancy.ParseTenantID(claim.TenantID)
	if err != nil {
		return err
	}
	return tenancy.WithTenantTx(ctx, r.db, tenant, nil, func(tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx, `UPDATE keel_meta.outbox_publish_heads
			SET claim_owner=NULL,lease_expires_at=NULL,updated_at=clock_timestamp()
			WHERE tenant_id=$1 AND aggregate_id=$2 AND next_version=$3 AND claim_owner=$4 AND lease_epoch=$5
			  AND lease_expires_at>clock_timestamp()`, string(tenant), claim.AggregateID, claim.Version, claim.Owner, claim.Epoch)
		if err != nil {
			return err
		}
		rows, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if rows != 1 {
			return outbox.ErrLeaseLost
		}
		result, err = tx.ExecContext(ctx, `UPDATE keel_meta.outbox_delivery
			SET delivery_state='blocked',last_error_code='outbox_corrupt',updated_at=clock_timestamp()
			WHERE tenant_id=$1 AND event_id=$2 AND aggregate_id=$3 AND aggregate_version=$4 AND delivery_state='pending'`,
			string(tenant), claim.EventID, claim.AggregateID, claim.Version)
		if err != nil {
			return err
		}
		rows, err = result.RowsAffected()
		if err != nil {
			return err
		}
		if rows != 1 {
			return ErrCorruptState
		}
		return nil
	})
}

func (r *Repository) Acknowledge(ctx context.Context, claim outbox.Claim) error {
	tenant, err := tenancy.ParseTenantID(claim.TenantID)
	if err != nil {
		return err
	}
	return tenancy.WithTenantTx(ctx, r.db, tenant, nil, func(tx *sql.Tx) error {
		var nextVersion int64
		var owner sql.NullString
		err := tx.QueryRowContext(ctx, `SELECT next_version,claim_owner FROM keel_meta.outbox_publish_heads
			WHERE tenant_id=$1 AND aggregate_id=$2 FOR UPDATE`, string(tenant), claim.AggregateID).Scan(&nextVersion, &owner)
		if errors.Is(err, sql.ErrNoRows) {
			return outbox.ErrLeaseLost
		}
		if err != nil {
			return err
		}
		var state string
		if err := tx.QueryRowContext(ctx, `SELECT delivery_state FROM keel_meta.outbox_delivery
			WHERE tenant_id=$1 AND event_id=$2 AND aggregate_id=$3 AND aggregate_version=$4 FOR UPDATE`,
			string(tenant), claim.EventID, claim.AggregateID, claim.Version).Scan(&state); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return outbox.ErrLeaseLost
			}
			return err
		}
		if state == "published" {
			return nil
		}
		if !owner.Valid || owner.String != claim.Owner || nextVersion != claim.Version {
			return outbox.ErrLeaseLost
		}
		result, err := tx.ExecContext(ctx, `UPDATE keel_meta.outbox_publish_heads
			SET next_version=next_version+1,claim_owner=NULL,lease_expires_at=NULL,updated_at=clock_timestamp()
			WHERE tenant_id=$1 AND aggregate_id=$2 AND next_version=$3 AND claim_owner=$4 AND lease_epoch=$5
			  AND lease_expires_at>clock_timestamp()`, string(tenant), claim.AggregateID, claim.Version, claim.Owner, claim.Epoch)
		if err != nil {
			return err
		}
		rows, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if rows != 1 {
			return outbox.ErrLeaseLost
		}
		result, err = tx.ExecContext(ctx, `UPDATE keel_meta.outbox_delivery
			SET delivery_state='published',published_at=clock_timestamp(),last_error_code=NULL,updated_at=clock_timestamp()
			WHERE tenant_id=$1 AND event_id=$2 AND aggregate_id=$3 AND aggregate_version=$4 AND delivery_state='pending'`,
			string(tenant), claim.EventID, claim.AggregateID, claim.Version)
		if err != nil {
			return err
		}
		rows, err = result.RowsAffected()
		if err != nil {
			return err
		}
		if rows != 1 {
			return ErrCorruptState
		}
		return nil
	})
}

func (r *Repository) RecordFailure(ctx context.Context, claim outbox.Claim, code string, delay time.Duration) error {
	tenant, err := tenancy.ParseTenantID(claim.TenantID)
	if err != nil {
		return err
	}
	switch code {
	case "broker_timeout", "broker_unavailable", "broker_rejected", "broker_error":
	default:
		return errors.New("broker error code is not allowlisted")
	}
	if delay < 0 || delay > 5*time.Minute {
		return errors.New("outbox retry delay must be between zero and five minutes")
	}
	return tenancy.WithTenantTx(ctx, r.db, tenant, nil, func(tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx, `UPDATE keel_meta.outbox_publish_heads
			SET claim_owner=NULL,lease_expires_at=NULL,updated_at=clock_timestamp()
			WHERE tenant_id=$1 AND aggregate_id=$2 AND next_version=$3 AND claim_owner=$4 AND lease_epoch=$5
			  AND lease_expires_at>clock_timestamp()`, string(tenant), claim.AggregateID, claim.Version, claim.Owner, claim.Epoch)
		if err != nil {
			return err
		}
		rows, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if rows != 1 {
			return outbox.ErrLeaseLost
		}
		result, err = tx.ExecContext(ctx, `UPDATE keel_meta.outbox_delivery
			SET attempt_count=attempt_count+1,next_attempt_at=clock_timestamp()+$1::double precision * interval '1 second',last_error_code=$2,updated_at=clock_timestamp()
			WHERE tenant_id=$3 AND event_id=$4 AND aggregate_id=$5 AND aggregate_version=$6 AND delivery_state='pending'`,
			delay.Seconds(), code, string(tenant), claim.EventID, claim.AggregateID, claim.Version)
		if err != nil {
			return err
		}
		rows, err = result.RowsAffected()
		if err != nil {
			return err
		}
		if rows != 1 {
			return ErrCorruptState
		}
		return nil
	})
}
