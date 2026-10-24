package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/sanskarpan/keel/internal/delivery/webhook"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

const maxReplayCandidateLimit = 5000

// ReplayCandidateRecord is one replay candidate from the operator capability. It carries delivery
// metadata, state, replay flag, endpoint status and key reference only; no URL or payload.
type ReplayCandidateRecord struct {
	Delivery       webhook.Delivery
	State          webhook.DeliveryState
	Attempts       int
	Replayed       bool
	EndpointStatus webhook.EndpointStatus
	KeyID          string
}

// ReplayCandidates lists failed or exhausted deliveries for one trusted tenant. The store must be
// constructed over the operator capability's connection.
func (s *Store) ReplayCandidates(ctx context.Context, tenant tenancy.TenantID, limit int) ([]ReplayCandidateRecord, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("webhook replay store database is required")
	}
	if ctx == nil {
		return nil, errors.New("webhook replay context is required")
	}
	if err := validateReplayTenant(tenant); err != nil {
		return nil, err
	}
	if limit < 1 || limit > maxReplayCandidateLimit {
		return nil, webhook.ErrInvalidReplay
	}

	var candidates []ReplayCandidateRecord
	err := inTenantTx(ctx, s.db, tenant, func(ctx context.Context, tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx,
			`SELECT r_delivery_id,r_event_id,r_endpoint_id,r_subscription_version,
			        r_state,r_attempts,r_replayed,r_endpoint_status,r_key_id
			   FROM keel_meta.list_webhook_replay_candidates($1)`, limit)
		if err != nil {
			return fmt.Errorf("list webhook replay candidates: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var deliveryID, eventID, endpointID, state, endpointStatus, keyID string
			var subscription, attempts int64
			var replayed bool
			if err := rows.Scan(&deliveryID, &eventID, &endpointID, &subscription,
				&state, &attempts, &replayed, &endpointStatus, &keyID); err != nil {
				return fmt.Errorf("scan webhook replay candidate: %w", err)
			}
			if subscription < 1 || subscription > webhook.MaxSubscriptionVersion ||
				attempts < 1 || attempts > 100 {
				return webhook.ErrInvalidReplay
			}
			delivery := webhook.Delivery{ID: deliveryID, Identity: webhook.Identity{
				Tenant: tenant, EventID: eventID, EndpointID: endpointID,
				SubscriptionVersion: uint32(subscription),
			}}
			if err := delivery.Validate(); err != nil {
				return webhook.ErrInvalidReplay
			}
			record := ReplayCandidateRecord{
				Delivery: delivery, State: webhook.DeliveryState(state), Attempts: int(attempts),
				Replayed: replayed, EndpointStatus: webhook.EndpointStatus(endpointStatus), KeyID: keyID,
			}
			switch record.State {
			case webhook.StateFailed, webhook.StateExhausted:
			default:
				return webhook.ErrInvalidReplay
			}
			switch record.EndpointStatus {
			case webhook.EndpointActive, webhook.EndpointInactive, webhook.EndpointUnknown:
			default:
				return webhook.ErrInvalidReplay
			}
			if keyID != "" && (len(keyID) < 4 || len(keyID) > 64) {
				return webhook.ErrInvalidReplay
			}
			candidates = append(candidates, record)
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("iterate webhook replay candidates: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return candidates, nil
}
