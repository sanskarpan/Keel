package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/sanskarpan/keel/internal/delivery/webhook"
)

// AuthorizeReplay records or reuses one operator replay request, writes the immutable transition
// audit row and returns the delivery to pending without granting a fresh retry budget. It requires
// the operator capability and an authorized tenant context; the database derives the tenant and
// validates the current state and endpoint revision atomically.
func (s *Store) AuthorizeReplay(ctx context.Context, request webhook.ReplayRequest) (webhook.ReplayAuthorization, error) {
	if s == nil || s.db == nil {
		return webhook.ReplayAuthorization{}, errors.New("webhook replay store database is required")
	}
	if ctx == nil {
		return webhook.ReplayAuthorization{}, errors.New("webhook replay context is required")
	}
	if err := request.Validate(); err != nil {
		return webhook.ReplayAuthorization{}, err
	}

	var authorization webhook.ReplayAuthorization
	err := inTenantTx(ctx, s.db, request.Tenant, func(ctx context.Context, tx *sql.Tx) error {
		var priorState string
		var requestedAt, priorFinishedAt, authorizedAt time.Time
		if err := tx.QueryRowContext(ctx,
			`SELECT r_replay_id,r_delivery_id,r_requested_by,r_reason,r_requested_at,
			        r_prior_state,r_prior_attempts,r_prior_finished_at,r_prior_lease_epoch,
			        r_authorized_at,r_created
			   FROM keel_meta.authorize_webhook_replay_requeue($1,$2,$3,$4)`,
			request.ReplayID, request.DeliveryID, request.RequestedBy, request.Reason).
			Scan(&authorization.ReplayID, &authorization.DeliveryID, &authorization.RequestedBy,
				&authorization.Reason, &requestedAt, &priorState, &authorization.PriorAttempts,
				&priorFinishedAt, &authorization.PriorLeaseEpoch, &authorizedAt,
				&authorization.Created); err != nil {
			return fmt.Errorf("authorize webhook replay: %w", err)
		}
		authorization.PriorState = webhook.DeliveryState(priorState)
		authorization.RequestedAt = requestedAt.UTC()
		authorization.PriorFinishedAt = priorFinishedAt.UTC()
		authorization.AuthorizedAt = authorizedAt.UTC()
		return nil
	})
	if err != nil {
		return webhook.ReplayAuthorization{}, replayAuthorizationError(err)
	}
	if authorization.ReplayID != request.ReplayID || authorization.DeliveryID != request.DeliveryID ||
		authorization.RequestedBy != request.RequestedBy || authorization.Reason != request.Reason {
		return webhook.ReplayAuthorization{}, errors.New("webhook replay authorization returned a different request")
	}
	if err := authorization.Validate(); err != nil {
		return webhook.ReplayAuthorization{}, fmt.Errorf("webhook replay authorization returned an invalid result: %w", err)
	}
	return authorization, nil
}

func replayAuthorizationError(err error) error {
	message := err.Error()
	switch {
	case strings.Contains(message, "capability is required"),
		strings.Contains(message, "permission denied for function"):
		return fmt.Errorf("%w: %v", webhook.ErrReplayUnauthorized, err)
	case strings.Contains(message, "webhook replay delivery was not found"):
		return fmt.Errorf("%w: %v", webhook.ErrReplayNotFound, err)
	case strings.Contains(message, "not eligible"):
		return fmt.Errorf("%w: %v", webhook.ErrReplayNotEligible, err)
	case strings.Contains(message, "already replayed"),
		strings.Contains(message, "conflicts with an existing replay"),
		strings.Contains(message, "duplicate key value"):
		return fmt.Errorf("%w: %v", webhook.ErrReplayConflict, err)
	default:
		return err
	}
}
