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

// SetEndpointLimit creates or updates one tenant's active-endpoint quota policy. The store must be
// constructed over the operator capability's connection.
func (s *Store) SetEndpointLimit(ctx context.Context, change webhook.EndpointLimitChange) (webhook.EndpointLimitPolicy, error) {
	var policy webhook.EndpointLimitPolicy
	if s == nil || s.db == nil {
		return policy, errors.New("webhook endpoint policy store database is required")
	}
	if ctx == nil {
		return policy, errors.New("webhook endpoint policy context is required")
	}
	if err := change.Validate(); err != nil {
		return policy, err
	}

	err := inTenantTx(ctx, s.db, change.Tenant, func(ctx context.Context, tx *sql.Tx) error {
		var changeID string
		var version int64
		var limit int
		var updated time.Time
		if err := tx.QueryRowContext(ctx,
			`SELECT r_change_id,r_version,r_active_endpoint_limit,r_updated_at
			   FROM keel_meta.set_webhook_endpoint_limit($1,$2,$3,$4,$5)`,
			change.ChangeID, change.RequestedBy, change.Limit, change.Reason, change.ExpectedVersion).
			Scan(&changeID, &version, &limit, &updated); err != nil {
			return fmt.Errorf("set webhook endpoint limit: %w", err)
		}
		if changeID != change.ChangeID || version < 1 || limit < 1 || limit > webhook.MaxEndpointLimit || updated.IsZero() {
			return webhook.ErrInvalidEndpoint
		}
		policy = webhook.EndpointLimitPolicy{
			ChangeID: changeID, Version: version, ActiveEndpointLimit: limit, UpdatedAt: updated.UTC(),
		}
		return nil
	})
	if err != nil {
		if strings.Contains(err.Error(), "policy change already exists") ||
			strings.Contains(err.Error(), "policy already exists") ||
			strings.Contains(err.Error(), "policy version conflict") {
			return webhook.EndpointLimitPolicy{}, webhook.ErrEndpointPolicyConflict
		}
		if strings.Contains(err.Error(), "policy request is invalid") {
			return webhook.EndpointLimitPolicy{}, webhook.ErrInvalidEndpoint
		}
		return webhook.EndpointLimitPolicy{}, err
	}
	return policy, nil
}

// SetDeliveryBatchLimit creates or updates one tenant's per-pass delivery lease limit. The store
// must be constructed over the operator capability's connection.
func (s *Store) SetDeliveryBatchLimit(ctx context.Context, change webhook.DeliveryBatchChange) (webhook.DeliveryBatchPolicy, error) {
	var policy webhook.DeliveryBatchPolicy
	if s == nil || s.db == nil {
		return policy, errors.New("webhook delivery policy store database is required")
	}
	if ctx == nil {
		return policy, errors.New("webhook delivery policy context is required")
	}
	if err := change.Validate(); err != nil {
		return policy, err
	}

	err := inTenantTx(ctx, s.db, change.Tenant, func(ctx context.Context, tx *sql.Tx) error {
		var changeID string
		var version int64
		var limit int
		var updated time.Time
		if err := tx.QueryRowContext(ctx,
			`SELECT r_change_id,r_version,r_delivery_batch_limit,r_updated_at
			   FROM keel_meta.set_webhook_delivery_batch_limit($1,$2,$3,$4,$5)`,
			change.ChangeID, change.RequestedBy, change.Limit, change.Reason, change.ExpectedVersion).
			Scan(&changeID, &version, &limit, &updated); err != nil {
			return fmt.Errorf("set webhook delivery batch limit: %w", err)
		}
		if changeID != change.ChangeID || version < 1 || limit < 1 || limit > webhook.MaxDeliveryBatchLimit || updated.IsZero() {
			return webhook.ErrInvalidEndpoint
		}
		policy = webhook.DeliveryBatchPolicy{
			ChangeID: changeID, Version: version, BatchLimit: limit, UpdatedAt: updated.UTC(),
		}
		return nil
	})
	if err != nil {
		if strings.Contains(err.Error(), "policy change already exists") ||
			strings.Contains(err.Error(), "policy already exists") ||
			strings.Contains(err.Error(), "policy version conflict") {
			return webhook.DeliveryBatchPolicy{}, webhook.ErrDeliveryPolicyConflict
		}
		if strings.Contains(err.Error(), "policy request is invalid") {
			return webhook.DeliveryBatchPolicy{}, webhook.ErrInvalidEndpoint
		}
		return webhook.DeliveryBatchPolicy{}, err
	}
	return policy, nil
}
