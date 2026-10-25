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

// EndpointStatusAt returns one endpoint's recorded status and subscription revision as of the
// query time. It carries no URL, key, payload or receiver data. An unknown endpoint or a time
// before the first recorded version returns webhook.ErrEndpointUnavailable. The store must be
// constructed over the operator capability's connection.
func (s *Store) EndpointStatusAt(ctx context.Context, query webhook.EndpointStatusAtQuery) (webhook.EndpointStatusPoint, error) {
	var point webhook.EndpointStatusPoint
	if s == nil || s.db == nil {
		return point, errors.New("webhook status history store database is required")
	}
	if ctx == nil {
		return point, errors.New("webhook status history context is required")
	}
	if err := query.Validate(); err != nil {
		return point, err
	}

	err := inTenantTx(ctx, s.db, query.Tenant, func(ctx context.Context, tx *sql.Tx) error {
		var status string
		var subscription int
		var version int64
		var recorded time.Time
		if err := tx.QueryRowContext(ctx,
			`SELECT r_status,r_subscription_version,r_version,r_recorded_at
			   FROM keel_meta.webhook_endpoint_status_at($1,$2)`,
			query.ID, query.At.UTC()).
			Scan(&status, &subscription, &version, &recorded); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return webhook.ErrEndpointUnavailable
			}
			return fmt.Errorf("read webhook endpoint status history: %w", err)
		}
		if (status != string(webhook.EndpointActive) && status != string(webhook.EndpointInactive)) ||
			subscription < 1 || subscription > webhook.MaxSubscriptionVersion ||
			version < 1 || recorded.IsZero() {
			return webhook.ErrInvalidEndpoint
		}
		point = webhook.EndpointStatusPoint{
			Tenant:              query.Tenant,
			ID:                  query.ID,
			Status:              webhook.EndpointStatus(status),
			SubscriptionVersion: uint32(subscription),
			Version:             version,
			RecordedAt:          recorded.UTC(),
		}
		return nil
	})
	if err != nil {
		if strings.Contains(err.Error(), "status history request is invalid") {
			return webhook.EndpointStatusPoint{}, webhook.ErrInvalidEndpoint
		}
		return webhook.EndpointStatusPoint{}, err
	}
	return point, nil
}
