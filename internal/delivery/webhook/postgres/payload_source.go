package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/sanskarpan/keel/internal/delivery/webhook"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

const webhookPayloadContentType = "application/json"

// Payload returns the exact allowlisted event body for one delivery. The tenant is supplied by the
// trusted scheduler, never by the delivery or receiver, and the delivery event must resolve to one
// outbox safe envelope. Missing, oversized or mismatched bodies are permanent delivery failures.
func (s *Store) Payload(ctx context.Context, tenant tenancy.TenantID, delivery webhook.Delivery) ([]byte, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("webhook delivery store database is required")
	}
	if ctx == nil {
		return nil, errors.New("webhook delivery context is required")
	}
	if err := validatePayloadTenant(tenant); err != nil {
		return nil, err
	}
	if err := delivery.Validate(); err != nil {
		return nil, err
	}
	if delivery.Identity.Tenant != tenant {
		return nil, webhook.ErrInvalidDelivery
	}
	eventID, err := uuid.Parse(delivery.Identity.EventID)
	if err != nil {
		return nil, webhook.ErrInvalidDelivery
	}

	var (
		readEventID string
		contentType string
		body        []byte
	)
	err = inTenantTx(ctx, s.db, tenant, func(ctx context.Context, tx *sql.Tx) error {
		return tx.QueryRowContext(ctx,
			`SELECT r_event_id,r_content_type,r_body
			   FROM keel_meta.read_webhook_delivery_body($1)`, delivery.ID).
			Scan(&readEventID, &contentType, &body)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, webhook.ErrInvalidDelivery
	}
	if err != nil {
		if strings.Contains(err.Error(), "body is invalid") {
			return nil, webhook.ErrInvalidDelivery
		}
		return nil, fmt.Errorf("read webhook delivery body: %w", err)
	}
	if contentType != webhookPayloadContentType {
		return nil, webhook.ErrInvalidDelivery
	}
	parsed, err := uuid.Parse(readEventID)
	if err != nil || parsed != eventID {
		return nil, webhook.ErrInvalidDelivery
	}
	if len(body) < 1 || len(body) > webhook.MaxAttemptBodyBytes {
		return nil, webhook.ErrInvalidDelivery
	}
	return body, nil
}

func validatePayloadTenant(tenant tenancy.TenantID) error {
	if string(tenant) == "" || string(tenant) == "00000000-0000-0000-0000-000000000000" {
		return webhook.ErrInvalidDelivery
	}
	if _, err := tenancy.ParseTenantID(string(tenant)); err != nil {
		return webhook.ErrInvalidDelivery
	}
	return nil
}
