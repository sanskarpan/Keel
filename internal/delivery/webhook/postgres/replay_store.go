package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/sanskarpan/keel/internal/delivery/webhook"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

// ReplayRecord is one immutable persisted manual replay request. Created reports whether this call
// inserted the record; an exact retry returns the stored record with Created false.
type ReplayRecord struct {
	ReplayID    string
	DeliveryID  string
	RequestedBy string
	Reason      string
	RequestedAt time.Time
	Created     bool
}

// RecordReplay records one operator's manual replay request in one tenant transaction. A replay ID
// retried with the same delivery, actor and reason is idempotent; any other reuse is a conflict. A
// second replay ID for an already replayed delivery is also a conflict.
func (s *Store) RecordReplay(ctx context.Context, request webhook.ReplayRequest) (ReplayRecord, error) {
	if s == nil || s.db == nil {
		return ReplayRecord{}, errors.New("webhook replay store database is required")
	}
	if ctx == nil {
		return ReplayRecord{}, errors.New("webhook replay context is required")
	}
	if err := request.Validate(); err != nil {
		return ReplayRecord{}, err
	}

	var record ReplayRecord
	err := inTenantTx(ctx, s.db, request.Tenant, func(ctx context.Context, tx *sql.Tx) error {
		var requestedAt time.Time
		if err := tx.QueryRowContext(ctx,
			`SELECT r_replay_id,r_delivery_id,r_requested_by,r_reason,r_requested_at,r_created
			   FROM keel_meta.record_webhook_replay($1,$2,$3,$4)`,
			request.ReplayID, request.DeliveryID, request.RequestedBy, request.Reason).
			Scan(&record.ReplayID, &record.DeliveryID, &record.RequestedBy, &record.Reason,
				&requestedAt, &record.Created); err != nil {
			return fmt.Errorf("record webhook replay: %w", err)
		}
		record.RequestedAt = requestedAt.UTC()
		return nil
	})
	if err != nil {
		return ReplayRecord{}, replayStoreError(err)
	}
	return record, nil
}

// ReplayRecorded reports whether the delivery already has a replay request for the tenant. It
// requires the operator capability and an authorized tenant context.
func (s *Store) ReplayRecorded(ctx context.Context, tenant tenancy.TenantID, deliveryID string) (bool, error) {
	if s == nil || s.db == nil {
		return false, errors.New("webhook replay store database is required")
	}
	if ctx == nil {
		return false, errors.New("webhook replay context is required")
	}
	if err := validateReplayTenant(tenant); err != nil {
		return false, err
	}
	if err := webhook.ValidateReplayDeliveryID(deliveryID); err != nil {
		return false, err
	}

	var recorded bool
	err := inTenantTx(ctx, s.db, tenant, func(ctx context.Context, tx *sql.Tx) error {
		return tx.QueryRowContext(ctx,
			`SELECT r_recorded FROM keel_meta.webhook_replay_recorded($1)`, deliveryID).
			Scan(&recorded)
	})
	if err != nil {
		return false, fmt.Errorf("query webhook replay record: %w", err)
	}
	return recorded, nil
}

func replayStoreError(err error) error {
	message := err.Error()
	if strings.Contains(message, "already replayed") ||
		strings.Contains(message, "conflicts with an existing replay") {
		return fmt.Errorf("%w: %v", webhook.ErrReplayConflict, err)
	}
	return err
}

func validateReplayTenant(tenant tenancy.TenantID) error {
	if string(tenant) == "" || string(tenant) == "00000000-0000-0000-0000-000000000000" {
		return webhook.ErrInvalidReplay
	}
	if _, err := tenancy.ParseTenantID(string(tenant)); err != nil {
		return webhook.ErrInvalidReplay
	}
	return nil
}
