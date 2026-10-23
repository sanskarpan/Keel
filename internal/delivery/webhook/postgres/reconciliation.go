package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sanskarpan/keel/internal/delivery/webhook"
)

// PlanReconciliation records one dry-run reconciliation page for one trusted tenant. It never
// creates deliveries. The store must be constructed over the operator capability's connection.
func (s *Store) PlanReconciliation(ctx context.Context, request webhook.ReconciliationRequest) (webhook.ReconciliationPage, error) {
	var page webhook.ReconciliationPage
	if s == nil || s.db == nil {
		return page, errors.New("webhook delivery store database is required")
	}
	if ctx == nil {
		return page, errors.New("webhook delivery context is required")
	}
	if err := request.Validate(); err != nil {
		return page, err
	}

	err := inTenantTx(ctx, s.db, request.Tenant, func(ctx context.Context, tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx,
			`SELECT r_event_id,r_event_created_at,r_missing_count
			   FROM keel_meta.plan_webhook_reconciliation($1,$2,$3,$4)`,
			request.RunID, request.RequestedBy, request.From, request.PageSize)
		if err != nil {
			return fmt.Errorf("plan webhook reconciliation: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			var eventID string
			var createdAt time.Time
			var missing int
			if err := rows.Scan(&eventID, &createdAt, &missing); err != nil {
				return fmt.Errorf("scan webhook reconciliation event: %w", err)
			}
			parsed, err := uuid.Parse(eventID)
			if err != nil || parsed == uuid.Nil || createdAt.IsZero() || missing < 0 || missing > 1_000_000 {
				return webhook.ErrInvalidReconciliation
			}
			page.Events = append(page.Events, webhook.ReconciliationEvent{
				EventID: eventID, CreatedAt: createdAt, Missing: missing,
			})
			page.Scanned++
			if missing > 0 {
				page.GapEvents++
				page.Missing += missing
			}
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("iterate webhook reconciliation events: %w", err)
		}
		return nil
	})
	if err != nil {
		if strings.Contains(err.Error(), "reconciliation run already exists") {
			return webhook.ReconciliationPage{}, webhook.ErrReconciliationConflict
		}
		if strings.Contains(err.Error(), "reconciliation request is invalid") ||
			strings.Contains(err.Error(), "start time is required") {
			return webhook.ReconciliationPage{}, webhook.ErrInvalidReconciliation
		}
		return webhook.ReconciliationPage{}, err
	}
	return page, nil
}
