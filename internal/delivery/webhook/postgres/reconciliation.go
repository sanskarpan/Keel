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
		if observer := s.reconciliationObserver(); observer != nil {
			observer.ObservePlanFailure()
		}
		if strings.Contains(err.Error(), "reconciliation run already exists") {
			return webhook.ReconciliationPage{}, webhook.ErrReconciliationConflict
		}
		if strings.Contains(err.Error(), "reconciliation request is invalid") ||
			strings.Contains(err.Error(), "start time is required") {
			return webhook.ReconciliationPage{}, webhook.ErrInvalidReconciliation
		}
		return webhook.ReconciliationPage{}, err
	}
	if observer := s.reconciliationObserver(); observer != nil {
		observer.ObserveReconciliationPlan(page)
	}
	return page, nil
}

// RepairReconciliation applies one recorded reconciliation run to the still-missing deliveries,
// revalidating each gap event against the endpoint status recorded at the event's time. The
// store must be constructed over the operator capability's connection.
func (s *Store) RepairReconciliation(ctx context.Context, request webhook.RepairRequest) (webhook.RepairResult, error) {
	var result webhook.RepairResult
	if s == nil || s.db == nil {
		return result, errors.New("webhook delivery store database is required")
	}
	if ctx == nil {
		return result, errors.New("webhook delivery context is required")
	}
	if err := request.Validate(); err != nil {
		return result, err
	}

	err := inTenantTx(ctx, s.db, request.Tenant, func(ctx context.Context, tx *sql.Tx) error {
		var repairID string
		var gaps, inserted, skipped int
		if err := tx.QueryRowContext(ctx,
			`SELECT r_repair_id,r_gap_events,r_inserted_deliveries,r_skipped_identities
			   FROM keel_meta.repair_webhook_reconciliation_run($1,$2,$3,$4)`,
			request.RepairID, request.RunID, request.RequestedBy, request.EventLimit).
			Scan(&repairID, &gaps, &inserted, &skipped); err != nil {
			return fmt.Errorf("repair webhook reconciliation: %w", err)
		}
		if repairID != request.RepairID || gaps < 0 || gaps > webhook.MaxReconciliationPage ||
			inserted < 0 || inserted > 10000 || skipped < 0 || skipped > 10000 {
			return webhook.ErrInvalidReconciliation
		}
		result = webhook.RepairResult{RepairID: repairID, GapEvents: gaps, InsertedDeliveries: inserted, SkippedIdentities: skipped}
		return nil
	})
	if err != nil {
		if observer := s.reconciliationObserver(); observer != nil {
			observer.ObserveRepairFailure()
		}
		if strings.Contains(err.Error(), "repair already exists") {
			return webhook.RepairResult{}, webhook.ErrReconciliationConflict
		}
		if strings.Contains(err.Error(), "exceeds the delivery bound") {
			return webhook.RepairResult{}, webhook.ErrReconciliationRepairLimit
		}
		if strings.Contains(err.Error(), "run was not found") ||
			strings.Contains(err.Error(), "repair request is invalid") {
			return webhook.RepairResult{}, webhook.ErrInvalidReconciliation
		}
		return webhook.RepairResult{}, err
	}
	if observer := s.reconciliationObserver(); observer != nil {
		observer.ObserveReconciliationRepair(result)
	}
	return result, nil
}

// ResetReconciliationCursor records an audited backward cursor move for one trusted tenant. The
// store must be constructed over the operator capability's connection.
func (s *Store) ResetReconciliationCursor(ctx context.Context, request webhook.CursorResetRequest) (webhook.CursorResetResult, error) {
	var result webhook.CursorResetResult
	if s == nil || s.db == nil {
		return result, errors.New("webhook delivery store database is required")
	}
	if ctx == nil {
		return result, errors.New("webhook delivery context is required")
	}
	if err := request.Validate(); err != nil {
		return result, err
	}

	err := inTenantTx(ctx, s.db, request.Tenant, func(ctx context.Context, tx *sql.Tx) error {
		var resetID, priorEventID, newEventID string
		var priorAt, newAt time.Time
		if err := tx.QueryRowContext(ctx,
			`SELECT r_reset_id,r_prior_created_at,r_prior_event_id,r_new_created_at,r_new_event_id
			   FROM keel_meta.reset_webhook_reconciliation_cursor($1,$2,$3,$4)`,
			request.ResetID, request.RequestedBy, request.To, request.Reason).
			Scan(&resetID, &priorAt, &priorEventID, &newAt, &newEventID); err != nil {
			return fmt.Errorf("reset webhook reconciliation cursor: %w", err)
		}
		prior, err := uuid.Parse(priorEventID)
		if err != nil || prior == uuid.Nil || resetID != request.ResetID ||
			priorAt.IsZero() || newAt.IsZero() || newEventID != uuid.Nil.String() ||
			newAt.After(priorAt) {
			return webhook.ErrInvalidReconciliation
		}
		result = webhook.CursorResetResult{
			ResetID: resetID, PriorAt: priorAt, PriorEventID: priorEventID, NewAt: newAt,
		}
		return nil
	})
	if err != nil {
		if strings.Contains(err.Error(), "reset already exists") {
			return webhook.CursorResetResult{}, webhook.ErrReconciliationConflict
		}
		if strings.Contains(err.Error(), "reset request is invalid") ||
			strings.Contains(err.Error(), "cursor was not found") ||
			strings.Contains(err.Error(), "must move backward") {
			return webhook.CursorResetResult{}, webhook.ErrInvalidReconciliation
		}
		return webhook.CursorResetResult{}, err
	}
	return result, nil
}
