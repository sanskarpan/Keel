package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/google/uuid"
	"github.com/sanskarpan/keel/internal/delivery/webhook"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

var (
	reconciliationRunIDPattern    = regexp.MustCompile(`^[A-Za-z0-9_-]{8,64}$`)
	reconciliationRunActorPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}$`)
)

func validateReconciliationTenant(tenant tenancy.TenantID) error {
	if string(tenant) == "" || string(tenant) == "00000000-0000-0000-0000-000000000000" {
		return webhook.ErrInvalidReconciliation
	}
	if _, err := tenancy.ParseTenantID(string(tenant)); err != nil {
		return webhook.ErrInvalidReconciliation
	}
	return nil
}

// ReconciliationRuns lists recent dry-run pages with their audited repair totals for one trusted
// tenant, newest first. It carries counts, identities and timestamps only. The store must be
// constructed over the operator capability's connection.
func (s *Store) ReconciliationRuns(ctx context.Context, tenant tenancy.TenantID, limit int) ([]webhook.ReconciliationRunSummary, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("webhook reconciliation store database is required")
	}
	if ctx == nil {
		return nil, errors.New("webhook reconciliation context is required")
	}
	if err := validateReconciliationTenant(tenant); err != nil {
		return nil, err
	}
	if limit < 1 || limit > webhook.MaxReconciliationRunHistory {
		return nil, webhook.ErrInvalidReconciliation
	}

	var runs []webhook.ReconciliationRunSummary
	err := inTenantTx(ctx, s.db, tenant, func(ctx context.Context, tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx,
			`SELECT r_run_id,r_requested_by,r_from_created_at,
			        r_cursor_to_created_at,r_cursor_to_event_id,
			        r_events_scanned,r_gap_events,r_missing_deliveries,
			        r_repaired_deliveries,r_skipped_identities,r_created_at
			   FROM keel_meta.list_webhook_reconciliation_runs($1)`, limit)
		if err != nil {
			return fmt.Errorf("list webhook reconciliation runs: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var runID, requestedBy string
			var fromCreatedAt, createdAt time.Time
			var cursorToCreatedAt sql.NullTime
			var cursorToEventID sql.NullString
			var scanned, gaps int
			var missing int64
			var repaired, skipped int
			if err := rows.Scan(&runID, &requestedBy, &fromCreatedAt,
				&cursorToCreatedAt, &cursorToEventID,
				&scanned, &gaps, &missing, &repaired, &skipped, &createdAt); err != nil {
				return fmt.Errorf("scan webhook reconciliation run: %w", err)
			}
			summary, err := newReconciliationRunSummary(
				runID, requestedBy, fromCreatedAt, cursorToCreatedAt, cursorToEventID,
				scanned, gaps, missing, repaired, skipped, createdAt)
			if err != nil {
				return err
			}
			runs = append(runs, summary)
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("iterate webhook reconciliation runs: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return runs, nil
}

func newReconciliationRunSummary(runID, requestedBy string, fromCreatedAt time.Time,
	cursorToCreatedAt sql.NullTime, cursorToEventID sql.NullString,
	scanned, gaps int, missing int64, repaired, skipped int,
	createdAt time.Time) (webhook.ReconciliationRunSummary, error) {
	var summary webhook.ReconciliationRunSummary
	if !reconciliationRunIDPattern.MatchString(runID) {
		return summary, webhook.ErrInvalidReconciliation
	}
	if !reconciliationRunActorPattern.MatchString(requestedBy) {
		return summary, webhook.ErrInvalidReconciliation
	}
	if fromCreatedAt.IsZero() || createdAt.IsZero() {
		return summary, webhook.ErrInvalidReconciliation
	}
	if cursorToEventID.Valid != cursorToCreatedAt.Valid {
		return summary, webhook.ErrInvalidReconciliation
	}
	cursorEvent := ""
	cursorTime := time.Time{}
	if cursorToEventID.Valid {
		parsed, err := uuid.Parse(cursorToEventID.String)
		if err != nil || parsed == uuid.Nil {
			return summary, webhook.ErrInvalidReconciliation
		}
		if cursorToCreatedAt.Time.IsZero() {
			return summary, webhook.ErrInvalidReconciliation
		}
		cursorEvent = cursorToEventID.String
		cursorTime = cursorToCreatedAt.Time.UTC()
	}
	if scanned < 0 || scanned > webhook.MaxReconciliationPage ||
		gaps < 0 || gaps > scanned || missing < 0 ||
		repaired < 0 || repaired > 10000 || skipped < 0 || skipped > 10000 {
		return summary, webhook.ErrInvalidReconciliation
	}
	return webhook.ReconciliationRunSummary{
		RunID: runID, RequestedBy: requestedBy, FromCreatedAt: fromCreatedAt.UTC(),
		CursorToCreatedAt: cursorTime, CursorToEventID: cursorEvent,
		EventsScanned: scanned, GapEvents: gaps, MissingDeliveries: missing,
		RepairedDeliveries: repaired, SkippedIdentities: skipped, CreatedAt: createdAt.UTC(),
	}, nil
}
