package budget

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

const (
	// CostScopeInference is the only budget scope the cost dashboard reports.
	CostScopeInference = "inference"
	// MaxCostEntries bounds the per-inference rows a single dashboard read may return.
	MaxCostEntries = 100
)

var (
	// ErrCostUnavailable means the tenant has no readable budget account for the requested period.
	ErrCostUnavailable = errors.New("AI cost breakdown is unavailable")
	// ErrCostScope means the requested scope is not a supported cost scope.
	ErrCostScope = errors.New("AI cost scope is not supported")
	// ErrCostRange means a stored cost value cannot be represented as a bounded micro-USD amount.
	ErrCostRange = errors.New("AI cost value is outside the supported range")
)

// CostWatermark identifies the ledger position a breakdown was computed from. A reader can
// compare watermarks to detect that a breakdown moved without re-deriving every row.
type CostWatermark struct {
	AccountVersion int64
	Entries        int64
	LastEntryAt    time.Time
}

// CostBreakdown is the tenant cost summary for one budget period.
//
// ConfirmedMicroUSD is the exact settled cost: the sum of the confirmed, reconciled and
// adjusted ledger entries, which is the same liability the budget account enforces.
// EstimatedMicroUSD is the cost of attempts that carry a current estimate and no settled
// outcome yet. UnknownMicroUSD is the exposure of attempts whose outcome is unknown.
// OutstandingMicroUSD is the exposure of admitted attempts that have not settled at all.
// The four amounts can overlap in time but never in one attempt: an attempt is estimated,
// unknown, confirmed or outstanding, never two of them.
type CostBreakdown struct {
	TenantID            tenancy.TenantID
	Scope               string
	PeriodID            string
	PeriodStart         time.Time
	PeriodEnd           time.Time
	Currency            string
	HardLimitMicroUSD   int64
	ConfirmedMicroUSD   int64
	EstimatedMicroUSD   int64
	UnknownMicroUSD     int64
	OutstandingMicroUSD int64
	OverrunBlocked      bool
	Watermark           CostWatermark
}

// CostEntry is one inference's cost state inside a period. It carries cost classes and
// liability state only: no prompt, response, model, provider or customer content.
type CostEntry struct {
	InferenceID       string
	ConfirmedMicroUSD int64
	EstimatedMicroUSD int64
	UnknownMicroUSD   int64
	ReservedMicroUSD  int64
	LiabilityState    string
	LastActivityAt    time.Time
}

// CostReader reads tenant-scoped cost breakdowns from the durable AI budget ledger.
// Every read runs in one read-only repeatable-read tenant transaction, so the returned
// summary, rows and watermark describe a single consistent snapshot of the ledger.
type CostReader struct {
	db *sql.DB
}

// NewCostReader creates a reader for the tenant-scoped AI cost ledger.
func NewCostReader(db *sql.DB) (*CostReader, error) {
	if db == nil {
		return nil, errors.New("AI cost database is required")
	}
	return &CostReader{db: db}, nil
}

// CostBreakdown returns the tenant cost summary for one budget period. An empty period ID
// selects the tenant's current period head. The read is tenant-scoped and never exposes
// another tenant's account, reservation or ledger row.
func (r *CostReader) CostBreakdown(ctx context.Context, tenant tenancy.TenantID, periodID string) (CostBreakdown, error) {
	if r == nil || r.db == nil {
		return CostBreakdown{}, errors.New("AI cost reader is required")
	}
	if !budgetUUID.MatchString(string(tenant)) {
		return CostBreakdown{}, ErrCostUnavailable
	}
	if periodID != "" && !budgetUUID.MatchString(periodID) {
		return CostBreakdown{}, ErrCostUnavailable
	}
	var breakdown CostBreakdown
	err := tenancy.WithTenantTx(ctx, r.db, tenant, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead}, func(tx *sql.Tx) error {
		selected, err := resolveCostPeriod(ctx, tx, tenant, periodID)
		if err != nil {
			return err
		}
		summary, err := readCostSummary(ctx, tx, tenant, selected)
		if err != nil {
			return err
		}
		breakdown = summary
		return nil
	})
	if err != nil {
		return CostBreakdown{}, err
	}
	return breakdown, nil
}

// CostEntries returns a bounded per-inference cost breakdown for one budget period, newest
// activity first. An empty period ID selects the tenant's current period head, and a limit
// outside [1,MaxCostEntries] is rejected rather than silently clamped.
func (r *CostReader) CostEntries(ctx context.Context, tenant tenancy.TenantID, periodID string, limit int) ([]CostEntry, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("AI cost reader is required")
	}
	if !budgetUUID.MatchString(string(tenant)) {
		return nil, ErrCostUnavailable
	}
	if periodID != "" && !budgetUUID.MatchString(periodID) {
		return nil, ErrCostUnavailable
	}
	if limit < 1 || limit > MaxCostEntries {
		return nil, fmt.Errorf("cost entry limit must be in [1,%d]", MaxCostEntries)
	}
	entries := make([]CostEntry, 0, limit)
	err := tenancy.WithTenantTx(ctx, r.db, tenant, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead}, func(tx *sql.Tx) error {
		selected, err := resolveCostPeriod(ctx, tx, tenant, periodID)
		if err != nil {
			return err
		}
		if err := requireCostAccount(ctx, tx, tenant, selected); err != nil {
			return err
		}
		rows, err := tx.QueryContext(ctx, `SELECT a.inference_id::text,
			COALESCE(SUM(CASE WHEN l.entry_kind IN ('confirmed','reconciliation','adjustment') THEN l.amount_micro_usd ELSE 0 END),0)::bigint,
			COALESCE(SUM(CASE WHEN l.entry_kind='estimated' THEN l.amount_micro_usd ELSE 0 END),0)::bigint,
			r.liability_state,r.amount_micro_usd,
			MAX(COALESCE(l.created_at,r.created_at))
			FROM keel_meta.ai_inference_admissions a
			JOIN keel_meta.ai_budget_reservations r
			  ON r.tenant_id=a.tenant_id AND r.inference_id=a.inference_id AND r.period_id=a.period_id AND r.scope=a.scope
			LEFT JOIN keel_meta.ai_usage_ledger l
			  ON l.tenant_id=a.tenant_id AND l.inference_id=a.inference_id AND l.attempt_id=a.attempt_id
			WHERE a.tenant_id=$1 AND a.scope=$2 AND a.period_id=$3
			GROUP BY a.inference_id,r.liability_state,r.amount_micro_usd
			ORDER BY MAX(COALESCE(l.created_at,r.created_at)) DESC
			LIMIT $4`, string(tenant), CostScopeInference, selected, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var entry CostEntry
			var confirmed, estimated, reserved int64
			if err := rows.Scan(&entry.InferenceID, &confirmed, &estimated, &entry.LiabilityState, &reserved, &entry.LastActivityAt); err != nil {
				return err
			}
			entry.ConfirmedMicroUSD = confirmed
			entry.EstimatedMicroUSD = estimated
			switch entry.LiabilityState {
			case "unknown":
				entry.UnknownMicroUSD = reserved
			case "reserved":
				entry.ReservedMicroUSD = reserved
			}
			entry.LastActivityAt = entry.LastActivityAt.UTC()
			entries = append(entries, entry)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return entries, nil
}

// resolveCostPeriod selects the requested budget period or the tenant's current period head.
func resolveCostPeriod(ctx context.Context, tx *sql.Tx, tenant tenancy.TenantID, periodID string) (string, error) {
	if periodID != "" {
		return periodID, nil
	}
	var selected string
	err := tx.QueryRowContext(ctx, `SELECT period_id::text FROM keel_meta.ai_budget_period_heads
		WHERE tenant_id=$1 AND scope=$2`, string(tenant), CostScopeInference).Scan(&selected)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrCostUnavailable
	}
	if err != nil {
		return "", err
	}
	return selected, nil
}

// requireCostAccount proves the tenant has a readable budget account for the period, so a
// missing period is reported instead of looking like a period without any cost.
func requireCostAccount(ctx context.Context, tx *sql.Tx, tenant tenancy.TenantID, periodID string) error {
	var exists bool
	err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM keel_meta.ai_budget_accounts
		WHERE tenant_id=$1 AND scope=$2 AND period_id=$3)`, string(tenant), CostScopeInference, periodID).Scan(&exists)
	if err != nil {
		return err
	}
	if !exists {
		return ErrCostUnavailable
	}
	return nil
}

// readCostSummary reads the period account, the ledger-derived cost classes and the
// watermark from one consistent snapshot.
func readCostSummary(ctx context.Context, tx *sql.Tx, tenant tenancy.TenantID, periodID string) (CostBreakdown, error) {
	breakdown := CostBreakdown{TenantID: tenant, Scope: CostScopeInference, PeriodID: periodID}
	var committed, reserved, unknownTotal, outstanding, estimated string
	var entries int64
	var lastEntry sql.NullTime
	err := tx.QueryRowContext(ctx, `SELECT b.period_start,b.period_end,b.currency,b.hard_limit_micro_usd,
		b.committed_micro_usd::text,b.reserved_micro_usd::text,b.overrun_blocked,b.version,
		COALESCE((SELECT SUM(r.amount_micro_usd) FROM keel_meta.ai_budget_reservations r
			WHERE r.tenant_id=b.tenant_id AND r.scope=b.scope AND r.period_id=b.period_id AND r.liability_state='unknown'),0)::text,
		COALESCE((SELECT SUM(r.amount_micro_usd) FROM keel_meta.ai_budget_reservations r
			WHERE r.tenant_id=b.tenant_id AND r.scope=b.scope AND r.period_id=b.period_id AND r.liability_state='reserved'),0)::text,
		COALESCE((SELECT SUM(l.amount_micro_usd) FROM keel_meta.ai_usage_ledger l
			JOIN keel_meta.ai_inference_admissions a
			  ON a.tenant_id=l.tenant_id AND a.inference_id=l.inference_id AND a.attempt_id=l.attempt_id
			WHERE l.tenant_id=b.tenant_id AND a.scope=b.scope AND a.period_id=b.period_id AND l.entry_kind='estimated'
			  AND NOT EXISTS (SELECT 1 FROM keel_meta.ai_usage_ledger x
			    WHERE x.tenant_id=l.tenant_id AND x.inference_id=l.inference_id AND x.attempt_id=l.attempt_id
			      AND x.entry_kind IN ('confirmed','reconciliation','no_charge'))),0)::text,
		(SELECT COUNT(*) FROM keel_meta.ai_usage_ledger l
			JOIN keel_meta.ai_inference_admissions a
			  ON a.tenant_id=l.tenant_id AND a.inference_id=l.inference_id AND a.attempt_id=l.attempt_id
			WHERE l.tenant_id=b.tenant_id AND a.scope=b.scope AND a.period_id=b.period_id),
		(SELECT MAX(l.created_at) FROM keel_meta.ai_usage_ledger l
			JOIN keel_meta.ai_inference_admissions a
			  ON a.tenant_id=l.tenant_id AND a.inference_id=l.inference_id AND a.attempt_id=l.attempt_id
			WHERE l.tenant_id=b.tenant_id AND a.scope=b.scope AND a.period_id=b.period_id)
		FROM keel_meta.ai_budget_accounts b
		WHERE b.tenant_id=$1 AND b.scope=$2 AND b.period_id=$3`,
		string(tenant), CostScopeInference, periodID).Scan(
		&breakdown.PeriodStart, &breakdown.PeriodEnd, &breakdown.Currency, &breakdown.HardLimitMicroUSD,
		&committed, &reserved, &breakdown.OverrunBlocked, &breakdown.Watermark.AccountVersion,
		&unknownTotal, &outstanding, &estimated, &entries, &lastEntry)
	if errors.Is(err, sql.ErrNoRows) {
		return CostBreakdown{}, ErrCostUnavailable
	}
	if err != nil {
		return CostBreakdown{}, err
	}
	if breakdown.ConfirmedMicroUSD, err = costAmount(committed); err != nil {
		return CostBreakdown{}, err
	}
	accountReserved, err := costAmount(reserved)
	if err != nil {
		return CostBreakdown{}, err
	}
	if breakdown.UnknownMicroUSD, err = costAmount(unknownTotal); err != nil {
		return CostBreakdown{}, err
	}
	if breakdown.OutstandingMicroUSD, err = costAmount(outstanding); err != nil {
		return CostBreakdown{}, err
	}
	if breakdown.EstimatedMicroUSD, err = costAmount(estimated); err != nil {
		return CostBreakdown{}, err
	}
	if accountReserved < breakdown.OutstandingMicroUSD {
		// The account's reserved liability must cover every outstanding reservation.
		return CostBreakdown{}, ErrCostUnavailable
	}
	breakdown.PeriodStart = breakdown.PeriodStart.UTC()
	breakdown.PeriodEnd = breakdown.PeriodEnd.UTC()
	breakdown.Watermark.Entries = entries
	if lastEntry.Valid {
		breakdown.Watermark.LastEntryAt = lastEntry.Time.UTC()
	}
	return breakdown, nil
}

// costAmount converts a stored micro-USD amount into a bounded integer.
func costAmount(raw string) (int64, error) {
	value, ok := new(big.Int).SetString(strings.TrimSpace(raw), 10)
	if !ok || value.Sign() < 0 || !value.IsInt64() {
		return 0, ErrCostRange
	}
	return value.Int64(), nil
}
