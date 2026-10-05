package budget

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

var (
	ErrBudgetUnavailable    = errors.New("AI budget admission is unavailable")
	ErrBudgetConflict       = errors.New("AI budget operation conflicts with committed state")
	ErrBudgetDenied         = errors.New("AI budget admission denied")
	ErrReconciliationDenied = errors.New("AI budget reconciliation authorization denied")
	budgetUUID              = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	principalRef            = regexp.MustCompile(`^principal:[A-Za-z0-9._~-]{1,120}$`)
	reasonCode              = regexp.MustCompile(`^[a-z][a-z0-9_]{1,39}$`)
)

// Repository performs all budget state transitions in tenant-scoped SQL transactions.
// Budget accounts are created and hard limits set by a separately authorized control plane.
type Repository struct {
	db         *sql.DB
	reconciler ReconciliationAuthorizer
	controlDB  *sql.DB
	controller BudgetControlAuthorizer
}

// ReconciliationAuthorizer must bind the actor to verified authentication and the exact
// tenant/attempt/decision. Nil authorization is fail-closed.
type ReconciliationAuthorizer interface {
	AuthorizeBudgetReconciliation(context.Context, tenancy.TenantID, string, string, string, string, string, int64) error
}

// BudgetControlAuthorizer authorizes hard-limit changes from a verified operator/control plane.
type BudgetControlAuthorizer interface {
	AuthorizeBudgetLimitChange(context.Context, tenancy.TenantID, string, string, string, int64) error
}

func NewRepository(db *sql.DB, reconciler ReconciliationAuthorizer, controlDB *sql.DB, controller BudgetControlAuthorizer) (*Repository, error) {
	if db == nil {
		return nil, errors.New("AI budget database is required")
	}
	return &Repository{db: db, reconciler: reconciler, controlDB: controlDB, controller: controller}, nil
}

// RaiseLimitAndReopen is a separately authorized and audited recovery operation using a
// dedicated keel_budget_control connection. It cannot lower the cap below committed liability.
func (r *Repository) RaiseLimitAndReopen(ctx context.Context, tenant tenancy.TenantID, periodID, eventID, actor, reason string, newLimit int64) error {
	if r.controlDB == nil || r.controller == nil || !budgetUUID.MatchString(string(tenant)) || !budgetUUID.MatchString(periodID) || !budgetUUID.MatchString(eventID) || !principalRef.MatchString(actor) || !reasonCode.MatchString(reason) || newLimit <= 0 {
		return ErrReconciliationDenied
	}
	if err := r.controller.AuthorizeBudgetLimitChange(ctx, tenant, periodID, actor, reason, newLimit); err != nil {
		return fmt.Errorf("%w: %v", ErrReconciliationDenied, err)
	}
	return tenancy.WithTenantTx(ctx, r.controlDB, tenant, nil, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `SELECT keel_meta.raise_ai_budget_limit($1,$2,$3,$4,$5,$6)`, string(tenant), eventID, periodID, actor, reason, newLimit)
		if err != nil && strings.Contains(strings.ToLower(err.Error()), "budget account is unavailable") {
			return ErrBudgetUnavailable
		}
		if err != nil && strings.Contains(strings.ToLower(err.Error()), "below committed and reserved liability") {
			return ErrBudgetDenied
		}
		return err
	})
}

type Admission struct {
	Tenant                                          tenancy.TenantID
	PeriodID, InferenceID, AttemptID, ReservationID string
	PeriodStart, PeriodEnd                          time.Time
	PrincipalBinding                                string
	RequestDigest                                   string
	Quote                                           Quote
}

type AdmissionResult struct {
	ReservationID, PeriodID string
	Replayed                bool
}

// Admit serializes on the pre-provisioned account row. The selected period is immutable
// on the admission and reservation; later settlement never consults the current period.
// Admit keeps the standalone budget API for non-queued operations. Provider queue
// admission should use AdmitWith so the reservation and job commit atomically.
func (r *Repository) Admit(ctx context.Context, in Admission) (AdmissionResult, error) {
	return r.AdmitWith(ctx, in, nil)
}

// AdmitWith performs the durable reservation and invokes afterReserve inside the
// same tenant transaction. A callback failure rolls back both admission and reserve.
// On idempotent replay it also runs, allowing the queue layer to verify the exact job.
func (r *Repository) AdmitWith(ctx context.Context, in Admission, afterReserve func(*sql.Tx, AdmissionResult) error) (AdmissionResult, error) {
	if err := validateAdmission(in); err != nil {
		return AdmissionResult{}, err
	}
	principalHash := sha256.Sum256([]byte(in.PrincipalBinding))
	requestHash, _ := hex.DecodeString(in.RequestDigest)
	policyHash, _ := hex.DecodeString(in.Quote.PolicyDigest())
	rateHash, _ := hex.DecodeString(in.Quote.RateCardDigest())
	quoteHash, _ := hex.DecodeString(in.Quote.Digest())
	result := AdmissionResult{}
	err := tenancy.WithTenantTx(ctx, r.db, in.Tenant, nil, func(tx *sql.Tx) error {
		var limit int64
		var committedText, reservedText string
		var blocked bool
		err := tx.QueryRowContext(ctx, `SELECT hard_limit_micro_usd, committed_micro_usd::text, reserved_micro_usd::text, overrun_blocked
			FROM keel_meta.ai_budget_accounts WHERE tenant_id=$1 AND period_id=$2 AND scope='inference' AND period_start=$3 AND period_end=$4 FOR UPDATE`,
			string(in.Tenant), in.PeriodID, in.PeriodStart.UTC(), in.PeriodEnd.UTC()).Scan(&limit, &committedText, &reservedText, &blocked)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrBudgetUnavailable
		}
		if err != nil {
			return err
		}
		quoteAt := in.Quote.QuotedAt()
		var priorPeriod, priorAttempt string
		var priorPrincipal, priorRequest, priorPolicy, priorRate, priorQuote []byte
		err = tx.QueryRowContext(ctx, `SELECT period_id::text, attempt_id::text, principal_binding_sha256, request_sha256, policy_sha256, rate_card_sha256, quote_sha256
			FROM keel_meta.ai_inference_admissions WHERE tenant_id=$1 AND inference_id=$2`, string(in.Tenant), in.InferenceID).
			Scan(&priorPeriod, &priorAttempt, &priorPrincipal, &priorRequest, &priorPolicy, &priorRate, &priorQuote)
		if err == nil {
			if priorPeriod != in.PeriodID || priorAttempt != in.AttemptID || !sameHash(priorPrincipal, principalHash[:]) || !sameHash(priorRequest, requestHash) || !sameHash(priorPolicy, policyHash) || !sameHash(priorRate, rateHash) || !sameHash(priorQuote, quoteHash) {
				return ErrBudgetConflict
			}
			var reservationID string
			if err := tx.QueryRowContext(ctx, `SELECT reservation_id::text FROM keel_meta.ai_budget_reservations WHERE tenant_id=$1 AND inference_id=$2`, string(in.Tenant), in.InferenceID).Scan(&reservationID); err != nil {
				return err
			}
			result = AdmissionResult{ReservationID: reservationID, PeriodID: in.PeriodID, Replayed: true}
			if afterReserve != nil {
				return afterReserve(tx, result)
			}
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		var activePeriod string
		if err := tx.QueryRowContext(ctx, `SELECT period_id::text FROM keel_meta.lock_ai_budget_period($1)`, string(in.Tenant)).Scan(&activePeriod); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrBudgetUnavailable
			}
			return err
		}
		if activePeriod != in.PeriodID {
			return ErrBudgetDenied
		}
		var databaseNow time.Time
		if err := tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&databaseNow); err != nil {
			return err
		}
		if databaseNow.Before(in.PeriodStart.UTC()) || !databaseNow.Before(in.PeriodEnd.UTC()) || quoteAt.IsZero() || quoteAt.Before(in.Quote.RateEffectiveFrom()) || databaseNow.Before(in.Quote.RateEffectiveFrom()) || !databaseNow.Before(in.Quote.RateEffectiveUntil()) || quoteAt.Before(databaseNow.Add(-maxQuoteAge)) || quoteAt.After(databaseNow.Add(maxQuoteFutureSkew)) {
			return ErrQuoteRejected
		}
		committed, okC := parseCounter(committedText)
		reserved, okR := parseCounter(reservedText)
		capacity := big.NewInt(limit)
		liability := big.NewInt(in.Quote.MaximumLiabilityMicroUSD())
		if !okC || !okR || blocked || new(big.Int).Add(new(big.Int).Add(new(big.Int).Set(committed), reserved), liability).Cmp(capacity) > 0 {
			return ErrBudgetDenied
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO keel_meta.ai_inference_admissions
			(tenant_id,inference_id,attempt_id,period_id,scope,principal_binding_sha256,request_sha256,policy_sha256,rate_card_id,rate_card_version,rate_card_sha256,quote_sha256,max_liability_micro_usd,currency,quoted_at,rate_effective_from,rate_effective_until)
			VALUES ($1,$2,$3,$4,'inference',$5,$6,$7,$8,$9,$10,$11,$12,'USD',$13,$14,$15)`,
			string(in.Tenant), in.InferenceID, in.AttemptID, in.PeriodID, principalHash[:], requestHash, policyHash, in.Quote.RateCardID(), in.Quote.RateCardVersion(), rateHash, quoteHash, in.Quote.MaximumLiabilityMicroUSD(), quoteAt, in.Quote.RateEffectiveFrom(), in.Quote.RateEffectiveUntil())
		if err != nil {
			return mapConflict(err)
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO keel_meta.ai_budget_reservations (tenant_id,reservation_id,inference_id,attempt_id,period_id,scope,amount_micro_usd,liability_state)
			VALUES ($1,$2,$3,$4,$5,'inference',$6,'reserved')`, string(in.Tenant), in.ReservationID, in.InferenceID, in.AttemptID, in.PeriodID, in.Quote.MaximumLiabilityMicroUSD())
		if err != nil {
			return mapConflict(err)
		}
		_, err = tx.ExecContext(ctx, `UPDATE keel_meta.ai_budget_accounts SET reserved_micro_usd=reserved_micro_usd+$3, version=version+1
			WHERE tenant_id=$1 AND period_id=$2`, string(in.Tenant), in.PeriodID, in.Quote.MaximumLiabilityMicroUSD())
		if err != nil {
			return err
		}
		result = AdmissionResult{ReservationID: in.ReservationID, PeriodID: in.PeriodID}
		if afterReserve != nil {
			return afterReserve(tx, result)
		}
		return nil
	})
	if err != nil {
		return AdmissionResult{}, err
	}
	return result, nil
}

// MarkUnknown records an ambiguous provider outcome while retaining its full reservation.
func (r *Repository) MarkUnknown(ctx context.Context, tenant tenancy.TenantID, inferenceID, source string) error {
	return r.finish(ctx, tenant, inferenceID, "unknown", 0, source, false)
}

// RecordEstimate appends a provisional usage estimate for an unknown attempt without changing
// committed or reserved counters. Estimates are evidence only; the complete reserve remains held.
func (r *Repository) RecordEstimate(ctx context.Context, tenant tenancy.TenantID, inferenceID string, amount int64, source string) error {
	if amount <= 0 || !budgetUUID.MatchString(string(tenant)) || !budgetUUID.MatchString(inferenceID) || len(source) < 1 || len(source) > 160 || strings.ContainsAny(source, "\r\n\x00") {
		return ErrBudgetConflict
	}
	return tenancy.WithTenantTx(ctx, r.db, tenant, nil, func(tx *sql.Tx) error {
		var attempt, state string
		if err := tx.QueryRowContext(ctx, `SELECT a.attempt_id::text,r.liability_state FROM keel_meta.ai_inference_admissions a JOIN keel_meta.ai_budget_reservations r USING(tenant_id,inference_id,attempt_id,period_id,scope) WHERE a.tenant_id=$1 AND a.inference_id=$2 FOR UPDATE OF r`, string(tenant), inferenceID).Scan(&attempt, &state); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrBudgetUnavailable
			}
			return err
		}
		var oldAmount int64
		var oldSource string
		err := tx.QueryRowContext(ctx, `SELECT amount_micro_usd,source_ref FROM keel_meta.ai_usage_ledger WHERE tenant_id=$1 AND attempt_id=$2 AND entry_kind='estimated'`, string(tenant), attempt).Scan(&oldAmount, &oldSource)
		if err == nil {
			if oldAmount == amount && oldSource == source {
				return nil
			}
			return ErrBudgetConflict
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if state != "unknown" {
			return ErrBudgetConflict
		}
		return appendLedger(ctx, tx, tenant, inferenceID, attempt, "estimated", amount, "estimated", source, "", "")
	})
}

// SettleConfirmed records actual cost in full, including overruns, and blocks further admission
// when the quote or hard period limit is exceeded. It never clamps a provider charge.
func (r *Repository) SettleConfirmed(ctx context.Context, tenant tenancy.TenantID, inferenceID string, actual int64, source string) error {
	if actual <= 0 {
		return ErrBudgetConflict
	}
	return r.finish(ctx, tenant, inferenceID, "confirmed", actual, source, false)
}

func (r *Repository) SettleNoCharge(ctx context.Context, tenant tenancy.TenantID, inferenceID, source string) error {
	return r.finish(ctx, tenant, inferenceID, "no_charge", 0, source, false)
}

// ReconcileUnknown is deliberately unavailable until a verified-identity authorizer is wired.
// The decision and reason are passed to the authorizer before any database mutation.
func (r *Repository) ReconcileUnknown(ctx context.Context, tenant tenancy.TenantID, inferenceID, actor, reason string, actual *int64, source string) error {
	if r.reconciler == nil || !principalRef.MatchString(actor) || !reasonCode.MatchString(reason) {
		return ErrReconciliationDenied
	}
	if actual != nil && *actual < 0 {
		return ErrBudgetConflict
	}
	decision := "no_charge"
	amount := int64(0)
	if actual != nil && *actual > 0 {
		decision, amount = "confirmed", *actual
	}
	if err := r.reconciler.AuthorizeBudgetReconciliation(ctx, tenant, inferenceID, actor, reason, source, decision, amount); err != nil {
		return fmt.Errorf("%w: %v", ErrReconciliationDenied, err)
	}
	if actual == nil {
		return r.finishAuthorized(ctx, tenant, inferenceID, "reconciliation", 0, source, true, actor, reason)
	}
	if *actual == 0 {
		return r.finishAuthorized(ctx, tenant, inferenceID, "reconciliation", 0, source, true, actor, reason)
	}
	return r.finishAuthorized(ctx, tenant, inferenceID, "reconciliation", *actual, source, true, actor, reason)
}

// AdjustSettled appends an authorized signed correction to a settled attempt. It preserves the
// original usage row, applies the delta to committed usage, and leaves an existing overrun block
// in place until RaiseLimitAndReopen explicitly approves recovery.
func (r *Repository) AdjustSettled(ctx context.Context, tenant tenancy.TenantID, inferenceID, actor, reason string, delta int64, source string) error {
	if r.reconciler == nil || !principalRef.MatchString(actor) || !reasonCode.MatchString(reason) || delta == 0 || !budgetUUID.MatchString(string(tenant)) || !budgetUUID.MatchString(inferenceID) || len(source) < 1 || len(source) > 160 || strings.ContainsAny(source, "\r\n\x00") {
		return ErrReconciliationDenied
	}
	if err := r.reconciler.AuthorizeBudgetReconciliation(ctx, tenant, inferenceID, actor, reason, source, "adjustment", delta); err != nil {
		return fmt.Errorf("%w: %v", ErrReconciliationDenied, err)
	}
	return tenancy.WithTenantTx(ctx, r.db, tenant, nil, func(tx *sql.Tx) error {
		var period, attempt, state string
		var committedText string
		var limit int64
		if err := tx.QueryRowContext(ctx, `SELECT a.period_id::text,a.attempt_id::text,r.liability_state,b.committed_micro_usd::text,b.hard_limit_micro_usd FROM keel_meta.ai_inference_admissions a JOIN keel_meta.ai_budget_reservations r USING(tenant_id,inference_id,attempt_id,period_id,scope) JOIN keel_meta.ai_budget_accounts b USING(tenant_id,period_id,scope) WHERE a.tenant_id=$1 AND a.inference_id=$2 FOR UPDATE OF r,b`, string(tenant), inferenceID).Scan(&period, &attempt, &state, &committedText, &limit); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrBudgetUnavailable
			}
			return err
		}
		var oldAmount int64
		var oldSource, oldActor, oldReason string
		err := tx.QueryRowContext(ctx, `SELECT amount_micro_usd,source_ref,reconciled_by,reason_code FROM keel_meta.ai_usage_ledger WHERE tenant_id=$1 AND attempt_id=$2 AND entry_kind='adjustment' AND source_ref=$3`, string(tenant), attempt, source).Scan(&oldAmount, &oldSource, &oldActor, &oldReason)
		if err == nil {
			if oldAmount == delta && oldSource == source && oldActor == actor && oldReason == reason {
				return nil
			}
			return ErrBudgetConflict
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if state != "settled" {
			return ErrBudgetConflict
		}
		committed, ok := parseCounter(committedText)
		if !ok {
			return ErrBudgetConflict
		}
		newCommitted := new(big.Int).Add(committed, big.NewInt(delta))
		if newCommitted.Sign() < 0 {
			return ErrBudgetConflict
		}
		_, err = tx.ExecContext(ctx, `UPDATE keel_meta.ai_budget_accounts SET committed_micro_usd=$3::numeric,overrun_blocked=overrun_blocked OR $4,version=version+1 WHERE tenant_id=$1 AND period_id=$2`, string(tenant), period, newCommitted.String(), newCommitted.Cmp(big.NewInt(limit)) > 0)
		if err != nil {
			return err
		}
		return appendLedger(ctx, tx, tenant, inferenceID, attempt, "adjustment", delta, "exact", source, actor, reason)
	})
}

func (r *Repository) finish(ctx context.Context, tenant tenancy.TenantID, inferenceID, kind string, amount int64, source string, reconciliation bool) error {
	return r.finishAuthorized(ctx, tenant, inferenceID, kind, amount, source, reconciliation, "", "")
}

func (r *Repository) finishAuthorized(ctx context.Context, tenant tenancy.TenantID, inferenceID, kind string, amount int64, source string, reconciliation bool, actor, reason string) error {
	if !budgetUUID.MatchString(string(tenant)) || !budgetUUID.MatchString(inferenceID) || len(source) < 1 || len(source) > 160 || strings.ContainsAny(source, "\r\n\x00") {
		return ErrBudgetConflict
	}
	return tenancy.WithTenantTx(ctx, r.db, tenant, nil, func(tx *sql.Tx) error {
		var period, attempt, state string
		var reservedAmount, maximum, limit int64
		var committedText, reservedText string
		err := tx.QueryRowContext(ctx, `SELECT a.period_id::text,a.attempt_id::text,a.max_liability_micro_usd,r.amount_micro_usd,r.liability_state,b.committed_micro_usd::text,b.reserved_micro_usd::text,b.hard_limit_micro_usd
			FROM keel_meta.ai_inference_admissions a JOIN keel_meta.ai_budget_reservations r USING(tenant_id,inference_id,attempt_id,period_id,scope)
			JOIN keel_meta.ai_budget_accounts b USING(tenant_id,period_id,scope)
			WHERE a.tenant_id=$1 AND a.inference_id=$2 FOR UPDATE OF r,b`, string(tenant), inferenceID).Scan(&period, &attempt, &maximum, &reservedAmount, &state, &committedText, &reservedText, &limit)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrBudgetUnavailable
		}
		if err != nil {
			return err
		}
		entryKind := kind
		if reconciliation {
			entryKind = "reconciliation"
		}
		var oldAmount int64
		var oldSource string
		err = tx.QueryRowContext(ctx, `SELECT amount_micro_usd,source_ref FROM keel_meta.ai_usage_ledger WHERE tenant_id=$1 AND attempt_id=$2 AND entry_kind=$3`, string(tenant), attempt, entryKind).Scan(&oldAmount, &oldSource)
		if err == nil {
			if oldAmount == amount && oldSource == source {
				return nil
			}
			return ErrBudgetConflict
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if reconciliation && state != "unknown" {
			return ErrBudgetConflict
		}
		if !reconciliation && kind == "unknown" && state != "reserved" {
			return ErrBudgetConflict
		}
		if !reconciliation && kind != "unknown" && state != "reserved" {
			return ErrBudgetConflict
		}
		if kind == "unknown" {
			if _, err = tx.ExecContext(ctx, `UPDATE keel_meta.ai_budget_reservations SET liability_state='unknown' WHERE tenant_id=$1 AND inference_id=$2`, string(tenant), inferenceID); err != nil {
				return err
			}
			return appendLedger(ctx, tx, tenant, inferenceID, attempt, "unknown", 0, "unknown", source, "", "")
		}
		committed, okC := parseCounter(committedText)
		reserved, okR := parseCounter(reservedText)
		if !okC || !okR {
			return ErrBudgetConflict
		}
		newCommitted := new(big.Int).Add(committed, big.NewInt(amount))
		newReserved := new(big.Int).Sub(reserved, big.NewInt(reservedAmount))
		if newReserved.Sign() < 0 {
			return ErrBudgetConflict
		}
		capacity := big.NewInt(limit)
		blocked := amount > maximum || newCommitted.Cmp(capacity) > 0 || new(big.Int).Add(new(big.Int).Set(newCommitted), newReserved).Cmp(capacity) > 0
		if _, err = tx.ExecContext(ctx, `UPDATE keel_meta.ai_budget_accounts SET committed_micro_usd=$3::numeric,reserved_micro_usd=$4::numeric,overrun_blocked=overrun_blocked OR $5,version=version+1 WHERE tenant_id=$1 AND period_id=$2`, string(tenant), period, newCommitted.String(), newReserved.String(), blocked); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE keel_meta.ai_budget_reservations SET liability_state='settled' WHERE tenant_id=$1 AND inference_id=$2`, string(tenant), inferenceID); err != nil {
			return err
		}
		if amount == 0 {
			return appendLedger(ctx, tx, tenant, inferenceID, attempt, entryKind, 0, "exact", source, actor, reason)
		}
		return appendLedger(ctx, tx, tenant, inferenceID, attempt, entryKind, amount, "exact", source, actor, reason)
	})
}

func appendLedger(ctx context.Context, tx *sql.Tx, tenant tenancy.TenantID, inference, attempt, kind string, amount int64, confidence, source, actor, reason string) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO keel_meta.ai_usage_ledger (tenant_id,entry_id,inference_id,attempt_id,entry_kind,amount_micro_usd,confidence,currency,source_ref,reconciled_by,reason_code) VALUES ($1,$2,$3,$4,$5,$6,$7,'USD',$8,NULLIF($9,''),NULLIF($10,''))`, string(tenant), uuid.NewString(), inference, attempt, kind, amount, confidence, source, actor, reason)
	return err
}
func validateAdmission(in Admission) error {
	if !budgetUUID.MatchString(string(in.Tenant)) || !budgetUUID.MatchString(in.PeriodID) || !budgetUUID.MatchString(in.InferenceID) || !budgetUUID.MatchString(in.AttemptID) || !budgetUUID.MatchString(in.ReservationID) || !principalRef.MatchString(in.PrincipalBinding) || !isSHA256(in.RequestDigest) || in.Quote.MaximumLiabilityMicroUSD() <= 0 || !isSHA256(in.Quote.Digest()) || !isSHA256(in.Quote.PolicyDigest()) || !isSHA256(in.Quote.RateCardDigest()) || in.PeriodStart.IsZero() || in.PeriodEnd.IsZero() || !in.PeriodStart.Before(in.PeriodEnd) {
		return ErrBudgetConflict
	}
	return nil
}
func isSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 32
}
func sameHash(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func parseCounter(raw string) (*big.Int, bool) {
	value, ok := new(big.Int).SetString(raw, 10)
	return value, ok && value.Sign() >= 0
}
func mapConflict(err error) error {
	if err == nil {
		return nil
	}
	if strings.Contains(strings.ToLower(err.Error()), "duplicate key") || strings.Contains(strings.ToLower(err.Error()), "unique constraint") {
		return ErrBudgetConflict
	}
	return err
}
