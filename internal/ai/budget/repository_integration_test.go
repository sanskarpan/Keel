package budget

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

type allowReconciliation struct{}

func (allowReconciliation) AuthorizeBudgetReconciliation(_ context.Context, _ tenancy.TenantID, _ string, _ string, _ string, _ string, _ string, _ int64) error {
	return nil
}

type allowBudgetControl struct{}

func (allowBudgetControl) AuthorizeBudgetLimitChange(_ context.Context, _ tenancy.TenantID, _ string, _ string, _ string, _ int64) error {
	return nil
}

func TestPostgreSQLBudgetAdmissionUnknownAndReconciliation(t *testing.T) {
	appDSN, adminDSN, controlDSN := os.Getenv("KEEL_TEST_DATABASE_URL"), os.Getenv("KEEL_TEST_ADMIN_DATABASE_URL"), os.Getenv("KEEL_TEST_BUDGET_CONTROL_DATABASE_URL")
	if appDSN == "" || adminDSN == "" {
		t.Skip("set KEEL_TEST_DATABASE_URL and KEEL_TEST_ADMIN_DATABASE_URL for budget PostgreSQL integration coverage")
	}
	open := func(dsn string) *sql.DB {
		t.Helper()
		parsed, err := url.Parse(dsn)
		if err != nil {
			t.Fatal(err)
		}
		db, err := sql.Open("pgx", parsed.String())
		if err != nil {
			t.Fatal(err)
		}
		db.SetMaxOpenConns(4)
		db.SetMaxIdleConns(4)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err = db.PingContext(ctx); err != nil {
			_ = db.Close()
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		return db
	}
	app, admin := open(appDSN), open(adminDSN)
	if controlDSN == "" {
		t.Fatal("KEEL_TEST_BUDGET_CONTROL_DATABASE_URL is required for budget recovery integration coverage")
	}
	control := open(controlDSN)
	ctx := context.Background()
	tenantID, periodID := uuid.NewString(), uuid.NewString()
	tenant, err := tenancy.ParseTenantID(tenantID)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	periodStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	periodEnd := periodStart.AddDate(0, 1, 0)
	if _, err = admin.ExecContext(ctx, `INSERT INTO keel_meta.ai_budget_accounts(tenant_id,period_id,scope,period_start,period_end,currency,hard_limit_micro_usd) VALUES($1,$2,'inference',$3,$4,'USD',20)`, tenantID, periodID, periodStart, periodEnd); err != nil {
		t.Fatal(err)
	}
	if _, err = admin.ExecContext(ctx, `INSERT INTO keel_meta.ai_budget_period_heads(tenant_id,scope,period_id) VALUES($1,'inference',$2)`, tenantID, periodID); err != nil {
		t.Fatal(err)
	}
	nextPeriodID := uuid.NewString()
	if _, err = admin.ExecContext(ctx, `INSERT INTO keel_meta.ai_budget_accounts(tenant_id,period_id,scope,period_start,period_end,currency,hard_limit_micro_usd) VALUES($1,$2,'inference',$3,$4,'USD',20)`, tenantID, nextPeriodID, periodEnd, periodEnd.AddDate(0, 1, 0)); err != nil {
		t.Fatal(err)
	}
	overlappingPeriodID := uuid.NewString()
	if _, err = admin.ExecContext(ctx, `INSERT INTO keel_meta.ai_budget_accounts(tenant_id,period_id,scope,period_start,period_end,currency,hard_limit_micro_usd) VALUES($1,$2,'inference',$3,$4,'USD',20)`, tenantID, overlappingPeriodID, periodStart, periodEnd); err != nil {
		t.Fatal(err)
	}
	book, err := NewRateBook([]RateCard{testRateCard()})
	if err != nil {
		t.Fatal(err)
	}
	quote, err := book.QuoteWorstCase(testPolicySnapshot(t), now)
	if err != nil {
		t.Fatal(err)
	}
	repo, err := NewRepository(app, allowReconciliation{}, control, allowBudgetControl{})
	if err != nil {
		t.Fatal(err)
	}
	// The app role intentionally cannot take a row lock by reading the raw
	// period-head table; it must use the tenant-checking definer function.
	err = tenancy.WithTenantTx(ctx, app, tenant, nil, func(tx *sql.Tx) error {
		var lockedPeriod string
		return tx.QueryRowContext(ctx, `SELECT period_id::text FROM keel_meta.ai_budget_period_heads WHERE tenant_id=$1 AND scope='inference' FOR SHARE`, tenantID).Scan(&lockedPeriod)
	})
	if err == nil {
		t.Fatal("application role directly row-locked the period head")
	}
	lockMismatchTenant, _ := tenancy.ParseTenantID(uuid.NewString())
	err = tenancy.WithTenantTx(ctx, app, tenant, nil, func(tx *sql.Tx) error {
		var period string
		return tx.QueryRowContext(ctx, `SELECT period_id::text FROM keel_meta.lock_ai_budget_period($1)`, string(lockMismatchTenant)).Scan(&period)
	})
	if err == nil {
		t.Fatal("period-lock function accepted a tenant other than the transaction context")
	}
	missingTenant, _ := tenancy.ParseTenantID(uuid.NewString())
	err = tenancy.WithTenantTx(ctx, app, missingTenant, nil, func(tx *sql.Tx) error {
		var period string
		return tx.QueryRowContext(ctx, `SELECT period_id::text FROM keel_meta.lock_ai_budget_period($1)`, string(missingTenant)).Scan(&period)
	})
	if !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("missing period head should return no row, got %v", err)
	}
	requestDigest := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	makeAdmission := func() Admission {
		return Admission{Tenant: tenant, PeriodID: periodID, InferenceID: uuid.NewString(), AttemptID: uuid.NewString(), ReservationID: uuid.NewString(), PeriodStart: periodStart, PeriodEnd: periodEnd, PrincipalBinding: "principal:integration-test", RequestDigest: requestDigest, Quote: quote}
	}
	const contenders = 8
	inputs := make([]Admission, contenders)
	for i := range inputs {
		inputs[i] = makeAdmission()
	}
	results := make([]AdmissionResult, contenders)
	errs := make([]error, contenders)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range inputs {
		wg.Add(1)
		go func(i int) { defer wg.Done(); <-start; results[i], errs[i] = repo.Admit(ctx, inputs[i]) }(i)
	}
	close(start)
	wg.Wait()
	admittedIndex := -1
	for i, admitErr := range errs {
		if admitErr == nil {
			if admittedIndex >= 0 {
				t.Fatal("concurrent budget admissions overspent the period")
			}
			admittedIndex = i
		} else if !errors.Is(admitErr, ErrBudgetDenied) {
			t.Fatalf("concurrent admission %d: %v", i, admitErr)
		}
	}
	if admittedIndex < 0 {
		t.Fatal("no concurrent admission was accepted")
	}
	in := inputs[admittedIndex]
	admitted := results[admittedIndex]
	replayed, err := repo.Admit(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	if !replayed.Replayed || replayed.ReservationID != admitted.ReservationID {
		t.Fatalf("admission replay mismatch: %#v %#v", admitted, replayed)
	}
	second := makeAdmission()
	if _, err = repo.Admit(ctx, second); !errors.Is(err, ErrBudgetDenied) {
		t.Fatalf("over-limit admission error=%v, want ErrBudgetDenied", err)
	}
	overlap := makeAdmission()
	overlap.PeriodID = overlappingPeriodID
	if _, err = repo.Admit(ctx, overlap); !errors.Is(err, ErrBudgetDenied) {
		t.Fatalf("unselected overlapping period bypassed the active cap: %v", err)
	}
	oldQuote, err := book.QuoteWorstCase(testPolicySnapshot(t), now.Add(-maxQuoteAge-time.Second))
	if err != nil {
		t.Fatal(err)
	}
	staleQuote := makeAdmission()
	staleQuote.Quote = oldQuote
	if _, err = repo.Admit(ctx, staleQuote); !errors.Is(err, ErrQuoteRejected) {
		t.Fatalf("stale quote admission error=%v, want ErrQuoteRejected", err)
	}
	stale := makeAdmission()
	stale.PeriodID = nextPeriodID
	stale.PeriodStart = periodEnd
	stale.PeriodEnd = periodEnd.AddDate(0, 1, 0)
	if _, err = admin.ExecContext(ctx, `UPDATE keel_meta.ai_budget_period_heads SET period_id=$2,updated_at=clock_timestamp() WHERE tenant_id=$1 AND scope='inference'`, tenantID, nextPeriodID); err != nil {
		t.Fatal(err)
	}
	if _, err = repo.Admit(ctx, stale); !errors.Is(err, ErrQuoteRejected) {
		t.Fatalf("future period admission error=%v, want ErrQuoteRejected", err)
	}
	if _, err = admin.ExecContext(ctx, `UPDATE keel_meta.ai_budget_period_heads SET period_id=$2,updated_at=clock_timestamp() WHERE tenant_id=$1 AND scope='inference'`, tenantID, periodID); err != nil {
		t.Fatal(err)
	}
	// A uniqueness conflict after admission insertion must roll the whole transaction back.
	conflictingAttempt := makeAdmission()
	conflictingAttempt.AttemptID = in.AttemptID
	if _, err = repo.Admit(ctx, conflictingAttempt); err == nil {
		t.Fatal("attempt ID reuse was accepted")
	}
	var committed, reserved int64
	if err = tenancy.WithTenantTx(ctx, app, tenant, nil, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT committed_micro_usd,reserved_micro_usd FROM keel_meta.ai_budget_accounts WHERE tenant_id=$1 AND period_id=$2`, tenantID, periodID).Scan(&committed, &reserved)
	}); err != nil {
		t.Fatal(err)
	}
	if committed != 0 || reserved != quote.MaximumLiabilityMicroUSD() {
		t.Fatalf("failed admission left partial counters: committed=%d reserved=%d", committed, reserved)
	}
	if err = repo.MarkUnknown(ctx, tenant, in.InferenceID, "provider-observation:opaque-1"); err != nil {
		t.Fatal(err)
	}
	if err = repo.MarkUnknown(ctx, tenant, in.InferenceID, "provider-observation:opaque-1"); err != nil {
		t.Fatalf("same unknown observation should be idempotent: %v", err)
	}
	if err = repo.RecordEstimate(ctx, tenant, in.InferenceID, 6, "provider-usage-estimate:opaque-1"); err != nil {
		t.Fatal(err)
	}
	if err = repo.RecordEstimate(ctx, tenant, in.InferenceID, 6, "provider-usage-estimate:opaque-1"); err != nil {
		t.Fatalf("same estimate should be idempotent: %v", err)
	}
	if err = repo.SettleConfirmed(ctx, tenant, in.InferenceID, 5, "late-provider-reply:opaque-1"); !errors.Is(err, ErrBudgetConflict) {
		t.Fatalf("unknown attempt bypassed authorized reconciliation: %v", err)
	}
	if err = tenancy.WithTenantTx(ctx, app, tenant, nil, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT reserved_micro_usd FROM keel_meta.ai_budget_accounts WHERE tenant_id=$1 AND period_id=$2`, tenantID, periodID).Scan(&reserved)
	}); err != nil {
		t.Fatal(err)
	}
	if reserved != quote.MaximumLiabilityMicroUSD() {
		t.Fatalf("unknown outcome released reservation: got %d", reserved)
	}
	actual := int64(25)
	if err = repo.ReconcileUnknown(ctx, tenant, in.InferenceID, "principal:integration-test", "provider_invoice_confirmed", &actual, "invoice-observation:opaque-2"); err != nil {
		t.Fatal(err)
	}
	if err = repo.ReconcileUnknown(ctx, tenant, in.InferenceID, "principal:integration-test", "provider_invoice_confirmed", &actual, "invoice-observation:opaque-2"); err != nil {
		t.Fatalf("same reconciliation should be idempotent: %v", err)
	}
	committed = 0
	var blocked int64
	var isBlocked bool
	if err = tenancy.WithTenantTx(ctx, app, tenant, nil, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT committed_micro_usd,reserved_micro_usd,CASE WHEN overrun_blocked THEN 1 ELSE 0 END FROM keel_meta.ai_budget_accounts WHERE tenant_id=$1 AND period_id=$2`, tenantID, periodID).Scan(&committed, &reserved, &blocked)
	}); err != nil {
		t.Fatal(err)
	}
	isBlocked = blocked == 1
	if committed != actual || reserved != 0 || !isBlocked {
		t.Fatalf("overrun was clamped or failed to block admission: committed=%d reserved=%d blocked=%v", committed, reserved, isBlocked)
	}
	if _, err = repo.Admit(ctx, second); !errors.Is(err, ErrBudgetDenied) {
		t.Fatalf("overrun did not block new admission: %v", err)
	}
	if err = tenancy.WithTenantTx(ctx, app, tenant, nil, func(tx *sql.Tx) error {
		_, e := tx.ExecContext(ctx, `UPDATE keel_meta.ai_budget_accounts SET overrun_blocked=false WHERE tenant_id=$1 AND period_id=$2`, tenantID, periodID)
		return e
	}); err == nil {
		t.Fatal("normal app role cleared an overrun block")
	}
	if err = tenancy.WithTenantTx(ctx, app, tenant, nil, func(tx *sql.Tx) error {
		_, e := tx.ExecContext(ctx, `UPDATE keel_meta.ai_budget_accounts SET hard_limit_micro_usd=100 WHERE tenant_id=$1 AND period_id=$2`, tenantID, periodID)
		return e
	}); err == nil {
		t.Fatal("normal app role changed the hard limit")
	}
	if err = tenancy.WithTenantTx(ctx, control, tenant, nil, func(tx *sql.Tx) error {
		_, e := tx.ExecContext(ctx, `UPDATE keel_meta.ai_budget_accounts SET overrun_blocked=false WHERE tenant_id=$1 AND period_id=$2`, tenantID, periodID)
		return e
	}); err == nil {
		t.Fatal("budget-control role bypassed the recovery routine")
	}
	if err = tenancy.WithTenantTx(ctx, control, tenant, nil, func(tx *sql.Tx) error {
		_, e := tx.ExecContext(ctx, `UPDATE keel_meta.ai_budget_accounts SET hard_limit_micro_usd=100 WHERE tenant_id=$1 AND period_id=$2`, tenantID, periodID)
		return e
	}); err == nil {
		t.Fatal("budget-control role bypassed the audited top-up function")
	}
	if err = tenancy.WithTenantTx(ctx, control, tenant, nil, func(tx *sql.Tx) error {
		_, e := tx.ExecContext(ctx, `INSERT INTO keel_meta.ai_budget_control_events(tenant_id,event_id,period_id,scope,actor_ref,reason_code,previous_limit_micro_usd,new_limit_micro_usd) VALUES($1,$2,$3,'inference','principal:integration-test','manual_override',20,50)`, tenantID, uuid.NewString(), periodID)
		return e
	}); err == nil {
		t.Fatal("budget-control role forged a control event")
	}
	if err = repo.AdjustSettled(ctx, tenant, in.InferenceID, "principal:integration-test", "invoice_correction", 2, "credit-note:opaque-1"); err != nil {
		t.Fatal(err)
	}
	if err = repo.AdjustSettled(ctx, tenant, in.InferenceID, "principal:integration-test", "invoice_correction", 2, "credit-note:opaque-1"); err != nil {
		t.Fatalf("same usage adjustment should be idempotent: %v", err)
	}
	if err = tenancy.WithTenantTx(ctx, app, tenant, nil, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT committed_micro_usd FROM keel_meta.ai_budget_accounts WHERE tenant_id=$1 AND period_id=$2`, tenantID, periodID).Scan(&committed)
	}); err != nil {
		t.Fatal(err)
	}
	if committed != actual+2 {
		t.Fatalf("append-only adjustment not reflected in committed total: got %d want %d", committed, actual+2)
	}
	if err = repo.AdjustSettled(ctx, tenant, in.InferenceID, "principal:integration-test", "invalid_refund", -100, "refund:underflow"); !errors.Is(err, ErrBudgetConflict) {
		t.Fatalf("negative adjustment below zero was accepted: %v", err)
	}
	if err = repo.AdjustSettled(ctx, tenant, in.InferenceID, "principal:integration-test", "provider_credit_confirmed", -2, "credit-note:opaque-2"); err != nil {
		t.Fatalf("valid negative adjustment failed: %v", err)
	}
	topUpID := uuid.NewString()
	if err = repo.RaiseLimitAndReopen(ctx, tenant, periodID, topUpID, "principal:integration-test", "operator_top_up", 50); err != nil {
		t.Fatal(err)
	}
	if err = repo.RaiseLimitAndReopen(ctx, tenant, periodID, topUpID, "principal:integration-test", "operator_top_up", 50); err != nil {
		t.Fatalf("same top-up retry should replay: %v", err)
	}
	if _, err = repo.Admit(ctx, second); err != nil {
		t.Fatalf("authorized top-up did not reopen account: %v", err)
	}
	if _, err = repo.Admit(ctx, second); err != nil {
		t.Fatalf("top-up retry should return the same reservation: %v", err)
	}
	var reconciledBy, reason string
	if err = tenancy.WithTenantTx(ctx, app, tenant, nil, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT reconciled_by,reason_code FROM keel_meta.ai_usage_ledger WHERE tenant_id=$1 AND inference_id=$2 AND entry_kind='reconciliation'`, tenantID, in.InferenceID).Scan(&reconciledBy, &reason)
	}); err != nil {
		t.Fatal(err)
	}
	if reconciledBy != "principal:integration-test" || reason != "provider_invoice_confirmed" {
		t.Fatalf("missing reconciliation attribution: actor=%q reason=%q", reconciledBy, reason)
	}
	// The unknown reservation remains attributed to its original period after rollover.
	if err = tenancy.WithTenantTx(ctx, app, tenant, nil, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT reserved_micro_usd FROM keel_meta.ai_budget_accounts WHERE tenant_id=$1 AND period_id=$2`, tenantID, nextPeriodID).Scan(&reserved)
	}); err != nil {
		t.Fatal(err)
	}
	if reserved != 0 {
		t.Fatalf("settlement was charged to the next period: reserved=%d", reserved)
	}
	otherTenant, _ := tenancy.ParseTenantID(uuid.NewString())
	var visible int
	if err = tenancy.WithTenantTx(ctx, app, otherTenant, nil, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT count(*) FROM keel_meta.ai_usage_ledger WHERE tenant_id=$1`, tenantID).Scan(&visible)
	}); err != nil {
		t.Fatal(err)
	}
	if visible != 0 {
		t.Fatalf("cross-tenant usage rows visible: %d", visible)
	}
	if _, err = admin.ExecContext(ctx, `UPDATE keel_meta.ai_usage_ledger SET amount_micro_usd=0 WHERE tenant_id=$1 AND inference_id=$2`, tenantID, in.InferenceID); err == nil {
		t.Fatal("ledger row update was not rejected")
	}
	if _, err = admin.ExecContext(ctx, `DELETE FROM keel_meta.ai_usage_ledger WHERE tenant_id=$1 AND inference_id=$2`, tenantID, in.InferenceID); err == nil {
		t.Fatal("ledger row deletion was not rejected")
	}
	var controlEvents int
	if err = tenancy.WithTenantTx(ctx, control, tenant, nil, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT count(*) FROM keel_meta.ai_budget_control_events WHERE tenant_id=$1 AND period_id=$2`, tenantID, periodID).Scan(&controlEvents)
	}); err != nil {
		t.Fatal(err)
	}
	if controlEvents != 1 {
		t.Fatalf("top-up audit event count=%d, want 1", controlEvents)
	}
	var adjustmentAmount int64
	if err = tenancy.WithTenantTx(ctx, app, tenant, nil, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT amount_micro_usd FROM keel_meta.ai_usage_ledger WHERE tenant_id=$1 AND inference_id=$2 AND entry_kind='adjustment' AND source_ref='credit-note:opaque-1'`, tenantID, in.InferenceID).Scan(&adjustmentAmount)
	}); err != nil {
		t.Fatal(err)
	}
	if adjustmentAmount != 2 {
		t.Fatalf("append-only adjustment amount=%d", adjustmentAmount)
	}
	var estimateConfidence string
	if err = tenancy.WithTenantTx(ctx, app, tenant, nil, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT confidence FROM keel_meta.ai_usage_ledger WHERE tenant_id=$1 AND inference_id=$2 AND entry_kind='estimated'`, tenantID, in.InferenceID).Scan(&estimateConfidence)
	}); err != nil {
		t.Fatal(err)
	}
	if estimateConfidence != "estimated" {
		t.Fatalf("usage estimate confidence=%q", estimateConfidence)
	}
	if _, err = admin.ExecContext(ctx, `UPDATE keel_meta.ai_budget_period_heads SET period_id=$2,updated_at=clock_timestamp() WHERE tenant_id=$1 AND scope='inference'`, tenantID, nextPeriodID); err != nil {
		t.Fatal(err)
	}
	if result, err := repo.Admit(ctx, in); err != nil || !result.Replayed {
		t.Fatalf("old-period admission replay failed after rollover: result=%#v error=%v", result, err)
	}
	// Cumulative totals use PostgreSQL numeric counters so an individually valid charge is still
	// recorded when it takes the tenant total past signed 64-bit range.
	overflowTenantID, overflowPeriodID := uuid.NewString(), uuid.NewString()
	overflowTenant, _ := tenancy.ParseTenantID(overflowTenantID)
	maxInt64 := "9223372036854775807"
	if _, err = admin.ExecContext(ctx, `INSERT INTO keel_meta.ai_budget_accounts(tenant_id,period_id,scope,period_start,period_end,currency,hard_limit_micro_usd,committed_micro_usd) VALUES($1,$2,'inference',$3,$4,'USD',$5::bigint,$5::numeric-14)`, overflowTenantID, overflowPeriodID, periodStart, periodEnd, maxInt64); err != nil {
		t.Fatal(err)
	}
	if _, err = admin.ExecContext(ctx, `INSERT INTO keel_meta.ai_budget_period_heads(tenant_id,scope,period_id) VALUES($1,'inference',$2)`, overflowTenantID, overflowPeriodID); err != nil {
		t.Fatal(err)
	}
	overflowAdmission := Admission{Tenant: overflowTenant, PeriodID: overflowPeriodID, InferenceID: uuid.NewString(), AttemptID: uuid.NewString(), ReservationID: uuid.NewString(), PeriodStart: periodStart, PeriodEnd: periodEnd, PrincipalBinding: "principal:integration-test", RequestDigest: requestDigest, Quote: quote}
	if _, err = repo.Admit(ctx, overflowAdmission); err != nil {
		t.Fatalf("near-limit reservation failed: %v", err)
	}
	if err = repo.SettleConfirmed(ctx, overflowTenant, overflowAdmission.InferenceID, 25, "provider-charge:overflow-fixture"); err != nil {
		t.Fatalf("valid charge was rejected when cumulative counter exceeded int64: %v", err)
	}
	var cumulative string
	if err = admin.QueryRowContext(ctx, `SELECT committed_micro_usd::text FROM keel_meta.ai_budget_accounts WHERE tenant_id=$1 AND period_id=$2`, overflowTenantID, overflowPeriodID).Scan(&cumulative); err != nil {
		t.Fatal(err)
	}
	if cumulative != "9223372036854775818" {
		t.Fatalf("cumulative confirmed amount=%s, expected value beyond int64", cumulative)
	}
}
