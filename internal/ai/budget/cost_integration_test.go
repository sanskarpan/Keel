package budget

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

func costTestDB(t *testing.T, dsn string) *sql.DB {
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

// seedCostTenant provisions a budget account and its period head for one tenant.
func seedCostTenant(t *testing.T, admin *sql.DB, tenantID, periodID string, limit int64) {
	t.Helper()
	now := time.Now().UTC()
	periodStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	periodEnd := periodStart.AddDate(0, 1, 0)
	if _, err := admin.ExecContext(context.Background(), `INSERT INTO keel_meta.ai_budget_accounts
		(tenant_id,period_id,scope,period_start,period_end,currency,hard_limit_micro_usd)
		VALUES($1,$2,'inference',$3,$4,'USD',$5)`, tenantID, periodID, periodStart, periodEnd, limit); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.ExecContext(context.Background(), `INSERT INTO keel_meta.ai_budget_period_heads(tenant_id,scope,period_id)
		VALUES($1,'inference',$2)`, tenantID, periodID); err != nil {
		t.Fatal(err)
	}
}

func TestPostgreSQLCostBreakdownSeparatesCostClasses(t *testing.T) {
	appDSN, adminDSN := os.Getenv("KEEL_TEST_DATABASE_URL"), os.Getenv("KEEL_TEST_ADMIN_DATABASE_URL")
	if appDSN == "" || adminDSN == "" {
		t.Skip("set KEEL_TEST_DATABASE_URL and KEEL_TEST_ADMIN_DATABASE_URL for cost dashboard integration coverage")
	}
	app, admin := costTestDB(t, appDSN), costTestDB(t, adminDSN)
	ctx := context.Background()
	tenantID, periodID := uuid.NewString(), uuid.NewString()
	tenant, err := tenancy.ParseTenantID(tenantID)
	if err != nil {
		t.Fatal(err)
	}
	seedCostTenant(t, admin, tenantID, periodID, 1000)

	book, err := NewRateBook([]RateCard{testRateCard()})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	quote, err := book.QuoteWorstCase(testPolicySnapshot(t), now)
	if err != nil {
		t.Fatal(err)
	}
	liability := quote.MaximumLiabilityMicroUSD()
	repo, err := NewRepository(app, allowReconciliation{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	admit := func() string {
		t.Helper()
		inferenceID := uuid.NewString()
		periodStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
		_, err := repo.Admit(ctx, Admission{Tenant: tenant, PeriodID: periodID, InferenceID: inferenceID,
			AttemptID: uuid.NewString(), ReservationID: uuid.NewString(), PeriodStart: periodStart,
			PeriodEnd: periodStart.AddDate(0, 1, 0), PrincipalBinding: "principal:cost-test",
			RequestDigest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Quote: quote})
		if err != nil {
			t.Fatalf("admit for cost breakdown: %v", err)
		}
		return inferenceID
	}

	confirmed := admit()
	unknown := admit()
	admit() // admitted and never settled: outstanding exposure
	if err := repo.SettleConfirmed(ctx, tenant, confirmed, 5, "provider-charge:cost-fixture"); err != nil {
		t.Fatalf("settle confirmed: %v", err)
	}
	if err := repo.MarkUnknown(ctx, tenant, unknown, "provider-observation:cost-fixture"); err != nil {
		t.Fatalf("mark unknown: %v", err)
	}
	if err := repo.RecordEstimate(ctx, tenant, unknown, 6, "provider-usage-estimate:cost-fixture"); err != nil {
		t.Fatalf("record estimate: %v", err)
	}

	reader, err := NewCostReader(app)
	if err != nil {
		t.Fatal(err)
	}
	breakdown, err := reader.CostBreakdown(ctx, tenant, periodID)
	if err != nil {
		t.Fatalf("read cost breakdown: %v", err)
	}
	if breakdown.ConfirmedMicroUSD != 5 {
		t.Fatalf("confirmed cost was %d, want 5", breakdown.ConfirmedMicroUSD)
	}
	if breakdown.EstimatedMicroUSD != 6 {
		t.Fatalf("estimated cost was %d, want 6", breakdown.EstimatedMicroUSD)
	}
	if breakdown.UnknownMicroUSD != liability {
		t.Fatalf("unknown exposure was %d, want %d", breakdown.UnknownMicroUSD, liability)
	}
	if breakdown.OutstandingMicroUSD != liability {
		t.Fatalf("outstanding exposure was %d, want %d", breakdown.OutstandingMicroUSD, liability)
	}
	if breakdown.HardLimitMicroUSD != 1000 || breakdown.Currency != "USD" || breakdown.Scope != CostScopeInference {
		t.Fatalf("unexpected account facts: %+v", breakdown)
	}
	if breakdown.OverrunBlocked {
		t.Fatal("a tenant inside its limit was reported as blocked")
	}
	if breakdown.Watermark.Entries != 3 {
		t.Fatalf("watermark counted %d ledger entries, want 3", breakdown.Watermark.Entries)
	}
	if breakdown.Watermark.AccountVersion == 0 || breakdown.Watermark.LastEntryAt.IsZero() {
		t.Fatalf("watermark did not advance: %+v", breakdown.Watermark)
	}

	entries, err := reader.CostEntries(ctx, tenant, periodID, 10)
	if err != nil {
		t.Fatalf("read cost entries: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected three cost entries, got %d: %+v", len(entries), entries)
	}
	states := map[string]CostEntry{}
	for _, entry := range entries {
		states[entry.LiabilityState] = entry
	}
	if entry, ok := states["settled"]; !ok || entry.ConfirmedMicroUSD != 5 {
		t.Fatalf("settled entry was not confirmed: %+v", entry)
	}
	if entry, ok := states["unknown"]; !ok || entry.UnknownMicroUSD != liability || entry.EstimatedMicroUSD != 6 {
		t.Fatalf("unknown entry was not classified: %+v", entry)
	}
	if entry, ok := states["reserved"]; !ok || entry.ReservedMicroUSD != liability {
		t.Fatalf("reserved entry was not classified: %+v", entry)
	}
}

func TestPostgreSQLCostBreakdownIsTenantScoped(t *testing.T) {
	appDSN, adminDSN := os.Getenv("KEEL_TEST_DATABASE_URL"), os.Getenv("KEEL_TEST_ADMIN_DATABASE_URL")
	if appDSN == "" || adminDSN == "" {
		t.Skip("set KEEL_TEST_DATABASE_URL and KEEL_TEST_ADMIN_DATABASE_URL for cost dashboard integration coverage")
	}
	app, admin := costTestDB(t, appDSN), costTestDB(t, adminDSN)
	ctx := context.Background()
	ownerID, ownerPeriod := uuid.NewString(), uuid.NewString()
	owner, err := tenancy.ParseTenantID(ownerID)
	if err != nil {
		t.Fatal(err)
	}
	seedCostTenant(t, admin, ownerID, ownerPeriod, 1000)
	otherID, otherPeriod := uuid.NewString(), uuid.NewString()
	other, err := tenancy.ParseTenantID(otherID)
	if err != nil {
		t.Fatal(err)
	}
	seedCostTenant(t, admin, otherID, otherPeriod, 1000)

	book, err := NewRateBook([]RateCard{testRateCard()})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	quote, err := book.QuoteWorstCase(testPolicySnapshot(t), now)
	if err != nil {
		t.Fatal(err)
	}
	repo, err := NewRepository(app, allowReconciliation{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	periodStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	inferenceID := uuid.NewString()
	if _, err := repo.Admit(ctx, Admission{Tenant: owner, PeriodID: ownerPeriod, InferenceID: inferenceID,
		AttemptID: uuid.NewString(), ReservationID: uuid.NewString(), PeriodStart: periodStart,
		PeriodEnd: periodStart.AddDate(0, 1, 0), PrincipalBinding: "principal:cost-test",
		RequestDigest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Quote: quote}); err != nil {
		t.Fatalf("admit for isolation check: %v", err)
	}

	reader, err := NewCostReader(app)
	if err != nil {
		t.Fatal(err)
	}
	otherBreakdown, err := reader.CostBreakdown(ctx, other, "")
	if err != nil {
		t.Fatalf("read other tenant breakdown: %v", err)
	}
	if otherBreakdown.ConfirmedMicroUSD != 0 || otherBreakdown.EstimatedMicroUSD != 0 ||
		otherBreakdown.UnknownMicroUSD != 0 || otherBreakdown.OutstandingMicroUSD != 0 {
		t.Fatalf("another tenant's cost leaked into the breakdown: %+v", otherBreakdown)
	}
	otherEntries, err := reader.CostEntries(ctx, other, "", 10)
	if err != nil {
		t.Fatalf("read other tenant entries: %v", err)
	}
	if len(otherEntries) != 0 {
		t.Fatalf("another tenant's cost entries leaked: %+v", otherEntries)
	}
	if _, err := reader.CostBreakdown(ctx, other, ownerPeriod); !errors.Is(err, ErrCostUnavailable) {
		t.Fatalf("reading another tenant's period returned %v", err)
	}
}

func TestPostgreSQLCostBreakdownRejectsUnknownPeriod(t *testing.T) {
	appDSN := os.Getenv("KEEL_TEST_DATABASE_URL")
	if appDSN == "" {
		t.Skip("set KEEL_TEST_DATABASE_URL for cost dashboard integration coverage")
	}
	app := costTestDB(t, appDSN)
	ctx := context.Background()
	tenant, err := tenancy.ParseTenantID(uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	reader, err := NewCostReader(app)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reader.CostBreakdown(ctx, tenant, uuid.NewString()); !errors.Is(err, ErrCostUnavailable) {
		t.Fatalf("a missing period returned %v", err)
	}
	if _, err := reader.CostEntries(ctx, tenant, uuid.NewString(), 10); !errors.Is(err, ErrCostUnavailable) {
		t.Fatalf("a missing period returned %v", err)
	}
}
