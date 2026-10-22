package budget

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

func TestPostgreSQLSpendAlertsUseQualifiedTenantHistory(t *testing.T) {
	appDSN, adminDSN := os.Getenv("KEEL_TEST_DATABASE_URL"), os.Getenv("KEEL_TEST_ADMIN_DATABASE_URL")
	if appDSN == "" || adminDSN == "" {
		t.Skip("set KEEL_TEST_DATABASE_URL and KEEL_TEST_ADMIN_DATABASE_URL for spend alert integration coverage")
	}
	app, admin := costTestDB(t, appDSN), costTestDB(t, adminDSN)
	ctx := context.Background()
	tenantID := uuid.NewString()
	tenant, err := tenancy.ParseTenantID(tenantID)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	currentStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)

	periods := []struct {
		committed int64
	}{
		{committed: 100}, {committed: 200}, {committed: 300},
	}
	previous := make([]string, 0, len(periods))
	for i, period := range periods {
		periodID := uuid.NewString()
		start := currentStart.AddDate(0, -(len(periods) - i), 0)
		if _, err := admin.ExecContext(ctx, `INSERT INTO keel_meta.ai_budget_accounts
			(tenant_id,period_id,scope,period_start,period_end,currency,hard_limit_micro_usd,committed_micro_usd,opening_committed_micro_usd)
			VALUES($1,$2,'inference',$3,$4,'USD',100000,$5,$5)`, tenantID, periodID, start, start.AddDate(0, 1, 0), period.committed); err != nil {
			t.Fatal(err)
		}
		previous = append(previous, periodID)
	}
	currentPeriod := uuid.NewString()
	if _, err := admin.ExecContext(ctx, `INSERT INTO keel_meta.ai_budget_accounts
		(tenant_id,period_id,scope,period_start,period_end,currency,hard_limit_micro_usd,committed_micro_usd,opening_committed_micro_usd)
		VALUES($1,$2,'inference',$3,$4,'USD',100000,$5,$5)`, tenantID, currentPeriod, currentStart, currentStart.AddDate(0, 1, 0), int64(1_000)); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.ExecContext(ctx, `INSERT INTO keel_meta.ai_budget_period_heads(tenant_id,scope,period_id)
		VALUES($1,'inference',$2)`, tenantID, currentPeriod); err != nil {
		t.Fatal(err)
	}

	reader, err := NewCostReader(app)
	if err != nil {
		t.Fatal(err)
	}
	breakdown, err := reader.CostBreakdown(ctx, tenant, currentPeriod)
	if err != nil {
		t.Fatalf("read breakdown: %v", err)
	}
	if breakdown.ConfirmedMicroUSD != 1_000 {
		t.Fatalf("settled spend was %d, want 1000", breakdown.ConfirmedMicroUSD)
	}
	history, err := reader.PeriodHistory(ctx, tenant, 10)
	if err != nil {
		t.Fatalf("read history: %v", err)
	}
	if len(history) != 4 {
		t.Fatalf("expected four historical periods, got %d: %+v", len(history), history)
	}
	if history[0].PeriodID != currentPeriod {
		t.Fatalf("history was not returned newest first: %+v", history)
	}

	policy := AlertPolicy{LimitWarningBasisPoints: 8_000, UnknownExposureBasisPoints: 5_000,
		ConfirmedThresholdMicroUSD: 500, AnomalyMultiplierBasisPoints: 20_000, MinimumHistoryPeriods: 3, MaximumAlerts: 8}
	evaluation, err := EvaluateSpendAlerts(policy, breakdown, history)
	if err != nil {
		t.Fatal(err)
	}
	if evaluation.Anomaly.Status != AnomalyQualified {
		t.Fatalf("anomaly status was %q", evaluation.Anomaly.Status)
	}
	if evaluation.Anomaly.BaselineMicroUSD != 200 {
		t.Fatalf("baseline was %d, want 200", evaluation.Anomaly.BaselineMicroUSD)
	}
	codes := map[string]int{}
	for _, alert := range evaluation.Alerts {
		codes[alert.Code]++
	}
	if codes[AlertSpendAnomaly] != 1 {
		t.Fatalf("a qualified anomaly was not raised: %+v", evaluation.Alerts)
	}
	if codes[AlertConfirmedThreshold] != 1 {
		t.Fatalf("the settled-spend threshold was not raised: %+v", evaluation.Alerts)
	}
	if codes[AlertLimitWarning] != 0 {
		t.Fatalf("a limit warning was raised far below the limit: %+v", evaluation.Alerts)
	}
}

func TestPostgreSQLSpendAlertsSkipTenantsWithoutHistory(t *testing.T) {
	appDSN, adminDSN := os.Getenv("KEEL_TEST_DATABASE_URL"), os.Getenv("KEEL_TEST_ADMIN_DATABASE_URL")
	if appDSN == "" || adminDSN == "" {
		t.Skip("set KEEL_TEST_DATABASE_URL and KEEL_TEST_ADMIN_DATABASE_URL for spend alert integration coverage")
	}
	app, admin := costTestDB(t, appDSN), costTestDB(t, adminDSN)
	ctx := context.Background()
	tenantID := uuid.NewString()
	tenant, err := tenancy.ParseTenantID(tenantID)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	start := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	periodID := uuid.NewString()
	if _, err := admin.ExecContext(ctx, `INSERT INTO keel_meta.ai_budget_accounts
		(tenant_id,period_id,scope,period_start,period_end,currency,hard_limit_micro_usd,committed_micro_usd,opening_committed_micro_usd)
		VALUES($1,$2,'inference',$3,$4,'USD',100000,$5,$5)`, tenantID, periodID, start, start.AddDate(0, 1, 0), int64(1_000)); err != nil {
		t.Fatal(err)
	}

	reader, err := NewCostReader(app)
	if err != nil {
		t.Fatal(err)
	}
	breakdown, err := reader.CostBreakdown(ctx, tenant, periodID)
	if err != nil {
		t.Fatalf("read breakdown: %v", err)
	}
	history, err := reader.PeriodHistory(ctx, tenant, 10)
	if err != nil {
		t.Fatalf("read history: %v", err)
	}
	policy := AlertPolicy{LimitWarningBasisPoints: 8_000, UnknownExposureBasisPoints: 5_000,
		ConfirmedThresholdMicroUSD: 500, AnomalyMultiplierBasisPoints: 20_000, MinimumHistoryPeriods: 3, MaximumAlerts: 8}
	evaluation, err := EvaluateSpendAlerts(policy, breakdown, history)
	if err != nil {
		t.Fatal(err)
	}
	if evaluation.Anomaly.Status != AnomalyInsufficientHistory {
		t.Fatalf("anomaly status was %q", evaluation.Anomaly.Status)
	}
	for _, alert := range evaluation.Alerts {
		if alert.Code == AlertSpendAnomaly {
			t.Fatalf("an anomaly was raised without history: %+v", evaluation.Alerts)
		}
	}
}
