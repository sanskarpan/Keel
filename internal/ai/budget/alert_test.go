package budget

import (
	"errors"
	"testing"

	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

func testAlertPolicy() AlertPolicy {
	return AlertPolicy{
		LimitWarningBasisPoints:      8_000,
		UnknownExposureBasisPoints:   5_000,
		ConfirmedThresholdMicroUSD:   1_000,
		AnomalyMultiplierBasisPoints: 20_000,
		MinimumHistoryPeriods:        3,
		MaximumAlerts:                8,
	}
}

func testCostBreakdown() CostBreakdown {
	return CostBreakdown{
		TenantID: tenancy.TenantID("11111111-1111-4111-8111-111111111111"),
		Scope:    CostScopeInference,
		PeriodID: "22222222-2222-4222-8222-222222222222",
		Currency: "USD",
	}
}

func TestAlertPolicyRejectsUnusableThresholds(t *testing.T) {
	cases := map[string]AlertPolicy{
		"zero warning ratio":      {LimitWarningBasisPoints: 0, UnknownExposureBasisPoints: 5_000, AnomalyMultiplierBasisPoints: 20_000, MinimumHistoryPeriods: 3, MaximumAlerts: 8},
		"ratio above one":         {LimitWarningBasisPoints: 10_001, UnknownExposureBasisPoints: 5_000, AnomalyMultiplierBasisPoints: 20_000, MinimumHistoryPeriods: 3, MaximumAlerts: 8},
		"negative spend limit":    {LimitWarningBasisPoints: 8_000, UnknownExposureBasisPoints: 5_000, ConfirmedThresholdMicroUSD: -1, AnomalyMultiplierBasisPoints: 20_000, MinimumHistoryPeriods: 3, MaximumAlerts: 8},
		"no history requirement":  {LimitWarningBasisPoints: 8_000, UnknownExposureBasisPoints: 5_000, AnomalyMultiplierBasisPoints: 20_000, MinimumHistoryPeriods: 0, MaximumAlerts: 8},
		"unbounded alert count":   {LimitWarningBasisPoints: 8_000, UnknownExposureBasisPoints: 5_000, AnomalyMultiplierBasisPoints: 20_000, MinimumHistoryPeriods: 3, MaximumAlerts: 99},
		"unbounded multiplier":    {LimitWarningBasisPoints: 8_000, UnknownExposureBasisPoints: 5_000, AnomalyMultiplierBasisPoints: 100_001, MinimumHistoryPeriods: 3, MaximumAlerts: 8},
		"single times multiplier": {LimitWarningBasisPoints: 8_000, UnknownExposureBasisPoints: 5_000, AnomalyMultiplierBasisPoints: 10_000, MinimumHistoryPeriods: 3, MaximumAlerts: 8},
		"unbounded unknown ratio": {LimitWarningBasisPoints: 8_000, UnknownExposureBasisPoints: 10_001, AnomalyMultiplierBasisPoints: 20_000, MinimumHistoryPeriods: 3, MaximumAlerts: 8},
	}
	for name, policy := range cases {
		t.Run(name, func(t *testing.T) {
			if err := policy.Validate(); !errors.Is(err, ErrAlertPolicy) {
				t.Fatalf("policy was accepted: %v", err)
			}
			if _, err := policy.Digest(); !errors.Is(err, ErrAlertPolicy) {
				t.Fatalf("policy digest was produced: %v", err)
			}
		})
	}
}

func TestAlertPolicyDigestIsStableAndBound(t *testing.T) {
	policy := testAlertPolicy()
	first, err := policy.Digest()
	if err != nil {
		t.Fatal(err)
	}
	second, err := policy.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("policy digest is not stable: %q != %q", first, second)
	}
	changed := policy
	changed.ConfirmedThresholdMicroUSD = policy.ConfirmedThresholdMicroUSD + 1
	other, err := changed.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if other == first {
		t.Fatal("a different policy produced the same digest")
	}
}

func TestEvaluateSpendAlertsRaisesThresholdAlerts(t *testing.T) {
	policy := testAlertPolicy()
	breakdown := testCostBreakdown()
	breakdown.HardLimitMicroUSD = 1_000
	breakdown.ConfirmedMicroUSD = 1_200
	breakdown.UnknownMicroUSD = 600
	breakdown.OutstandingMicroUSD = 100
	breakdown.OverrunBlocked = true

	evaluation, err := EvaluateSpendAlerts(policy, breakdown, nil)
	if err != nil {
		t.Fatal(err)
	}
	codes := alertCodes(evaluation.Alerts)
	for _, expected := range []string{AlertLimitBlocked, AlertLimitWarning, AlertUnknownExposure, AlertConfirmedThreshold} {
		if codes[expected] != 1 {
			t.Fatalf("alert %q was not raised: %+v", expected, evaluation.Alerts)
		}
	}
	if evaluation.Alerts[0].Code != AlertLimitBlocked || evaluation.Alerts[0].Severity != SeverityCritical {
		t.Fatalf("the blocking alert is not first and critical: %+v", evaluation.Alerts[0])
	}
	for _, alert := range evaluation.Alerts {
		if alert.Code == AlertSpendAnomaly {
			t.Fatalf("an anomaly was raised without qualified history: %+v", alert)
		}
		if alert.AmountMicroUSD < 0 || alert.ThresholdMicroUSD < 0 {
			t.Fatalf("an alert carried an invalid amount: %+v", alert)
		}
	}
	if evaluation.Anomaly.Status != AnomalyInsufficientHistory {
		t.Fatalf("anomaly status was %q", evaluation.Anomaly.Status)
	}
}

func TestEvaluateSpendAlertsRequiresQualifiedHistoryForAnomalies(t *testing.T) {
	policy := testAlertPolicy()
	breakdown := testCostBreakdown()
	breakdown.HardLimitMicroUSD = 10_000
	breakdown.ConfirmedMicroUSD = 5_000

	evaluation, err := EvaluateSpendAlerts(policy, breakdown, []CostPeriod{{ConfirmedMicroUSD: 100}, {ConfirmedMicroUSD: 100}})
	if err != nil {
		t.Fatal(err)
	}
	if evaluation.Anomaly.Status != AnomalyInsufficientHistory {
		t.Fatalf("anomaly status was %q", evaluation.Anomaly.Status)
	}
	if alertCodes(evaluation.Alerts)[AlertSpendAnomaly] != 0 {
		t.Fatalf("an anomaly was raised without enough history: %+v", evaluation.Alerts)
	}

	evaluation, err = EvaluateSpendAlerts(policy, breakdown, []CostPeriod{{ConfirmedMicroUSD: 0}, {ConfirmedMicroUSD: 0}, {ConfirmedMicroUSD: 0}})
	if err != nil {
		t.Fatal(err)
	}
	if evaluation.Anomaly.Status != AnomalyInsufficientHistory {
		t.Fatalf("anomaly status was %q", evaluation.Anomaly.Status)
	}

	evaluation, err = EvaluateSpendAlerts(policy, breakdown, []CostPeriod{{ConfirmedMicroUSD: 100}, {ConfirmedMicroUSD: 200}, {ConfirmedMicroUSD: 300}})
	if err != nil {
		t.Fatal(err)
	}
	if evaluation.Anomaly.Status != AnomalyQualified {
		t.Fatalf("anomaly status was %q", evaluation.Anomaly.Status)
	}
	if evaluation.Anomaly.BaselineMicroUSD != 200 {
		t.Fatalf("baseline was %d, want 200", evaluation.Anomaly.BaselineMicroUSD)
	}
	if alertCodes(evaluation.Alerts)[AlertSpendAnomaly] != 1 {
		t.Fatalf("a qualified anomaly was not raised: %+v", evaluation.Alerts)
	}
}

func TestEvaluateSpendAlertsKeepsSpendWithinHistory(t *testing.T) {
	policy := testAlertPolicy()
	breakdown := testCostBreakdown()
	breakdown.HardLimitMicroUSD = 10_000
	breakdown.ConfirmedMicroUSD = 150

	evaluation, err := EvaluateSpendAlerts(policy, breakdown, []CostPeriod{{ConfirmedMicroUSD: 100}, {ConfirmedMicroUSD: 200}, {ConfirmedMicroUSD: 300}})
	if err != nil {
		t.Fatal(err)
	}
	if evaluation.Anomaly.Status != AnomalyWithinHistory {
		t.Fatalf("anomaly status was %q", evaluation.Anomaly.Status)
	}
	if alertCodes(evaluation.Alerts)[AlertSpendAnomaly] != 0 {
		t.Fatalf("a within-history spend raised an anomaly: %+v", evaluation.Alerts)
	}
}

func TestEvaluateSpendAlertsBoundsAndOrdersAlerts(t *testing.T) {
	policy := testAlertPolicy()
	policy.MaximumAlerts = 2
	breakdown := testCostBreakdown()
	breakdown.HardLimitMicroUSD = 1_000
	breakdown.ConfirmedMicroUSD = 900
	breakdown.UnknownMicroUSD = 900
	breakdown.OutstandingMicroUSD = 900
	breakdown.OverrunBlocked = true

	evaluation, err := EvaluateSpendAlerts(policy, breakdown, []CostPeriod{{ConfirmedMicroUSD: 1}, {ConfirmedMicroUSD: 1}, {ConfirmedMicroUSD: 1}})
	if err != nil {
		t.Fatal(err)
	}
	if len(evaluation.Alerts) != 2 {
		t.Fatalf("expected two bounded alerts, got %+v", evaluation.Alerts)
	}
	if evaluation.Alerts[0].Code != AlertLimitBlocked || evaluation.Alerts[1].Code != AlertLimitWarning {
		t.Fatalf("alerts were not ordered by severity: %+v", evaluation.Alerts)
	}
}

func TestEvaluateSpendAlertsRejectsIncompleteState(t *testing.T) {
	policy := testAlertPolicy()
	if _, err := EvaluateSpendAlerts(policy, CostBreakdown{}, nil); !errors.Is(err, ErrCostUnavailable) {
		t.Fatalf("an incomplete breakdown returned %v", err)
	}
	if _, err := EvaluateSpendAlerts(AlertPolicy{}, testCostBreakdown(), nil); !errors.Is(err, ErrAlertPolicy) {
		t.Fatalf("an invalid policy returned %v", err)
	}
}

func alertCodes(alerts []Alert) map[string]int {
	codes := make(map[string]int, len(alerts))
	for _, alert := range alerts {
		codes[alert.Code]++
	}
	return codes
}
