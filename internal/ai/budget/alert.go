package budget

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
)

const (
	// AlertLimitBlocked is raised when the budget account has blocked further admission.
	AlertLimitBlocked = "budget.limit_blocked"
	// AlertLimitWarning is raised when committed and reserved liability approach the hard limit.
	AlertLimitWarning = "budget.limit_warning"
	// AlertUnknownExposure is raised when unknown liability approaches the hard limit.
	AlertUnknownExposure = "cost.unknown_exposure"
	// AlertConfirmedThreshold is raised when settled spend crosses an absolute threshold.
	AlertConfirmedThreshold = "cost.confirmed_threshold"
	// AlertSpendAnomaly is raised when settled spend exceeds the tenant's own history.
	AlertSpendAnomaly = "cost.spend_anomaly"

	// SeverityCritical marks an alert that blocks or stops spend.
	SeverityCritical = "critical"
	// SeverityWarning marks an alert that requires review.
	SeverityWarning = "warning"

	// AnomalyQualified means the tenant history was sufficient to judge the spend.
	AnomalyQualified = "qualified"
	// AnomalyInsufficientHistory means the tenant has too little history to judge the spend.
	AnomalyInsufficientHistory = "insufficient_history"
	// AnomalyZeroBaseline means the tenant history has no settled spend to compare against.
	AnomalyZeroBaseline = "zero_baseline"
	// AnomalyWithinHistory means settled spend stays within the tenant's own history.
	AnomalyWithinHistory = "within_history"
)

var (
	// ErrAlertPolicy means the alert policy is not a usable, bounded configuration.
	ErrAlertPolicy = errors.New("AI spend alert policy is invalid")
)

// AlertPolicy is the immutable, code-owned threshold configuration for spend alerting.
// Basis points are used for ratios so a threshold never depends on floating point.
type AlertPolicy struct {
	// LimitWarningBasisPoints is the share of the hard limit that raises a warning.
	LimitWarningBasisPoints int64
	// UnknownExposureBasisPoints is the share of the hard limit that raises an unknown-exposure alert.
	UnknownExposureBasisPoints int64
	// ConfirmedThresholdMicroUSD is the settled spend that raises an absolute alert.
	ConfirmedThresholdMicroUSD int64
	// AnomalyMultiplierBasisPoints is the multiple of the historical baseline that raises an anomaly,
	// expressed in basis points: 10000 is one times, 20000 is two times.
	AnomalyMultiplierBasisPoints int64
	// MinimumHistoryPeriods is how many past periods with settled spend qualify an anomaly check.
	MinimumHistoryPeriods int
	// MaximumAlerts bounds how many alerts one evaluation may return.
	MaximumAlerts int
}

// Validate rejects a policy that could flood operators or misjudge spend.
func (p AlertPolicy) Validate() error {
	if p.LimitWarningBasisPoints < 1 || p.LimitWarningBasisPoints > 10_000 ||
		p.UnknownExposureBasisPoints < 1 || p.UnknownExposureBasisPoints > 10_000 ||
		p.ConfirmedThresholdMicroUSD < 0 ||
		p.AnomalyMultiplierBasisPoints <= 10_000 || p.AnomalyMultiplierBasisPoints > 100_000 ||
		p.MinimumHistoryPeriods < 1 || p.MinimumHistoryPeriods > MaxCostHistoryPeriods ||
		p.MaximumAlerts < 1 || p.MaximumAlerts > 16 {
		return ErrAlertPolicy
	}
	return nil
}

// Digest is the canonical identity of the policy, so an evaluation can be tied to the exact
// thresholds that produced it.
func (p AlertPolicy) Digest() (string, error) {
	if err := p.Validate(); err != nil {
		return "", err
	}
	canonical := strings.Join([]string{
		fmt.Sprintf("limit_warning_bp=%d", p.LimitWarningBasisPoints),
		fmt.Sprintf("unknown_exposure_bp=%d", p.UnknownExposureBasisPoints),
		fmt.Sprintf("confirmed_threshold_micro_usd=%d", p.ConfirmedThresholdMicroUSD),
		fmt.Sprintf("anomaly_multiplier_bp=%d", p.AnomalyMultiplierBasisPoints),
		fmt.Sprintf("minimum_history_periods=%d", p.MinimumHistoryPeriods),
		fmt.Sprintf("maximum_alerts=%d", p.MaximumAlerts),
	}, "\n")
	sum := sha256.Sum256([]byte(canonical))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// Alert is one content-free spend signal. It carries a fixed code, a fixed severity, an
// amount in micro-USD and the period it belongs to, and never customer or request content.
type Alert struct {
	Code              string
	Severity          string
	AmountMicroUSD    int64
	ThresholdMicroUSD int64
	PeriodID          string
}

// AnomalyAssessment states whether the tenant history was sufficient to judge the spend and
// why the anomaly check did or did not fire.
type AnomalyAssessment struct {
	Status           string
	BaselineMicroUSD int64
	ObservedMicroUSD int64
	RatioBasisPoints int64
	HistoryPeriods   int
}

// AlertEvaluation is the result of one evaluation: the raised alerts and the anomaly verdict.
type AlertEvaluation struct {
	Alerts  []Alert
	Anomaly AnomalyAssessment
	Policy  string
}

// EvaluateSpendAlerts turns one tenant's cost state into bounded, content-free alerts.
//
// The threshold checks use the current period: a blocked account, liability approaching the
// hard limit, unknown exposure approaching the hard limit, and settled spend crossing an
// absolute threshold. The anomaly check compares settled spend with the tenant's own settled
// history and only fires when that history qualifies: too little history or an empty baseline
// is reported as not qualified rather than as a silent pass.
func EvaluateSpendAlerts(policy AlertPolicy, current CostBreakdown, history []CostPeriod) (AlertEvaluation, error) {
	if err := policy.Validate(); err != nil {
		return AlertEvaluation{}, err
	}
	if current.TenantID == "" || current.PeriodID == "" || current.Currency == "" {
		return AlertEvaluation{}, ErrCostUnavailable
	}
	digest, err := policy.Digest()
	if err != nil {
		return AlertEvaluation{}, err
	}
	evaluation := AlertEvaluation{Policy: digest, Alerts: make([]Alert, 0, policy.MaximumAlerts)}
	committed := current.ConfirmedMicroUSD
	// Exposure is the liability the account still holds: unsettled reservations plus the
	// reservations of attempts whose outcome is unknown. The estimated amount is the expected
	// cost of some of those unsettled attempts, so it is not added to the exposure again.
	exposure := current.OutstandingMicroUSD + current.UnknownMicroUSD

	if current.OverrunBlocked {
		evaluation.Alerts = append(evaluation.Alerts, Alert{Code: AlertLimitBlocked, Severity: SeverityCritical,
			AmountMicroUSD: committed + exposure, ThresholdMicroUSD: current.HardLimitMicroUSD, PeriodID: current.PeriodID})
	}
	if current.HardLimitMicroUSD > 0 {
		if threshold := scaled(current.HardLimitMicroUSD, policy.LimitWarningBasisPoints); committed+exposure >= threshold {
			evaluation.Alerts = append(evaluation.Alerts, Alert{Code: AlertLimitWarning, Severity: SeverityWarning,
				AmountMicroUSD: committed + exposure, ThresholdMicroUSD: threshold, PeriodID: current.PeriodID})
		}
		if threshold := scaled(current.HardLimitMicroUSD, policy.UnknownExposureBasisPoints); current.UnknownMicroUSD >= threshold {
			evaluation.Alerts = append(evaluation.Alerts, Alert{Code: AlertUnknownExposure, Severity: SeverityWarning,
				AmountMicroUSD: current.UnknownMicroUSD, ThresholdMicroUSD: threshold, PeriodID: current.PeriodID})
		}
	}
	if policy.ConfirmedThresholdMicroUSD > 0 && committed >= policy.ConfirmedThresholdMicroUSD {
		evaluation.Alerts = append(evaluation.Alerts, Alert{Code: AlertConfirmedThreshold, Severity: SeverityWarning,
			AmountMicroUSD: committed, ThresholdMicroUSD: policy.ConfirmedThresholdMicroUSD, PeriodID: current.PeriodID})
	}

	evaluation.Anomaly = assessSpendAnomaly(policy, current, history)
	if evaluation.Anomaly.Status == AnomalyQualified {
		evaluation.Alerts = append(evaluation.Alerts, Alert{Code: AlertSpendAnomaly, Severity: SeverityWarning,
			AmountMicroUSD: evaluation.Anomaly.ObservedMicroUSD, ThresholdMicroUSD: evaluation.Anomaly.BaselineMicroUSD,
			PeriodID: current.PeriodID})
	}
	sort.SliceStable(evaluation.Alerts, func(i, j int) bool {
		return alertRank(evaluation.Alerts[i].Code) < alertRank(evaluation.Alerts[j].Code)
	})
	if len(evaluation.Alerts) > policy.MaximumAlerts {
		evaluation.Alerts = evaluation.Alerts[:policy.MaximumAlerts]
	}
	return evaluation, nil
}

// assessSpendAnomaly compares settled spend with the tenant's own settled history. The check
// qualifies only with enough past periods that carry settled spend.
func assessSpendAnomaly(policy AlertPolicy, current CostBreakdown, history []CostPeriod) AnomalyAssessment {
	assessment := AnomalyAssessment{ObservedMicroUSD: current.ConfirmedMicroUSD, Status: AnomalyWithinHistory}
	settled := make([]int64, 0, len(history))
	for _, period := range history {
		if period.PeriodID == current.PeriodID {
			// The period under evaluation is never its own baseline.
			continue
		}
		if period.ConfirmedMicroUSD > 0 {
			settled = append(settled, period.ConfirmedMicroUSD)
		}
	}
	assessment.HistoryPeriods = len(settled)
	if len(settled) < policy.MinimumHistoryPeriods {
		assessment.Status = AnomalyInsufficientHistory
		return assessment
	}
	baseline := median(settled)
	assessment.BaselineMicroUSD = baseline
	if baseline <= 0 {
		assessment.Status = AnomalyZeroBaseline
		return assessment
	}
	assessment.RatioBasisPoints = ratioBasisPoints(current.ConfirmedMicroUSD, baseline)
	if current.ConfirmedMicroUSD >= scaled(baseline, policy.AnomalyMultiplierBasisPoints) {
		assessment.Status = AnomalyQualified
		return assessment
	}
	assessment.Status = AnomalyWithinHistory
	return assessment
}

// alertRank fixes the evaluation order so two evaluations of the same state agree.
func alertRank(code string) int {
	switch code {
	case AlertLimitBlocked:
		return 0
	case AlertLimitWarning:
		return 1
	case AlertUnknownExposure:
		return 2
	case AlertConfirmedThreshold:
		return 3
	case AlertSpendAnomaly:
		return 4
	default:
		return 5
	}
}

// scaled applies basis points to an amount without floating point.
func scaled(amount, basisPoints int64) int64 {
	if amount <= 0 || basisPoints <= 0 {
		return 0
	}
	return amount * basisPoints / 10_000
}

// ratioBasisPoints expresses observed against baseline in basis points.
func ratioBasisPoints(observed, baseline int64) int64 {
	if observed <= 0 || baseline <= 0 {
		return 0
	}
	return observed * 10_000 / baseline
}

// median returns the middle settled amount of a sorted history, averaging the two middle
// values for an even count with integer arithmetic.
func median(values []int64) int64 {
	if len(values) == 0 {
		return 0
	}
	sorted := append([]int64(nil), values...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	middle := len(sorted) / 2
	if len(sorted)%2 == 1 {
		return sorted[middle]
	}
	return (sorted[middle-1] + sorted[middle]) / 2
}
