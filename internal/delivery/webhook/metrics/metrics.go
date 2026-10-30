// Package metrics exposes content-free webhook delivery metrics. Labels are fixed outcome names;
// tenant, endpoint, event, URL, payload and error strings are never recorded.
package metrics

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/sanskarpan/keel/internal/delivery/webhook"
	"github.com/sanskarpan/keel/internal/delivery/webhook/scheduler"
)

// Recorder is a process-local, concurrency-safe metrics recorder. Values reset on process restart.
type Recorder struct {
	mu            sync.Mutex
	passes        uint64
	discoveryErrs uint64
	tenantErrs    uint64
	dueTenants    int64
	dueDeliveries int64
	oldestDue     time.Duration
	lastSuccess   time.Time
	leases        uint64
	delivered     uint64
	retry         uint64
	exhausted     uint64
	failed        uint64
	deferred      uint64
	skipped       uint64
	plans         uint64
	planScanned   uint64
	planGaps      uint64
	planMissing   uint64
	planErrs      uint64
	repairs       uint64
	repaired      uint64
	repairSkipped uint64
	repairErrs    uint64
}

// New returns an empty recorder.
func New() *Recorder { return &Recorder{} }

// ObservePass records one discovery pass. A failed pass increments the error counter and retains
// the last successful backlog gauges.
func (m *Recorder) ObservePass(observation scheduler.PassObservation) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.passes++
	if observation.DiscoveryFailed {
		m.discoveryErrs++
		return
	}
	m.dueTenants = int64(observation.Tenants)
	m.dueDeliveries = observation.DueDeliveries
	m.oldestDue = observation.OldestDue
	m.lastSuccess = time.Now()
}

// ObserveTenant records one tenant batch.
func (m *Recorder) ObserveTenant(observation scheduler.TenantObservation) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.leases += uint64(observation.Report.Leased)
	m.delivered += uint64(observation.Report.Delivered)
	m.retry += uint64(observation.Report.RetryScheduled)
	m.exhausted += uint64(observation.Report.Exhausted)
	m.failed += uint64(observation.Report.Failed)
	m.deferred += uint64(observation.Report.Deferred)
	m.skipped += uint64(observation.Report.Skipped)
	if observation.Failed {
		m.tenantErrs++
	}
}

// ObserveReconciliationPlan records one recorded dry-run page. Only counts are kept; no
// tenant, event, endpoint or error strings.
func (m *Recorder) ObserveReconciliationPlan(page webhook.ReconciliationPage) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.plans++
	m.planScanned += uint64(max(page.Scanned, 0))
	m.planGaps += uint64(max(page.GapEvents, 0))
	m.planMissing += uint64(max(page.Missing, 0))
}

// ObserveReconciliationRepair records one audited repair invocation. Only counts are kept.
func (m *Recorder) ObserveReconciliationRepair(result webhook.RepairResult) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.repairs++
	m.repaired += uint64(max(result.InsertedDeliveries, 0))
	m.repairSkipped += uint64(max(result.SkippedIdentities, 0))
}

// ObservePlanFailure records one failed dry-run page after request validation. Only the
// operation is kept; no tenant, event or error strings.
func (m *Recorder) ObservePlanFailure() {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.planErrs++
}

// ObserveRepairFailure records one failed repair invocation after request validation.
func (m *Recorder) ObserveRepairFailure() {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.repairErrs++
}

// PrometheusMetrics implements the management endpoint's MetricsExtension contract.
func (m *Recorder) PrometheusMetrics() string {
	if m == nil {
		return ""
	}
	m.mu.Lock()
	passes, discoveryErrs, tenantErrs := m.passes, m.discoveryErrs, m.tenantErrs
	dueTenants, dueDeliveries := m.dueTenants, m.dueDeliveries
	oldestDue, lastSuccess := m.oldestDue, m.lastSuccess
	leases, delivered, retry, exhausted := m.leases, m.delivered, m.retry, m.exhausted
	failed, deferred, skipped := m.failed, m.deferred, m.skipped
	plans, planScanned, planGaps := m.plans, m.planScanned, m.planGaps
	planMissing, planErrs := m.planMissing, m.planErrs
	repairs, repaired := m.repairs, m.repaired
	repairSkipped, repairErrs := m.repairSkipped, m.repairErrs
	m.mu.Unlock()

	var b strings.Builder
	fmt.Fprintln(&b, "# HELP keel_webhook_discovery_passes_total Tenant discovery passes attempted.")
	fmt.Fprintln(&b, "# TYPE keel_webhook_discovery_passes_total counter")
	fmt.Fprintf(&b, "keel_webhook_discovery_passes_total %d\n", passes)
	fmt.Fprintln(&b, "# HELP keel_webhook_discovery_errors_total Tenant discovery passes that failed.")
	fmt.Fprintln(&b, "# TYPE keel_webhook_discovery_errors_total counter")
	fmt.Fprintf(&b, "keel_webhook_discovery_errors_total %d\n", discoveryErrs)
	fmt.Fprintln(&b, "# HELP keel_webhook_due_tenants Tenants with due work in the last successful discovery pass.")
	fmt.Fprintln(&b, "# TYPE keel_webhook_due_tenants gauge")
	fmt.Fprintf(&b, "keel_webhook_due_tenants %d\n", dueTenants)
	fmt.Fprintln(&b, "# HELP keel_webhook_due_deliveries Due or lease-expired deliveries in the last successful discovery pass.")
	fmt.Fprintln(&b, "# TYPE keel_webhook_due_deliveries gauge")
	fmt.Fprintf(&b, "keel_webhook_due_deliveries %d\n", dueDeliveries)
	fmt.Fprintln(&b, "# HELP keel_webhook_oldest_due_age_seconds Age of the earliest due delivery in the last successful discovery pass.")
	fmt.Fprintln(&b, "# TYPE keel_webhook_oldest_due_age_seconds gauge")
	fmt.Fprintf(&b, "keel_webhook_oldest_due_age_seconds %.3f\n", oldestDue.Seconds())
	fmt.Fprintln(&b, "# HELP keel_webhook_last_discovery_timestamp_seconds Unix time of the last successful discovery pass.")
	fmt.Fprintln(&b, "# TYPE keel_webhook_last_discovery_timestamp_seconds gauge")
	lastSeconds := float64(0)
	if !lastSuccess.IsZero() {
		lastSeconds = float64(lastSuccess.UnixNano()) / float64(time.Second)
	}
	fmt.Fprintf(&b, "keel_webhook_last_discovery_timestamp_seconds %.3f\n", lastSeconds)
	fmt.Fprintln(&b, "# HELP keel_webhook_tenant_errors_total Tenant batches that returned an error.")
	fmt.Fprintln(&b, "# TYPE keel_webhook_tenant_errors_total counter")
	fmt.Fprintf(&b, "keel_webhook_tenant_errors_total %d\n", tenantErrs)
	fmt.Fprintln(&b, "# HELP keel_webhook_attempts_started_total Delivery attempts started under a lease.")
	fmt.Fprintln(&b, "# TYPE keel_webhook_attempts_started_total counter")
	fmt.Fprintf(&b, "keel_webhook_attempts_started_total %d\n", leases)
	fmt.Fprintln(&b, "# HELP keel_webhook_outcomes_total Delivery attempts by terminal or scheduled disposition.")
	fmt.Fprintln(&b, "# TYPE keel_webhook_outcomes_total counter")
	for _, outcome := range []struct {
		name  string
		value uint64
	}{
		{"delivered", delivered},
		{"retry_scheduled", retry},
		{"exhausted", exhausted},
		{"failed", failed},
		{"deferred", deferred},
		{"skipped", skipped},
	} {
		fmt.Fprintf(&b, "keel_webhook_outcomes_total{outcome=%q} %d\n", outcome.name, outcome.value)
	}
	fmt.Fprintln(&b, "# HELP keel_webhook_reconciliation_plans_total Recorded dry-run reconciliation pages.")
	fmt.Fprintln(&b, "# TYPE keel_webhook_reconciliation_plans_total counter")
	fmt.Fprintf(&b, "keel_webhook_reconciliation_plans_total %d\n", plans)
	fmt.Fprintln(&b, "# HELP keel_webhook_reconciliation_scanned_total Outbox events scanned by recorded pages.")
	fmt.Fprintln(&b, "# TYPE keel_webhook_reconciliation_scanned_total counter")
	fmt.Fprintf(&b, "keel_webhook_reconciliation_scanned_total %d\n", planScanned)
	fmt.Fprintln(&b, "# HELP keel_webhook_reconciliation_gaps_total Page events with missing deliveries.")
	fmt.Fprintln(&b, "# TYPE keel_webhook_reconciliation_gaps_total counter")
	fmt.Fprintf(&b, "keel_webhook_reconciliation_gaps_total %d\n", planGaps)
	fmt.Fprintln(&b, "# HELP keel_webhook_reconciliation_missing_total Missing deliveries counted by recorded pages.")
	fmt.Fprintln(&b, "# TYPE keel_webhook_reconciliation_missing_total counter")
	fmt.Fprintf(&b, "keel_webhook_reconciliation_missing_total %d\n", planMissing)
	fmt.Fprintln(&b, "# HELP keel_webhook_reconciliation_repairs_total Audited repair invocations.")
	fmt.Fprintln(&b, "# TYPE keel_webhook_reconciliation_repairs_total counter")
	fmt.Fprintf(&b, "keel_webhook_reconciliation_repairs_total %d\n", repairs)
	fmt.Fprintln(&b, "# HELP keel_webhook_reconciliation_repaired_total Deliveries inserted by repairs.")
	fmt.Fprintln(&b, "# TYPE keel_webhook_reconciliation_repaired_total counter")
	fmt.Fprintf(&b, "keel_webhook_reconciliation_repaired_total %d\n", repaired)
	fmt.Fprintln(&b, "# HELP keel_webhook_reconciliation_skipped_total Endpoint-event identities skipped by repairs.")
	fmt.Fprintln(&b, "# TYPE keel_webhook_reconciliation_skipped_total counter")
	fmt.Fprintf(&b, "keel_webhook_reconciliation_skipped_total %d\n", repairSkipped)
	fmt.Fprintln(&b, "# HELP keel_webhook_reconciliation_errors_total Failed dry-run pages and repairs by operation.")
	fmt.Fprintln(&b, "# TYPE keel_webhook_reconciliation_errors_total counter")
	fmt.Fprintf(&b, "keel_webhook_reconciliation_errors_total{op=%q} %d\n", "plan", planErrs)
	fmt.Fprintf(&b, "keel_webhook_reconciliation_errors_total{op=%q} %d\n", "repair", repairErrs)
	return b.String()
}
