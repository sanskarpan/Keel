// Package metrics exposes content-free webhook delivery metrics. Labels are fixed outcome names;
// tenant, endpoint, event, URL, payload and error strings are never recorded.
package metrics

import (
	"fmt"
	"strings"
	"sync"
	"time"

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
	return b.String()
}
