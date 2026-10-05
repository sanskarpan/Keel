package erasureworker

import (
	"fmt"
	"strings"
	"sync"

	"github.com/sanskarpan/keel/internal/retrieval/postgres"
)

// Metrics aggregates erasure worker poll outcomes without scope labels.
// Its zero value is ready to use.
type Metrics struct {
	mu         sync.Mutex
	polls      uint64
	claimed    uint64
	completed  uint64
	blocked    uint64
	pending    uint64
	errors     uint64
	backlog    postgres.ErasureBacklog
	hasBacklog bool
}

// ObserveErasurePoll implements Observer.
func (m *Metrics) ObserveErasurePoll(observation Observation) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.polls++
	add := func(total *uint64, value int) {
		if value > 0 {
			*total += uint64(value)
		}
	}
	add(&m.claimed, observation.Claimed)
	add(&m.completed, observation.Completed)
	add(&m.blocked, observation.Blocked)
	add(&m.pending, observation.Pending)
	add(&m.errors, observation.Errors)
}

// ObserveErasureBacklog stores the latest bounded, scope-local snapshot. The
// caller controls sampling frequency and should use a database deadline.
func (m *Metrics) ObserveErasureBacklog(backlog postgres.ErasureBacklog) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.backlog = backlog
	m.hasBacklog = true
	m.mu.Unlock()
}

// PrometheusMetrics implements health.MetricsExtension. All series have fixed
// names and no labels, so concurrent tenants cannot create high-cardinality or
// identifying metric dimensions.
func (m *Metrics) PrometheusMetrics() string {
	if m == nil {
		return ""
	}
	m.mu.Lock()
	polls, claimed, completed := m.polls, m.claimed, m.completed
	blocked, pending, errors := m.blocked, m.pending, m.errors
	backlog, hasBacklog := m.backlog, m.hasBacklog
	m.mu.Unlock()

	var output strings.Builder
	writeCounter := func(name, help string, value uint64) {
		fmt.Fprintf(&output, "# HELP %s %s.\n# TYPE %s counter\n%s %d\n", name, help, name, name, value)
	}
	writeCounter("keel_erasure_worker_polls_total", "Erasure worker polls completed.", polls)
	writeCounter("keel_erasure_worker_jobs_claimed_total", "Erasure jobs claimed by the worker.", claimed)
	writeCounter("keel_erasure_worker_jobs_completed_total", "Erasure jobs completed by the worker.", completed)
	writeCounter("keel_erasure_worker_jobs_blocked_total", "Erasure jobs blocked by the worker.", blocked)
	writeCounter("keel_erasure_worker_jobs_pending_total", "Erasure jobs left pending after a worker poll.", pending)
	writeCounter("keel_erasure_worker_poll_errors_total", "Erasure worker polls that returned an error.", errors)
	if hasBacklog {
		writeGauge := func(name, help string, value any) {
			fmt.Fprintf(&output, "# HELP %s %s.\n# TYPE %s gauge\n%s %v\n", name, help, name, name, value)
		}
		writeGauge("keel_erasure_worker_backlog_fenced_jobs", "Sampled fenced jobs in the current tenant/cohort scope.", backlog.Fenced)
		writeGauge("keel_erasure_worker_backlog_cleanup_pending_jobs", "Sampled cleanup-pending jobs in the current tenant/cohort scope.", backlog.CleanupPending)
		writeGauge("keel_erasure_worker_backlog_blocked_jobs", "Sampled blocked jobs in the current tenant/cohort scope.", backlog.Blocked)
		writeGauge("keel_erasure_worker_backlog_due_jobs", "Sampled unleased erasure jobs currently due.", backlog.Due)
		writeGauge("keel_erasure_worker_backlog_deferred_jobs", "Sampled erasure jobs waiting for retry backoff.", backlog.Deferred)
		writeGauge("keel_erasure_worker_backlog_leased_jobs", "Sampled erasure jobs with a live worker lease.", backlog.Leased)
		writeGauge("keel_erasure_worker_backlog_expired_lease_jobs", "Sampled erasure jobs with an expired worker lease.", backlog.ExpiredLease)
		writeGauge("keel_erasure_worker_backlog_oldest_age_seconds", "Age of the oldest sampled outstanding erasure job.", backlog.OldestOutstanding.Seconds())
		truncated := 0
		if backlog.Truncated {
			truncated = 1
		}
		writeGauge("keel_erasure_worker_backlog_sample_truncated", "Whether outstanding jobs exceeded the 10000-row sample cap.", truncated)
		writeGauge("keel_erasure_worker_backlog_sample_timestamp_seconds", "Unix timestamp when the database sampled erasure backlog.", backlog.SampledAt.Unix())
	}
	return output.String()
}
