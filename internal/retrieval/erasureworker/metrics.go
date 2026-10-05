package erasureworker

import (
	"fmt"
	"strings"
	"sync"
)

// Metrics aggregates erasure worker poll outcomes without scope labels.
// Its zero value is ready to use.
type Metrics struct {
	mu        sync.Mutex
	polls     uint64
	claimed   uint64
	completed uint64
	blocked   uint64
	pending   uint64
	errors    uint64
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

// PrometheusMetrics implements health.MetricsExtension. All series have fixed
// names and no labels, so concurrent tenants cannot create high-cardinality or
// identifying metric dimensions.
func (m *Metrics) PrometheusMetrics() string {
	if m == nil {
		return ""
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	var output strings.Builder
	writeCounter := func(name, help string, value uint64) {
		fmt.Fprintf(&output, "# HELP %s %s.\n# TYPE %s counter\n%s %d\n", name, help, name, name, value)
	}
	writeCounter("keel_erasure_worker_polls_total", "Erasure worker polls completed.", m.polls)
	writeCounter("keel_erasure_worker_jobs_claimed_total", "Erasure jobs claimed by the worker.", m.claimed)
	writeCounter("keel_erasure_worker_jobs_completed_total", "Erasure jobs completed by the worker.", m.completed)
	writeCounter("keel_erasure_worker_jobs_blocked_total", "Erasure jobs blocked by the worker.", m.blocked)
	writeCounter("keel_erasure_worker_jobs_pending_total", "Erasure jobs left pending after a worker poll.", m.pending)
	writeCounter("keel_erasure_worker_poll_errors_total", "Erasure worker polls that returned an error.", m.errors)
	return output.String()
}
