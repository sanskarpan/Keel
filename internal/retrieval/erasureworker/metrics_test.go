package erasureworker

import (
	"strings"
	"sync"
	"testing"
)

func TestMetricsAggregatePollOutcomesWithoutLabels(t *testing.T) {
	var metrics Metrics
	metrics.ObserveErasurePoll(Observation{ScopeCount: 1, Claimed: 1, Completed: 1})
	metrics.ObserveErasurePoll(Observation{ScopeCount: 1, Claimed: 1, Blocked: 1, Errors: 1})
	metrics.ObserveErasurePoll(Observation{ScopeCount: 1, Pending: 1, Errors: 1, Claimed: -4})

	output := metrics.PrometheusMetrics()
	for _, expected := range []string{
		"keel_erasure_worker_polls_total 3",
		"keel_erasure_worker_jobs_claimed_total 2",
		"keel_erasure_worker_jobs_completed_total 1",
		"keel_erasure_worker_jobs_blocked_total 1",
		"keel_erasure_worker_jobs_pending_total 1",
		"keel_erasure_worker_poll_errors_total 2",
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("metrics output missing %q: %s", expected, output)
		}
	}
	if strings.Contains(output, "tenant=") || strings.Contains(output, "visibility=") || strings.Contains(output, "labels={") {
		t.Fatalf("metrics contain scope labels: %s", output)
	}
}

func TestMetricsConcurrentObservation(t *testing.T) {
	var metrics Metrics
	const workers, observations = 8, 100
	var group sync.WaitGroup
	for range workers {
		group.Add(1)
		go func() {
			defer group.Done()
			for range observations {
				metrics.ObserveErasurePoll(Observation{Claimed: 1, Pending: 1})
			}
		}()
	}
	group.Wait()
	output := metrics.PrometheusMetrics()
	for _, expected := range []string{
		"keel_erasure_worker_polls_total 800",
		"keel_erasure_worker_jobs_claimed_total 800",
		"keel_erasure_worker_jobs_pending_total 800",
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("concurrent metric update missing %q: %s", expected, output)
		}
	}
}
