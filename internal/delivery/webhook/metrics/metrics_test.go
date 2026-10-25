package metrics

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sanskarpan/keel/internal/delivery/webhook"
	"github.com/sanskarpan/keel/internal/delivery/webhook/scheduler"
	"github.com/sanskarpan/keel/internal/delivery/webhook/worker"
)

func TestRecorderRendersReconciliationMetrics(t *testing.T) {
	recorder := New()
	recorder.ObserveReconciliationPlan(webhook.ReconciliationPage{
		Scanned: 3, GapEvents: 2, Missing: 4,
	})
	recorder.ObserveReconciliationRepair(webhook.RepairResult{
		GapEvents: 2, InsertedDeliveries: 3, SkippedIdentities: 1,
	})
	output := recorder.PrometheusMetrics()
	for _, expected := range []string{
		"keel_webhook_reconciliation_plans_total 1",
		"keel_webhook_reconciliation_scanned_total 3",
		"keel_webhook_reconciliation_gaps_total 2",
		"keel_webhook_reconciliation_missing_total 4",
		"keel_webhook_reconciliation_repairs_total 1",
		"keel_webhook_reconciliation_repaired_total 3",
		"keel_webhook_reconciliation_skipped_total 1",
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("metrics output missing %q:\n%s", expected, output)
		}
	}
	if count := strings.Count(output, "{"); count != 6 {
		t.Fatalf("metrics output has %d labeled series, want only the 6 fixed outcomes:\n%s", count, output)
	}
}

func TestRecorderRendersContentFreeMetrics(t *testing.T) {
	recorder := New()
	recorder.ObservePass(scheduler.PassObservation{
		Tenants:       2,
		DueDeliveries: 5,
		OldestDue:     90 * time.Second,
	})
	recorder.ObserveTenant(scheduler.TenantObservation{Report: worker.Report{
		Leased: 3, Delivered: 1, RetryScheduled: 1, Exhausted: 1,
	}})
	recorder.ObserveTenant(scheduler.TenantObservation{
		Report: worker.Report{Leased: 1, Failed: 1},
		Failed: true,
	})
	output := recorder.PrometheusMetrics()
	for _, expected := range []string{
		"keel_webhook_discovery_passes_total 1",
		"keel_webhook_discovery_errors_total 0",
		"keel_webhook_due_tenants 2",
		"keel_webhook_due_deliveries 5",
		"keel_webhook_oldest_due_age_seconds 90.000",
		"keel_webhook_tenant_errors_total 1",
		"keel_webhook_attempts_started_total 4",
		`keel_webhook_outcomes_total{outcome="delivered"} 1`,
		`keel_webhook_outcomes_total{outcome="retry_scheduled"} 1`,
		`keel_webhook_outcomes_total{outcome="exhausted"} 1`,
		`keel_webhook_outcomes_total{outcome="failed"} 1`,
		`keel_webhook_outcomes_total{outcome="deferred"} 0`,
		`keel_webhook_outcomes_total{outcome="skipped"} 0`,
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("metrics output missing %q:\n%s", expected, output)
		}
	}
	if strings.Contains(output, "11111111") || strings.Contains(output, "http") {
		t.Fatalf("metrics output leaked an identifier or URL:\n%s", output)
	}
}

func TestRecorderRetainsBacklogAfterDiscoveryFailure(t *testing.T) {
	recorder := New()
	recorder.ObservePass(scheduler.PassObservation{Tenants: 3, DueDeliveries: 7, OldestDue: time.Minute})
	recorder.ObservePass(scheduler.PassObservation{DiscoveryFailed: true})
	output := recorder.PrometheusMetrics()
	if !strings.Contains(output, "keel_webhook_due_tenants 3") ||
		!strings.Contains(output, "keel_webhook_due_deliveries 7") ||
		!strings.Contains(output, "keel_webhook_discovery_errors_total 1") {
		t.Fatalf("failure did not retain backlog or count the error:\n%s", output)
	}
}

func TestRecorderIsConcurrencySafe(t *testing.T) {
	recorder := New()
	var wait sync.WaitGroup
	for range 20 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			recorder.ObservePass(scheduler.PassObservation{Tenants: 1, DueDeliveries: 1})
			recorder.ObserveTenant(scheduler.TenantObservation{Report: worker.Report{Leased: 1, Delivered: 1}})
			_ = recorder.PrometheusMetrics()
		}()
	}
	wait.Wait()
	output := recorder.PrometheusMetrics()
	if !strings.Contains(output, "keel_webhook_attempts_started_total 20") ||
		!strings.Contains(output, `keel_webhook_outcomes_total{outcome="delivered"} 20`) {
		t.Fatalf("concurrent observations were lost:\n%s", output)
	}
}

func TestNilRecorderIsInert(t *testing.T) {
	var recorder *Recorder
	recorder.ObservePass(scheduler.PassObservation{DiscoveryFailed: true})
	recorder.ObserveTenant(scheduler.TenantObservation{})
	recorder.ObserveReconciliationPlan(webhook.ReconciliationPage{Scanned: 1})
	recorder.ObserveReconciliationRepair(webhook.RepairResult{GapEvents: 1})
	if recorder.PrometheusMetrics() != "" {
		t.Fatal("nil recorder returned metrics")
	}
}
