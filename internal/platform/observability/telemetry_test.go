package observability

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestLoggerObserverWritesOnlySanitizedBoundedFields(t *testing.T) {
	var output bytes.Buffer
	observer := NewLoggerObserver(&output)
	observer.Observe(Event{
		Operation: "outbox.publish", Outcome: "raw provider error", Duration: 24 * time.Hour,
		SchemaVersion: 99, RetryCount: 1000, TraceID: "not-a-trace-id",
	})
	line := output.String()
	for _, forbidden := range []string{"tenant/secret", "raw provider error", "not-a-trace-id"} {
		if strings.Contains(line, forbidden) {
			t.Fatalf("unsafe value logged: %s", line)
		}
	}
	for _, expected := range []string{`"operation":"outbox.publish"`, `"outcome":"unknown"`, `"duration_ms":3600000`, `"retry_count":100`} {
		if !strings.Contains(line, expected) {
			t.Fatalf("log line %q does not contain %q", line, expected)
		}
	}
	if strings.Contains(line, `"schema_version"`) {
		t.Fatalf("invalid schema version was emitted: %s", line)
	}
}

func TestSanitizeEventRejectsOutcomeFromAnotherOperation(t *testing.T) {
	event := sanitizeEvent(Event{Operation: "outbox.publish", Outcome: "applied"})
	if event.Outcome != "unknown" {
		t.Fatalf("cross-operation outcome was accepted: %+v", event)
	}
}

func TestObserveSafelyContainsObserverPanic(t *testing.T) {
	ObserveSafely(panicObserver{}, Event{Operation: "outbox.publish", Outcome: "published"})
}

func TestDatabaseOperationsAcceptOnlyTheirOwnOutcomes(t *testing.T) {
	for operation, allowed := range map[string][]string{
		"order.create":          {"ok", "error"},
		"order.read":            {"ok", "not_found", "error"},
		"order.stream.updates":  {"ok", "error"},
		"outbox.repair.apply":   {"ok", "error"},
		"order.stream.snapshot": {"ok", "not_found", "error"},
		"order.readpage":        {"ok", "not_found", "error"},
		"order.history":         {"ok", "not_found", "error"},
		"order.page":            {"ok", "not_found", "error"},
		"order.view":            {"ok", "not_found", "error"},
		"order.submit":          {"ok", "error"},
		"outbox.repair.list":    {"ok", "error"},
	} {
		for _, outcome := range allowed {
			if got := sanitizeEvent(Event{Operation: operation, Outcome: outcome}); got.Outcome != outcome {
				t.Fatalf("operation %q rejected its own outcome %q: %+v", operation, outcome, got)
			}
		}
	}
}

func TestDatabaseOperationRejectsMessagingOutcome(t *testing.T) {
	event := sanitizeEvent(Event{Operation: "order.create", Outcome: "published"})
	if event.Outcome != "unknown" {
		t.Fatalf("messaging outcome was accepted by a database operation: %+v", event)
	}
}

func TestDatabaseOperationRejectsUnknownOperation(t *testing.T) {
	event := sanitizeEvent(Event{Operation: "orders.execute", Outcome: "ok"})
	if event.Operation != "unknown" || event.Outcome != "unknown" {
		t.Fatalf("unregistered operation was accepted: %+v", event)
	}
}

func TestDatabaseEventOmitsMessagingOnlyFields(t *testing.T) {
	var output bytes.Buffer
	NewLoggerObserver(&output).Observe(Event{
		Operation: "order.create", Outcome: "ok", Duration: 12 * time.Millisecond,
		RetryCount: 7, SchemaVersion: 2, TraceID: "4bf92f3577b34da6a3ce929d0e0e4736",
	})
	line := output.String()
	for _, expected := range []string{`"operation":"order.create"`, `"outcome":"ok"`, `"duration_ms":12`, `"trace_id":"4bf92f3577b34da6a3ce929d0e0e4736"`} {
		if !strings.Contains(line, expected) {
			t.Fatalf("log line %q does not contain %q", line, expected)
		}
	}
	for _, unexpected := range []string{`"retry_count"`, `"schema_version"`} {
		if strings.Contains(line, unexpected) {
			t.Fatalf("messaging-only field %q was emitted for a database operation: %s", unexpected, line)
		}
	}
}

func TestObserveSafelyIgnoresNilObserverForDatabaseOperation(t *testing.T) {
	ObserveSafely(nil, Event{Operation: "order.read", Outcome: "not_found"})
}

type panicObserver struct{}

func (panicObserver) Observe(Event) { panic("observer failure") }
