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

type panicObserver struct{}

func (panicObserver) Observe(Event) { panic("observer failure") }
