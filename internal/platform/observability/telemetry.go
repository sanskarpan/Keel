package observability

import (
	"io"
	"log/slog"
	"time"

	"github.com/sanskarpan/keel/internal/platform/tracecontext"
)

// Event contains only bounded operational attributes. Callers must use the declared
// operation and outcome values; no event, tenant, broker, or customer identifiers belong here.
type Event struct {
	Operation     string
	Outcome       string
	Duration      time.Duration
	SchemaVersion int
	RetryCount    int
	TraceID       string
}

// Observer receives privacy-safe operational events. Implementations must be non-blocking.
type Observer interface {
	Observe(Event)
}

// LoggerObserver writes only allowlisted and bounded event fields.
type LoggerObserver struct {
	logger *slog.Logger
}

func NewLoggerObserver(writer io.Writer) *LoggerObserver {
	if writer == nil {
		return &LoggerObserver{}
	}
	return &LoggerObserver{logger: slog.New(slog.NewJSONHandler(writer, nil))}
}

func (o *LoggerObserver) Observe(event Event) {
	if o == nil || o.logger == nil {
		return
	}
	event = sanitizeEvent(event)
	attrs := []any{
		"operation", event.Operation,
		"outcome", event.Outcome,
		"duration_ms", event.Duration.Milliseconds(),
	}
	if event.SchemaVersion > 0 {
		attrs = append(attrs, "schema_version", event.SchemaVersion)
	}
	if event.Operation == "outbox.publish" {
		attrs = append(attrs, "retry_count", event.RetryCount)
	}
	if event.TraceID != "" {
		attrs = append(attrs, "trace_id", event.TraceID)
	}
	o.logger.Info("messaging operation completed", attrs...)
}

// ObserveSafely prevents a broken optional observer from changing business or offset outcomes.
func ObserveSafely(observer Observer, event Event) {
	if observer == nil {
		return
	}
	defer func() { _ = recover() }()
	observer.Observe(sanitizeEvent(event))
}

func sanitizeEvent(event Event) Event {
	if event.Operation != "outbox.publish" && event.Operation != "projector.process" {
		event.Operation = "unknown"
	}
	validOutcome := false
	switch event.Operation {
	case "outbox.publish":
		switch event.Outcome {
		case "published", "retry_scheduled", "blocked", "no_work", "error":
			validOutcome = true
		}
	case "projector.process":
		switch event.Outcome {
		case "applied", "duplicate", "deferred", "quarantined", "error":
			validOutcome = true
		}
	}
	if !validOutcome {
		event.Outcome = "unknown"
	}
	if event.Duration < 0 {
		event.Duration = 0
	}
	if event.Duration > time.Hour {
		event.Duration = time.Hour
	}
	if event.SchemaVersion < 0 || event.SchemaVersion > 2 {
		event.SchemaVersion = 0
	}
	if event.RetryCount < 0 {
		event.RetryCount = 0
	} else if event.RetryCount > 100 {
		event.RetryCount = 100
	}
	if event.TraceID != "" {
		parsed, ok := tracecontext.Parse("00-" + event.TraceID + "-0000000000000001-01")
		if !ok {
			event.TraceID = ""
		} else {
			event.TraceID = parsed.TraceID
		}
	}
	return event
}
