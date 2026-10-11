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
	if isMessagingOperation(event.Operation) {
		if event.SchemaVersion > 0 {
			attrs = append(attrs, "schema_version", event.SchemaVersion)
		}
		if event.Operation == "outbox.publish" {
			attrs = append(attrs, "retry_count", event.RetryCount)
		}
	}
	if event.TraceID != "" {
		attrs = append(attrs, "trace_id", event.TraceID)
	}
	o.logger.Info("operation completed", attrs...)
}

// isMessagingOperation reports whether the event came from the broker relay/projector boundary.
// Those operations carry envelope schema and retry fields that database operations never have.
func isMessagingOperation(operation string) bool {
	return operation == "outbox.publish" || operation == "projector.process"
}

// ObserveSafely prevents a broken optional observer from changing business or offset outcomes.
func ObserveSafely(observer Observer, event Event) {
	if observer == nil {
		return
	}
	defer func() { _ = recover() }()
	observer.Observe(sanitizeEvent(event))
}

// allowedOutcomes maps every published operation to the only outcomes that may be reported for it.
// An operation absent from this map, or an outcome absent from its entry, becomes "unknown".
var allowedOutcomes = map[string]map[string]bool{
	"outbox.publish": {
		"published": true, "retry_scheduled": true, "blocked": true, "no_work": true, "error": true,
	},
	"projector.process": {
		"applied": true, "duplicate": true, "deferred": true, "quarantined": true, "error": true,
	},
	"order.create":          {"ok": true, "error": true},
	"order.submit":          {"ok": true, "error": true},
	"order.read":            {"ok": true, "not_found": true, "error": true},
	"order.history":         {"ok": true, "not_found": true, "error": true},
	"order.view":            {"ok": true, "not_found": true, "error": true},
	"order.page":            {"ok": true, "not_found": true, "error": true},
	"order.readpage":        {"ok": true, "not_found": true, "error": true},
	"order.stream.snapshot": {"ok": true, "not_found": true, "error": true},
	"order.stream.updates":  {"ok": true, "error": true},
	"outbox.repair.list":    {"ok": true, "error": true},
	"outbox.repair.apply":   {"ok": true, "error": true},
}

func sanitizeEvent(event Event) Event {
	outcomes, known := allowedOutcomes[event.Operation]
	if !known {
		event.Operation = "unknown"
	}
	if !outcomes[event.Outcome] {
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
