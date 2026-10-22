package observability

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"time"
)

// StatementKind classifies a database statement by the effect it can have. The kind is the
// only statement attribute that leaves the process: it never carries SQL text, arguments,
// identifiers, row contents, or database error text.
type StatementKind string

const (
	// StatementRead marks a statement that only reads durable state.
	StatementRead StatementKind = "read"
	// StatementWrite marks a statement that can change durable state.
	StatementWrite StatementKind = "write"
)

// MaxRecordedStatements bounds how many statements one operation may buffer. The bound keeps
// a pathological statement loop from growing process memory through observation alone.
const MaxRecordedStatements = 64

type statementRecorderKey struct{}

// StatementRecorder buffers bounded statement timings for one logical operation so they can
// be published after that operation's transaction has finished. Buffering keeps observation
// from extending a transaction or holding database locks open.
type StatementRecorder struct {
	mutex    sync.Mutex
	observer Observer
	traceID  string
	events   []Event
}

// NewStatementRecorder creates a recorder for one operation. A nil observer records nothing,
// and the trace ID is taken only from a validated trusted correlation context.
func NewStatementRecorder(observer Observer, ctx context.Context) *StatementRecorder {
	recorder := &StatementRecorder{observer: observer}
	if traceID, ok := TraceIDFromContext(ctx); ok {
		recorder.traceID = traceID
	}
	return recorder
}

// WithStatementRecorder binds a recorder to a context so statement helpers can find it.
func WithStatementRecorder(ctx context.Context, recorder *StatementRecorder) context.Context {
	if ctx == nil || recorder == nil {
		return ctx
	}
	return context.WithValue(ctx, statementRecorderKey{}, recorder)
}

// StatementRecorderFromContext returns the recorder bound to the context, if any.
func StatementRecorderFromContext(ctx context.Context) (*StatementRecorder, bool) {
	if ctx == nil {
		return nil, false
	}
	recorder, ok := ctx.Value(statementRecorderKey{}).(*StatementRecorder)
	return recorder, ok && recorder != nil
}

// Record captures one completed statement. A statement that returned no row is a successful
// statement and is reported as such; only a statement failure is reported as an error.
func (r *StatementRecorder) Record(kind StatementKind, elapsed time.Duration, err error) {
	if r == nil || r.observer == nil {
		return
	}
	operation := ""
	switch kind {
	case StatementRead:
		operation = "query.read"
	case StatementWrite:
		operation = "query.write"
	default:
		return
	}
	outcome := "ok"
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		outcome = "error"
	}
	r.mutex.Lock()
	defer r.mutex.Unlock()
	if len(r.events) >= MaxRecordedStatements {
		return
	}
	r.events = append(r.events, Event{Operation: operation, Outcome: outcome, Duration: elapsed, TraceID: r.traceID})
}

// Flush publishes the buffered statements to the observer. It is safe to call more than once.
func (r *StatementRecorder) Flush() {
	if r == nil || r.observer == nil {
		return
	}
	r.mutex.Lock()
	events := r.events
	r.events = nil
	r.mutex.Unlock()
	for _, event := range events {
		ObserveSafely(r.observer, event)
	}
}
