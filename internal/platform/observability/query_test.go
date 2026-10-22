package observability

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"
)

// recordingObserver captures emitted events so statement observation can be asserted directly.
type recordingObserver struct {
	events []Event
}

func (o *recordingObserver) Observe(event Event) {
	o.events = append(o.events, event)
}

func TestStatementRecorderClassifiesStatementKinds(t *testing.T) {
	observer := &recordingObserver{}
	recorder := NewStatementRecorder(observer, context.Background())
	recorder.Record(StatementRead, 3*time.Millisecond, nil)
	recorder.Record(StatementWrite, 4*time.Millisecond, nil)
	recorder.Flush()

	if len(observer.events) != 2 {
		t.Fatalf("expected two statement events, got %d: %+v", len(observer.events), observer.events)
	}
	if observer.events[0].Operation != "query.read" || observer.events[0].Outcome != "ok" {
		t.Fatalf("read statement was not classified: %+v", observer.events[0])
	}
	if observer.events[1].Operation != "query.write" || observer.events[1].Outcome != "ok" {
		t.Fatalf("write statement was not classified: %+v", observer.events[1])
	}
}

func TestStatementRecorderIgnoresUnknownStatementKind(t *testing.T) {
	observer := &recordingObserver{}
	recorder := NewStatementRecorder(observer, context.Background())
	recorder.Record(StatementKind("truncate"), time.Millisecond, nil)
	recorder.Flush()

	if len(observer.events) != 0 {
		t.Fatalf("an unregistered statement kind was recorded: %+v", observer.events)
	}
}

func TestStatementRecorderTreatsMissingRowAsSuccessfulStatement(t *testing.T) {
	observer := &recordingObserver{}
	recorder := NewStatementRecorder(observer, context.Background())
	recorder.Record(StatementRead, time.Millisecond, sql.ErrNoRows)
	recorder.Flush()

	if len(observer.events) != 1 || observer.events[0].Outcome != "ok" {
		t.Fatalf("a missing row was not reported as a successful statement: %+v", observer.events)
	}
}

func TestStatementRecorderReportsStatementFailure(t *testing.T) {
	observer := &recordingObserver{}
	recorder := NewStatementRecorder(observer, context.Background())
	recorder.Record(StatementWrite, time.Millisecond, errors.New("pq: duplicate key value violates unique constraint"))
	recorder.Flush()

	if len(observer.events) != 1 || observer.events[0].Outcome != "error" {
		t.Fatalf("a failed statement was not reported as an error: %+v", observer.events)
	}
}

func TestStatementRecorderKeepsValidatedTraceOnly(t *testing.T) {
	const traceID = "4bf92f3577b34da6a3ce929d0e0e4736"
	traced, ok := WithRemoteTraceparent(context.Background(), "00-"+traceID+"-00f067aa0ba902b7-01")
	if !ok {
		t.Fatal("build traced context")
	}
	observer := &recordingObserver{}
	recorder := NewStatementRecorder(observer, traced)
	recorder.Record(StatementRead, time.Millisecond, nil)
	recorder.Flush()
	if len(observer.events) != 1 || observer.events[0].TraceID != traceID {
		t.Fatalf("validated trace ID was not reported: %+v", observer.events)
	}

	observer = &recordingObserver{}
	recorder = NewStatementRecorder(observer, context.Background())
	recorder.Record(StatementRead, time.Millisecond, nil)
	recorder.Flush()
	if len(observer.events) != 1 || observer.events[0].TraceID != "" {
		t.Fatalf("untraced statement reported a trace ID: %+v", observer.events)
	}
}

func TestStatementRecorderBoundsBufferedStatements(t *testing.T) {
	observer := &recordingObserver{}
	recorder := NewStatementRecorder(observer, context.Background())
	for range MaxRecordedStatements + 10 {
		recorder.Record(StatementRead, time.Millisecond, nil)
	}
	recorder.Flush()

	if len(observer.events) != MaxRecordedStatements {
		t.Fatalf("expected %d buffered statements, got %d", MaxRecordedStatements, len(observer.events))
	}
}

func TestStatementRecorderFlushPublishesOnce(t *testing.T) {
	observer := &recordingObserver{}
	recorder := NewStatementRecorder(observer, context.Background())
	recorder.Record(StatementRead, time.Millisecond, nil)
	recorder.Flush()
	recorder.Flush()

	if len(observer.events) != 1 {
		t.Fatalf("statement events were published more than once: %+v", observer.events)
	}
}

func TestStatementRecorderWithoutObserverStaysSilent(t *testing.T) {
	recorder := NewStatementRecorder(nil, context.Background())
	recorder.Record(StatementRead, time.Millisecond, nil)
	recorder.Flush()
}

func TestStatementRecorderContainsObserverFailure(t *testing.T) {
	recorder := NewStatementRecorder(panicObserver{}, context.Background())
	recorder.Record(StatementRead, time.Millisecond, nil)
	recorder.Flush()
}

func TestStatementRecorderContextRoundTrip(t *testing.T) {
	recorder := NewStatementRecorder(&recordingObserver{}, context.Background())
	ctx := WithStatementRecorder(context.Background(), recorder)
	found, ok := StatementRecorderFromContext(ctx)
	if !ok || found != recorder {
		t.Fatal("the statement recorder was not recovered from the context")
	}
	if _, ok := StatementRecorderFromContext(context.Background()); ok {
		t.Fatal("a context without a recorder reported one")
	}
	if got := WithStatementRecorder(context.Background(), nil); got != context.Background() {
		t.Fatal("a nil recorder changed the context")
	}
}

func TestTraceIDFromContextRejectsUntrustedParent(t *testing.T) {
	ctx, ok := WithRemoteTraceparent(context.Background(), "not-a-traceparent")
	if ok {
		t.Fatal("invalid remote traceparent was accepted")
	}
	if traceID, found := TraceIDFromContext(ctx); found || traceID != "" {
		t.Fatalf("rejected trace context produced a trace ID: %q", traceID)
	}
}
