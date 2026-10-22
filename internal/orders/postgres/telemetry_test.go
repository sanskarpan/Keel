package postgres

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sanskarpan/keel/internal/orders"
	"github.com/sanskarpan/keel/internal/platform/observability"
)

// recordingObserver captures emitted events so repository telemetry can be asserted directly.
type recordingObserver struct {
	mutex  sync.Mutex
	events []observability.Event
}

func (o *recordingObserver) Observe(event observability.Event) {
	o.mutex.Lock()
	defer o.mutex.Unlock()
	o.events = append(o.events, event)
}

func (o *recordingObserver) snapshot() []observability.Event {
	o.mutex.Lock()
	defer o.mutex.Unlock()
	return append([]observability.Event(nil), o.events...)
}

func (o *recordingObserver) reset() {
	o.mutex.Lock()
	defer o.mutex.Unlock()
	o.events = nil
}

func observedOperation(t *testing.T, observer *recordingObserver) observability.Event {
	t.Helper()
	events := operationEvents(observer.snapshot())
	if len(events) != 1 {
		t.Fatalf("expected exactly one operation event, got %d: %+v", len(events), events)
	}
	return events[0]
}

// operationEvents keeps the repository operation events and drops the statement events, so a
// test can assert one boundary without depending on how many statements the operation ran.
func operationEvents(events []observability.Event) []observability.Event {
	operations := make([]observability.Event, 0, len(events))
	for _, event := range events {
		if strings.HasPrefix(event.Operation, "query.") {
			continue
		}
		operations = append(operations, event)
	}
	return operations
}

// statementEvents keeps only the database statement events.
func statementEvents(events []observability.Event) []observability.Event {
	statements := make([]observability.Event, 0, len(events))
	for _, event := range events {
		if strings.HasPrefix(event.Operation, "query.") {
			statements = append(statements, event)
		}
	}
	return statements
}

func TestRepositoryOperationTelemetryReportsValidatedTraceOnly(t *testing.T) {
	observer := &recordingObserver{}
	repository := &Repository{observer: observer}
	const traceID = "4bf92f3577b34da6a3ce929d0e0e4736"

	traced, ok := observability.WithRemoteTraceparent(context.Background(), "00-"+traceID+"-00f067aa0ba902b7-01")
	if !ok {
		t.Fatal("build traced context")
	}
	_, done := repository.begin(traced, "order.create")
	done(nil)
	if got := observedOperation(t, observer).TraceID; got != traceID {
		t.Fatalf("validated trace ID was not reported: %q", got)
	}

	observer.reset()
	_, done = repository.begin(context.Background(), "order.create")
	done(nil)
	if got := observedOperation(t, observer).TraceID; got != "" {
		t.Fatalf("untraced operation reported a trace ID: %q", got)
	}
}

func TestRepositoryOperationTelemetryIgnoresRejectedTraceParent(t *testing.T) {
	observer := &recordingObserver{}
	repository := &Repository{observer: observer}
	ctx, ok := observability.WithRemoteTraceparent(context.Background(), "not-a-traceparent")
	if ok {
		t.Fatal("invalid remote traceparent was accepted")
	}
	_, done := repository.begin(ctx, "order.read")
	done(nil)
	if got := observedOperation(t, observer).TraceID; got != "" {
		t.Fatalf("rejected trace context produced telemetry: %q", got)
	}
}

func TestRepositoryOperationTelemetryClassifiesOutcomes(t *testing.T) {
	cases := []struct {
		name    string
		err     error
		outcome string
	}{
		{"success", nil, "ok"},
		{"failure", errors.New("database unavailable"), "error"},
		{"missing", orders.ErrNotFound, "not_found"},
		{"wrapped missing", errors.Join(errors.New("read failed"), orders.ErrNotFound), "not_found"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			observer := &recordingObserver{}
			repository := &Repository{observer: observer}
			_, done := repository.begin(context.Background(), "order.read")
			done(testCase.err)
			if got := observedOperation(t, observer).Outcome; got != testCase.outcome {
				t.Fatalf("outcome %q does not classify %v", got, testCase.err)
			}
		})
	}
}

func TestRepositoryOperationTelemetryCarriesNoIdentifiers(t *testing.T) {
	observer := &recordingObserver{}
	repository := &Repository{observer: observer}
	_, done := repository.begin(context.Background(), "order.create")
	done(errors.New(`pq: duplicate key value violates unique constraint "order_tenant_pkey" on tenant 4bf92f35`))

	event := observedOperation(t, observer)
	if event.RetryCount != 0 || event.SchemaVersion != 0 {
		t.Fatalf("messaging-only fields were populated: %+v", event)
	}
	rendered := strings.Join([]string{event.Operation, event.Outcome}, " ")
	for _, forbidden := range []string{"4bf92f35", "order_tenant_pkey", "duplicate key", "pq:"} {
		if strings.Contains(rendered, forbidden) {
			t.Fatalf("identifier or raw database error leaked into telemetry: %q", rendered)
		}
	}
}

func TestRepositoryOperationTelemetryContainsObserverFailure(t *testing.T) {
	repository := &Repository{observer: panicObserver{}}
	_, done := repository.begin(context.Background(), "order.create")
	done(nil)
}

func TestRepositoryWithoutObserverStaysSilent(t *testing.T) {
	repository := &Repository{}
	_, done := repository.begin(context.Background(), "order.read")
	done(orders.ErrNotFound)
}

func TestPostgreSQLRepositoryOperationTelemetry(t *testing.T) {
	db, tenant, _ := repositoryTestDB(t)
	observer := &recordingObserver{}
	repo, err := NewRepository(db, WithObserver(observer))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	orderID := nextUUID()
	metadata := testMetadata(string(tenant), orderID)

	if _, err := repo.Create(ctx, tenant, testCreate("telemetry-"+nextUUID()), metadata, "telemetry-create-0001", "principal:requester-1"); err != nil {
		t.Fatalf("create for telemetry: %v", err)
	}
	if event := observedOperation(t, observer); event.Operation != "order.create" || event.Outcome != "ok" {
		t.Fatalf("create emitted %+v", event)
	}

	observer.reset()
	if _, err := repo.Load(ctx, tenant, orderID); err != nil {
		t.Fatalf("load for telemetry: %v", err)
	}
	if event := observedOperation(t, observer); event.Operation != "order.read" || event.Outcome != "ok" {
		t.Fatalf("load emitted %+v", event)
	}

	observer.reset()
	if _, err := repo.ReadOrder(ctx, tenant, orderID); err != nil {
		t.Fatalf("read order for telemetry: %v", err)
	}
	if event := observedOperation(t, observer); event.Operation != "order.view" || event.Outcome != "ok" {
		t.Fatalf("read order emitted %+v", event)
	}

	observer.reset()
	if _, err := repo.Load(ctx, tenant, nextUUID()); !errors.Is(err, orders.ErrNotFound) {
		t.Fatalf("missing load returned %v", err)
	}
	if event := observedOperation(t, observer); event.Operation != "order.read" || event.Outcome != "not_found" {
		t.Fatalf("missing load emitted %+v", event)
	}
}

type panicObserver struct{}

func (panicObserver) Observe(observability.Event) { panic("observer failure") }

func TestRepositoryStatementTelemetryPublishesAfterTheOperation(t *testing.T) {
	observer := &recordingObserver{}
	repository := &Repository{observer: observer}
	ctx, done := repository.begin(context.Background(), "order.read")

	recorder, ok := observability.StatementRecorderFromContext(ctx)
	if !ok {
		t.Fatal("the repository operation did not bind a statement recorder")
	}
	recorder.Record(observability.StatementRead, 5*time.Millisecond, nil)
	recorder.Record(observability.StatementWrite, 7*time.Millisecond, errors.New("pq: deadlock detected"))
	if statements := statementEvents(observer.snapshot()); len(statements) != 0 {
		t.Fatalf("statement events were published before the operation finished: %+v", statements)
	}

	done(nil)
	statements := statementEvents(observer.snapshot())
	if len(statements) != 2 {
		t.Fatalf("expected two statement events, got %+v", statements)
	}
	if statements[0].Operation != "query.read" || statements[0].Outcome != "ok" {
		t.Fatalf("read statement was not classified: %+v", statements[0])
	}
	if statements[1].Operation != "query.write" || statements[1].Outcome != "error" {
		t.Fatalf("failed write statement was not classified: %+v", statements[1])
	}
	if operations := operationEvents(observer.snapshot()); len(operations) != 1 {
		t.Fatalf("expected one operation event, got %+v", operations)
	}
}

func TestRepositoryStatementTelemetryCarriesNoStatementContent(t *testing.T) {
	observer := &recordingObserver{}
	repository := &Repository{observer: observer}
	ctx, done := repository.begin(context.Background(), "order.create")
	recorder, ok := observability.StatementRecorderFromContext(ctx)
	if !ok {
		t.Fatal("the repository operation did not bind a statement recorder")
	}
	recorder.Record(observability.StatementWrite, time.Millisecond,
		errors.New(`pq: duplicate key value violates unique constraint "order_tenant_pkey" on tenant 4bf92f35`))
	done(nil)

	statements := statementEvents(observer.snapshot())
	if len(statements) != 1 {
		t.Fatalf("expected one statement event, got %+v", statements)
	}
	rendered := strings.Join([]string{statements[0].Operation, statements[0].Outcome}, " ")
	for _, forbidden := range []string{"4bf92f35", "order_tenant_pkey", "duplicate key", "pq:", "INSERT", "SELECT"} {
		if strings.Contains(rendered, forbidden) {
			t.Fatalf("statement content leaked into telemetry: %q", rendered)
		}
	}
}

func TestRepositoryStatementTelemetryStaysSilentWithoutObserver(t *testing.T) {
	repository := &Repository{}
	ctx, done := repository.begin(context.Background(), "order.read")
	recorder, ok := observability.StatementRecorderFromContext(ctx)
	if !ok {
		t.Fatal("the repository operation did not bind a statement recorder")
	}
	recorder.Record(observability.StatementRead, time.Millisecond, nil)
	done(nil)
}

func TestPostgreSQLRepositoryStatementTelemetry(t *testing.T) {
	db, tenant, _ := repositoryTestDB(t)
	observer := &recordingObserver{}
	repo, err := NewRepository(db, WithObserver(observer))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	orderID := nextUUID()
	metadata := testMetadata(string(tenant), orderID)

	if _, err := repo.Create(ctx, tenant, testCreate("statement-"+nextUUID()), metadata, "statement-create-0001", "principal:requester-1"); err != nil {
		t.Fatalf("create for statement telemetry: %v", err)
	}
	statements := statementEvents(observer.snapshot())
	if len(statements) == 0 {
		t.Fatal("the create operation reported no database statements")
	}
	writes := 0
	for _, statement := range statements {
		if statement.Operation == "query.write" {
			writes++
		}
		if statement.Outcome != "ok" && statement.Outcome != "error" {
			t.Fatalf("unexpected statement outcome: %+v", statement)
		}
	}
	if writes == 0 {
		t.Fatalf("the create operation reported no write statements: %+v", statements)
	}

	observer.reset()
	if _, err := repo.Load(ctx, tenant, orderID); err != nil {
		t.Fatalf("load for statement telemetry: %v", err)
	}
	statements = statementEvents(observer.snapshot())
	if len(statements) == 0 {
		t.Fatal("the load operation reported no database statements")
	}
	for _, statement := range statements {
		if statement.Operation != "query.read" {
			t.Fatalf("the load operation reported a non-read statement: %+v", statement)
		}
	}
}
