package postgres

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

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
	events := observer.snapshot()
	if len(events) != 1 {
		t.Fatalf("expected exactly one operation event, got %d: %+v", len(events), events)
	}
	return events[0]
}

func TestRepositoryOperationTelemetryReportsValidatedTraceOnly(t *testing.T) {
	observer := &recordingObserver{}
	repository := &Repository{observer: observer}
	const traceID = "4bf92f3577b34da6a3ce929d0e0e4736"

	traced, ok := observability.WithRemoteTraceparent(context.Background(), "00-"+traceID+"-00f067aa0ba902b7-01")
	if !ok {
		t.Fatal("build traced context")
	}
	repository.begin(traced, "order.create")(nil)
	if got := observedOperation(t, observer).TraceID; got != traceID {
		t.Fatalf("validated trace ID was not reported: %q", got)
	}

	observer.reset()
	repository.begin(context.Background(), "order.create")(nil)
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
	repository.begin(ctx, "order.read")(nil)
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
			repository.begin(context.Background(), "order.read")(testCase.err)
			if got := observedOperation(t, observer).Outcome; got != testCase.outcome {
				t.Fatalf("outcome %q does not classify %v", got, testCase.err)
			}
		})
	}
}

func TestRepositoryOperationTelemetryCarriesNoIdentifiers(t *testing.T) {
	observer := &recordingObserver{}
	repository := &Repository{observer: observer}
	done := repository.begin(context.Background(), "order.create")
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
	done := repository.begin(context.Background(), "order.create")
	done(nil)
}

func TestRepositoryWithoutObserverStaysSilent(t *testing.T) {
	repository := &Repository{}
	repository.begin(context.Background(), "order.read")(orders.ErrNotFound)
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
