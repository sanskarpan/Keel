package outbox

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sanskarpan/keel/internal/platform/observability"
)

type fakeStore struct {
	claim      Claim
	message    Message
	loadErr    error
	available  bool
	ackErr     error
	retryErr   error
	blockErr   error
	acked      bool
	blocked    bool
	retryCode  string
	retryDelay time.Duration
}

func (s *fakeStore) ClaimNext(context.Context, string, string, time.Duration) (Claim, bool, error) {
	return s.claim, s.available, nil
}
func (s *fakeStore) LoadClaimed(context.Context, Claim) (Message, error) { return s.message, s.loadErr }
func (s *fakeStore) Acknowledge(context.Context, Claim) error            { s.acked = true; return s.ackErr }
func (s *fakeStore) RecordFailure(_ context.Context, _ Claim, code string, delay time.Duration) error {
	s.retryCode, s.retryDelay = code, delay
	return s.retryErr
}
func (s *fakeStore) BlockPoison(context.Context, Claim) error { s.blocked = true; return s.blockErr }

type fakeBroker struct {
	err error
	got Message
}

func (b *fakeBroker) Publish(_ context.Context, message Message) error { b.got = message; return b.err }

func TestPublisherAcknowledgesOnlyBrokerSuccess(t *testing.T) {
	store := &fakeStore{claim: Claim{EventID: "stable-event", AttemptCount: 0}, message: Message{EventID: "stable-event", Payload: []byte(`{"event_id":"stable-event"}`)}, available: true}
	broker := &fakeBroker{}
	publisher, err := NewPublisher(store, broker, Config{LeaseDuration: 2 * time.Second, PublishTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	result, err := publisher.RunOnce(context.Background(), "11111111-1111-4111-8111-111111111111", "relay-1")
	if err != nil {
		t.Fatal(err)
	}
	if !result.Claimed || !result.Published || result.RetryScheduled || !store.acked || broker.got.EventID != "stable-event" {
		t.Fatalf("unexpected successful publish result=%+v acknowledged=%t message=%+v", result, store.acked, broker.got)
	}
}

func TestPublisherEmitsBoundedSuccessEventAndContainsObserverPanic(t *testing.T) {
	observer := &eventObserver{}
	store := &fakeStore{claim: Claim{EventID: "stable-event", AttemptCount: 1}, message: Message{
		SchemaVersion: 2, Traceparent: "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
	}, available: true}
	publisher, err := NewPublisher(store, &fakeBroker{}, Config{LeaseDuration: 2 * time.Second, PublishTimeout: time.Second, Observer: observer})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.RunOnce(context.Background(), "private-tenant", "private-worker"); err != nil {
		t.Fatal(err)
	}
	if len(observer.events) != 1 {
		t.Fatalf("observed %d events, want one", len(observer.events))
	}
	event := observer.events[0]
	if event.Operation != "outbox.publish" || event.Outcome != "published" || event.SchemaVersion != 2 || event.RetryCount != 1 || event.TraceID != "4bf92f3577b34da6a3ce929d0e0e4736" {
		t.Fatalf("unexpected telemetry event: %+v", event)
	}
	retryObserver := &eventObserver{}
	retryStore := &fakeStore{claim: Claim{EventID: "stable-event", AttemptCount: 2}, message: store.message, available: true}
	retryPublisher, err := NewPublisher(retryStore, &fakeBroker{err: ErrBrokerUnavailable}, Config{
		LeaseDuration: 2 * time.Second, PublishTimeout: time.Second, Observer: retryObserver,
	})
	if err != nil {
		t.Fatal(err)
	}
	retried, err := retryPublisher.RunOnce(context.Background(), "private-tenant", "private-worker")
	if err != nil || !retried.RetryScheduled {
		t.Fatalf("retry result=%+v err=%v", retried, err)
	}
	if got := retryObserver.events[0]; got.Outcome != "retry_scheduled" || got.RetryCount != 2 || got.TraceID != event.TraceID {
		t.Fatalf("retry telemetry lost bounded correlation: %+v", got)
	}
	v1Observer := &eventObserver{}
	v1Store := &fakeStore{claim: Claim{EventID: "stable-event"}, message: Message{
		SchemaVersion: 1, Traceparent: "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
	}, available: true}
	v1Publisher, err := NewPublisher(v1Store, &fakeBroker{}, Config{
		LeaseDuration: 2 * time.Second, PublishTimeout: time.Second, Observer: v1Observer,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v1Publisher.RunOnce(context.Background(), "private-tenant", "private-worker"); err != nil {
		t.Fatal(err)
	}
	if got := v1Observer.events[0]; got.SchemaVersion != 1 || got.TraceID != "" {
		t.Fatalf("v1 telemetry must omit trace correlation: %+v", got)
	}
	panicPublisher, err := NewPublisher(store, &fakeBroker{}, Config{LeaseDuration: 2 * time.Second, PublishTimeout: time.Second, Observer: panicEventObserver{}})
	if err != nil {
		t.Fatal(err)
	}
	result, err := panicPublisher.RunOnce(context.Background(), "private-tenant", "private-worker")
	if err != nil || !result.Published {
		t.Fatalf("observer panic changed publish outcome: result=%+v err=%v", result, err)
	}
}

type eventObserver struct{ events []observability.Event }

func (o *eventObserver) Observe(event observability.Event) { o.events = append(o.events, event) }

type panicEventObserver struct{}

func (panicEventObserver) Observe(observability.Event) { panic("observer failure") }

func TestPublisherPersistsClassifiedFailureWithoutAcknowledging(t *testing.T) {
	store := &fakeStore{claim: Claim{EventID: "stable-event", AttemptCount: 2}, available: true}
	broker := &fakeBroker{err: ErrBrokerUnavailable}
	publisher, err := NewPublisher(store, broker, Config{LeaseDuration: 2 * time.Second, PublishTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	result, err := publisher.RunOnce(context.Background(), "11111111-1111-4111-8111-111111111111", "relay-1")
	if err != nil {
		t.Fatal(err)
	}
	if !result.Claimed || result.Published || !result.RetryScheduled || result.ErrorCode != "broker_unavailable" || store.acked {
		t.Fatalf("unexpected failed publish result=%+v acknowledged=%t", result, store.acked)
	}
	if store.retryCode != "broker_unavailable" || store.retryDelay <= 0 || store.retryDelay > maximumRetryDelay {
		t.Fatalf("retry record code/delay=%q/%s", store.retryCode, store.retryDelay)
	}
}

func TestPublisherRejectsTimeoutLongerThanLease(t *testing.T) {
	_, err := NewPublisher(&fakeStore{}, &fakeBroker{}, Config{LeaseDuration: time.Second, PublishTimeout: time.Second})
	if err == nil {
		t.Fatal("publish timeout equal to lease was accepted")
	}
}

func TestRetryDelayIsStableBoundedAndJittered(t *testing.T) {
	first := RetryDelay("event-a", 1)
	if first != RetryDelay("event-a", 1) {
		t.Fatal("retry delay is not deterministic")
	}
	if first < 0 || first >= time.Second {
		t.Fatalf("attempt 1 delay=%s, want [0s,1s)", first)
	}
	if first == RetryDelay("event-b", 1) {
		t.Fatal("different event identities received the same first retry jitter")
	}
	if delay := RetryDelay("event-a", 100); delay < 0 || delay >= maximumRetryDelay {
		t.Fatalf("capped retry delay=%s, want [0,%s)", delay, maximumRetryDelay)
	}
}

func TestPublisherReturnsPersistenceErrorWhenRetryCannotBeRecorded(t *testing.T) {
	store := &fakeStore{claim: Claim{EventID: "stable-event"}, available: true, retryErr: errors.New("database unavailable")}
	broker := &fakeBroker{err: context.DeadlineExceeded}
	observer := &eventObserver{}
	publisher, err := NewPublisher(store, broker, Config{LeaseDuration: 2 * time.Second, PublishTimeout: time.Second, Observer: observer})
	if err != nil {
		t.Fatal(err)
	}
	result, err := publisher.RunOnce(context.Background(), "11111111-1111-4111-8111-111111111111", "relay-1")
	if err == nil || !result.RetryScheduled || result.ErrorCode != "broker_timeout" {
		t.Fatalf("result=%+v error=%v; expected durable retry error", result, err)
	}
	if len(observer.events) != 1 || observer.events[0].Outcome != "error" {
		t.Fatalf("failed retry persistence must not be reported as scheduled: %+v", observer.events)
	}
}

func TestPublisherDurablyBlocksCorruptEnvelopeWithoutAdvancingHead(t *testing.T) {
	store := &fakeStore{claim: Claim{EventID: "stable-event"}, available: true, loadErr: ErrPoisonEnvelope}
	observer := &eventObserver{}
	publisher, err := NewPublisher(store, &fakeBroker{}, Config{LeaseDuration: 2 * time.Second, PublishTimeout: time.Second, Observer: observer})
	if err != nil {
		t.Fatal(err)
	}
	result, err := publisher.RunOnce(context.Background(), "11111111-1111-4111-8111-111111111111", "relay-1")
	if !errors.Is(err, ErrPoisonEnvelope) || !result.Blocked || result.ErrorCode != "outbox_corrupt" || !store.blocked || store.acked {
		t.Fatalf("result=%+v err=%v blocked=%t acknowledged=%t", result, err, store.blocked, store.acked)
	}
	if len(observer.events) != 1 || observer.events[0].Outcome != "blocked" {
		t.Fatalf("durably blocked envelope has the wrong telemetry outcome: %+v", observer.events)
	}
}
