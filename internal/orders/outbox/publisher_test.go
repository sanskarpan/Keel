package outbox

import (
	"context"
	"errors"
	"testing"
	"time"
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
	publisher, err := NewPublisher(store, broker, Config{LeaseDuration: 2 * time.Second, PublishTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	result, err := publisher.RunOnce(context.Background(), "11111111-1111-4111-8111-111111111111", "relay-1")
	if err == nil || !result.RetryScheduled || result.ErrorCode != "broker_timeout" {
		t.Fatalf("result=%+v error=%v; expected durable retry error", result, err)
	}
}

func TestPublisherDurablyBlocksCorruptEnvelopeWithoutAdvancingHead(t *testing.T) {
	store := &fakeStore{claim: Claim{EventID: "stable-event"}, available: true, loadErr: ErrPoisonEnvelope}
	publisher, err := NewPublisher(store, &fakeBroker{}, Config{LeaseDuration: 2 * time.Second, PublishTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	result, err := publisher.RunOnce(context.Background(), "11111111-1111-4111-8111-111111111111", "relay-1")
	if !errors.Is(err, ErrPoisonEnvelope) || !result.Blocked || result.ErrorCode != "outbox_corrupt" || !store.blocked || store.acked {
		t.Fatalf("result=%+v err=%v blocked=%t acknowledged=%t", result, err, store.blocked, store.acked)
	}
}
