package replay

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sanskarpan/keel/internal/ai/contextvault"
)

var testRequest = Request{
	TenantID: "11111111-1111-4111-8111-111111111111", ActorID: "22222222-2222-4222-8222-222222222222",
	RecordID: "33333333-3333-4333-8333-333333333333", Version: 2,
	Purpose: "read_only_replay", Reason: "support_diagnostic", RequestID: "request_0123456789abcdef",
}

type testKeys struct {
	unwraps atomic.Int32
}

func (k *testKeys) WrapKey(_ context.Context, _ contextvault.KeyBinding, key []byte) ([]byte, error) {
	return append([]byte{0xa5}, key...), nil
}

func (k *testKeys) UnwrapKey(_ context.Context, _ contextvault.KeyBinding, wrapped []byte) ([]byte, error) {
	k.unwraps.Add(1)
	if len(wrapped) != 33 || wrapped[0] != 0xa5 {
		return nil, errors.New("invalid test wrapped key")
	}
	return append([]byte(nil), wrapped[1:]...), nil
}

type testAuthorizer struct {
	err   error
	calls int
}

func (a *testAuthorizer) AuthorizeReplay(_ context.Context, _ Request) error {
	a.calls++
	return a.err
}

type testRepository struct {
	scope     contextvault.Scope
	envelope  contextvault.Envelope
	denials   int
	begins    int
	finishes  int
	outcome   Outcome
	beginErr  error
	finishErr error
}

func (r *testRepository) RecordDenied(_ context.Context, _ Request) error {
	r.denials++
	return nil
}

func (r *testRepository) BeginReplay(_ context.Context, _ Request) (contextvault.Scope, contextvault.Envelope, error) {
	r.begins++
	return r.scope, r.envelope, r.beginErr
}

func (r *testRepository) FinishReplay(_ context.Context, _ Request, outcome Outcome) error {
	r.finishes++
	r.outcome = outcome
	return r.finishErr
}

func (r *testRepository) DeliverReplay(_ context.Context, _ Request, deliver func() Outcome) error {
	r.finishes++
	r.outcome = deliver()
	if r.finishErr != nil {
		return r.finishErr
	}
	if r.outcome != OutcomeComplete {
		return ErrUnavailable
	}
	return nil
}

type testConsumer struct {
	got   []byte
	err   error
	calls int
}

func (c *testConsumer) Consume(_ context.Context, _ Request, plaintext []byte) error {
	c.calls++
	c.got = append([]byte(nil), plaintext...)
	return c.err
}

func newTestService(t *testing.T, auth *testAuthorizer, repo *testRepository, keys *testKeys, consumer *testConsumer) *Service {
	t.Helper()
	scope := contextvault.Scope{TenantID: testRequest.TenantID, RecordID: testRequest.RecordID,
		Version: testRequest.Version, PolicyDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	envelope, err := contextvault.Encrypt(context.Background(), keys, "test-key", scope, []byte("sensitive prompt"))
	if err != nil {
		t.Fatal(err)
	}
	repo.scope, repo.envelope = scope, envelope
	service, err := NewService(auth, repo, keys, consumer)
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func TestReplayDenialPrecedesRepositoryAndKeyAccess(t *testing.T) {
	auth := &testAuthorizer{err: errors.New("denied")}
	repo, keys, consumer := &testRepository{}, &testKeys{}, &testConsumer{}
	service := newTestService(t, auth, repo, keys, consumer)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := service.Execute(ctx, testRequest); !errors.Is(err, ErrNotAuthorized) {
		t.Fatalf("Execute error=%v, want authorization denial", err)
	}
	if auth.calls != 1 || repo.denials != 1 || repo.begins != 0 || keys.unwraps.Load() != 0 || consumer.calls != 0 {
		t.Fatalf("unauthorized replay crossed boundary: auth=%d deny_audit=%d begin=%d unwrap=%d consume=%d",
			auth.calls, repo.denials, repo.begins, keys.unwraps.Load(), consumer.calls)
	}
}

func TestReplayDeliversOnlyAuthenticatedExactVersionAndRecordsCompletion(t *testing.T) {
	auth := &testAuthorizer{}
	repo, keys, consumer := &testRepository{}, &testKeys{}, &testConsumer{}
	service := newTestService(t, auth, repo, keys, consumer)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := service.Execute(ctx, testRequest); err != nil {
		t.Fatalf("Execute error=%v", err)
	}
	if auth.calls != 1 || repo.begins != 1 || repo.finishes != 1 || repo.outcome != OutcomeComplete ||
		keys.unwraps.Load() != 1 || consumer.calls != 1 || string(consumer.got) != "sensitive prompt" {
		t.Fatalf("replay path mismatch: auth=%d begin=%d finish=%d outcome=%s unwrap=%d consume=%d payload=%q",
			auth.calls, repo.begins, repo.finishes, repo.outcome, keys.unwraps.Load(), consumer.calls, consumer.got)
	}
}

func TestReplayDeliveryFailureIsTerminalAndContentFree(t *testing.T) {
	auth := &testAuthorizer{}
	repo, keys, consumer := &testRepository{}, &testKeys{}, &testConsumer{err: errors.New("private sink error")}
	service := newTestService(t, auth, repo, keys, consumer)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := service.Execute(ctx, testRequest); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Execute error=%v, want generic unavailable", err)
	}
	if repo.finishes != 1 || repo.outcome != OutcomeDeliveryError {
		t.Fatalf("terminal audit mismatch: finishes=%d outcome=%q", repo.finishes, repo.outcome)
	}
}

func TestReplayRequiresDeadlineAndCanonicalizesScope(t *testing.T) {
	auth := &testAuthorizer{}
	repo, keys, consumer := &testRepository{}, &testKeys{}, &testConsumer{}
	service := newTestService(t, auth, repo, keys, consumer)
	if err := service.Execute(context.Background(), testRequest); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("no-deadline error=%v, want invalid request", err)
	}
	request := testRequest
	request.TenantID = "11111111-1111-4111-8111-111111111111"
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := service.Execute(ctx, request); err != nil {
		t.Fatalf("canonical scope replay error=%v", err)
	}
}

func TestReplayRejectsInvalidIdentityAndNilDependencies(t *testing.T) {
	if _, err := NewService(nil, &testRepository{}, &testKeys{}, &testConsumer{}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("nil authorizer error=%v", err)
	}
	service, err := NewService(&testAuthorizer{}, &testRepository{}, &testKeys{}, &testConsumer{})
	if err != nil {
		t.Fatal(err)
	}
	request := testRequest
	request.Reason = "arbitrary free-form sensitive details"
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := service.Execute(ctx, request); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("invalid reason error=%v", err)
	}
}
