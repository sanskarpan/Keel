package erasureworker

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sanskarpan/keel/internal/platform/tenancy"
	"github.com/sanskarpan/keel/internal/retrieval/postgres"
)

type processorFunc func(context.Context, tenancy.TenantID, string) (postgres.ErasureJob, bool, error)

func (f processorFunc) ProcessOne(ctx context.Context, tenant tenancy.TenantID, visibility string) (postgres.ErasureJob, bool, error) {
	return f(ctx, tenant, visibility)
}

type observerFunc func(Observation)

func (f observerFunc) ObserveErasurePoll(observation Observation) {
	f(observation)
}

type noopObserver struct{}

func (noopObserver) ObserveErasurePoll(Observation) {}

func noopErrorHandler(error) {}

func validScope() Scope {
	return Scope{Tenant: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", VisibilityKey: "private_documents"}
}

func TestNewValidatesAndNormalizesAuthorizedScope(t *testing.T) {
	processor := processorFunc(func(context.Context, tenancy.TenantID, string) (postgres.ErasureJob, bool, error) {
		return postgres.ErasureJob{}, false, nil
	})
	scope := validScope()
	scope.Tenant = "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"
	runtime, err := New(processor, scope, time.Second, noopObserver{}, noopErrorHandler)
	if err != nil {
		t.Fatalf("construct runtime: %v", err)
	}
	if got := string(runtime.scope.Tenant); got != "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" {
		t.Fatalf("tenant was not normalized: %q", got)
	}
	if got := runtime.scope.VisibilityKey; got != "private_documents" {
		t.Fatalf("visibility key changed unexpectedly: %q", got)
	}

	for _, tc := range []struct {
		name      string
		processor Processor
		scope     Scope
		interval  time.Duration
		observer  Observer
		onError   ErrorHandler
	}{
		{name: "nil processor", processor: nil, scope: validScope(), interval: time.Second, observer: noopObserver{}, onError: noopErrorHandler},
		{name: "nil observer", processor: processor, scope: validScope(), interval: time.Second, onError: noopErrorHandler},
		{name: "nil error handler", processor: processor, scope: validScope(), interval: time.Second, observer: noopObserver{}},
		{name: "invalid tenant", processor: processor, scope: Scope{VisibilityKey: "private_documents"}, interval: time.Second, observer: noopObserver{}, onError: noopErrorHandler},
		{name: "invalid visibility", processor: processor, scope: Scope{Tenant: validScope().Tenant, VisibilityKey: " "}, interval: time.Second, observer: noopObserver{}, onError: noopErrorHandler},
		{name: "poll interval too short", processor: processor, scope: validScope(), interval: MinPollInterval - time.Nanosecond, observer: noopObserver{}, onError: noopErrorHandler},
		{name: "poll interval too long", processor: processor, scope: validScope(), interval: MaxPollInterval + time.Nanosecond, observer: noopObserver{}, onError: noopErrorHandler},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(tc.processor, tc.scope, tc.interval, tc.observer, tc.onError); err == nil {
				t.Fatal("expected invalid runtime configuration to fail")
			}
		})
	}
}

func TestPollOnceReportsTerminalOutcomeAndError(t *testing.T) {
	failure := errors.New("provider unavailable")
	processor := processorFunc(func(_ context.Context, tenant tenancy.TenantID, visibility string) (postgres.ErasureJob, bool, error) {
		if tenant != validScope().Tenant || visibility != validScope().VisibilityKey {
			t.Fatalf("runtime used wrong scope: %s/%s", tenant, visibility)
		}
		return postgres.ErasureJob{State: "blocked"}, true, failure
	})
	runtime, err := New(processor, validScope(), time.Second, noopObserver{}, noopErrorHandler)
	if err != nil {
		t.Fatal(err)
	}
	observation, err := runtime.PollOnce(context.Background())
	if !errors.Is(err, failure) {
		t.Fatalf("expected processor error, got %v", err)
	}
	want := Observation{ScopeCount: 1, Claimed: 1, Blocked: 1, Errors: 1}
	if observation != want {
		t.Fatalf("unexpected poll observation: got %#v, want %#v", observation, want)
	}
}

func TestPollOnceHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	processor := processorFunc(func(context.Context, tenancy.TenantID, string) (postgres.ErasureJob, bool, error) {
		calls++
		cancel()
		return postgres.ErasureJob{State: "cleanup_pending"}, true, nil
	})
	runtime, err := New(processor, validScope(), time.Second, noopObserver{}, noopErrorHandler)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.PollOnce(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation, got %v", err)
	}
	if calls != 1 {
		t.Fatalf("runtime called processor %d times; want 1", calls)
	}
}

func TestRunPollsAndShutsDownOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	processor := processorFunc(func(context.Context, tenancy.TenantID, string) (postgres.ErasureJob, bool, error) {
		calls++
		return postgres.ErasureJob{}, false, nil
	})
	observations := 0
	observer := observerFunc(func(observation Observation) {
		observations++
		if observation != (Observation{ScopeCount: 1}) {
			t.Errorf("unexpected poll observation: %#v", observation)
		}
		cancel()
	})
	runtime, err := New(processor, validScope(), MaxPollInterval, observer, noopErrorHandler)
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.Run(ctx); err != nil {
		t.Fatalf("run should shut down cleanly: %v", err)
	}
	if calls != 1 || observations != 1 {
		t.Fatalf("run did not make exactly one poll before shutdown: calls=%d observations=%d", calls, observations)
	}
}

func TestRunReportsPollErrorsBeforeObserving(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	wantErr := errors.New("provider unavailable")
	processor := processorFunc(func(context.Context, tenancy.TenantID, string) (postgres.ErasureJob, bool, error) {
		return postgres.ErasureJob{State: "blocked"}, true, wantErr
	})
	var handled error
	var observed Observation
	observer := observerFunc(func(observation Observation) {
		observed = observation
		cancel()
	})
	runtime, err := New(processor, validScope(), MinPollInterval, observer, func(err error) { handled = err })
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.Run(ctx); err != nil {
		t.Fatalf("run should shut down cleanly: %v", err)
	}
	if !errors.Is(handled, wantErr) {
		t.Fatalf("worker error handler did not receive processor error: %v", handled)
	}
	if observed != (Observation{ScopeCount: 1, Claimed: 1, Blocked: 1, Errors: 1}) {
		t.Fatalf("unexpected error observation: %#v", observed)
	}
}
