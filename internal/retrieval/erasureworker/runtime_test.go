package erasureworker

import (
	"context"
	"errors"
	"reflect"
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

func TestNewValidatesAndCopiesAuthorizedScopes(t *testing.T) {
	processor := processorFunc(func(context.Context, tenancy.TenantID, string) (postgres.ErasureJob, bool, error) {
		return postgres.ErasureJob{}, false, nil
	})
	scopes := []Scope{{Tenant: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", VisibilityKey: "private_documents"}}
	runtime, err := New(processor, scopes, time.Second, noopObserver{}, noopErrorHandler)
	if err != nil {
		t.Fatalf("construct runtime: %v", err)
	}
	scopes[0].Tenant = "invalid"
	if got := runtime.scopes[0].Tenant; got != "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" {
		t.Fatalf("runtime scope was aliased to caller memory: %q", got)
	}

	for _, tc := range []struct {
		name     string
		scopes   []Scope
		interval time.Duration
	}{
		{name: "empty scope set", scopes: nil, interval: time.Second},
		{name: "invalid tenant", scopes: []Scope{{Tenant: "invalid", VisibilityKey: "private_documents"}}, interval: time.Second},
		{name: "invalid visibility", scopes: []Scope{{Tenant: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", VisibilityKey: " "}}, interval: time.Second},
		{name: "duplicate scope", scopes: []Scope{{Tenant: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", VisibilityKey: "private_documents"}, {Tenant: "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA", VisibilityKey: "private_documents"}}, interval: time.Second},
		{name: "poll interval too short", scopes: []Scope{{Tenant: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", VisibilityKey: "private_documents"}}, interval: MinPollInterval - time.Nanosecond},
		{name: "poll interval too long", scopes: []Scope{{Tenant: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", VisibilityKey: "private_documents"}}, interval: MaxPollInterval + time.Nanosecond},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(processor, tc.scopes, tc.interval, noopObserver{}, noopErrorHandler); err == nil {
				t.Fatal("expected invalid runtime configuration to fail")
			}
		})
	}
}

func TestPollOnceIsBoundedAndContinuesAfterScopeError(t *testing.T) {
	tenantA := tenancy.TenantID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
	tenantB := tenancy.TenantID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
	wantScopes := []Scope{{Tenant: tenantA, VisibilityKey: "private_documents"}, {Tenant: tenantB, VisibilityKey: "supplier_portal"}}
	var gotScopes []Scope
	failure := errors.New("transient database error")
	processor := processorFunc(func(_ context.Context, tenant tenancy.TenantID, visibility string) (postgres.ErasureJob, bool, error) {
		gotScopes = append(gotScopes, Scope{Tenant: tenant, VisibilityKey: visibility})
		if tenant == tenantA {
			return postgres.ErasureJob{State: "blocked"}, true, failure
		}
		return postgres.ErasureJob{State: "complete"}, true, nil
	})
	runtime, err := New(processor, wantScopes, time.Second, noopObserver{}, noopErrorHandler)
	if err != nil {
		t.Fatal(err)
	}
	observation, err := runtime.PollOnce(context.Background())
	if !errors.Is(err, failure) {
		t.Fatalf("expected aggregated scope error, got %v", err)
	}
	want := Observation{ScopeCount: 2, Claimed: 2, Completed: 1, Blocked: 1, Errors: 1}
	if !reflect.DeepEqual(observation, want) {
		t.Fatalf("unexpected poll observation: got %#v, want %#v", observation, want)
	}
	if !reflect.DeepEqual(gotScopes, wantScopes) {
		t.Fatalf("runtime did not process exactly one bounded attempt per scope: got %#v", gotScopes)
	}
}

func TestPollOnceHonorsCancellationBeforeNextScope(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	tenantA := tenancy.TenantID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
	tenantB := tenancy.TenantID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
	var calls int
	processor := processorFunc(func(_ context.Context, tenant tenancy.TenantID, _ string) (postgres.ErasureJob, bool, error) {
		calls++
		if tenant == tenantA {
			cancel()
		}
		return postgres.ErasureJob{}, true, nil
	})
	runtime, err := New(processor, []Scope{{Tenant: tenantA, VisibilityKey: "private_documents"}, {Tenant: tenantB, VisibilityKey: "supplier_portal"}}, time.Second, noopObserver{}, noopErrorHandler)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.PollOnce(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation, got %v", err)
	}
	if calls != 1 {
		t.Fatalf("runtime called processor %d times after cancellation; want 1", calls)
	}
}

func TestRunPollsAndShutsDownOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var calls int
	processor := processorFunc(func(context.Context, tenancy.TenantID, string) (postgres.ErasureJob, bool, error) {
		calls++
		return postgres.ErasureJob{}, false, nil
	})
	var observations int
	observer := observerFunc(func(observation Observation) {
		observations++
		if observation != (Observation{ScopeCount: 1}) {
			t.Errorf("unexpected poll observation: %#v", observation)
		}
		cancel()
	})
	runtime, err := New(processor,
		[]Scope{{Tenant: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", VisibilityKey: "private_documents"}},
		MaxPollInterval, observer, noopErrorHandler)
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
