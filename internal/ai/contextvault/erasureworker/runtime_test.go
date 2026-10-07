package erasureworker

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sanskarpan/keel/internal/ai/contextvault/postgres"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

func TestRuntimeValidatesOneAuthorizedScopeAndPollsWithoutScopeLabels(t *testing.T) {
	processor := &fakeProcessor{claimed: true, job: postgres.ErasureJob{State: "complete"}}
	observer := &fakeObserver{}
	var reported error
	runtime, err := New(processor, Scope{Tenant: tenancy.TenantID("11111111-1111-4111-8111-111111111111")}, time.Second, observer, func(err error) {
		reported = err
	})
	if err != nil {
		t.Fatal(err)
	}
	observation, err := runtime.PollOnce(context.Background())
	if err != nil || observation.Claimed != 1 || observation.Completed != 1 || observation.Errors != 0 ||
		processor.tenant != "11111111-1111-4111-8111-111111111111" {
		t.Fatalf("observation=%+v err=%v processor=%+v", observation, err, processor)
	}
	if reported != nil || observer.calls != 0 {
		t.Fatalf("constructor/poll unexpectedly emitted error=%v observer_calls=%d", reported, observer.calls)
	}
}

func TestRuntimeReportsOnlyAggregatedErrorsAndCancelsCleanly(t *testing.T) {
	processor := &fakeProcessor{claimed: true, job: postgres.ErasureJob{State: "blocked"}, err: errors.New("safe worker error")}
	observer := &fakeObserver{}
	var reported error
	runtime, err := New(processor, Scope{Tenant: tenancy.TenantID("11111111-1111-4111-8111-111111111111")}, time.Second, observer, func(err error) {
		reported = err
	})
	if err != nil {
		t.Fatal(err)
	}
	observation, err := runtime.PollOnce(context.Background())
	if !errors.Is(err, processor.err) || observation.Errors != 1 || observation.Blocked != 1 {
		t.Fatalf("observation=%+v err=%v", observation, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := runtime.Run(ctx); err != nil {
		t.Fatalf("cancelled run returned error: %v", err)
	}
	if reported != nil || observer.calls != 0 {
		t.Fatalf("cancelled run did work: reported=%v observer_calls=%d", reported, observer.calls)
	}
}

func TestRuntimeCountsLegalHoldSeparatelyFromCompletedErasure(t *testing.T) {
	processor := &fakeProcessor{claimed: true, job: postgres.ErasureJob{State: "held"}}
	observer := &fakeObserver{}
	runtime, err := New(processor, Scope{Tenant: tenancy.TenantID("11111111-1111-4111-8111-111111111111")}, time.Second, observer, func(error) {})
	if err != nil {
		t.Fatal(err)
	}
	observation, err := runtime.PollOnce(context.Background())
	if err != nil || observation.Claimed != 1 || observation.Held != 1 || observation.Completed != 0 {
		t.Fatalf("held observation=%+v err=%v", observation, err)
	}
}

func TestRuntimeRejectsInvalidScopeAndPollingBounds(t *testing.T) {
	processor := &fakeProcessor{}
	observer := &fakeObserver{}
	valid := Scope{Tenant: tenancy.TenantID("11111111-1111-4111-8111-111111111111")}
	for _, test := range []struct {
		name     string
		scope    Scope
		interval time.Duration
	}{
		{name: "invalid tenant", scope: Scope{Tenant: tenancy.TenantID("bad")}, interval: time.Second},
		{name: "short poll", scope: valid, interval: time.Millisecond},
		{name: "long poll", scope: valid, interval: MaxPollInterval + time.Second},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := New(processor, test.scope, test.interval, observer, func(error) {}); err == nil {
				t.Fatal("invalid runtime configuration was accepted")
			}
		})
	}
}

type fakeProcessor struct {
	claimed bool
	job     postgres.ErasureJob
	err     error
	tenant  string
}

func (p *fakeProcessor) ProcessOne(_ context.Context, tenant tenancy.TenantID) (postgres.ErasureJob, bool, error) {
	p.tenant = string(tenant)
	return p.job, p.claimed, p.err
}

type fakeObserver struct{ calls int }

func (o *fakeObserver) ObserveContextErasurePoll(Observation) { o.calls++ }
