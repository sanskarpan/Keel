package workflowdispatch

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sanskarpan/keel/internal/platform/tenancy"
	"github.com/sanskarpan/keel/internal/supplier/caseworkflow"
	"github.com/sanskarpan/keel/internal/supplier/workflowdispatch/postgres"
)

const testWorkerID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"

type fakeStore struct {
	lease     postgres.Lease
	found     bool
	completed bool
	failure   string
	retry     time.Duration
}

func (s *fakeStore) Claim(context.Context, tenancy.TenantID, string, time.Duration) (postgres.Lease, bool, error) {
	return s.lease, s.found, nil
}
func (s *fakeStore) Complete(context.Context, postgres.Lease) error { s.completed = true; return nil }
func (s *fakeStore) Fail(_ context.Context, _ postgres.Lease, retry time.Duration, code string) error {
	s.retry, s.failure = retry, code
	return nil
}

type fakeSender struct{ err error }

func (s fakeSender) Deliver(context.Context, tenancy.TenantID, caseworkflow.EventSignal) error {
	return s.err
}

func TestDispatchOneCompletesAfterDurableTemporalAck(t *testing.T) {
	tenant, _ := tenancy.ParseTenantID("11111111-1111-4111-8111-111111111111")
	store := &fakeStore{found: true, lease: postgres.Lease{TenantID: tenant, IntentID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", CaseID: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", Version: 1, EventType: "supplier.case.created", EventHash: strings.Repeat("a", 64), Attempt: 1, Owner: testWorkerID, Epoch: 1}}
	dispatcher, err := New(store, fakeSender{}, testWorkerID)
	if err != nil {
		t.Fatal(err)
	}
	found, err := dispatcher.DispatchOne(context.Background(), tenant)
	if err != nil || !found || !store.completed || store.failure != "" {
		t.Fatalf("dispatch found=%v err=%v store=%+v", found, err, store)
	}
}

func TestDispatchOnePersistsBoundedRetryCode(t *testing.T) {
	tenant, _ := tenancy.ParseTenantID("11111111-1111-4111-8111-111111111111")
	lease := postgres.Lease{TenantID: tenant, IntentID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", CaseID: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", Version: 1, EventType: "supplier.case.created", EventHash: strings.Repeat("a", 64), Attempt: 2, Owner: testWorkerID, Epoch: 1}
	store := &fakeStore{found: true, lease: lease}
	dispatcher, err := New(store, fakeSender{err: errors.New("sensitive endpoint details")}, testWorkerID)
	if err != nil {
		t.Fatal(err)
	}
	found, err := dispatcher.DispatchOne(context.Background(), tenant)
	if !found || err == nil || strings.Contains(err.Error(), "sensitive") || store.failure != "temporal_unavailable" || store.retry != RetryDelay(lease.IntentID, lease.Attempt) {
		t.Fatalf("failure was not safely deferred: found=%v err=%v store=%+v", found, err, store)
	}
}

func TestRetryDelayIsStableAndBounded(t *testing.T) {
	for attempt := uint32(1); attempt <= 30; attempt++ {
		first := RetryDelay("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", attempt)
		second := RetryDelay("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", attempt)
		if first != second || first < time.Second/2 || first > 15*time.Minute {
			t.Fatalf("attempt %d retry delay=%s repeated=%s", attempt, first, second)
		}
	}
}
