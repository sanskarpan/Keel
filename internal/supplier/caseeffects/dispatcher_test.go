package caseeffects

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/sanskarpan/keel/internal/platform/tenancy"
	"github.com/sanskarpan/keel/internal/supplier/caseeffects/postgres"
)

type fakeStore struct {
	context                  postgres.Context
	active                   bool
	failed, completed, noops int
	errorCode                string
}

func (s *fakeStore) LoadContext(context.Context, postgres.Lease) (postgres.Context, bool, error) {
	return s.context, s.active, nil
}
func (s *fakeStore) Complete(context.Context, postgres.Lease) error     { s.completed++; return nil }
func (s *fakeStore) CompleteNoop(context.Context, postgres.Lease) error { s.noops++; return nil }
func (s *fakeStore) Fail(_ context.Context, _ postgres.Lease, _ time.Duration, code string) error {
	s.failed++
	s.errorCode = code
	return nil
}

type fakeSink struct {
	keys, digests []string
	recipients    [][]string
	fail          bool
	expires       int
}

func (s *fakeSink) ExpireSupplierCase(context.Context, string, string) error { s.expires++; return nil }

func (s *fakeSink) DeliverReminder(_ context.Context, key, digest, occurrence string, recipients []string, _ time.Time) error {
	s.keys = append(s.keys, key)
	s.digests = append(s.digests, digest)
	s.recipients = append(s.recipients, append([]string{}, recipients...))
	if s.fail {
		return errors.New("provider error contains private customer data")
	}
	return nil
}

func TestReminderDispatcherKeepsStableEffectIdentityAcrossUncertainDelivery(t *testing.T) {
	store := &fakeStore{active: true, context: postgres.Context{CaseState: "submitted", EffectType: "case_reminder", DeadlineAt: time.Now().Add(time.Hour), Recipients: []string{"principal:reviewer-1"}}}
	sink := &fakeSink{fail: true}
	dispatcher, err := New(store, sink, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	tenant, _ := tenancy.ParseTenantID("11111111-1111-4111-8111-111111111111")
	first := postgres.Lease{TenantID: tenant, EffectID: "22222222-2222-4222-8222-222222222222", CaseID: "33333333-3333-4333-8333-333333333333", EffectKey: "case:reminder:midpoint", EffectType: "case_reminder", Occurrence: "midpoint", Digest: "abc", Owner: "44444444-4444-4444-8444-444444444444", Epoch: 1}
	if err := dispatcher.Execute(context.Background(), first); err == nil || err.Error() != "supplier case reminder was deferred" {
		t.Fatalf("provider detail escaped or retry was not persisted: %v", err)
	}
	if store.failed != 1 || store.errorCode != "sink_unavailable" {
		t.Fatalf("retry outcome was not coarse and durable: %+v", store)
	}
	sink.fail = false
	second := first
	second.Owner = "55555555-5555-4555-8555-555555555555"
	second.Epoch = 2
	if err := dispatcher.Execute(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	if store.completed != 1 || !reflect.DeepEqual(sink.keys, []string{first.EffectKey, first.EffectKey}) || !reflect.DeepEqual(sink.digests, []string{first.Digest, first.Digest}) || !reflect.DeepEqual(sink.recipients[0], sink.recipients[1]) {
		t.Fatalf("effect retry changed logical identity or recipients: sink=%+v store=%+v", sink, store)
	}
	store.active = false
	if err := dispatcher.Execute(context.Background(), second); err != nil || store.noops != 1 {
		t.Fatalf("inactive case did not become a no-op: err=%v store=%+v", err, store)
	}
}

func TestExpiryEffectInvokesLockedIdempotentCaseTransition(t *testing.T) {
	store := &fakeStore{active: true, context: postgres.Context{CaseState: "submitted", EffectType: "case_expiry", DeadlineAt: time.Now().Add(-time.Minute)}}
	sink := &fakeSink{}
	dispatcher, err := New(store, sink, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	tenant, _ := tenancy.ParseTenantID("11111111-1111-4111-8111-111111111111")
	lease := postgres.Lease{TenantID: tenant, EffectID: "22222222-2222-4222-8222-222222222222", CaseID: "33333333-3333-4333-8333-333333333333", EffectKey: "case:expiry:deadline", EffectType: "case_expiry", Occurrence: "deadline", Digest: "abc", Owner: "44444444-4444-4444-8444-444444444444", Epoch: 1}
	if err := dispatcher.Execute(context.Background(), lease); err != nil {
		t.Fatal(err)
	}
	if sink.expires != 1 || store.noops != 1 || store.completed != 0 {
		t.Fatalf("expiry effect was not durably finalized after the idempotent case transition: sink=%+v store=%+v", sink, store)
	}
}
