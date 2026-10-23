package worker

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sanskarpan/keel/internal/delivery/webhook"
	"github.com/sanskarpan/keel/internal/delivery/webhook/postgres"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

var testNow = time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)

type breakerSave struct {
	endpointID      string
	expectedVersion int64
	state           webhook.BreakerState
}

type fakeStore struct {
	leases         []postgres.Lease
	leaseErr       error
	breakers       map[string]postgres.BreakerSnapshot
	breakerErr     error
	saves          []breakerSave
	saveErr        error
	endpoints      map[string]webhook.Endpoint
	endpointErrors map[string]error
	recorded       []postgres.AttemptResult
	recordState    webhook.DeliveryState
	recordErr      error
	trace          *[]string
}

func (s *fakeStore) Lease(context.Context, tenancy.TenantID, int, time.Duration) ([]postgres.Lease, error) {
	return s.leases, s.leaseErr
}

func (s *fakeStore) Endpoint(_ context.Context, _ tenancy.TenantID, endpointID string, _ uint32) (webhook.Endpoint, error) {
	if err := s.endpointErrors[endpointID]; err != nil {
		return webhook.Endpoint{}, err
	}
	endpoint, exists := s.endpoints[endpointID]
	if !exists {
		return webhook.Endpoint{}, webhook.ErrEndpointUnavailable
	}
	return endpoint, nil
}

func (s *fakeStore) Breaker(_ context.Context, _ tenancy.TenantID, endpointID string) (postgres.BreakerSnapshot, error) {
	if s.breakerErr != nil {
		return postgres.BreakerSnapshot{}, s.breakerErr
	}
	snapshot, exists := s.breakers[endpointID]
	if !exists {
		return postgres.BreakerSnapshot{State: webhook.BreakerState{Status: webhook.BreakerClosed}}, nil
	}
	return snapshot, nil
}

func (s *fakeStore) SaveBreaker(_ context.Context, _ tenancy.TenantID, endpointID string, expectedVersion int64, state webhook.BreakerState) (postgres.BreakerSnapshot, error) {
	if s.saveErr != nil {
		return postgres.BreakerSnapshot{}, s.saveErr
	}
	if s.trace != nil {
		*s.trace = append(*s.trace, "save")
	}
	s.saves = append(s.saves, breakerSave{endpointID: endpointID, expectedVersion: expectedVersion, state: state})
	return postgres.BreakerSnapshot{State: state, Version: expectedVersion + 1}, nil
}

func (s *fakeStore) RecordAttempt(_ context.Context, _ postgres.Lease, result postgres.AttemptResult) (postgres.DeliveryState, error) {
	if s.recordErr != nil {
		return postgres.DeliveryState{}, s.recordErr
	}
	if s.trace != nil {
		*s.trace = append(*s.trace, "record")
	}
	s.recorded = append(s.recorded, result)
	return postgres.DeliveryState{State: s.recordState, Attempts: 1}, nil
}

type fakePayloads struct {
	body []byte
	err  error
}

func (p fakePayloads) Payload(context.Context, tenancy.TenantID, webhook.Delivery) ([]byte, error) {
	return p.body, p.err
}

type fakeSender struct {
	result  webhook.AttemptResult
	err     error
	calls   int
	request webhook.AttemptRequest
	trace   *[]string
}

func (s *fakeSender) Execute(_ context.Context, request webhook.AttemptRequest) (webhook.AttemptResult, error) {
	s.calls++
	s.request = request
	if s.trace != nil {
		*s.trace = append(*s.trace, "send")
	}
	return s.result, s.err
}

func testTenant(t *testing.T) tenancy.TenantID {
	t.Helper()
	tenant, err := tenancy.ParseTenantID(uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	return tenant
}

func testLease(t *testing.T, tenant tenancy.TenantID) postgres.Lease {
	t.Helper()
	endpointID := uuid.NewString()
	return postgres.Lease{
		Delivery: webhook.Delivery{
			ID: uuid.NewString(),
			Identity: webhook.Identity{
				Tenant:              tenant,
				EventID:             "evt_" + uuid.NewString(),
				EndpointID:          endpointID,
				SubscriptionVersion: 1,
			},
		},
		AttemptNumber:  1,
		AttemptID:      uuid.NewString(),
		LeaseEpoch:     1,
		LeaseExpiresAt: testNow.Add(time.Minute),
		FirstAttemptAt: testNow.Add(-time.Minute),
	}
}

func testEndpoint(lease postgres.Lease) webhook.Endpoint {
	return webhook.Endpoint{
		Tenant:              lease.Delivery.Identity.Tenant,
		ID:                  lease.Delivery.Identity.EndpointID,
		URL:                 "https://receiver.example.com/hooks/orders",
		KeyID:               "key_webhook_test",
		SubscriptionVersion: lease.Delivery.Identity.SubscriptionVersion,
		Status:              webhook.EndpointActive,
	}
}

func testScheduler(t *testing.T, maxAttempts int) *webhook.Scheduler {
	t.Helper()
	scheduler, err := webhook.NewSchedulerWithRand(webhook.RetryPolicy{
		MaxAttempts: maxAttempts,
		Window:      24 * time.Hour,
		Base:        10 * time.Second,
		Cap:         time.Hour,
	}, func() float64 { return 0.5 })
	if err != nil {
		t.Fatal(err)
	}
	return scheduler
}

func newRunner(t *testing.T, store Store, payloads PayloadSource, sender Sender) *Runner {
	t.Helper()
	runner, err := New(store, payloads, sender, testScheduler(t, 12), webhook.DefaultBreakerPolicy(),
		WithClock(func() time.Time { return testNow }))
	if err != nil {
		t.Fatal(err)
	}
	return runner
}

func TestRunDelivered(t *testing.T) {
	tenant := testTenant(t)
	lease := testLease(t, tenant)
	store := &fakeStore{
		leases:      []postgres.Lease{lease},
		endpoints:   map[string]webhook.Endpoint{lease.Delivery.Identity.EndpointID: testEndpoint(lease)},
		recordState: webhook.StateDelivered,
	}
	sender := &fakeSender{result: webhook.AttemptResult{Outcome: webhook.OutcomeDelivered, HTTPStatus: 200, Latency: 25 * time.Millisecond}}
	runner := newRunner(t, store, fakePayloads{body: []byte(`{"ok":true}`)}, sender)

	report, err := runner.Run(context.Background(), tenant, 10)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if report.Leased != 1 || report.Delivered != 1 {
		t.Fatalf("report = %+v", report)
	}
	if sender.calls != 1 || len(store.recorded) != 1 {
		t.Fatalf("sender calls = %d, recorded = %d", sender.calls, len(store.recorded))
	}
	recorded := store.recorded[0]
	if recorded.Outcome != webhook.OutcomeDelivered || recorded.HTTPStatus != 200 ||
		recorded.Latency != 25*time.Millisecond || recorded.NextAttemptAt != nil {
		t.Fatalf("recorded = %+v", recorded)
	}
	if len(store.saves) != 0 {
		t.Fatalf("delivered from a closed breaker saved %d breaker states", len(store.saves))
	}
	if sender.request.AttemptID != lease.AttemptID || sender.request.AttemptNumber != 1 ||
		string(sender.request.Body) != `{"ok":true}` || !sender.request.Now.Equal(testNow) {
		t.Fatalf("attempt request = %+v", sender.request)
	}
}

func TestRunRetryableOpensBreaker(t *testing.T) {
	tenant := testTenant(t)
	lease := testLease(t, tenant)
	store := &fakeStore{
		leases:    []postgres.Lease{lease},
		endpoints: map[string]webhook.Endpoint{lease.Delivery.Identity.EndpointID: testEndpoint(lease)},
		breakers: map[string]postgres.BreakerSnapshot{
			lease.Delivery.Identity.EndpointID: {
				State: webhook.BreakerState{Status: webhook.BreakerClosed, Failures: 4},
			},
		},
		recordState: webhook.StatePending,
	}
	sender := &fakeSender{result: webhook.AttemptResult{Outcome: webhook.OutcomeRetryable, HTTPStatus: 503}}
	runner := newRunner(t, store, fakePayloads{body: []byte(`{}`)}, sender)

	report, err := runner.Run(context.Background(), tenant, 10)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if report.RetryScheduled != 1 {
		t.Fatalf("report = %+v", report)
	}
	if len(store.recorded) != 1 || store.recorded[0].NextAttemptAt == nil ||
		!store.recorded[0].NextAttemptAt.After(testNow) {
		t.Fatalf("recorded = %+v", store.recorded)
	}
	if len(store.saves) != 1 {
		t.Fatalf("saves = %+v", store.saves)
	}
	saved := store.saves[0]
	if saved.endpointID != lease.Delivery.Identity.EndpointID || saved.expectedVersion != 0 ||
		saved.state.Status != webhook.BreakerOpen || saved.state.OpenFor != webhook.DefaultBreakerOpenFor {
		t.Fatalf("saved breaker = %+v", saved)
	}
}

func TestRunPermanentClosesBreaker(t *testing.T) {
	tenant := testTenant(t)
	lease := testLease(t, tenant)
	store := &fakeStore{
		leases:    []postgres.Lease{lease},
		endpoints: map[string]webhook.Endpoint{lease.Delivery.Identity.EndpointID: testEndpoint(lease)},
		breakers: map[string]postgres.BreakerSnapshot{
			lease.Delivery.Identity.EndpointID: {
				State: webhook.BreakerState{Status: webhook.BreakerClosed, Failures: 2},
			},
		},
		recordState: webhook.StateFailed,
	}
	sender := &fakeSender{result: webhook.AttemptResult{Outcome: webhook.OutcomePermanent, HTTPStatus: 400}}
	runner := newRunner(t, store, fakePayloads{body: []byte(`{}`)}, sender)

	report, err := runner.Run(context.Background(), tenant, 10)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if report.Failed != 1 {
		t.Fatalf("report = %+v", report)
	}
	if len(store.saves) != 1 || store.saves[0].state != (webhook.BreakerState{Status: webhook.BreakerClosed}) {
		t.Fatalf("saves = %+v", store.saves)
	}
	if store.recorded[0].NextAttemptAt != nil {
		t.Fatalf("permanent attempt scheduled a retry: %+v", store.recorded[0])
	}
}

func TestRunBreakerOpenDefersWithoutSending(t *testing.T) {
	tenant := testTenant(t)
	lease := testLease(t, tenant)
	store := &fakeStore{
		leases:    []postgres.Lease{lease},
		endpoints: map[string]webhook.Endpoint{lease.Delivery.Identity.EndpointID: testEndpoint(lease)},
		breakers: map[string]postgres.BreakerSnapshot{
			lease.Delivery.Identity.EndpointID: {
				State: webhook.BreakerState{
					Status:   webhook.BreakerOpen,
					OpenedAt: testNow.Add(-10 * time.Second),
					OpenFor:  30 * time.Second,
				},
				Version: 3,
			},
		},
		recordState: webhook.StatePending,
	}
	sender := &fakeSender{}
	runner := newRunner(t, store, fakePayloads{body: []byte(`{}`)}, sender)

	report, err := runner.Run(context.Background(), tenant, 10)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if report.Deferred != 1 || sender.calls != 0 {
		t.Fatalf("report = %+v, sender calls = %d", report, sender.calls)
	}
	if len(store.recorded) != 1 || store.recorded[0].Outcome != webhook.OutcomeRetryable ||
		store.recorded[0].HTTPStatus != 0 || store.recorded[0].NextAttemptAt == nil {
		t.Fatalf("recorded = %+v", store.recorded)
	}
	if !store.recorded[0].NextAttemptAt.After(testNow.Add(19 * time.Second)) {
		t.Fatalf("deferred until %s, want after the cooldown", store.recorded[0].NextAttemptAt)
	}
	if len(store.saves) != 0 {
		t.Fatalf("still-open breaker was rewritten: %+v", store.saves)
	}
}

func TestRunHalfOpenSavesProbeBeforeSending(t *testing.T) {
	tenant := testTenant(t)
	lease := testLease(t, tenant)
	store := &fakeStore{
		leases:    []postgres.Lease{lease},
		endpoints: map[string]webhook.Endpoint{lease.Delivery.Identity.EndpointID: testEndpoint(lease)},
		breakers: map[string]postgres.BreakerSnapshot{
			lease.Delivery.Identity.EndpointID: {
				State: webhook.BreakerState{
					Status:   webhook.BreakerOpen,
					OpenedAt: testNow.Add(-31 * time.Second),
					OpenFor:  30 * time.Second,
				},
				Version: 6,
			},
		},
		recordState: webhook.StateDelivered,
	}
	trace := []string{}
	store.trace = &trace
	sender := &fakeSender{
		result: webhook.AttemptResult{Outcome: webhook.OutcomeDelivered, HTTPStatus: 204},
		trace:  &trace,
	}
	runner := newRunner(t, store, fakePayloads{body: []byte(`{}`)}, sender)

	report, err := runner.Run(context.Background(), tenant, 10)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if report.Delivered != 1 {
		t.Fatalf("report = %+v", report)
	}
	if len(store.saves) != 2 {
		t.Fatalf("saves = %+v", store.saves)
	}
	if store.saves[0].state.Status != webhook.BreakerHalfOpen || store.saves[0].state.Probes != 1 ||
		store.saves[0].expectedVersion != 6 {
		t.Fatalf("probe admission save = %+v", store.saves[0])
	}
	if store.saves[1].state != (webhook.BreakerState{Status: webhook.BreakerClosed}) ||
		store.saves[1].expectedVersion != 7 {
		t.Fatalf("closing save = %+v", store.saves[1])
	}
	if strings.Join(trace, ",") != "save,send,record,save" {
		t.Fatalf("trace = %v", trace)
	}
}

func TestRunHalfOpenProbeCapDefers(t *testing.T) {
	tenant := testTenant(t)
	lease := testLease(t, tenant)
	store := &fakeStore{
		leases:    []postgres.Lease{lease},
		endpoints: map[string]webhook.Endpoint{lease.Delivery.Identity.EndpointID: testEndpoint(lease)},
		breakers: map[string]postgres.BreakerSnapshot{
			lease.Delivery.Identity.EndpointID: {
				State: webhook.BreakerState{
					Status:   webhook.BreakerHalfOpen,
					OpenedAt: testNow.Add(-time.Minute),
					OpenFor:  30 * time.Second,
					Probes:   1,
				},
				Version: 2,
			},
		},
		recordState: webhook.StatePending,
	}
	sender := &fakeSender{}
	runner := newRunner(t, store, fakePayloads{body: []byte(`{}`)}, sender)

	report, err := runner.Run(context.Background(), tenant, 10)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if report.Deferred != 1 || sender.calls != 0 {
		t.Fatalf("report = %+v, sender calls = %d", report, sender.calls)
	}
	if store.recorded[0].NextAttemptAt == nil ||
		!store.recorded[0].NextAttemptAt.After(testNow.Add(4*time.Second)) {
		t.Fatalf("deferred until %v, want at least the minimum defer", store.recorded[0].NextAttemptAt)
	}
}

func TestRunEndpointUnavailableIsPermanent(t *testing.T) {
	tenant := testTenant(t)
	lease := testLease(t, tenant)
	store := &fakeStore{
		leases:         []postgres.Lease{lease},
		endpoints:      map[string]webhook.Endpoint{},
		endpointErrors: map[string]error{lease.Delivery.Identity.EndpointID: webhook.ErrEndpointUnavailable},
		recordState:    webhook.StateFailed,
	}
	sender := &fakeSender{}
	runner := newRunner(t, store, fakePayloads{body: []byte(`{}`)}, sender)

	report, err := runner.Run(context.Background(), tenant, 10)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if report.Failed != 1 || sender.calls != 0 {
		t.Fatalf("report = %+v, sender calls = %d", report, sender.calls)
	}
	if store.recorded[0].Outcome != webhook.OutcomePermanent || store.recorded[0].HTTPStatus != 0 {
		t.Fatalf("recorded = %+v", store.recorded[0])
	}
}

func TestRunInvalidPayloadIsPermanent(t *testing.T) {
	tenant := testTenant(t)
	lease := testLease(t, tenant)
	store := &fakeStore{
		leases:      []postgres.Lease{lease},
		endpoints:   map[string]webhook.Endpoint{lease.Delivery.Identity.EndpointID: testEndpoint(lease)},
		recordState: webhook.StateFailed,
	}
	sender := &fakeSender{}
	runner := newRunner(t, store, fakePayloads{err: webhook.ErrInvalidDelivery}, sender)

	report, err := runner.Run(context.Background(), tenant, 10)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if report.Failed != 1 || sender.calls != 0 {
		t.Fatalf("report = %+v, sender calls = %d", report, sender.calls)
	}
	if store.recorded[0].Outcome != webhook.OutcomePermanent {
		t.Fatalf("recorded = %+v", store.recorded[0])
	}
}

func TestRunPayloadFetchFailureRetries(t *testing.T) {
	tenant := testTenant(t)
	lease := testLease(t, tenant)
	store := &fakeStore{
		leases:      []postgres.Lease{lease},
		endpoints:   map[string]webhook.Endpoint{lease.Delivery.Identity.EndpointID: testEndpoint(lease)},
		recordState: webhook.StatePending,
	}
	sender := &fakeSender{}
	runner := newRunner(t, store, fakePayloads{err: errors.New("payload store is unavailable")}, sender)

	report, err := runner.Run(context.Background(), tenant, 10)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if report.RetryScheduled != 1 || sender.calls != 0 {
		t.Fatalf("report = %+v, sender calls = %d", report, sender.calls)
	}
	if store.recorded[0].Outcome != webhook.OutcomeRetryable ||
		store.recorded[0].NextAttemptAt == nil {
		t.Fatalf("recorded = %+v", store.recorded[0])
	}
}

func TestRunBreakerSaveConflictSkipsSend(t *testing.T) {
	tenant := testTenant(t)
	lease := testLease(t, tenant)
	store := &fakeStore{
		leases:    []postgres.Lease{lease},
		endpoints: map[string]webhook.Endpoint{lease.Delivery.Identity.EndpointID: testEndpoint(lease)},
		breakers: map[string]postgres.BreakerSnapshot{
			lease.Delivery.Identity.EndpointID: {
				State: webhook.BreakerState{
					Status:   webhook.BreakerOpen,
					OpenedAt: testNow.Add(-31 * time.Second),
					OpenFor:  30 * time.Second,
				},
				Version: 4,
			},
		},
		saveErr: errors.New("version conflict"),
	}
	sender := &fakeSender{}
	runner := newRunner(t, store, fakePayloads{body: []byte(`{}`)}, sender)

	report, err := runner.Run(context.Background(), tenant, 10)
	if err == nil || !strings.Contains(err.Error(), "version conflict") {
		t.Fatalf("Run() error = %v", err)
	}
	if report.Skipped != 1 || sender.calls != 0 || len(store.recorded) != 0 {
		t.Fatalf("report = %+v, sender calls = %d, recorded = %d", report, sender.calls, len(store.recorded))
	}
}

func TestRunRetryExhausted(t *testing.T) {
	tenant := testTenant(t)
	lease := testLease(t, tenant)
	store := &fakeStore{
		leases:      []postgres.Lease{lease},
		endpoints:   map[string]webhook.Endpoint{lease.Delivery.Identity.EndpointID: testEndpoint(lease)},
		recordState: webhook.StateExhausted,
	}
	sender := &fakeSender{result: webhook.AttemptResult{Outcome: webhook.OutcomeRetryable, HTTPStatus: 500}}
	runner, err := New(store, fakePayloads{body: []byte(`{}`)}, sender, testScheduler(t, 1),
		webhook.DefaultBreakerPolicy(), WithClock(func() time.Time { return testNow }))
	if err != nil {
		t.Fatal(err)
	}

	report, err := runner.Run(context.Background(), tenant, 10)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if report.Exhausted != 1 {
		t.Fatalf("report = %+v", report)
	}
	if store.recorded[0].NextAttemptAt != nil {
		t.Fatalf("exhausted attempt scheduled a retry: %+v", store.recorded[0])
	}
}

func TestRunContinuesAfterOneFailure(t *testing.T) {
	tenant := testTenant(t)
	good := testLease(t, tenant)
	bad := testLease(t, tenant)
	store := &fakeStore{
		leases:    []postgres.Lease{bad, good},
		endpoints: map[string]webhook.Endpoint{good.Delivery.Identity.EndpointID: testEndpoint(good)},
		endpointErrors: map[string]error{
			bad.Delivery.Identity.EndpointID: errors.New("endpoint store is unavailable"),
		},
		recordState: webhook.StateDelivered,
	}
	sender := &fakeSender{result: webhook.AttemptResult{Outcome: webhook.OutcomeDelivered, HTTPStatus: 200}}
	runner := newRunner(t, store, fakePayloads{body: []byte(`{}`)}, sender)

	report, err := runner.Run(context.Background(), tenant, 10)
	if err == nil {
		t.Fatal("expected the per-delivery failure to be reported")
	}
	if report.Delivered != 1 || report.Skipped != 1 {
		t.Fatalf("report = %+v", report)
	}
}

func TestRunValidatesInput(t *testing.T) {
	tenant := testTenant(t)
	store := &fakeStore{}
	if _, err := New(nil, fakePayloads{}, &fakeSender{}, testScheduler(t, 12), webhook.DefaultBreakerPolicy()); err == nil {
		t.Fatal("expected a nil store to be rejected")
	}
	if _, err := New(store, nil, &fakeSender{}, testScheduler(t, 12), webhook.DefaultBreakerPolicy()); err == nil {
		t.Fatal("expected a nil payload source to be rejected")
	}
	if _, err := New(store, fakePayloads{}, nil, testScheduler(t, 12), webhook.DefaultBreakerPolicy()); err == nil {
		t.Fatal("expected a nil sender to be rejected")
	}
	if _, err := New(store, fakePayloads{}, &fakeSender{}, nil, webhook.DefaultBreakerPolicy()); err == nil {
		t.Fatal("expected a nil scheduler to be rejected")
	}
	if _, err := New(store, fakePayloads{}, &fakeSender{}, testScheduler(t, 12), webhook.BreakerPolicy{}); err == nil {
		t.Fatal("expected an invalid breaker policy to be rejected")
	}
	if _, err := New(store, fakePayloads{}, &fakeSender{}, testScheduler(t, 12), webhook.DefaultBreakerPolicy(),
		WithLeaseDuration(time.Second)); err == nil {
		t.Fatal("expected a short lease to be rejected")
	}

	runner := newRunner(t, store, fakePayloads{}, &fakeSender{})
	if _, err := runner.Run(nil, tenant, 10); err == nil {
		t.Fatal("expected a nil context to be rejected")
	}
	for _, invalid := range []tenancy.TenantID{"", "00000000-0000-0000-0000-000000000000", "not-a-uuid"} {
		if _, err := runner.Run(context.Background(), invalid, 10); err == nil {
			t.Fatalf("expected tenant %q to be rejected", invalid)
		}
	}
	for _, batch := range []int{0, -1, MaxBatch + 1} {
		if _, err := runner.Run(context.Background(), tenant, batch); err == nil {
			t.Fatalf("expected batch %d to be rejected", batch)
		}
	}
}

func TestRunSkipsInvalidLease(t *testing.T) {
	tenant := testTenant(t)
	lease := testLease(t, tenant)
	lease.FirstAttemptAt = time.Time{}
	store := &fakeStore{leases: []postgres.Lease{lease}}
	sender := &fakeSender{}
	runner := newRunner(t, store, fakePayloads{}, sender)

	report, err := runner.Run(context.Background(), tenant, 10)
	if err == nil {
		t.Fatal("expected the invalid lease to be reported")
	}
	if report.Skipped != 1 || sender.calls != 0 {
		t.Fatalf("report = %+v, sender calls = %d", report, sender.calls)
	}
}
