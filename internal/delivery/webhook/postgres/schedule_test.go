package postgres

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/sanskarpan/keel/internal/delivery/webhook"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	db, err := sql.Open("pgx", "postgres://127.0.0.1:1/keel?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return &Store{db: db}
}

func validLease(t *testing.T) Lease {
	t.Helper()
	identity := webhook.Identity{
		Tenant:              randomTenant(t),
		EventID:             "evt_" + uuid.NewString(),
		EndpointID:          uuid.NewString(),
		SubscriptionVersion: 1,
	}
	return Lease{
		Delivery: webhook.Delivery{
			ID:       uuid.NewString(),
			Identity: identity,
		},
		AttemptNumber:  1,
		AttemptID:      uuid.NewString(),
		LeaseEpoch:     1,
		LeaseExpiresAt: time.Now().Add(time.Minute).UTC(),
	}
}

func randomTenant(t *testing.T) tenancy.TenantID {
	t.Helper()
	tenant, err := tenancy.ParseTenantID(uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	return tenant
}

func TestLeaseValidate(t *testing.T) {
	valid := validLease(t)
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid lease rejected: %v", err)
	}
	cases := map[string]func(*Lease){
		"zero attempt":      func(l *Lease) { l.AttemptNumber = 0 },
		"large attempt":     func(l *Lease) { l.AttemptNumber = 101 },
		"bad attempt id":    func(l *Lease) { l.AttemptID = "../attempt" },
		"zero epoch":        func(l *Lease) { l.LeaseEpoch = 0 },
		"zero expiry":       func(l *Lease) { l.LeaseExpiresAt = time.Time{} },
		"bad delivery id":   func(l *Lease) { l.Delivery.ID = "x" },
		"zero tenant":       func(l *Lease) { l.Delivery.Identity.Tenant = "" },
		"bad event id":      func(l *Lease) { l.Delivery.Identity.EventID = "short" },
		"zero subscription": func(l *Lease) { l.Delivery.Identity.SubscriptionVersion = 0 },
	}
	for name, mutate := range cases {
		lease := valid
		mutate(&lease)
		if err := lease.Validate(); err == nil {
			t.Fatalf("%s: expected the lease to be rejected", name)
		}
	}
}

func TestStoreLeaseRejectsInvalidInput(t *testing.T) {
	store := &Store{}
	ctx := context.Background()
	tenant := randomTenant(t)
	if _, err := store.Lease(ctx, tenant, 1, time.Minute); err == nil {
		t.Fatal("expected a nil database to be rejected")
	}
	store = testStore(t)
	if _, err := store.Lease(nil, tenant, 1, time.Minute); err == nil {
		t.Fatal("expected a nil context to be rejected")
	}
	for _, invalid := range []tenancy.TenantID{"", "00000000-0000-0000-0000-000000000000", "not-a-uuid"} {
		if _, err := store.Lease(ctx, invalid, 1, time.Minute); err == nil {
			t.Fatalf("expected tenant %q to be rejected", invalid)
		}
	}
	for _, limit := range []int{0, -1, 101} {
		if _, err := store.Lease(ctx, tenant, limit, time.Minute); err == nil {
			t.Fatalf("expected limit %d to be rejected", limit)
		}
	}
	for _, leaseFor := range []time.Duration{0, 4 * time.Second, 301 * time.Second, 5500 * time.Millisecond} {
		if _, err := store.Lease(ctx, tenant, 1, leaseFor); err == nil {
			t.Fatalf("expected lease duration %v to be rejected", leaseFor)
		}
	}
}

func TestStoreRecordAttemptRejectsInvalidInput(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	lease := validLease(t)
	next := time.Now().Add(time.Minute)

	if _, err := store.RecordAttempt(ctx, lease, AttemptResult{Outcome: "sent", HTTPStatus: 200}); err == nil {
		t.Fatal("expected an invalid outcome to be rejected")
	}
	if _, err := store.RecordAttempt(ctx, lease, AttemptResult{Outcome: webhook.OutcomeDelivered, HTTPStatus: 500}); err == nil {
		t.Fatal("expected a non-2xx delivered attempt to be rejected")
	}
	if _, err := store.RecordAttempt(ctx, lease, AttemptResult{Outcome: webhook.OutcomeRetryable, HTTPStatus: 600}); err == nil {
		t.Fatal("expected an out-of-range status to be rejected")
	}
	if _, err := store.RecordAttempt(ctx, lease, AttemptResult{Outcome: webhook.OutcomeRetryable, HTTPStatus: 503, Latency: -time.Second}); err == nil {
		t.Fatal("expected a negative latency to be rejected")
	}
	if _, err := store.RecordAttempt(ctx, lease, AttemptResult{Outcome: webhook.OutcomeRetryable, HTTPStatus: 503, Latency: 11 * time.Minute}); err == nil {
		t.Fatal("expected an oversized latency to be rejected")
	}
	if _, err := store.RecordAttempt(ctx, lease, AttemptResult{Outcome: webhook.OutcomeDelivered, HTTPStatus: 204, NextAttemptAt: &next}); err == nil {
		t.Fatal("expected a delivered attempt with a retry time to be rejected")
	}
	if _, err := store.RecordAttempt(ctx, lease, AttemptResult{Outcome: webhook.OutcomePermanent, HTTPStatus: 404, NextAttemptAt: &next}); err == nil {
		t.Fatal("expected a permanent attempt with a retry time to be rejected")
	}
	if _, err := store.RecordAttempt(nil, lease, AttemptResult{Outcome: webhook.OutcomeDelivered, HTTPStatus: 200}); err == nil {
		t.Fatal("expected a nil context to be rejected")
	}
	if _, err := store.RecordAttempt(ctx, Lease{}, AttemptResult{Outcome: webhook.OutcomeDelivered, HTTPStatus: 200}); err == nil {
		t.Fatal("expected an invalid lease to be rejected")
	}
}

func TestDeliveryStateHelpers(t *testing.T) {
	for _, state := range []webhook.DeliveryState{
		webhook.StatePending, webhook.StateInFlight, webhook.StateDelivered,
		webhook.StateFailed, webhook.StateExhausted,
	} {
		if !state.Valid() {
			t.Fatalf("state %q reported invalid", state)
		}
	}
	for _, state := range []webhook.DeliveryState{"", "queued", "sent"} {
		if state.Valid() {
			t.Fatalf("state %q reported valid", state)
		}
	}
	for _, state := range []webhook.DeliveryState{webhook.StateDelivered, webhook.StateFailed, webhook.StateExhausted} {
		if !state.Terminal() {
			t.Fatalf("state %q reported non-terminal", state)
		}
	}
	for _, state := range []webhook.DeliveryState{webhook.StatePending, webhook.StateInFlight} {
		if state.Terminal() {
			t.Fatalf("state %q reported terminal", state)
		}
	}
}
