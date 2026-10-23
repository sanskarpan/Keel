package postgres

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sanskarpan/keel/internal/delivery/webhook"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

func leaseOne(t *testing.T, store *Store, tenant tenancy.TenantID) Lease {
	t.Helper()
	leases, err := store.Lease(context.Background(), tenant, 10, 30*time.Second)
	if err != nil {
		t.Fatalf("Lease: %v", err)
	}
	if len(leases) != 1 {
		t.Fatalf("expected one due delivery, got %d", len(leases))
	}
	return leases[0]
}

func attemptCount(t *testing.T, admin *sql.DB, tenant tenancy.TenantID) int {
	t.Helper()
	var count int
	if err := admin.QueryRowContext(context.Background(),
		`SELECT count(*) FROM keel_meta.webhook_delivery_attempts WHERE tenant_id=$1`,
		string(tenant)).Scan(&count); err != nil {
		t.Fatalf("count webhook attempts: %v", err)
	}
	return count
}

func TestPostgreSQLWebhookDeliveryLeaseAndRecord(t *testing.T) {
	webhookDB, adminDB := webhookTestDatabases(t)
	store := newStore(t, webhookDB)
	identity := randomIdentity(t)
	claim, err := store.Ensure(context.Background(), identity)
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}

	started := time.Now()
	lease := leaseOne(t, store, identity.Tenant)
	if lease.Delivery.ID != claim.Delivery.ID || lease.Delivery.Identity != identity {
		t.Fatalf("lease returned a different delivery: %+v", lease.Delivery)
	}
	if lease.AttemptNumber != 1 || lease.LeaseEpoch != 1 || lease.AttemptID == "" {
		t.Fatalf("unexpected first lease: %+v", lease)
	}
	if lease.LeaseExpiresAt.Before(started.Add(29*time.Second)) ||
		lease.LeaseExpiresAt.After(started.Add(31*time.Second)) {
		t.Fatalf("lease expiry %s is outside the requested 30s window", lease.LeaseExpiresAt)
	}
	if lease.FirstAttemptAt.Before(started.Add(-time.Second)) ||
		lease.FirstAttemptAt.After(started.Add(time.Second)) {
		t.Fatalf("lease first attempt %s is outside the lease start", lease.FirstAttemptAt)
	}
	if leases, err := store.Lease(context.Background(), identity.Tenant, 10, 30*time.Second); err != nil {
		t.Fatalf("second Lease: %v", err)
	} else if len(leases) != 0 {
		t.Fatalf("a leased delivery was handed out twice: %d", len(leases))
	}
	if count := attemptCount(t, adminDB, identity.Tenant); count != 0 {
		t.Fatalf("expected no recorded attempt before completion, got %d", count)
	}

	due := time.Now()
	state, err := store.RecordAttempt(context.Background(), lease, AttemptResult{
		Outcome:       webhook.OutcomeRetryable,
		HTTPStatus:    503,
		Latency:       120 * time.Millisecond,
		NextAttemptAt: &due,
	})
	if err != nil {
		t.Fatalf("RecordAttempt retryable: %v", err)
	}
	if state.State != webhook.StatePending || state.Attempts != 1 || state.FinishedAt != nil {
		t.Fatalf("unexpected retryable state: %+v", state)
	}
	if state.NextAttemptAt == nil || state.NextAttemptAt.Sub(due).Abs() > time.Millisecond {
		t.Fatalf("retryable state next attempt = %v, want %s", state.NextAttemptAt, due)
	}

	second := leaseOne(t, store, identity.Tenant)
	if second.AttemptNumber != 2 || second.LeaseEpoch != 2 || second.AttemptID == lease.AttemptID {
		t.Fatalf("unexpected second lease: %+v", second)
	}
	state, err = store.RecordAttempt(context.Background(), second, AttemptResult{
		Outcome:    webhook.OutcomeDelivered,
		HTTPStatus: 204,
		Latency:    15 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("RecordAttempt delivered: %v", err)
	}
	if state.State != webhook.StateDelivered || state.Attempts != 2 ||
		state.NextAttemptAt != nil || state.FinishedAt == nil {
		t.Fatalf("unexpected delivered state: %+v", state)
	}
	if count := attemptCount(t, adminDB, identity.Tenant); count != 2 {
		t.Fatalf("expected two recorded attempts, got %d", count)
	}
	if leases, err := store.Lease(context.Background(), identity.Tenant, 10, 30*time.Second); err != nil {
		t.Fatalf("terminal Lease: %v", err)
	} else if len(leases) != 0 {
		t.Fatalf("a terminal delivery was leased again: %d", len(leases))
	}
}

func TestPostgreSQLWebhookDeliveryFencesStaleLease(t *testing.T) {
	webhookDB, adminDB := webhookTestDatabases(t)
	store := newStore(t, webhookDB)
	identity := randomIdentity(t)
	if _, err := store.Ensure(context.Background(), identity); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	stale := leaseOne(t, store, identity.Tenant)

	if _, err := adminDB.ExecContext(context.Background(),
		`UPDATE keel_meta.webhook_delivery_state
		    SET lease_expires_at=clock_timestamp()-interval '1 second',updated_at=clock_timestamp()
		  WHERE tenant_id=$1 AND delivery_id=$2`, string(identity.Tenant), stale.Delivery.ID); err != nil {
		t.Fatalf("expire lease: %v", err)
	}
	current := leaseOne(t, store, identity.Tenant)
	if current.AttemptNumber != 2 || current.LeaseEpoch != 2 {
		t.Fatalf("unexpected re-lease: %+v", current)
	}

	_, err := store.RecordAttempt(context.Background(), stale, AttemptResult{
		Outcome:    webhook.OutcomeDelivered,
		HTTPStatus: 200,
	})
	if err == nil {
		t.Fatal("expected the stale lease to be rejected")
	}
	if !strings.Contains(err.Error(), "not leased") {
		t.Fatalf("expected a lease fence error, got %v", err)
	}
	if count := attemptCount(t, adminDB, identity.Tenant); count != 0 {
		t.Fatalf("a stale attempt was recorded: %d", count)
	}

	if _, err := store.RecordAttempt(context.Background(), current, AttemptResult{
		Outcome:    webhook.OutcomeDelivered,
		HTTPStatus: 200,
	}); err != nil {
		t.Fatalf("RecordAttempt current lease: %v", err)
	}
	if count := attemptCount(t, adminDB, identity.Tenant); count != 1 {
		t.Fatalf("expected one recorded attempt, got %d", count)
	}
}

func TestPostgreSQLWebhookDeliveryExhaustionAndPermanentFailure(t *testing.T) {
	webhookDB, adminDB := webhookTestDatabases(t)
	store := newStore(t, webhookDB)

	exhaustedIdentity := randomIdentity(t)
	if _, err := store.Ensure(context.Background(), exhaustedIdentity); err != nil {
		t.Fatalf("Ensure exhausted: %v", err)
	}
	lease := leaseOne(t, store, exhaustedIdentity.Tenant)
	state, err := store.RecordAttempt(context.Background(), lease, AttemptResult{
		Outcome:    webhook.OutcomeRetryable,
		HTTPStatus: 503,
		Latency:    200 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("RecordAttempt exhausted: %v", err)
	}
	if state.State != webhook.StateExhausted || state.NextAttemptAt != nil || state.FinishedAt == nil {
		t.Fatalf("unexpected exhausted state: %+v", state)
	}
	if _, err := adminDB.ExecContext(context.Background(),
		`UPDATE keel_meta.webhook_delivery_state SET state='pending',next_attempt_at=clock_timestamp()
		  WHERE tenant_id=$1 AND delivery_id=$2`,
		string(exhaustedIdentity.Tenant), lease.Delivery.ID); err == nil {
		t.Fatal("expected the terminal state to reject an update")
	} else if !strings.Contains(err.Error(), "terminal") {
		t.Fatalf("expected a terminal state error, got %v", err)
	}

	failedIdentity := randomIdentity(t)
	if _, err := store.Ensure(context.Background(), failedIdentity); err != nil {
		t.Fatalf("Ensure failed: %v", err)
	}
	lease = leaseOne(t, store, failedIdentity.Tenant)
	state, err = store.RecordAttempt(context.Background(), lease, AttemptResult{
		Outcome:    webhook.OutcomePermanent,
		HTTPStatus: 404,
		Latency:    10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("RecordAttempt permanent: %v", err)
	}
	if state.State != webhook.StateFailed || state.FinishedAt == nil {
		t.Fatalf("unexpected failed state: %+v", state)
	}

	tooLate := time.Now().Add(-2 * time.Minute)
	lateIdentity := randomIdentity(t)
	if _, err := store.Ensure(context.Background(), lateIdentity); err != nil {
		t.Fatalf("Ensure late: %v", err)
	}
	lease = leaseOne(t, store, lateIdentity.Tenant)
	if _, err := store.RecordAttempt(context.Background(), lease, AttemptResult{
		Outcome:       webhook.OutcomeRetryable,
		HTTPStatus:    503,
		NextAttemptAt: &tooLate,
	}); err == nil {
		t.Fatal("expected a retry in the past to be rejected")
	}
}

func TestPostgreSQLWebhookDeliveryDeniesDirectStateAccess(t *testing.T) {
	webhookDB, adminDB := webhookTestDatabases(t)
	store := newStore(t, webhookDB)
	identity := randomIdentity(t)
	if _, err := store.Ensure(context.Background(), identity); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	lease := leaseOne(t, store, identity.Tenant)

	ctx := context.Background()
	for _, statement := range []string{
		`SELECT count(*) FROM keel_meta.webhook_delivery_state`,
		`SELECT count(*) FROM keel_meta.webhook_delivery_attempts`,
		`INSERT INTO keel_meta.webhook_delivery_attempts (tenant_id,delivery_id,attempt_number,attempt_id,lease_epoch,outcome,http_status,latency_ms) VALUES ('11111111-1111-4111-8111-111111111111','delivery_0001',1,'attempt_0001',1,'retryable',503,1)`,
		`UPDATE keel_meta.webhook_delivery_state SET state='delivered'`,
	} {
		if _, err := webhookDB.ExecContext(ctx, statement); err == nil {
			t.Fatalf("expected the webhook capability to be denied: %s", statement)
		}
	}

	if _, err := store.RecordAttempt(ctx, lease, AttemptResult{
		Outcome:    webhook.OutcomeDelivered,
		HTTPStatus: 200,
	}); err != nil {
		t.Fatalf("RecordAttempt: %v", err)
	}
	if _, err := adminDB.ExecContext(ctx,
		`DELETE FROM keel_meta.webhook_delivery_state WHERE tenant_id=$1 AND delivery_id=$2`,
		string(identity.Tenant), lease.Delivery.ID); err == nil {
		t.Fatal("expected the state ledger to reject a delete")
	} else if !strings.Contains(err.Error(), "cannot be deleted") {
		t.Fatalf("expected a delete error, got %v", err)
	}
	if _, err := adminDB.ExecContext(ctx,
		`UPDATE keel_meta.webhook_delivery_attempts SET latency_ms=1 WHERE delivery_id=$1`,
		lease.Delivery.ID); err == nil {
		t.Fatal("expected the attempt log to reject an update")
	} else if !strings.Contains(err.Error(), "append-only") {
		t.Fatalf("expected an append-only error, got %v", err)
	}
	if _, err := adminDB.ExecContext(ctx,
		`DELETE FROM keel_meta.webhook_delivery_attempts WHERE delivery_id=$1`,
		lease.Delivery.ID); err == nil {
		t.Fatal("expected the attempt log to reject a delete")
	} else if !strings.Contains(err.Error(), "append-only") {
		t.Fatalf("expected an append-only error, got %v", err)
	}
	if _, err := adminDB.ExecContext(ctx,
		`UPDATE keel_meta.webhook_delivery_state SET attempts=0 WHERE tenant_id=$1 AND delivery_id=$2`,
		string(identity.Tenant), lease.Delivery.ID); err == nil {
		t.Fatal("expected the state counters to reject a decrease")
	} else if !strings.Contains(err.Error(), "monotonic") && !strings.Contains(err.Error(), "terminal") {
		t.Fatalf("expected a monotonic counter error, got %v", err)
	}
}

func TestPostgreSQLWebhookDeliveryScheduleRequiresCapability(t *testing.T) {
	appDSN := os.Getenv("KEEL_TEST_DATABASE_URL")
	if appDSN == "" {
		t.Skip("set KEEL_TEST_DATABASE_URL for the webhook scheduling denial case")
	}
	appDB := webhookTestDB(t, appDSN)
	store := newStore(t, appDB)
	tenant := randomTenant(t)
	if _, err := store.Lease(context.Background(), tenant, 1, 30*time.Second); err == nil {
		t.Fatal("expected a role without the webhook capability to be denied a lease")
	}
	lease := Lease{
		Delivery: webhook.Delivery{
			ID:       uuid.NewString(),
			Identity: webhook.Identity{Tenant: tenant, EventID: "evt_00000001", EndpointID: uuid.NewString(), SubscriptionVersion: 1},
		},
		AttemptNumber:  1,
		AttemptID:      uuid.NewString(),
		LeaseEpoch:     1,
		LeaseExpiresAt: time.Now().Add(time.Minute),
		FirstAttemptAt: time.Now().UTC(),
	}
	if _, err := store.RecordAttempt(context.Background(), lease, AttemptResult{
		Outcome:    webhook.OutcomeDelivered,
		HTTPStatus: 200,
	}); err == nil {
		t.Fatal("expected a role without the webhook capability to be denied an attempt record")
	}
}

func TestPostgreSQLWebhookDeliveryConcurrentLease(t *testing.T) {
	webhookDB, _ := webhookTestDatabases(t)
	store := newStore(t, webhookDB)
	tenant := randomTenant(t)
	const deliveries = 5
	for index := 0; index < deliveries; index++ {
		if _, err := store.Ensure(context.Background(), webhook.Identity{
			Tenant:              tenant,
			EventID:             "evt_" + strings.ReplaceAll(uuid.NewString(), "-", ""),
			EndpointID:          uuid.NewString(),
			SubscriptionVersion: 1,
		}); err != nil {
			t.Fatalf("Ensure %d: %v", index, err)
		}
	}

	const workers = 5
	var wait sync.WaitGroup
	wait.Add(workers)
	results := make([][]Lease, workers)
	errs := make([]error, workers)
	for index := 0; index < workers; index++ {
		index := index
		go func() {
			defer wait.Done()
			results[index], errs[index] = store.Lease(context.Background(), tenant, 2, 30*time.Second)
		}()
	}
	wait.Wait()

	seen := make(map[string]struct{}, deliveries)
	total := 0
	for index := range results {
		if errs[index] != nil {
			t.Fatalf("worker %d: %v", index, errs[index])
		}
		for _, lease := range results[index] {
			if _, duplicate := seen[lease.Delivery.ID]; duplicate {
				t.Fatalf("delivery %q was leased twice", lease.Delivery.ID)
			}
			seen[lease.Delivery.ID] = struct{}{}
			total++
		}
	}
	if total != deliveries {
		t.Fatalf("expected %d leased deliveries, got %d", deliveries, total)
	}
}
