package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sanskarpan/keel/internal/delivery/webhook"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

func replayAuthorizationDatabases(t *testing.T) (*sql.DB, *sql.DB, *sql.DB, *sql.DB) {
	t.Helper()
	appDSN := os.Getenv("KEEL_TEST_DATABASE_URL")
	webhookDSN := os.Getenv("KEEL_TEST_WEBHOOK_DATABASE_URL")
	operatorDSN := os.Getenv("KEEL_TEST_OPERATOR_DATABASE_URL")
	adminDSN := os.Getenv("KEEL_TEST_ADMIN_DATABASE_URL")
	if appDSN == "" || webhookDSN == "" || operatorDSN == "" || adminDSN == "" {
		t.Skip("set KEEL_TEST_DATABASE_URL, KEEL_TEST_WEBHOOK_DATABASE_URL, KEEL_TEST_OPERATOR_DATABASE_URL and KEEL_TEST_ADMIN_DATABASE_URL for webhook replay authorization coverage")
	}
	return webhookTestDB(t, appDSN), webhookTestDB(t, webhookDSN),
		webhookTestDB(t, operatorDSN), webhookTestDB(t, adminDSN)
}

type replayFixture struct {
	tenant     tenancy.TenantID
	endpointID string
	deliveryID string
}

func terminalReplayFixture(t *testing.T, registry *Registry, store *Store, tenant tenancy.TenantID, outcome webhook.Outcome) replayFixture {
	t.Helper()
	ctx := context.Background()
	registration := validRegistryRegistration()
	endpoint, err := registry.Register(ctx, tenant, registration, 0)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	identity := webhook.Identity{
		Tenant:              tenant,
		EventID:             "evt_" + strings.ReplaceAll(uuid.NewString(), "-", ""),
		EndpointID:          endpoint.ID,
		SubscriptionVersion: endpoint.SubscriptionVersion,
	}
	claim, err := store.Ensure(ctx, identity)
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	lease := leaseOne(t, store, tenant)
	result := AttemptResult{Outcome: outcome, HTTPStatus: 503, Latency: 10 * time.Millisecond}
	switch outcome {
	case webhook.OutcomePermanent:
		result.HTTPStatus = 410
	case webhook.OutcomeDelivered:
		result.HTTPStatus = 200
	}
	state, err := store.RecordAttempt(ctx, lease, result)
	if err != nil {
		t.Fatalf("RecordAttempt: %v", err)
	}
	wantState := map[webhook.Outcome]webhook.DeliveryState{
		webhook.OutcomePermanent: webhook.StateFailed,
		webhook.OutcomeRetryable: webhook.StateExhausted,
		webhook.OutcomeDelivered: webhook.StateDelivered,
	}[outcome]
	if state.State != wantState {
		t.Fatalf("recorded state = %s, want %s", state.State, wantState)
	}
	return replayFixture{tenant: tenant, endpointID: endpoint.ID, deliveryID: claim.Delivery.ID}
}

type replayStateSnapshot struct {
	State          string
	Attempts       int
	FirstAttemptAt *time.Time
	NextAttemptAt  *time.Time
	LeaseEpoch     int64
	LeaseExpiresAt *time.Time
	DeliveredAt    *time.Time
	FinishedAt     *time.Time
}

func nullTimePointer(value sql.NullTime) *time.Time {
	if !value.Valid {
		return nil
	}
	normalized := value.Time.UTC()
	return &normalized
}

func readReplayState(t *testing.T, admin *sql.DB, tenant tenancy.TenantID, deliveryID string) replayStateSnapshot {
	t.Helper()
	var snapshot replayStateSnapshot
	var first, next, leaseExpires, delivered, finished sql.NullTime
	if err := admin.QueryRowContext(context.Background(),
		`SELECT state,attempts,first_attempt_at,next_attempt_at,lease_epoch,lease_expires_at,
		        delivered_at,finished_at
		   FROM keel_meta.webhook_delivery_state WHERE tenant_id=$1 AND delivery_id=$2`,
		string(tenant), deliveryID).
		Scan(&snapshot.State, &snapshot.Attempts, &first, &next, &snapshot.LeaseEpoch,
			&leaseExpires, &delivered, &finished); err != nil {
		t.Fatalf("read webhook delivery state: %v", err)
	}
	snapshot.FirstAttemptAt = nullTimePointer(first)
	snapshot.NextAttemptAt = nullTimePointer(next)
	snapshot.LeaseExpiresAt = nullTimePointer(leaseExpires)
	snapshot.DeliveredAt = nullTimePointer(delivered)
	snapshot.FinishedAt = nullTimePointer(finished)
	return snapshot
}

func replayTransitionCount(t *testing.T, admin *sql.DB, tenant tenancy.TenantID) int {
	t.Helper()
	var count int
	if err := admin.QueryRowContext(context.Background(),
		`SELECT count(*) FROM keel_meta.webhook_replay_transitions WHERE tenant_id=$1`,
		string(tenant)).Scan(&count); err != nil {
		t.Fatalf("count webhook replay transitions: %v", err)
	}
	return count
}

type replayTransitionRow struct {
	DeliveryID      string
	PriorState      string
	PriorAttempts   int
	PriorFinishedAt time.Time
	PriorLeaseEpoch int64
	AuthorizedAt    time.Time
}

func readReplayTransition(t *testing.T, admin *sql.DB, tenant tenancy.TenantID, replayID string) replayTransitionRow {
	t.Helper()
	var row replayTransitionRow
	if err := admin.QueryRowContext(context.Background(),
		`SELECT delivery_id,prior_state,prior_attempts,prior_finished_at,prior_lease_epoch,
		        authorized_at
		   FROM keel_meta.webhook_replay_transitions WHERE tenant_id=$1 AND replay_id=$2`,
		string(tenant), replayID).
		Scan(&row.DeliveryID, &row.PriorState, &row.PriorAttempts, &row.PriorFinishedAt,
			&row.PriorLeaseEpoch, &row.AuthorizedAt); err != nil {
		t.Fatalf("read webhook replay transition: %v", err)
	}
	return row
}

func TestAuthorizeReplayRequeuesWithoutFreshBudget(t *testing.T) {
	appDB, webhookDB, operatorDB, adminDB := replayAuthorizationDatabases(t)
	registry := newRegistry(t, appDB)
	deliveryStore := newStore(t, webhookDB)
	replayStore := newStore(t, operatorDB)
	ctx := context.Background()

	for name, testCase := range map[string]struct {
		outcome webhook.Outcome
		prior   webhook.DeliveryState
	}{
		"failed":    {webhook.OutcomePermanent, webhook.StateFailed},
		"exhausted": {webhook.OutcomeRetryable, webhook.StateExhausted},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := terminalReplayFixture(t, registry, deliveryStore, randomTenant(t), testCase.outcome)
			before := readReplayState(t, adminDB, fixture.tenant, fixture.deliveryID)
			if before.State != string(testCase.prior) || before.Attempts != 1 || before.FinishedAt == nil {
				t.Fatalf("before = %+v, want one finished %s attempt", before, testCase.prior)
			}

			request := replayRequest(fixture.tenant, fixture.deliveryID)
			authorization, err := replayStore.AuthorizeReplay(ctx, request)
			if err != nil {
				t.Fatalf("AuthorizeReplay: %v", err)
			}
			if !authorization.Created {
				t.Fatal("expected the first authorization to create the replay")
			}
			if authorization.ReplayID != request.ReplayID ||
				authorization.DeliveryID != request.DeliveryID ||
				authorization.RequestedBy != request.RequestedBy ||
				authorization.Reason != request.Reason {
				t.Fatalf("authorization = %+v, want request %+v", authorization, request)
			}
			if authorization.PriorState != testCase.prior || authorization.PriorAttempts != before.Attempts ||
				authorization.PriorLeaseEpoch != before.LeaseEpoch ||
				!authorization.PriorFinishedAt.Equal(*before.FinishedAt) {
				t.Fatalf("authorization prior = %+v, want %+v", authorization, before)
			}
			if authorization.RequestedAt.Location() != time.UTC ||
				authorization.AuthorizedAt.Location() != time.UTC {
				t.Fatalf("authorization times are not UTC: %+v", authorization)
			}

			after := readReplayState(t, adminDB, fixture.tenant, fixture.deliveryID)
			if after.State != string(webhook.StatePending) {
				t.Fatalf("state after authorization = %s, want pending", after.State)
			}
			if after.Attempts != before.Attempts || after.LeaseEpoch != before.LeaseEpoch ||
				!equalTimePointers(after.FirstAttemptAt, before.FirstAttemptAt) {
				t.Fatalf("authorization changed the retry budget: before=%+v after=%+v", before, after)
			}
			if after.NextAttemptAt == nil || after.LeaseExpiresAt != nil ||
				after.DeliveredAt != nil || after.FinishedAt != nil {
				t.Fatalf("pending shape = %+v, want next attempt only", after)
			}

			transition := readReplayTransition(t, adminDB, fixture.tenant, request.ReplayID)
			if transition.DeliveryID != fixture.deliveryID ||
				transition.PriorState != string(testCase.prior) ||
				transition.PriorAttempts != before.Attempts ||
				transition.PriorLeaseEpoch != before.LeaseEpoch ||
				!transition.PriorFinishedAt.Equal(*before.FinishedAt) {
				t.Fatalf("transition = %+v, want prior %+v", transition, before)
			}
			if count := replayTransitionCount(t, adminDB, fixture.tenant); count != 1 {
				t.Fatalf("transition rows = %d, want 1", count)
			}
			if count := replayRowCount(t, adminDB, fixture.tenant); count != 1 {
				t.Fatalf("replay rows = %d, want 1", count)
			}

			repeated, err := replayStore.AuthorizeReplay(ctx, request)
			if err != nil {
				t.Fatalf("AuthorizeReplay(repeat): %v", err)
			}
			if repeated.Created {
				t.Fatal("expected the repeated authorization to be idempotent")
			}
			if !repeated.AuthorizedAt.Equal(authorization.AuthorizedAt) ||
				repeated.PriorState != authorization.PriorState ||
				repeated.PriorAttempts != authorization.PriorAttempts {
				t.Fatalf("repeated authorization = %+v, want %+v", repeated, authorization)
			}
			if count := replayTransitionCount(t, adminDB, fixture.tenant); count != 1 {
				t.Fatalf("transition rows after repeat = %d, want 1", count)
			}

			for conflictName, change := range map[string]func(*webhook.ReplayRequest){
				"different reason": func(r *webhook.ReplayRequest) { r.Reason = "a different justification" },
				"different actor":  func(r *webhook.ReplayRequest) { r.RequestedBy = "other@example.com" },
				"second replay": func(r *webhook.ReplayRequest) {
					r.ReplayID = replayRequest(fixture.tenant, fixture.deliveryID).ReplayID
				},
			} {
				t.Run(conflictName, func(t *testing.T) {
					candidate := request
					change(&candidate)
					if _, err := replayStore.AuthorizeReplay(ctx, candidate); !errors.Is(err, webhook.ErrReplayConflict) {
						t.Fatalf("AuthorizeReplay() error = %v, want ErrReplayConflict", err)
					}
				})
			}
			if count := replayTransitionCount(t, adminDB, fixture.tenant); count != 1 {
				t.Fatalf("transition rows after conflicts = %d, want 1", count)
			}

			next := leaseOne(t, deliveryStore, fixture.tenant)
			if next.AttemptNumber != before.Attempts+1 || next.LeaseEpoch != before.LeaseEpoch+1 {
				t.Fatalf("next lease = %+v, want attempt %d and epoch %d",
					next, before.Attempts+1, before.LeaseEpoch+1)
			}
		})
	}
}

func TestAuthorizeReplayConcurrentSingleWinner(t *testing.T) {
	appDB, webhookDB, operatorDB, adminDB := replayAuthorizationDatabases(t)
	registry := newRegistry(t, appDB)
	deliveryStore := newStore(t, webhookDB)
	replayStore := newStore(t, operatorDB)
	ctx := context.Background()

	fixture := terminalReplayFixture(t, registry, deliveryStore, randomTenant(t), webhook.OutcomePermanent)
	before := readReplayState(t, adminDB, fixture.tenant, fixture.deliveryID)
	requests := []webhook.ReplayRequest{
		replayRequest(fixture.tenant, fixture.deliveryID),
		replayRequest(fixture.tenant, fixture.deliveryID),
	}
	start := make(chan struct{})
	results := make(chan error, len(requests))
	var wait sync.WaitGroup
	for _, request := range requests {
		request := request
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			_, err := replayStore.AuthorizeReplay(ctx, request)
			results <- err
		}()
	}
	close(start)
	wait.Wait()
	close(results)

	var succeeded, conflicted int
	for err := range results {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, webhook.ErrReplayConflict):
			conflicted++
		default:
			t.Fatalf("unexpected concurrent authorization error: %v", err)
		}
	}
	if succeeded != 1 || conflicted != 1 {
		t.Fatalf("concurrent authorizations = %d success, %d conflict; want one of each", succeeded, conflicted)
	}
	if count := replayTransitionCount(t, adminDB, fixture.tenant); count != 1 {
		t.Fatalf("transition rows = %d, want 1", count)
	}
	if count := replayRowCount(t, adminDB, fixture.tenant); count != 1 {
		t.Fatalf("replay rows = %d, want 1", count)
	}
	after := readReplayState(t, adminDB, fixture.tenant, fixture.deliveryID)
	if after.State != string(webhook.StatePending) || after.Attempts != before.Attempts ||
		after.LeaseEpoch != before.LeaseEpoch {
		t.Fatalf("concurrent authorization state = %+v, want pending with preserved budget", after)
	}
}

func equalTimePointers(left, right *time.Time) bool {
	if left == nil || right == nil {
		return left == right
	}
	return left.Equal(*right)
}

func TestAuthorizeReplayRequiresEligibleState(t *testing.T) {
	appDB, webhookDB, operatorDB, adminDB := replayAuthorizationDatabases(t)
	registry := newRegistry(t, appDB)
	deliveryStore := newStore(t, webhookDB)
	replayStore := newStore(t, operatorDB)
	ctx := context.Background()

	create := func(t *testing.T, lease bool, outcome *webhook.Outcome) replayFixture {
		t.Helper()
		tenant := randomTenant(t)
		registration := validRegistryRegistration()
		endpoint, err := registry.Register(ctx, tenant, registration, 0)
		if err != nil {
			t.Fatalf("Register: %v", err)
		}
		identity := webhook.Identity{
			Tenant:              tenant,
			EventID:             "evt_" + strings.ReplaceAll(uuid.NewString(), "-", ""),
			EndpointID:          endpoint.ID,
			SubscriptionVersion: endpoint.SubscriptionVersion,
		}
		claim, err := deliveryStore.Ensure(ctx, identity)
		if err != nil {
			t.Fatalf("Ensure: %v", err)
		}
		fixture := replayFixture{tenant: tenant, endpointID: endpoint.ID, deliveryID: claim.Delivery.ID}
		if !lease {
			return fixture
		}
		grant := leaseOne(t, deliveryStore, tenant)
		if outcome == nil {
			return fixture
		}
		if _, err := deliveryStore.RecordAttempt(ctx, grant, AttemptResult{
			Outcome: *outcome, HTTPStatus: 200, Latency: 5 * time.Millisecond,
		}); err != nil {
			t.Fatalf("RecordAttempt: %v", err)
		}
		return fixture
	}

	delivered := webhook.OutcomeDelivered
	for name, testCase := range map[string]struct {
		build func(*testing.T) replayFixture
		state webhook.DeliveryState
	}{
		"pending":   {func(t *testing.T) replayFixture { return create(t, false, nil) }, webhook.StatePending},
		"in flight": {func(t *testing.T) replayFixture { return create(t, true, nil) }, webhook.StateInFlight},
		"delivered": {func(t *testing.T) replayFixture { return create(t, true, &delivered) }, webhook.StateDelivered},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := testCase.build(t)
			before := readReplayState(t, adminDB, fixture.tenant, fixture.deliveryID)
			if before.State != string(testCase.state) {
				t.Fatalf("state = %s, want %s", before.State, testCase.state)
			}
			if _, err := replayStore.AuthorizeReplay(ctx, replayRequest(fixture.tenant, fixture.deliveryID)); !errors.Is(err, webhook.ErrReplayNotEligible) {
				t.Fatalf("AuthorizeReplay() error = %v, want ErrReplayNotEligible", err)
			}
			after := readReplayState(t, adminDB, fixture.tenant, fixture.deliveryID)
			if after.State != before.State || after.Attempts != before.Attempts ||
				after.LeaseEpoch != before.LeaseEpoch {
				t.Fatalf("ineligible authorization changed state: before=%+v after=%+v", before, after)
			}
			if count := replayTransitionCount(t, adminDB, fixture.tenant); count != 0 {
				t.Fatalf("transition rows = %d, want 0", count)
			}
			if count := replayRowCount(t, adminDB, fixture.tenant); count != 0 {
				t.Fatalf("replay rows = %d, want 0", count)
			}
		})
	}

	t.Run("unknown delivery", func(t *testing.T) {
		fixture := create(t, false, nil)
		before := readReplayState(t, adminDB, fixture.tenant, fixture.deliveryID)
		unknown := fixture.deliveryID[:len(fixture.deliveryID)-1] + "0"
		if unknown == fixture.deliveryID {
			unknown = fixture.deliveryID[:len(fixture.deliveryID)-1] + "1"
		}
		if _, err := replayStore.AuthorizeReplay(ctx, replayRequest(fixture.tenant, unknown)); !errors.Is(err, webhook.ErrReplayNotFound) {
			t.Fatalf("AuthorizeReplay(unknown) error = %v, want ErrReplayNotFound", err)
		}
		after := readReplayState(t, adminDB, fixture.tenant, fixture.deliveryID)
		if after.State != before.State || after.Attempts != before.Attempts {
			t.Fatalf("unknown delivery changed state: before=%+v after=%+v", before, after)
		}
	})

	t.Run("other tenant", func(t *testing.T) {
		fixture := terminalReplayFixture(t, registry, deliveryStore, randomTenant(t), webhook.OutcomePermanent)
		before := readReplayState(t, adminDB, fixture.tenant, fixture.deliveryID)
		otherTenant := randomTenant(t)
		if _, err := replayStore.AuthorizeReplay(ctx, replayRequest(otherTenant, fixture.deliveryID)); !errors.Is(err, webhook.ErrReplayNotFound) {
			t.Fatalf("AuthorizeReplay(other tenant) error = %v, want ErrReplayNotFound", err)
		}
		after := readReplayState(t, adminDB, fixture.tenant, fixture.deliveryID)
		if after.State != before.State || after.Attempts != before.Attempts {
			t.Fatalf("other tenant changed state: before=%+v after=%+v", before, after)
		}
		if count := replayTransitionCount(t, adminDB, otherTenant); count != 0 {
			t.Fatalf("other tenant transition rows = %d, want 0", count)
		}
	})
}

func TestAuthorizeReplayRequiresEligibleEndpoint(t *testing.T) {
	appDB, webhookDB, operatorDB, adminDB := replayAuthorizationDatabases(t)
	registry := newRegistry(t, appDB)
	deliveryStore := newStore(t, webhookDB)
	replayStore := newStore(t, operatorDB)
	ctx := context.Background()

	for name, mutate := range map[string]func(*testing.T, replayFixture){
		"inactive endpoint": func(t *testing.T, fixture replayFixture) {
			if _, err := registry.SetStatus(ctx, fixture.tenant, fixture.endpointID, webhook.EndpointInactive, 1); err != nil {
				t.Fatalf("SetStatus: %v", err)
			}
		},
		"subscription revision": func(t *testing.T, fixture replayFixture) {
			registration := validRegistryRegistration()
			registration.ID = fixture.endpointID
			registration.SubscriptionVersion = 2
			if _, err := registry.Register(ctx, fixture.tenant, registration, 1); err != nil {
				t.Fatalf("Register(revision): %v", err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := terminalReplayFixture(t, registry, deliveryStore, randomTenant(t), webhook.OutcomePermanent)
			mutate(t, fixture)
			before := readReplayState(t, adminDB, fixture.tenant, fixture.deliveryID)
			if _, err := replayStore.AuthorizeReplay(ctx, replayRequest(fixture.tenant, fixture.deliveryID)); !errors.Is(err, webhook.ErrReplayNotEligible) {
				t.Fatalf("AuthorizeReplay() error = %v, want ErrReplayNotEligible", err)
			}
			after := readReplayState(t, adminDB, fixture.tenant, fixture.deliveryID)
			if after.State != before.State || after.Attempts != before.Attempts {
				t.Fatalf("ineligible endpoint changed state: before=%+v after=%+v", before, after)
			}
			if count := replayTransitionCount(t, adminDB, fixture.tenant); count != 0 {
				t.Fatalf("transition rows = %d, want 0", count)
			}
			if count := replayRowCount(t, adminDB, fixture.tenant); count != 0 {
				t.Fatalf("replay rows = %d, want 0", count)
			}
		})
	}
}

func TestAuthorizeReplayRequiresOperatorCapability(t *testing.T) {
	appDB, webhookDB, _, adminDB := replayAuthorizationDatabases(t)
	registry := newRegistry(t, appDB)
	deliveryStore := newStore(t, webhookDB)
	fixture := terminalReplayFixture(t, registry, deliveryStore, randomTenant(t), webhook.OutcomePermanent)
	before := readReplayState(t, adminDB, fixture.tenant, fixture.deliveryID)
	request := replayRequest(fixture.tenant, fixture.deliveryID)

	for role, store := range map[string]*Store{
		"app":     newStore(t, appDB),
		"webhook": deliveryStore,
	} {
		t.Run(role, func(t *testing.T) {
			if _, err := store.AuthorizeReplay(context.Background(), request); !errors.Is(err, webhook.ErrReplayUnauthorized) {
				t.Fatalf("AuthorizeReplay() error = %v, want ErrReplayUnauthorized", err)
			}
		})
	}
	after := readReplayState(t, adminDB, fixture.tenant, fixture.deliveryID)
	if after.State != before.State || after.Attempts != before.Attempts {
		t.Fatalf("unauthorized authorization changed state: before=%+v after=%+v", before, after)
	}
	if count := replayTransitionCount(t, adminDB, fixture.tenant); count != 0 {
		t.Fatalf("transition rows = %d, want 0", count)
	}
	if count := replayRowCount(t, adminDB, fixture.tenant); count != 0 {
		t.Fatalf("replay rows = %d, want 0", count)
	}
}

func TestReplayTransitionIsImmutable(t *testing.T) {
	appDB, webhookDB, operatorDB, adminDB := replayAuthorizationDatabases(t)
	registry := newRegistry(t, appDB)
	deliveryStore := newStore(t, webhookDB)
	replayStore := newStore(t, operatorDB)
	ctx := context.Background()
	fixture := terminalReplayFixture(t, registry, deliveryStore, randomTenant(t), webhook.OutcomePermanent)
	request := replayRequest(fixture.tenant, fixture.deliveryID)
	if _, err := replayStore.AuthorizeReplay(ctx, request); err != nil {
		t.Fatalf("AuthorizeReplay: %v", err)
	}

	if _, err := adminDB.ExecContext(ctx,
		`UPDATE keel_meta.webhook_replay_transitions SET prior_state='exhausted' WHERE tenant_id=$1`,
		string(fixture.tenant)); err == nil || !strings.Contains(err.Error(), "immutable") {
		t.Fatalf("admin update error = %v, want immutable rejection", err)
	}
	if _, err := adminDB.ExecContext(ctx,
		`DELETE FROM keel_meta.webhook_replay_transitions WHERE tenant_id=$1`,
		string(fixture.tenant)); err == nil || !strings.Contains(err.Error(), "immutable") {
		t.Fatalf("admin delete error = %v, want immutable rejection", err)
	}
	if count := replayTransitionCount(t, adminDB, fixture.tenant); count != 1 {
		t.Fatalf("transition rows after mutation attempts = %d, want 1", count)
	}
}

func TestDeliveryStateGuardRejectsUnauditedRequeue(t *testing.T) {
	appDB, webhookDB, _, adminDB := replayAuthorizationDatabases(t)
	registry := newRegistry(t, appDB)
	deliveryStore := newStore(t, webhookDB)
	ctx := context.Background()

	for name, testCase := range map[string]struct {
		outcome webhook.Outcome
		state   webhook.DeliveryState
	}{
		"failed":    {webhook.OutcomePermanent, webhook.StateFailed},
		"delivered": {webhook.OutcomeDelivered, webhook.StateDelivered},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := terminalReplayFixture(t, registry, deliveryStore, randomTenant(t), testCase.outcome)
			if err := updateDeliveryStateDirect(ctx, webhookDB, fixture.tenant, fixture.deliveryID, "pending"); err == nil {
				t.Fatal("expected an unaudited requeue to be rejected")
			}
			if after := readReplayState(t, adminDB, fixture.tenant, fixture.deliveryID); after.State != string(testCase.state) {
				t.Fatalf("state after rejected requeue = %s, want %s", after.State, testCase.state)
			}
		})
	}
}

func updateDeliveryStateDirect(ctx context.Context, db *sql.DB, tenant tenancy.TenantID, deliveryID, state string) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, "SELECT set_config('keel.tenant_id', $1, true)", string(tenant)); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx,
		`UPDATE keel_meta.webhook_delivery_state
		    SET state=$2,next_attempt_at=clock_timestamp(),lease_expires_at=NULL,
		        delivered_at=NULL,finished_at=NULL,updated_at=clock_timestamp()
		  WHERE tenant_id=$1 AND delivery_id=$3`,
		string(tenant), state, deliveryID)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func TestAuthorizeReplayRequiresStore(t *testing.T) {
	ctx := context.Background()
	request := replayRequest(randomTenant(t), uuid.NewString())
	if _, err := (*Store)(nil).AuthorizeReplay(ctx, request); err == nil {
		t.Fatal("expected a nil store to be rejected")
	}
	if _, err := (&Store{}).AuthorizeReplay(ctx, request); err == nil {
		t.Fatal("expected a store without a database to be rejected")
	}
}

func TestReplayAuthorizationErrorMapping(t *testing.T) {
	cases := []struct {
		err  error
		want error
	}{
		{errors.New("webhook replay capability is required"), webhook.ErrReplayUnauthorized},
		{errors.New(`permission denied for function authorize_webhook_replay_requeue`), webhook.ErrReplayUnauthorized},
		{errors.New("webhook replay delivery was not found"), webhook.ErrReplayNotFound},
		{errors.New("webhook delivery is not eligible for replay"), webhook.ErrReplayNotEligible},
		{errors.New("webhook replay endpoint is not eligible"), webhook.ErrReplayNotEligible},
		{errors.New("webhook delivery was already replayed"), webhook.ErrReplayConflict},
		{errors.New("webhook replay request conflicts with an existing replay"), webhook.ErrReplayConflict},
		{errors.New(`duplicate key value violates unique constraint`), webhook.ErrReplayConflict},
	}
	for _, testCase := range cases {
		mapped := replayAuthorizationError(testCase.err)
		if !errors.Is(mapped, testCase.want) {
			t.Fatalf("replayAuthorizationError(%q) = %v, want %v", testCase.err, mapped, testCase.want)
		}
	}
	plain := fmt.Errorf("unexpected database failure")
	if mapped := replayAuthorizationError(plain); !errors.Is(mapped, plain) {
		t.Fatalf("replayAuthorizationError(plain) = %v, want the original error", mapped)
	}
}
