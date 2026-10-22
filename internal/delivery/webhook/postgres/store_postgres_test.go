package postgres

import (
	"context"
	"database/sql"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/sanskarpan/keel/internal/delivery/webhook"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

func webhookTestDB(t *testing.T, dsn string) *sql.DB {
	t.Helper()
	parsed, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("pgx", parsed.String())
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(8)
	db.SetMaxIdleConns(8)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err = db.PingContext(ctx); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func webhookTestDatabases(t *testing.T) (*sql.DB, *sql.DB) {
	t.Helper()
	webhookDSN, adminDSN := os.Getenv("KEEL_TEST_WEBHOOK_DATABASE_URL"), os.Getenv("KEEL_TEST_ADMIN_DATABASE_URL")
	if webhookDSN == "" || adminDSN == "" {
		t.Skip("set KEEL_TEST_WEBHOOK_DATABASE_URL and KEEL_TEST_ADMIN_DATABASE_URL for webhook delivery integration coverage")
	}
	return webhookTestDB(t, webhookDSN), webhookTestDB(t, adminDSN)
}

func newStore(t *testing.T, db *sql.DB) *Store {
	t.Helper()
	store, err := New(db)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func randomIdentity(t *testing.T) webhook.Identity {
	t.Helper()
	tenant, err := tenancy.ParseTenantID(uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	return webhook.Identity{
		Tenant:              tenant,
		EventID:             "evt_" + strings.ReplaceAll(uuid.NewString(), "-", ""),
		EndpointID:          uuid.NewString(),
		SubscriptionVersion: 1,
	}
}

func deliveryCount(t *testing.T, admin *sql.DB, tenant tenancy.TenantID) int {
	t.Helper()
	var count int
	if err := admin.QueryRowContext(context.Background(),
		`SELECT count(*) FROM keel_meta.webhook_deliveries WHERE tenant_id=$1`, string(tenant)).Scan(&count); err != nil {
		t.Fatalf("count webhook deliveries: %v", err)
	}
	return count
}

func TestPostgreSQLWebhookDeliveryClaimIsIdempotent(t *testing.T) {
	webhookDB, adminDB := webhookTestDatabases(t)
	store := newStore(t, webhookDB)
	identity := randomIdentity(t)

	first, err := store.Ensure(context.Background(), identity)
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if !first.Created {
		t.Fatal("expected the first claim to create the delivery")
	}
	if first.Delivery.ID == "" || first.CreatedAt.IsZero() {
		t.Fatalf("expected a delivery id and creation time, got %+v", first)
	}
	if first.Delivery.Identity != identity {
		t.Fatalf("claim returned a different identity: %+v", first.Delivery.Identity)
	}

	second, err := store.Ensure(context.Background(), identity)
	if err != nil {
		t.Fatalf("Ensure duplicate: %v", err)
	}
	if second.Created {
		t.Fatal("expected a duplicate claim not to create a delivery")
	}
	if second.Delivery.ID != first.Delivery.ID {
		t.Fatalf("duplicate claim minted a new id: %q vs %q", second.Delivery.ID, first.Delivery.ID)
	}
	if !second.CreatedAt.Equal(first.CreatedAt) {
		t.Fatalf("duplicate claim changed the creation time: %s vs %s", second.CreatedAt, first.CreatedAt)
	}
	if count := deliveryCount(t, adminDB, identity.Tenant); count != 1 {
		t.Fatalf("expected one recorded delivery, got %d", count)
	}
}

func TestPostgreSQLWebhookDeliveryScopesIdentity(t *testing.T) {
	webhookDB, _ := webhookTestDatabases(t)
	store := newStore(t, webhookDB)

	base := randomIdentity(t)
	otherTenant := randomIdentity(t)
	variants := []webhook.Identity{
		base,
		func() webhook.Identity { v := base; v.SubscriptionVersion = base.SubscriptionVersion + 1; return v }(),
		func() webhook.Identity { v := base; v.EndpointID = uuid.NewString(); return v }(),
		func() webhook.Identity {
			v := base
			v.EventID = "evt_" + strings.ReplaceAll(uuid.NewString(), "-", "")
			return v
		}(),
		func() webhook.Identity { v := base; v.Tenant = otherTenant.Tenant; return v }(),
	}

	seen := make(map[string]struct{}, len(variants))
	for index, identity := range variants {
		claim, err := store.Ensure(context.Background(), identity)
		if err != nil {
			t.Fatalf("variant %d: Ensure: %v", index, err)
		}
		if !claim.Created {
			t.Fatalf("variant %d: expected a new delivery", index)
		}
		if _, duplicate := seen[claim.Delivery.ID]; duplicate {
			t.Fatalf("variant %d reused delivery id %q", index, claim.Delivery.ID)
		}
		seen[claim.Delivery.ID] = struct{}{}
	}

	for index, identity := range variants {
		claim, err := store.Ensure(context.Background(), identity)
		if err != nil {
			t.Fatalf("repeat %d: Ensure: %v", index, err)
		}
		if claim.Created {
			t.Fatalf("repeat %d: expected the recorded delivery", index)
		}
	}
}

func TestPostgreSQLWebhookDeliveryClaimConcurrent(t *testing.T) {
	webhookDB, adminDB := webhookTestDatabases(t)
	identity := randomIdentity(t)

	const claimers = 4
	var createdCount int32
	ids := make([]string, claimers)
	errs := make([]error, claimers)
	var start sync.WaitGroup
	start.Add(1)
	var done sync.WaitGroup
	for index := 0; index < claimers; index++ {
		index := index
		done.Add(1)
		go func() {
			defer done.Done()
			store, err := New(webhookDB)
			if err != nil {
				errs[index] = err
				return
			}
			start.Wait()
			claim, err := store.Ensure(context.Background(), identity)
			if err != nil {
				errs[index] = err
				return
			}
			ids[index] = claim.Delivery.ID
			if claim.Created {
				atomic.AddInt32(&createdCount, 1)
			}
		}()
	}
	start.Done()
	done.Wait()

	for index, err := range errs {
		if err != nil {
			t.Fatalf("claimer %d: %v", index, err)
		}
	}
	if createdCount != 1 {
		t.Fatalf("expected exactly one creator, got %d", createdCount)
	}
	for index, id := range ids {
		if id != ids[0] {
			t.Fatalf("claimer %d saw delivery %q, want %q", index, id, ids[0])
		}
	}
	if count := deliveryCount(t, adminDB, identity.Tenant); count != 1 {
		t.Fatalf("expected one recorded delivery, got %d", count)
	}
}

func TestPostgreSQLWebhookDeliveryDeniesDirectAccessAndMutation(t *testing.T) {
	webhookDB, adminDB := webhookTestDatabases(t)
	store := newStore(t, webhookDB)
	claim, err := store.Ensure(context.Background(), randomIdentity(t))
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}

	ctx := context.Background()
	for _, statement := range []string{
		`SELECT count(*) FROM keel_meta.webhook_deliveries`,
		`INSERT INTO keel_meta.webhook_deliveries (tenant_id,event_id,endpoint_id,subscription_version,delivery_id) VALUES ('11111111-1111-4111-8111-111111111111','event_00000001','endpoint_0001',1,'delivery_0001')`,
		`UPDATE keel_meta.webhook_deliveries SET event_id='event_00000002'`,
		`DELETE FROM keel_meta.webhook_deliveries`,
	} {
		if _, err := webhookDB.ExecContext(ctx, statement); err == nil {
			t.Fatalf("expected the webhook capability to be denied: %s", statement)
		}
	}

	if _, err := adminDB.ExecContext(ctx,
		`UPDATE keel_meta.webhook_deliveries SET event_id='event_00000003' WHERE delivery_id=$1`, claim.Delivery.ID); err == nil {
		t.Fatal("expected the immutable ledger to reject an update")
	} else if !strings.Contains(err.Error(), "immutable") {
		t.Fatalf("expected an immutability error, got %v", err)
	}
	if _, err := adminDB.ExecContext(ctx,
		`DELETE FROM keel_meta.webhook_deliveries WHERE delivery_id=$1`, claim.Delivery.ID); err == nil {
		t.Fatal("expected the immutable ledger to reject a delete")
	} else if !strings.Contains(err.Error(), "immutable") {
		t.Fatalf("expected an immutability error, got %v", err)
	}
}

func TestPostgreSQLWebhookDeliveryRequiresCapability(t *testing.T) {
	appDSN := os.Getenv("KEEL_TEST_DATABASE_URL")
	if appDSN == "" {
		t.Skip("set KEEL_TEST_DATABASE_URL for the webhook capability denial case")
	}
	appDB := webhookTestDB(t, appDSN)
	identity := randomIdentity(t)
	tx, err := appDB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(context.Background(), "SELECT set_config('keel.tenant_id', $1, true)", string(identity.Tenant)); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(context.Background(),
		`SELECT * FROM keel_meta.claim_webhook_delivery($1,$2,$3,$4)`,
		identity.EventID, identity.EndpointID, 1, uuid.NewString()); err == nil {
		t.Fatal("expected a role without the webhook capability to be denied")
	}
}

func TestPostgreSQLWebhookDeliveryClaimRejectsInvalidInput(t *testing.T) {
	webhookDB, _ := webhookTestDatabases(t)
	identity := randomIdentity(t)

	cases := []struct {
		name     string
		eventID  string
		endpoint string
		version  int
		delivery string
	}{
		{name: "short event", eventID: "short", endpoint: identity.EndpointID, version: 1, delivery: uuid.NewString()},
		{name: "bad endpoint", eventID: identity.EventID, endpoint: "../escape", version: 1, delivery: uuid.NewString()},
		{name: "zero version", eventID: identity.EventID, endpoint: identity.EndpointID, version: 0, delivery: uuid.NewString()},
		{name: "short delivery", eventID: identity.EventID, endpoint: identity.EndpointID, version: 1, delivery: "x"},
	}
	for _, testCase := range cases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			tx, err := webhookDB.BeginTx(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback() }()
			if _, err := tx.ExecContext(context.Background(), "SELECT set_config('keel.tenant_id', $1, true)", string(identity.Tenant)); err != nil {
				t.Fatal(err)
			}
			var deliveryID string
			var created bool
			var createdAt time.Time
			err = tx.QueryRowContext(context.Background(),
				`SELECT delivery_id,created,created_at FROM keel_meta.claim_webhook_delivery($1,$2,$3,$4)`,
				testCase.eventID, testCase.endpoint, testCase.version, testCase.delivery).
				Scan(&deliveryID, &created, &createdAt)
			if err == nil {
				t.Fatalf("expected an invalid claim to be rejected, got %q", deliveryID)
			}
		})
	}
}

func TestPostgreSQLWebhookDeliveryClaimRequiresTenantContext(t *testing.T) {
	webhookDB, _ := webhookTestDatabases(t)
	identity := randomIdentity(t)

	tx, err := webhookDB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	var deliveryID string
	var created bool
	var createdAt time.Time
	err = tx.QueryRowContext(context.Background(),
		`SELECT delivery_id,created,created_at FROM keel_meta.claim_webhook_delivery($1,$2,$3,$4)`,
		identity.EventID, identity.EndpointID, 1, uuid.NewString()).
		Scan(&deliveryID, &created, &createdAt)
	if err == nil {
		t.Fatal("expected a claim without an authorized tenant to be rejected")
	}
}
