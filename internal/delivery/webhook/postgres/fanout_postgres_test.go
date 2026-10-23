package postgres

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/sanskarpan/keel/internal/delivery/webhook"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

func fanoutDatabases(t *testing.T) (*sql.DB, *sql.DB, *sql.DB) {
	t.Helper()
	appDSN := os.Getenv("KEEL_TEST_DATABASE_URL")
	webhookDSN := os.Getenv("KEEL_TEST_WEBHOOK_DATABASE_URL")
	adminDSN := os.Getenv("KEEL_TEST_ADMIN_DATABASE_URL")
	if appDSN == "" || webhookDSN == "" || adminDSN == "" {
		t.Skip("set KEEL_TEST_DATABASE_URL, KEEL_TEST_WEBHOOK_DATABASE_URL and KEEL_TEST_ADMIN_DATABASE_URL for webhook fanout coverage")
	}
	return webhookTestDB(t, appDSN), webhookTestDB(t, webhookDSN), webhookTestDB(t, adminDSN)
}

func registerFanoutEndpoint(t *testing.T, registry *Registry, tenant tenancy.TenantID, subscription uint32) webhook.Endpoint {
	t.Helper()
	endpoint, err := registry.Register(context.Background(), tenant, webhook.EndpointRegistration{
		ID:                  "ep_" + strings.ReplaceAll(uuid.NewString(), "-", ""),
		URL:                 "https://example.com/hooks/" + uuid.NewString(),
		KeyID:               "key_" + strings.ReplaceAll(uuid.NewString(), "-", ""),
		SubscriptionVersion: subscription,
	}, 0)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	return endpoint
}

func insertFanoutOutbox(t *testing.T, adminDB *sql.DB, tenant tenancy.TenantID, eventID string) {
	t.Helper()
	orderID := uuid.NewString()
	hash := make([]byte, 32)
	ctx := context.Background()
	if _, err := adminDB.ExecContext(ctx,
		`INSERT INTO keel_meta.order_heads
		 (tenant_id,order_id,external_reference,supplier_id,status,version,command_snapshot,snapshot_hash)
		 VALUES ($1,$2,$3,$4,'draft',1,'{}'::jsonb,$5)`,
		string(tenant), orderID, "ref-"+uuid.NewString(), uuid.NewString(), hash); err != nil {
		t.Fatalf("insert order head: %v", err)
	}
	if _, err := adminDB.ExecContext(ctx,
		`INSERT INTO keel_meta.order_events
		 (tenant_id,order_id,aggregate_version,event_id,event_type,event_data,event_hash,occurred_at)
		 VALUES ($1,$2,1,$3,'order.created','{}'::jsonb,$4,clock_timestamp())`,
		string(tenant), orderID, eventID, hash); err != nil {
		t.Fatalf("insert order event: %v", err)
	}
	if _, err := adminDB.ExecContext(ctx,
		`INSERT INTO keel_meta.event_outbox
		 (tenant_id,event_id,aggregate_id,aggregate_version,event_type,schema_version,safe_envelope)
		 VALUES ($1,$2,$3,1,'order.created',1,$4::jsonb)`,
		string(tenant), eventID, orderID, `{"event_id":"`+eventID+`"}`); err != nil {
		t.Fatalf("insert outbox event: %v", err)
	}
}

func fanout(t *testing.T, db *sql.DB, tenant tenancy.TenantID, eventID string) int {
	t.Helper()
	var inserted int
	err := inTenantTx(context.Background(), db, tenant, func(ctx context.Context, tx *sql.Tx) error {
		return tx.QueryRowContext(ctx,
			`SELECT keel_meta.fanout_webhook_deliveries($1)`, eventID).Scan(&inserted)
	})
	if err != nil {
		t.Fatalf("fanout: %v", err)
	}
	return inserted
}

type fanoutDelivery struct {
	EndpointID          string
	SubscriptionVersion int
	DeliveryID          string
}

func readFanoutDeliveries(t *testing.T, adminDB *sql.DB, tenant tenancy.TenantID, eventID string) []fanoutDelivery {
	t.Helper()
	rows, err := adminDB.QueryContext(context.Background(),
		`SELECT endpoint_id,subscription_version,delivery_id
		   FROM keel_meta.webhook_deliveries
		  WHERE tenant_id=$1 AND event_id=$2 ORDER BY endpoint_id`, string(tenant), eventID)
	if err != nil {
		t.Fatalf("read fanout deliveries: %v", err)
	}
	defer rows.Close()
	var deliveries []fanoutDelivery
	for rows.Next() {
		var delivery fanoutDelivery
		if err := rows.Scan(&delivery.EndpointID, &delivery.SubscriptionVersion, &delivery.DeliveryID); err != nil {
			t.Fatalf("scan fanout delivery: %v", err)
		}
		deliveries = append(deliveries, delivery)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate fanout deliveries: %v", err)
	}
	return deliveries
}

func TestPostgreSQLFanoutCreatesOneDeliveryPerActiveEndpoint(t *testing.T) {
	appDB, _, adminDB := fanoutDatabases(t)
	registry := newRegistry(t, appDB)
	tenant := payloadTenant(t)
	eventID := uuid.NewString()
	insertFanoutOutbox(t, adminDB, tenant, eventID)

	first := registerFanoutEndpoint(t, registry, tenant, 1)
	second := registerFanoutEndpoint(t, registry, tenant, 2)
	inactive := registerFanoutEndpoint(t, registry, tenant, 1)
	if _, err := registry.SetStatus(context.Background(), tenant, inactive.ID, webhook.EndpointInactive, inactive.Version); err != nil {
		t.Fatalf("SetStatus: %v", err)
	}
	if count := fanout(t, appDB, tenant, eventID); count != 2 {
		t.Fatalf("fanout inserted %d deliveries, want 2", count)
	}

	deliveries := readFanoutDeliveries(t, adminDB, tenant, eventID)
	if len(deliveries) != 2 {
		t.Fatalf("recorded deliveries = %d, want 2", len(deliveries))
	}
	want := map[string]int{first.ID: 1, second.ID: 2}
	for _, delivery := range deliveries {
		if want[delivery.EndpointID] != delivery.SubscriptionVersion {
			t.Fatalf("delivery %+v does not match an active endpoint revision", delivery)
		}
		if delivery.DeliveryID == inactive.ID || delivery.DeliveryID == "" {
			t.Fatalf("invalid delivery identity %+v", delivery)
		}
		if len(delivery.DeliveryID) < 8 {
			t.Fatalf("delivery ID is too short: %q", delivery.DeliveryID)
		}
	}
	if count := fanout(t, appDB, tenant, eventID); count != 0 {
		t.Fatalf("repeat fanout inserted %d deliveries, want 0", count)
	}
	if after := readFanoutDeliveries(t, adminDB, tenant, eventID); len(after) != 2 {
		t.Fatalf("repeat fanout changed the delivery count to %d", len(after))
	}
}

func TestPostgreSQLFanoutUsesTheCurrentEndpointRevision(t *testing.T) {
	appDB, _, adminDB := fanoutDatabases(t)
	registry := newRegistry(t, appDB)
	tenant := payloadTenant(t)
	endpoint := registerFanoutEndpoint(t, registry, tenant, 1)
	firstEvent, secondEvent := uuid.NewString(), uuid.NewString()
	insertFanoutOutbox(t, adminDB, tenant, firstEvent)
	insertFanoutOutbox(t, adminDB, tenant, secondEvent)

	if count := fanout(t, appDB, tenant, firstEvent); count != 1 {
		t.Fatalf("first fanout inserted %d deliveries, want 1", count)
	}
	updated, err := registry.Register(context.Background(), tenant, webhook.EndpointRegistration{
		ID:                  endpoint.ID,
		URL:                 endpoint.URL,
		KeyID:               endpoint.KeyID,
		SubscriptionVersion: 2,
	}, endpoint.Version)
	if err != nil {
		t.Fatalf("Register revision: %v", err)
	}
	if count := fanout(t, appDB, tenant, secondEvent); count != 1 {
		t.Fatalf("second fanout inserted %d deliveries, want 1", count)
	}
	first := readFanoutDeliveries(t, adminDB, tenant, firstEvent)
	second := readFanoutDeliveries(t, adminDB, tenant, secondEvent)
	if len(first) != 1 || first[0].SubscriptionVersion != 1 {
		t.Fatalf("first event deliveries = %+v, want revision 1", first)
	}
	if len(second) != 1 || second[0].SubscriptionVersion != int(updated.SubscriptionVersion) {
		t.Fatalf("second event deliveries = %+v, want revision %d", second, updated.SubscriptionVersion)
	}
}

func TestPostgreSQLFanoutRejectsUnknownEventsAndOtherTenants(t *testing.T) {
	appDB, _, adminDB := fanoutDatabases(t)
	registry := newRegistry(t, appDB)
	tenant := payloadTenant(t)
	other := payloadTenant(t)
	registerFanoutEndpoint(t, registry, tenant, 1)
	eventID := uuid.NewString()
	insertFanoutOutbox(t, adminDB, tenant, eventID)

	if err := inTenantTx(context.Background(), appDB, other, func(ctx context.Context, tx *sql.Tx) error {
		var count int
		return tx.QueryRowContext(ctx,
			`SELECT keel_meta.fanout_webhook_deliveries($1)`, eventID).Scan(&count)
	}); err == nil {
		t.Fatal("expected a cross-tenant event to be rejected")
	}
	if err := inTenantTx(context.Background(), appDB, tenant, func(ctx context.Context, tx *sql.Tx) error {
		var count int
		return tx.QueryRowContext(ctx,
			`SELECT keel_meta.fanout_webhook_deliveries($1)`, uuid.NewString()).Scan(&count)
	}); err == nil {
		t.Fatal("expected an unknown event to be rejected")
	}
	if deliveries := readFanoutDeliveries(t, adminDB, tenant, eventID); len(deliveries) != 0 {
		t.Fatalf("rejected fanout wrote %d deliveries", len(deliveries))
	}
}

func TestPostgreSQLFanoutRequiresAppCapability(t *testing.T) {
	_, webhookDB, adminDB := fanoutDatabases(t)
	tenant := payloadTenant(t)
	eventID := uuid.NewString()
	insertFanoutOutbox(t, adminDB, tenant, eventID)
	err := inTenantTx(context.Background(), webhookDB, tenant, func(ctx context.Context, tx *sql.Tx) error {
		var count int
		return tx.QueryRowContext(ctx,
			`SELECT keel_meta.fanout_webhook_deliveries($1)`, eventID).Scan(&count)
	})
	if err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("expected execute denial, got %v", err)
	}
}

func TestPostgreSQLFanoutIsConcurrentSingleWinner(t *testing.T) {
	appDB, _, adminDB := fanoutDatabases(t)
	registry := newRegistry(t, appDB)
	tenant := payloadTenant(t)
	eventID := uuid.NewString()
	insertFanoutOutbox(t, adminDB, tenant, eventID)
	for range 3 {
		registerFanoutEndpoint(t, registry, tenant, 1)
	}

	start := make(chan struct{})
	results := make(chan int, 2)
	errs := make(chan error, 2)
	var wait sync.WaitGroup
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			var inserted int
			err := inTenantTx(context.Background(), appDB, tenant, func(ctx context.Context, tx *sql.Tx) error {
				return tx.QueryRowContext(ctx,
					`SELECT keel_meta.fanout_webhook_deliveries($1)`, eventID).Scan(&inserted)
			})
			results <- inserted
			errs <- err
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	close(errs)

	total := 0
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent fanout: %v", err)
		}
	}
	for inserted := range results {
		total += inserted
	}
	if total != 3 {
		t.Fatalf("concurrent fanout inserted %d deliveries, want 3", total)
	}
	if deliveries := readFanoutDeliveries(t, adminDB, tenant, eventID); len(deliveries) != 3 {
		t.Fatalf("recorded deliveries = %d, want 3", len(deliveries))
	}
}

func TestPostgreSQLFanoutRejectsMalformedInput(t *testing.T) {
	appDB, _, _ := fanoutDatabases(t)
	tenant := payloadTenant(t)
	for _, eventID := range []string{"", "not-a-uuid", strings.Repeat("a", 36)} {
		err := inTenantTx(context.Background(), appDB, tenant, func(ctx context.Context, tx *sql.Tx) error {
			var count int
			return tx.QueryRowContext(ctx,
				`SELECT keel_meta.fanout_webhook_deliveries($1)`, eventID).Scan(&count)
		})
		if err == nil {
			t.Fatalf("expected malformed event %q to be rejected", eventID)
		}
	}
}
