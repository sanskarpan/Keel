package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/sanskarpan/keel/internal/delivery/webhook"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

func TestPayloadRejectsUntrustedInput(t *testing.T) {
	db, err := sql.Open("pgx", "postgres://invalid:invalid@127.0.0.1:1/invalid?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := &Store{db: db}
	tenant := payloadTenant(t)
	delivery := webhook.Delivery{
		ID: "delivery_" + strings.ReplaceAll(uuid.NewString(), "-", ""),
		Identity: webhook.Identity{
			Tenant:              tenant,
			EventID:             uuid.NewString(),
			EndpointID:          uuid.NewString(),
			SubscriptionVersion: 1,
		},
	}
	cases := []struct {
		name     string
		tenant   tenancy.TenantID
		delivery webhook.Delivery
	}{
		{"zero tenant", "00000000-0000-0000-0000-000000000000", delivery},
		{"invalid tenant", "not-a-tenant", delivery},
		{"mismatched tenant", payloadTenant(t), delivery},
		{"invalid delivery id", tenant, func() webhook.Delivery { d := delivery; d.ID = "short"; return d }()},
		{"non uuid event", tenant, func() webhook.Delivery {
			d := delivery
			d.Identity.EventID = "evt_" + strings.Repeat("a", 12)
			return d
		}()},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if _, err := store.Payload(context.Background(), test.tenant, test.delivery); !errors.Is(err, webhook.ErrInvalidDelivery) {
				t.Fatalf("expected ErrInvalidDelivery, got %v", err)
			}
		})
	}
}

func TestPayloadRequiresContextAndDatabase(t *testing.T) {
	db, err := sql.Open("pgx", "postgres://invalid:invalid@127.0.0.1:1/invalid?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := &Store{db: db}
	delivery := webhook.Delivery{
		ID: "delivery_" + strings.ReplaceAll(uuid.NewString(), "-", ""),
		Identity: webhook.Identity{
			Tenant:              payloadTenant(t),
			EventID:             uuid.NewString(),
			EndpointID:          uuid.NewString(),
			SubscriptionVersion: 1,
		},
	}
	if _, err := store.Payload(nil, delivery.Identity.Tenant, delivery); err == nil {
		t.Fatal("expected a nil context error")
	}
	if _, err := (*Store)(nil).Payload(context.Background(), delivery.Identity.Tenant, delivery); err == nil {
		t.Fatal("expected a nil store error")
	}
	if _, err := store.Payload(context.Background(), delivery.Identity.Tenant, delivery); err == nil || errors.Is(err, webhook.ErrInvalidDelivery) {
		t.Fatalf("expected a retryable database error, got %v", err)
	}
}

func TestPostgreSQLPayloadReturnsCanonicalEnvelope(t *testing.T) {
	webhookDB, adminDB := webhookTestDatabases(t)
	store := newStore(t, webhookDB)
	tenant := payloadTenant(t)
	eventID := uuid.NewString()
	envelope := payloadEnvelope(tenant, eventID)
	delivery := insertPayloadDelivery(t, webhookDB, adminDB, tenant, eventID, envelope)

	first, err := store.Payload(context.Background(), tenant, delivery)
	if err != nil {
		t.Fatalf("Payload: %v", err)
	}
	second, err := store.Payload(context.Background(), tenant, delivery)
	if err != nil {
		t.Fatalf("Payload retry: %v", err)
	}
	if string(first) != string(second) {
		t.Fatal("payload bytes changed between reads")
	}

	var canonical string
	if err := adminDB.QueryRowContext(context.Background(),
		`SELECT safe_envelope::text FROM keel_meta.event_outbox WHERE tenant_id=$1 AND event_id=$2`,
		string(tenant), eventID).Scan(&canonical); err != nil {
		t.Fatalf("read canonical envelope: %v", err)
	}
	if string(first) != canonical {
		t.Fatalf("payload is not the canonical safe envelope:\n got %s\nwant %s", first, canonical)
	}
	if len(first) == 0 || len(first) > webhook.MaxAttemptBodyBytes {
		t.Fatalf("payload length %d is outside the attempt bound", len(first))
	}
}

func TestPostgreSQLPayloadScopesTenant(t *testing.T) {
	webhookDB, adminDB := webhookTestDatabases(t)
	store := newStore(t, webhookDB)
	tenant := payloadTenant(t)
	other := payloadTenant(t)
	eventID := uuid.NewString()
	delivery := insertPayloadDelivery(t, webhookDB, adminDB, tenant, eventID, payloadEnvelope(tenant, eventID))

	if _, err := store.Payload(context.Background(), other, delivery); !errors.Is(err, webhook.ErrInvalidDelivery) {
		t.Fatalf("expected cross-tenant denial, got %v", err)
	}
	crossed := delivery
	crossed.Identity.Tenant = other
	if _, err := store.Payload(context.Background(), tenant, crossed); !errors.Is(err, webhook.ErrInvalidDelivery) {
		t.Fatalf("expected a tenant mismatch denial, got %v", err)
	}
}

func TestPostgreSQLPayloadRejectsMissingAndOversizedBodies(t *testing.T) {
	webhookDB, adminDB := webhookTestDatabases(t)
	store := newStore(t, webhookDB)

	missingTenant := payloadTenant(t)
	missingEvent := uuid.NewString()
	missing := ensurePayloadDelivery(t, webhookDB, missingTenant, missingEvent)
	if _, err := store.Payload(context.Background(), missingTenant, missing); !errors.Is(err, webhook.ErrInvalidDelivery) {
		t.Fatalf("expected a missing body to be permanent, got %v", err)
	}

	largeTenant := payloadTenant(t)
	largeEvent := uuid.NewString()
	large, err := json.Marshal(map[string]string{"blob": strings.Repeat("a", webhook.MaxAttemptBodyBytes)})
	if err != nil {
		t.Fatal(err)
	}
	delivery := insertPayloadDelivery(t, webhookDB, adminDB, largeTenant, largeEvent, string(large))
	if _, err := store.Payload(context.Background(), largeTenant, delivery); !errors.Is(err, webhook.ErrInvalidDelivery) {
		t.Fatalf("expected an oversized body to be permanent, got %v", err)
	}
}

func TestPostgreSQLPayloadRequiresWebhookCapability(t *testing.T) {
	webhookDB, adminDB := webhookTestDatabases(t)
	tenant := payloadTenant(t)
	eventID := uuid.NewString()
	delivery := insertPayloadDelivery(t, webhookDB, adminDB, tenant, eventID, payloadEnvelope(tenant, eventID))

	ctx := context.Background()
	if _, err := webhookDB.ExecContext(ctx, `SELECT set_config('keel.tenant_id',$1,false)`, string(tenant)); err != nil {
		t.Fatal(err)
	}
	if _, err := webhookDB.ExecContext(ctx, `SELECT safe_envelope FROM keel_meta.event_outbox`); err == nil {
		t.Fatal("expected direct outbox access to be denied")
	}

	appDSN := os.Getenv("KEEL_TEST_DATABASE_URL")
	if appDSN == "" {
		t.Skip("set KEEL_TEST_DATABASE_URL to check capability denial")
	}
	appDB := webhookTestDB(t, appDSN)
	if _, err := appDB.ExecContext(ctx, `SELECT set_config('keel.tenant_id',$1,false)`, string(tenant)); err != nil {
		t.Fatal(err)
	}
	if _, err := appDB.ExecContext(ctx,
		`SELECT * FROM keel_meta.read_webhook_delivery_body($1)`, delivery.ID); err == nil {
		t.Fatal("expected the non-webhook capability to be denied")
	}

	unsetDB := webhookTestDB(t, os.Getenv("KEEL_TEST_WEBHOOK_DATABASE_URL"))
	if _, err := unsetDB.ExecContext(ctx, `SELECT * FROM keel_meta.read_webhook_delivery_body($1)`, delivery.ID); err == nil {
		t.Fatal("expected an unset tenant context to be rejected")
	}
}

func TestPostgreSQLPayloadRequiresWebhookFunctionGrant(t *testing.T) {
	appDSN := os.Getenv("KEEL_TEST_DATABASE_URL")
	if appDSN == "" {
		t.Skip("set KEEL_TEST_DATABASE_URL to check function grant denial")
	}
	appDB := webhookTestDB(t, appDSN)
	ctx := context.Background()
	if _, err := appDB.ExecContext(ctx, `SELECT set_config('keel.tenant_id',$1,false)`, uuid.NewString()); err != nil {
		t.Fatal(err)
	}
	if _, err := appDB.ExecContext(ctx,
		`SELECT * FROM keel_meta.read_webhook_delivery_body($1)`, "delivery_12345678"); err == nil ||
		!strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("expected execute denial, got %v", err)
	}
}

func payloadTenant(t *testing.T) tenancy.TenantID {
	t.Helper()
	tenant, err := tenancy.ParseTenantID(uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	return tenant
}

func payloadEnvelope(tenant tenancy.TenantID, eventID string) string {
	return `{"schema_version":1,"event_id":"` + eventID + `","tenant_id":"` + string(tenant) +
		`","aggregate_id":"` + uuid.NewString() + `","aggregate_version":1,"event_type":"order.created",` +
		`"occurred_at":"2026-01-02T03:04:05Z"}`
}

func insertPayloadDelivery(t *testing.T, webhookDB, adminDB *sql.DB, tenant tenancy.TenantID, eventID, envelope string) webhook.Delivery {
	t.Helper()
	orderID := uuid.NewString()
	hash := make([]byte, 32)
	if _, err := adminDB.ExecContext(context.Background(),
		`INSERT INTO keel_meta.order_heads
		 (tenant_id,order_id,external_reference,supplier_id,status,version,command_snapshot,snapshot_hash)
		 VALUES ($1,$2,$3,$4,'draft',1,'{}'::jsonb,$5)`,
		string(tenant), orderID, "ref-"+uuid.NewString(), uuid.NewString(), hash); err != nil {
		t.Fatalf("insert order head: %v", err)
	}
	if _, err := adminDB.ExecContext(context.Background(),
		`INSERT INTO keel_meta.order_events
		 (tenant_id,order_id,aggregate_version,event_id,event_type,event_data,event_hash,occurred_at)
		 VALUES ($1,$2,1,$3,'order.created','{}'::jsonb,$4,clock_timestamp())`,
		string(tenant), orderID, eventID, hash); err != nil {
		t.Fatalf("insert order event: %v", err)
	}
	if _, err := adminDB.ExecContext(context.Background(),
		`INSERT INTO keel_meta.event_outbox
		 (tenant_id,event_id,aggregate_id,aggregate_version,event_type,schema_version,safe_envelope)
		 VALUES ($1,$2,$3,1,'order.created',1,$4::jsonb)`,
		string(tenant), eventID, orderID, envelope); err != nil {
		t.Fatalf("insert outbox envelope: %v", err)
	}
	return ensurePayloadDelivery(t, webhookDB, tenant, eventID)
}

func ensurePayloadDelivery(t *testing.T, webhookDB *sql.DB, tenant tenancy.TenantID, eventID string) webhook.Delivery {
	t.Helper()
	store := newStore(t, webhookDB)
	claim, err := store.Ensure(context.Background(), webhook.Identity{
		Tenant:              tenant,
		EventID:             eventID,
		EndpointID:          uuid.NewString(),
		SubscriptionVersion: 1,
	})
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	return claim.Delivery
}
