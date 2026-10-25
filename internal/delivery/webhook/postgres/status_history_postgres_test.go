package postgres

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/sanskarpan/keel/internal/delivery/webhook"
)

func TestPostgreSQLWebhookEndpointStatusHistory(t *testing.T) {
	appDB, webhookDB, operatorDB, adminDB := reconciliationDatabases(t)
	registry := newRegistry(t, appDB)
	store := newReconciliationStore(t, operatorDB)
	ctx := context.Background()
	tenant := payloadTenant(t)
	registration := validRegistryRegistration()

	created, err := registry.Register(ctx, tenant, registration, 0)
	if err != nil {
		t.Fatalf("register endpoint: %v", err)
	}
	updated, err := registry.Register(ctx, tenant, webhook.EndpointRegistration{
		ID: registration.ID, URL: "https://example.com/webhooks/history-v2",
		KeyID: "key_2027", SubscriptionVersion: 2,
	}, created.Version)
	if err != nil {
		t.Fatalf("update endpoint: %v", err)
	}
	deactivated, err := registry.SetStatus(ctx, tenant, registration.ID, webhook.EndpointInactive, updated.Version)
	if err != nil {
		t.Fatalf("deactivate endpoint: %v", err)
	}
	reactivated, err := registry.SetStatus(ctx, tenant, registration.ID, webhook.EndpointActive, deactivated.Version)
	if err != nil {
		t.Fatalf("reactivate endpoint: %v", err)
	}
	if reactivated.Version != 4 {
		t.Fatalf("endpoint version = %d, want 4", reactivated.Version)
	}

	var rows int
	if err := adminDB.QueryRowContext(ctx,
		`SELECT count(*) FROM keel_meta.webhook_endpoint_status_history WHERE tenant_id=$1 AND endpoint_id=$2`,
		string(tenant), registration.ID).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 4 {
		t.Fatalf("status history rows = %d, want 4", rows)
	}

	point, err := store.EndpointStatusAt(ctx, webhook.EndpointStatusAtQuery{
		Tenant: tenant, ID: registration.ID, At: updated.UpdatedAt,
	})
	if err != nil {
		t.Fatalf("status at v2 time: %v", err)
	}
	if point.Version != 2 || point.Status != webhook.EndpointActive || point.SubscriptionVersion != 2 {
		t.Fatalf("status at v2 time = %+v, want version 2 active subscription 2", point)
	}

	point, err = store.EndpointStatusAt(ctx, webhook.EndpointStatusAtQuery{
		Tenant: tenant, ID: registration.ID, At: time.Now().UTC().Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("current status: %v", err)
	}
	if point.Version != 4 || point.Status != webhook.EndpointActive || point.SubscriptionVersion != 2 {
		t.Fatalf("current status = %+v, want version 4 active subscription 2", point)
	}

	point, err = store.EndpointStatusAt(ctx, webhook.EndpointStatusAtQuery{
		Tenant: tenant, ID: registration.ID, At: deactivated.UpdatedAt,
	})
	if err != nil {
		t.Fatalf("status at deactivation time: %v", err)
	}
	if point.Version != 3 || point.Status != webhook.EndpointInactive {
		t.Fatalf("status at deactivation time = %+v, want version 3 inactive", point)
	}

	if _, err := store.EndpointStatusAt(ctx, webhook.EndpointStatusAtQuery{
		Tenant: tenant, ID: registration.ID, At: created.UpdatedAt.Add(-time.Second),
	}); !errors.Is(err, webhook.ErrEndpointUnavailable) {
		t.Fatalf("pre-creation query error = %v, want unavailable", err)
	}
	if _, err := store.EndpointStatusAt(ctx, webhook.EndpointStatusAtQuery{
		Tenant: tenant, ID: "endpoint_0123456789abcdef", At: time.Now().UTC(),
	}); !errors.Is(err, webhook.ErrEndpointUnavailable) {
		t.Fatalf("unknown endpoint query error = %v, want unavailable", err)
	}
	if _, err := store.EndpointStatusAt(ctx, webhook.EndpointStatusAtQuery{
		Tenant: tenant, ID: "short", At: time.Now().UTC(),
	}); !errors.Is(err, webhook.ErrInvalidEndpoint) {
		t.Fatalf("invalid endpoint query error = %v, want invalid", err)
	}

	if _, err := adminDB.ExecContext(ctx,
		`UPDATE keel_meta.webhook_endpoint_status_history SET status='active'
		  WHERE tenant_id=$1 AND endpoint_id=$2`,
		string(tenant), registration.ID); err == nil {
		t.Fatal("status history was mutable")
	}
	if _, err := adminDB.ExecContext(ctx,
		`DELETE FROM keel_meta.webhook_endpoint_status_history
		  WHERE tenant_id=$1 AND endpoint_id=$2`,
		string(tenant), registration.ID); err == nil {
		t.Fatal("status history was deletable")
	}
	for _, db := range []*sql.DB{appDB, webhookDB} {
		if _, err := db.ExecContext(ctx,
			`SELECT keel_meta.webhook_endpoint_status_at($1,$2)`,
			registration.ID, time.Now().UTC()); err == nil {
			t.Fatal("status history query executed without the operator capability")
		}
	}
	if _, err := operatorDB.ExecContext(ctx,
		`SELECT count(*) FROM keel_meta.webhook_endpoint_status_history`); err == nil {
		t.Fatal("operator read the status history table directly")
	}
}
