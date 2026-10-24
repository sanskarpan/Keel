package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sanskarpan/keel/internal/delivery/webhook"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

func deliveryBatchChange(tenant tenancy.TenantID, limit int, expected int64) webhook.DeliveryBatchChange {
	return webhook.DeliveryBatchChange{
		Tenant: tenant, ChangeID: "pol_" + strings.ReplaceAll(uuid.NewString(), "-", ""),
		RequestedBy: "operator@example.com", Limit: limit,
		Reason: "throttle the tenant delivery batch", ExpectedVersion: expected,
	}
}

func TestPostgreSQLTenantDeliveryBatchPolicy(t *testing.T) {
	appDB, webhookDB, operatorDB, adminDB := reconciliationDatabases(t)
	store := newReconciliationStore(t, operatorDB)
	tenant := payloadTenant(t)

	create := deliveryBatchChange(tenant, 2, 0)
	policy, err := store.SetDeliveryBatchLimit(context.Background(), create)
	if err != nil {
		t.Fatal(err)
	}
	if policy.Version != 1 || policy.BatchLimit != 2 {
		t.Fatalf("created policy = %+v", policy)
	}

	update := deliveryBatchChange(tenant, 4, 1)
	policy, err = store.SetDeliveryBatchLimit(context.Background(), update)
	if err != nil || policy.Version != 2 || policy.BatchLimit != 4 {
		t.Fatalf("updated policy = %+v err=%v", policy, err)
	}

	insertScheduledDelivery(t, adminDB, tenant, "pending", time.Now().UTC().Add(-time.Minute))
	source, err := NewTenantSource(webhookDB)
	if err != nil {
		t.Fatal(err)
	}
	tenants, err := source.DueTenants(context.Background(), 1000)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, entry := range tenants {
		if entry.Tenant == tenant {
			found = true
			if entry.BatchLimit != 4 {
				t.Fatalf("discovered batch limit = %d, want 4", entry.BatchLimit)
			}
		}
	}
	if !found {
		t.Fatal("tenant with due delivery was not discovered")
	}

	duplicate := update
	duplicate.ChangeID = create.ChangeID
	if _, err := store.SetDeliveryBatchLimit(context.Background(), duplicate); !errors.Is(err, webhook.ErrDeliveryPolicyConflict) {
		t.Fatalf("duplicate change error = %v, want conflict", err)
	}
	if _, err := store.SetDeliveryBatchLimit(context.Background(), deliveryBatchChange(tenant, 3, 1)); !errors.Is(err, webhook.ErrDeliveryPolicyConflict) {
		t.Fatalf("stale version error = %v, want conflict", err)
	}
	if _, err := store.SetDeliveryBatchLimit(context.Background(), deliveryBatchChange(tenant, webhook.MaxDeliveryBatchLimit+1, 2)); err == nil {
		t.Fatal("oversized delivery batch limit was accepted")
	}

	var changes int
	if err := adminDB.QueryRowContext(context.Background(),
		`SELECT count(*) FROM keel_meta.webhook_tenant_delivery_policy_history WHERE tenant_id=$1`,
		string(tenant)).Scan(&changes); err != nil {
		t.Fatal(err)
	}
	if changes != 2 {
		t.Fatalf("delivery policy history rows = %d, want 2", changes)
	}
	if _, err := appDB.ExecContext(context.Background(),
		`SELECT keel_meta.set_webhook_delivery_batch_limit($1,$2,$3,$4,$5)`,
		create.ChangeID, create.RequestedBy, create.Limit, create.Reason, create.ExpectedVersion); err == nil {
		t.Fatal("delivery policy change executed without the operator capability")
	}
	if _, err := operatorDB.ExecContext(context.Background(),
		`SELECT count(*) FROM keel_meta.webhook_tenant_delivery_policies`); err == nil {
		t.Fatal("operator read the delivery policy table directly")
	}
	if _, err := adminDB.ExecContext(context.Background(),
		`UPDATE keel_meta.webhook_tenant_delivery_policy_history SET new_limit=9 WHERE tenant_id=$1`,
		string(tenant)); err == nil {
		t.Fatal("delivery policy history was mutable")
	}
}
