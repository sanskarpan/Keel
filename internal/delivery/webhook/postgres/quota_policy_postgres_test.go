package postgres

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/sanskarpan/keel/internal/delivery/webhook"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

func endpointLimitChange(tenant tenancy.TenantID, limit int, expected int64) webhook.EndpointLimitChange {
	return webhook.EndpointLimitChange{
		Tenant: tenant, ChangeID: "pol_" + strings.ReplaceAll(uuid.NewString(), "-", ""),
		RequestedBy: "operator@example.com", Limit: limit,
		Reason: "adjust the tenant endpoint limit", ExpectedVersion: expected,
	}
}

func TestPostgreSQLTenantEndpointQuotaPolicy(t *testing.T) {
	appDB, webhookDB, operatorDB, adminDB := reconciliationDatabases(t)
	store := newReconciliationStore(t, operatorDB)
	registry := newRegistry(t, appDB)
	tenant := payloadTenant(t)

	create := endpointLimitChange(tenant, 1, 0)
	policy, err := store.SetEndpointLimit(context.Background(), create)
	if err != nil {
		t.Fatal(err)
	}
	if policy.Version != 1 || policy.ActiveEndpointLimit != 1 {
		t.Fatalf("created policy = %+v", policy)
	}
	endpoints := registerQuotaEndpoints(t, registry, tenant, 1)
	blocked := validRegistryRegistration()
	blocked.ID = "ep_" + uuid.NewString()
	if _, err := registry.Register(context.Background(), tenant, blocked, 0); !errors.Is(err, webhook.ErrEndpointQuota) {
		t.Fatalf("second endpoint error = %v, want quota", err)
	}

	raise := endpointLimitChange(tenant, 2, 1)
	policy, err = store.SetEndpointLimit(context.Background(), raise)
	if err != nil || policy.Version != 2 || policy.ActiveEndpointLimit != 2 {
		t.Fatalf("raised policy = %+v err=%v", policy, err)
	}
	if _, err := registry.Register(context.Background(), tenant, blocked, 0); err != nil {
		t.Fatalf("second endpoint after raise: %v", err)
	}

	lower := endpointLimitChange(tenant, 1, 2)
	policy, err = store.SetEndpointLimit(context.Background(), lower)
	if err != nil || policy.Version != 3 || policy.ActiveEndpointLimit != 1 {
		t.Fatalf("lowered policy = %+v err=%v", policy, err)
	}
	third := validRegistryRegistration()
	third.ID = "ep_" + uuid.NewString()
	if _, err := registry.Register(context.Background(), tenant, third, 0); !errors.Is(err, webhook.ErrEndpointQuota) {
		t.Fatalf("third endpoint after lowering = %v, want quota", err)
	}
	if count := activeEndpointCount(t, adminDB, tenant); count != 2 {
		t.Fatalf("lowering changed active endpoints to %d", count)
	}
	first := endpoints[0]
	if _, err := registry.Register(context.Background(), tenant, webhook.EndpointRegistration{
		ID: first.ID, URL: "https://example.com/webhooks/updated", KeyID: "key_2027",
		SubscriptionVersion: 1,
	}, first.Version); err != nil {
		t.Fatalf("over-limit update rejected: %v", err)
	}

	if _, err := store.SetEndpointLimit(context.Background(), endpointLimitChange(tenant, 2, 1)); !errors.Is(err, webhook.ErrEndpointPolicyConflict) {
		t.Fatalf("stale version error = %v, want conflict", err)
	}
	if _, err := store.SetEndpointLimit(context.Background(), lower); !errors.Is(err, webhook.ErrEndpointPolicyConflict) {
		t.Fatalf("duplicate change error = %v, want conflict", err)
	}

	var changes int
	if err := adminDB.QueryRowContext(context.Background(),
		`SELECT count(*) FROM keel_meta.webhook_tenant_policy_history WHERE tenant_id=$1`,
		string(tenant)).Scan(&changes); err != nil {
		t.Fatal(err)
	}
	if changes != 3 {
		t.Fatalf("policy history rows = %d, want 3", changes)
	}
	for _, db := range []*sql.DB{appDB, webhookDB} {
		if _, err := db.ExecContext(context.Background(),
			`SELECT keel_meta.set_webhook_endpoint_limit($1,$2,$3,$4,$5)`,
			create.ChangeID, create.RequestedBy, create.Limit, create.Reason, create.ExpectedVersion); err == nil {
			t.Fatal("policy change executed without the operator capability")
		}
	}
	if _, err := operatorDB.ExecContext(context.Background(),
		`SELECT count(*) FROM keel_meta.webhook_tenant_policies`); err == nil {
		t.Fatal("operator read the policy table directly")
	}
	if _, err := adminDB.ExecContext(context.Background(),
		`UPDATE keel_meta.webhook_tenant_policy_history SET new_limit=99 WHERE tenant_id=$1`,
		string(tenant)); err == nil {
		t.Fatal("policy history was mutable")
	}
}
