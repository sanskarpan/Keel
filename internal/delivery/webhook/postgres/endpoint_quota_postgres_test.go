package postgres

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/sanskarpan/keel/internal/delivery/webhook"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

func activeEndpointCount(t *testing.T, adminDB *sql.DB, tenant tenancy.TenantID) int {
	t.Helper()
	var count int
	if err := adminDB.QueryRowContext(context.Background(),
		`SELECT count(*) FROM keel_meta.webhook_endpoints WHERE tenant_id=$1 AND status='active'`,
		string(tenant)).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func registerQuotaEndpoints(t *testing.T, registry *Registry, tenant tenancy.TenantID, count int) []webhook.Endpoint {
	t.Helper()
	endpoints := make([]webhook.Endpoint, 0, count)
	for range count {
		registration := validRegistryRegistration()
		registration.ID = "ep_" + uuid.NewString()
		endpoint, err := registry.Register(context.Background(), tenant, registration, 0)
		if err != nil {
			t.Fatalf("register endpoint %d: %v", len(endpoints)+1, err)
		}
		endpoints = append(endpoints, endpoint)
	}
	return endpoints
}

func TestPostgreSQLWebhookEndpointQuota(t *testing.T) {
	appDB, _, adminDB := registryTestDatabases(t)
	registry := newRegistry(t, appDB)
	tenant := randomTenant(t)
	endpoints := registerQuotaEndpoints(t, registry, tenant, webhook.MaxActiveEndpointsPerTenant)

	registration := validRegistryRegistration()
	registration.ID = "ep_" + uuid.NewString()
	if _, err := registry.Register(context.Background(), tenant, registration, 0); !errors.Is(err, webhook.ErrEndpointQuota) {
		t.Fatalf("over-quota create error = %v, want endpoint quota", err)
	}
	if count := activeEndpointCount(t, adminDB, tenant); count != webhook.MaxActiveEndpointsPerTenant {
		t.Fatalf("active endpoints = %d, want %d", count, webhook.MaxActiveEndpointsPerTenant)
	}

	first := endpoints[0]
	updated, err := registry.Register(context.Background(), tenant, webhook.EndpointRegistration{
		ID:                  first.ID,
		URL:                 "https://example.com/webhooks/updated",
		KeyID:               "key_2027",
		SubscriptionVersion: 2,
	}, first.Version)
	if err != nil {
		t.Fatalf("over-quota update: %v", err)
	}
	if updated.Version != first.Version+1 {
		t.Fatalf("updated version = %d, want %d", updated.Version, first.Version+1)
	}

	deactivated, err := registry.SetStatus(context.Background(), tenant, first.ID, webhook.EndpointInactive, updated.Version)
	if err != nil {
		t.Fatalf("deactivate at quota: %v", err)
	}
	replacement := validRegistryRegistration()
	replacement.ID = "ep_" + uuid.NewString()
	if _, err := registry.Register(context.Background(), tenant, replacement, 0); err != nil {
		t.Fatalf("create after deactivation: %v", err)
	}
	if _, err := registry.SetStatus(context.Background(), tenant, first.ID, webhook.EndpointActive, deactivated.Version); !errors.Is(err, webhook.ErrEndpointQuota) {
		t.Fatalf("over-quota reactivation error = %v, want endpoint quota", err)
	}

	second := endpoints[1]
	if _, err := registry.SetStatus(context.Background(), tenant, second.ID, webhook.EndpointInactive, second.Version); err != nil {
		t.Fatalf("second deactivation: %v", err)
	}
	if _, err := registry.SetStatus(context.Background(), tenant, first.ID, webhook.EndpointActive, deactivated.Version); err != nil {
		t.Fatalf("reactivation after slot freed: %v", err)
	}

	other := randomTenant(t)
	otherRegistration := validRegistryRegistration()
	otherRegistration.ID = "ep_" + uuid.NewString()
	if _, err := registry.Register(context.Background(), other, otherRegistration, 0); err != nil {
		t.Fatalf("other tenant registration: %v", err)
	}
}

func TestPostgreSQLWebhookEndpointQuotaConcurrentCreate(t *testing.T) {
	appDB, _, adminDB := registryTestDatabases(t)
	registry := newRegistry(t, appDB)
	tenant := randomTenant(t)
	registerQuotaEndpoints(t, registry, tenant, webhook.MaxActiveEndpointsPerTenant-1)

	var wait sync.WaitGroup
	results := make([]error, 2)
	for i := range results {
		wait.Add(1)
		go func(i int) {
			defer wait.Done()
			registration := validRegistryRegistration()
			registration.ID = "ep_" + uuid.NewString()
			_, results[i] = registry.Register(context.Background(), tenant, registration, 0)
		}(i)
	}
	wait.Wait()
	successes, quota := 0, 0
	for _, err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, webhook.ErrEndpointQuota):
			quota++
		default:
			t.Fatalf("unexpected concurrent registration error: %v", err)
		}
	}
	if successes != 1 || quota != 1 {
		t.Fatalf("concurrent results successes=%d quota=%d, want 1/1", successes, quota)
	}
	if count := activeEndpointCount(t, adminDB, tenant); count != webhook.MaxActiveEndpointsPerTenant {
		t.Fatalf("active endpoints = %d, want %d", count, webhook.MaxActiveEndpointsPerTenant)
	}
}
