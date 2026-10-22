package postgres

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/sanskarpan/keel/internal/delivery/webhook"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

func registryTestDatabases(t *testing.T) (*sql.DB, *sql.DB, *sql.DB) {
	t.Helper()
	appDSN, webhookDSN, adminDSN := os.Getenv("KEEL_TEST_DATABASE_URL"), os.Getenv("KEEL_TEST_WEBHOOK_DATABASE_URL"), os.Getenv("KEEL_TEST_ADMIN_DATABASE_URL")
	if appDSN == "" || webhookDSN == "" || adminDSN == "" {
		t.Skip("set KEEL_TEST_DATABASE_URL, KEEL_TEST_WEBHOOK_DATABASE_URL and KEEL_TEST_ADMIN_DATABASE_URL for webhook endpoint integration coverage")
	}
	return webhookTestDB(t, appDSN), webhookTestDB(t, webhookDSN), webhookTestDB(t, adminDSN)
}

func newRegistry(t *testing.T, db *sql.DB) *Registry {
	t.Helper()
	registry, err := NewRegistry(db)
	if err != nil {
		t.Fatal(err)
	}
	return registry
}

func endpointRowCount(t *testing.T, admin *sql.DB, tenant string) int {
	t.Helper()
	var count int
	if err := admin.QueryRowContext(context.Background(),
		`SELECT count(*) FROM keel_meta.webhook_endpoints WHERE tenant_id=$1`, tenant).Scan(&count); err != nil {
		t.Fatalf("count webhook endpoints: %v", err)
	}
	return count
}

func TestRegistryLifecycle(t *testing.T) {
	appDB, webhookDB, admin := registryTestDatabases(t)
	registry := newRegistry(t, appDB)
	store := newStore(t, webhookDB)
	ctx := context.Background()
	tenant := randomTenant(t)
	registration := validRegistryRegistration()

	created, err := registry.Register(ctx, tenant, registration, 0)
	if err != nil {
		t.Fatalf("Register(create) error = %v", err)
	}
	if created.ID != registration.ID || created.URL != registration.URL || created.KeyID != registration.KeyID {
		t.Fatalf("created endpoint = %+v, want %+v", created, registration)
	}
	if created.Version != 1 || created.Status != webhook.EndpointActive || created.SubscriptionVersion != 1 {
		t.Fatalf("created endpoint version/status = %d/%s/%d, want 1/active/1",
			created.Version, created.Status, created.SubscriptionVersion)
	}
	if created.CreatedAt.IsZero() || created.UpdatedAt.Before(created.CreatedAt) {
		t.Fatalf("created endpoint timestamps = %v/%v", created.CreatedAt, created.UpdatedAt)
	}
	if count := endpointRowCount(t, admin, string(tenant)); count != 1 {
		t.Fatalf("endpoint rows = %d, want 1", count)
	}

	if _, err = registry.Register(ctx, tenant, registration, 0); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("Register(duplicate) error = %v, want duplicate rejection", err)
	}
	if _, err = registry.Register(ctx, tenant, registration, 2); err == nil || !strings.Contains(err.Error(), "version conflict") {
		t.Fatalf("Register(stale) error = %v, want version conflict", err)
	}

	updatedRegistration := registration
	updatedRegistration.URL = "https://example.com/webhooks/orders-v2"
	updatedRegistration.KeyID = "key_2027"
	updatedRegistration.SubscriptionVersion = 2
	updated, err := registry.Register(ctx, tenant, updatedRegistration, 1)
	if err != nil {
		t.Fatalf("Register(update) error = %v", err)
	}
	if updated.Version != 2 || updated.SubscriptionVersion != 2 || updated.URL != updatedRegistration.URL || updated.KeyID != updatedRegistration.KeyID {
		t.Fatalf("updated endpoint = %+v", updated)
	}
	if !updated.CreatedAt.Equal(created.CreatedAt) {
		t.Fatalf("creation time changed from %v to %v", created.CreatedAt, updated.CreatedAt)
	}

	target, err := store.Endpoint(ctx, tenant, registration.ID, 2)
	if err != nil {
		t.Fatalf("Endpoint(active) error = %v", err)
	}
	if target.URL != updatedRegistration.URL || target.KeyID != updatedRegistration.KeyID || target.SubscriptionVersion != 2 {
		t.Fatalf("resolved endpoint = %+v, want %+v", target, updatedRegistration)
	}
	if target.Status != webhook.EndpointActive {
		t.Fatalf("resolved endpoint status = %s, want active", target.Status)
	}

	for name, lookup := range map[string]struct {
		tenant              string
		endpointID          string
		subscriptionVersion uint32
	}{
		"stale revision": {tenant: string(tenant), endpointID: registration.ID, subscriptionVersion: 1},
		"unknown endpoint": {
			tenant: string(tenant), endpointID: uuid.NewString(), subscriptionVersion: 2,
		},
		"other tenant": {
			tenant: string(randomTenant(t)), endpointID: registration.ID, subscriptionVersion: 2,
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := store.Endpoint(ctx, tenancyTenant(t, lookup.tenant), lookup.endpointID, lookup.subscriptionVersion); !errors.Is(err, webhook.ErrEndpointUnavailable) {
				t.Fatalf("Endpoint() error = %v, want ErrEndpointUnavailable", err)
			}
		})
	}

	deactivated, err := registry.SetStatus(ctx, tenant, registration.ID, webhook.EndpointInactive, 2)
	if err != nil {
		t.Fatalf("SetStatus(inactive) error = %v", err)
	}
	if deactivated.Version != 3 || deactivated.Status != webhook.EndpointInactive {
		t.Fatalf("deactivated endpoint = %+v", deactivated)
	}
	if _, err := store.Endpoint(ctx, tenant, registration.ID, 2); !errors.Is(err, webhook.ErrEndpointUnavailable) {
		t.Fatalf("Endpoint(inactive) error = %v, want ErrEndpointUnavailable", err)
	}
	if _, err := registry.SetStatus(ctx, tenant, registration.ID, webhook.EndpointActive, 2); err == nil || !strings.Contains(err.Error(), "version conflict") {
		t.Fatalf("SetStatus(stale) error = %v, want version conflict", err)
	}

	reactivated, err := registry.SetStatus(ctx, tenant, registration.ID, webhook.EndpointActive, 3)
	if err != nil {
		t.Fatalf("SetStatus(active) error = %v", err)
	}
	if reactivated.Version != 4 || reactivated.Status != webhook.EndpointActive {
		t.Fatalf("reactivated endpoint = %+v", reactivated)
	}
	if _, err := store.Endpoint(ctx, tenant, registration.ID, 2); err != nil {
		t.Fatalf("Endpoint(reactivated) error = %v", err)
	}
	if count := endpointRowCount(t, admin, string(tenant)); count != 1 {
		t.Fatalf("endpoint rows after lifecycle = %d, want 1", count)
	}
}

func TestRegistryConcurrentUpdate(t *testing.T) {
	appDB, _, _ := registryTestDatabases(t)
	registry := newRegistry(t, appDB)
	ctx := context.Background()
	tenant := randomTenant(t)
	registration := validRegistryRegistration()
	if _, err := registry.Register(ctx, tenant, registration, 0); err != nil {
		t.Fatalf("Register(create) error = %v", err)
	}

	var waitGroup sync.WaitGroup
	errs := make([]error, 2)
	for index := 0; index < 2; index++ {
		waitGroup.Add(1)
		go func(index int) {
			defer waitGroup.Done()
			candidate := registration
			candidate.URL = registration.URL + "?writer=" + string(rune('a'+index))
			_, errs[index] = registry.Register(ctx, tenant, candidate, 1)
		}(index)
	}
	waitGroup.Wait()

	successes := 0
	for _, err := range errs {
		if err == nil {
			successes++
		} else if !strings.Contains(err.Error(), "version conflict") {
			t.Fatalf("concurrent update error = %v, want version conflict", err)
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent update successes = %d, want 1", successes)
	}
	stored, err := registry.Register(ctx, tenant, registration, 2)
	if err != nil {
		t.Fatalf("Register(after concurrency) error = %v", err)
	}
	if stored.Version != 3 {
		t.Fatalf("endpoint version = %d, want 3", stored.Version)
	}
}

func TestRegistryDirectAccessDenied(t *testing.T) {
	appDB, webhookDB, admin := registryTestDatabases(t)
	registry := newRegistry(t, appDB)
	ctx := context.Background()
	tenant := randomTenant(t)
	registration := validRegistryRegistration()
	if _, err := registry.Register(ctx, tenant, registration, 0); err != nil {
		t.Fatalf("Register(create) error = %v", err)
	}

	statements := map[string]string{
		"select": `SELECT count(*) FROM keel_meta.webhook_endpoints`,
		"insert": `INSERT INTO keel_meta.webhook_endpoints
			(tenant_id,endpoint_id,url,key_id,subscription_version,status)
			VALUES ('11111111-1111-1111-1111-111111111111','endpoint_99',
			        'https://example.com/hook','key_2026',1,'active')`,
		"update": `UPDATE keel_meta.webhook_endpoints SET status='inactive'`,
		"delete": `DELETE FROM keel_meta.webhook_endpoints`,
	}
	for role, db := range map[string]*sql.DB{"app": appDB, "webhook": webhookDB} {
		for name, statement := range statements {
			t.Run(role+" "+name, func(t *testing.T) {
				if _, err := db.ExecContext(ctx, statement); err == nil || !strings.Contains(strings.ToLower(err.Error()), "permission denied") {
					t.Fatalf("direct %s error = %v, want permission denied", name, err)
				}
			})
		}
	}

	if count := endpointRowCount(t, admin, string(tenant)); count != 1 {
		t.Fatalf("endpoint rows = %d, want 1", count)
	}
	if _, err := admin.ExecContext(ctx, `DELETE FROM keel_meta.webhook_endpoints WHERE tenant_id=$1`, string(tenant)); err == nil || !strings.Contains(err.Error(), "cannot be deleted") {
		t.Fatalf("admin delete error = %v, want deletion rejection", err)
	}
}

func TestRegistryCapabilityBoundaries(t *testing.T) {
	appDB, webhookDB, _ := registryTestDatabases(t)
	ctx := context.Background()
	tenant := randomTenant(t)
	registration := validRegistryRegistration()

	if _, err := newRegistry(t, webhookDB).Register(ctx, tenant, registration, 0); err == nil || !strings.Contains(strings.ToLower(err.Error()), "permission denied") {
		t.Fatalf("webhook role registration error = %v, want permission denied", err)
	}
	if _, err := newStore(t, appDB).Endpoint(ctx, tenant, registration.ID, 1); err == nil || !strings.Contains(strings.ToLower(err.Error()), "permission denied") {
		t.Fatalf("app role resolution error = %v, want permission denied", err)
	}
}

func tenancyTenant(t *testing.T, value string) (tenant tenancy.TenantID) {
	t.Helper()
	parsed, err := tenancy.ParseTenantID(value)
	if err != nil {
		t.Fatalf("parse tenant %q: %v", value, err)
	}
	return parsed
}
