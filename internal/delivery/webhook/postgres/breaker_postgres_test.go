package postgres

import (
	"context"
	"database/sql"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sanskarpan/keel/internal/delivery/webhook"
)

func TestBreakerStoreLifecycle(t *testing.T) {
	appDB, webhookDB, admin := registryTestDatabases(t)
	registry := newRegistry(t, appDB)
	store := newStore(t, webhookDB)
	ctx := context.Background()
	tenant := randomTenant(t)
	registration := validRegistryRegistration()
	if _, err := registry.Register(ctx, tenant, registration, 0); err != nil {
		t.Fatalf("Register(endpoint) error = %v", err)
	}
	endpointID := registration.ID

	missing, err := store.Breaker(ctx, tenant, endpointID)
	if err != nil {
		t.Fatalf("Breaker(missing) error = %v", err)
	}
	if missing.Version != 0 || missing.State.Status != webhook.BreakerClosed || missing.State.Failures != 0 {
		t.Fatalf("missing breaker = %+v, want closed version 0", missing)
	}

	saved, err := store.SaveBreaker(ctx, tenant, endpointID, 0, webhook.BreakerState{
		Status: webhook.BreakerClosed, Failures: 4,
	})
	if err != nil {
		t.Fatalf("SaveBreaker(closed) error = %v", err)
	}
	if saved.Version != 1 || saved.State.Status != webhook.BreakerClosed || saved.State.Failures != 4 {
		t.Fatalf("saved closed breaker = %+v", saved)
	}
	if _, err := store.SaveBreaker(ctx, tenant, endpointID, 0, webhook.BreakerState{}); err == nil || !strings.Contains(err.Error(), "version conflict") {
		t.Fatalf("SaveBreaker(stale create) error = %v, want version conflict", err)
	}

	now := time.Now().UTC().Truncate(time.Microsecond)
	opened, err := store.SaveBreaker(ctx, tenant, endpointID, 1, webhook.BreakerState{
		Status: webhook.BreakerOpen, OpenedAt: now, OpenFor: 30 * time.Second,
	})
	if err != nil {
		t.Fatalf("SaveBreaker(open) error = %v", err)
	}
	if opened.Version != 2 || opened.State.Status != webhook.BreakerOpen ||
		opened.State.OpenFor != 30*time.Second || !opened.State.OpenedAt.Equal(now) {
		t.Fatalf("opened breaker = %+v", opened)
	}
	loaded, err := store.Breaker(ctx, tenant, endpointID)
	if err != nil {
		t.Fatalf("Breaker(open) error = %v", err)
	}
	if loaded != opened {
		t.Fatalf("loaded breaker = %+v, want %+v", loaded, opened)
	}
	if !loaded.State.OpenUntil().Equal(now.Add(30 * time.Second)) {
		t.Fatalf("OpenUntil() = %v, want %v", loaded.State.OpenUntil(), now.Add(30*time.Second))
	}

	halfOpen, err := store.SaveBreaker(ctx, tenant, endpointID, 2, webhook.BreakerState{
		Status: webhook.BreakerHalfOpen, OpenedAt: now, OpenFor: time.Minute, Probes: 1,
	})
	if err != nil {
		t.Fatalf("SaveBreaker(half_open) error = %v", err)
	}
	if halfOpen.Version != 3 || halfOpen.State.Probes != 1 {
		t.Fatalf("half-open breaker = %+v", halfOpen)
	}

	closed, err := store.SaveBreaker(ctx, tenant, endpointID, 3, webhook.BreakerState{})
	if err != nil {
		t.Fatalf("SaveBreaker(closed again) error = %v", err)
	}
	if closed.Version != 4 || closed.State.Status != webhook.BreakerClosed || !closed.State.OpenedAt.IsZero() {
		t.Fatalf("reclosed breaker = %+v", closed)
	}

	var count int
	if err := admin.QueryRowContext(ctx,
		`SELECT count(*) FROM keel_meta.webhook_endpoint_breakers WHERE tenant_id=$1`, string(tenant)).Scan(&count); err != nil {
		t.Fatalf("count breakers: %v", err)
	}
	if count != 1 {
		t.Fatalf("breaker rows = %d, want 1", count)
	}
}

func TestBreakerStoreConcurrentSave(t *testing.T) {
	appDB, webhookDB, _ := registryTestDatabases(t)
	registry := newRegistry(t, appDB)
	store := newStore(t, webhookDB)
	ctx := context.Background()
	tenant := randomTenant(t)
	registration := validRegistryRegistration()
	if _, err := registry.Register(ctx, tenant, registration, 0); err != nil {
		t.Fatalf("Register(endpoint) error = %v", err)
	}
	if _, err := store.SaveBreaker(ctx, tenant, registration.ID, 0, webhook.BreakerState{}); err != nil {
		t.Fatalf("SaveBreaker(initial) error = %v", err)
	}

	var waitGroup sync.WaitGroup
	errs := make([]error, 2)
	for index := 0; index < 2; index++ {
		waitGroup.Add(1)
		go func(index int) {
			defer waitGroup.Done()
			_, errs[index] = store.SaveBreaker(ctx, tenant, registration.ID, 1, webhook.BreakerState{
				Status: webhook.BreakerClosed, Failures: index + 1,
			})
		}(index)
	}
	waitGroup.Wait()

	successes := 0
	for _, err := range errs {
		if err == nil {
			successes++
		} else if !strings.Contains(err.Error(), "version conflict") {
			t.Fatalf("concurrent breaker save error = %v, want version conflict", err)
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent breaker saves = %d, want 1", successes)
	}
	loaded, err := store.Breaker(ctx, tenant, registration.ID)
	if err != nil {
		t.Fatalf("Breaker(after concurrency) error = %v", err)
	}
	if loaded.Version != 2 || loaded.State.Failures < 1 || loaded.State.Failures > 2 {
		t.Fatalf("breaker after concurrency = %+v", loaded)
	}
}

func TestBreakerStoreAccessDenied(t *testing.T) {
	appDB, webhookDB, admin := registryTestDatabases(t)
	registry := newRegistry(t, appDB)
	store := newStore(t, webhookDB)
	ctx := context.Background()
	tenant := randomTenant(t)
	registration := validRegistryRegistration()
	if _, err := registry.Register(ctx, tenant, registration, 0); err != nil {
		t.Fatalf("Register(endpoint) error = %v", err)
	}
	if _, err := store.SaveBreaker(ctx, tenant, registration.ID, 0, webhook.BreakerState{}); err != nil {
		t.Fatalf("SaveBreaker(initial) error = %v", err)
	}

	statements := map[string]string{
		"select": `SELECT count(*) FROM keel_meta.webhook_endpoint_breakers`,
		"insert": `INSERT INTO keel_meta.webhook_endpoint_breakers
			(tenant_id,endpoint_id,status) VALUES
			('11111111-1111-1111-1111-111111111111','endpoint_99','closed')`,
		"update": `UPDATE keel_meta.webhook_endpoint_breakers SET failures=failures+1`,
		"delete": `DELETE FROM keel_meta.webhook_endpoint_breakers`,
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

	if _, err := newStore(t, appDB).Breaker(ctx, tenant, registration.ID); err == nil || !strings.Contains(strings.ToLower(err.Error()), "permission denied") {
		t.Fatalf("app role breaker load error = %v, want permission denied", err)
	}
	if _, err := admin.ExecContext(ctx,
		`DELETE FROM keel_meta.webhook_endpoint_breakers WHERE tenant_id=$1`, string(tenant)); err == nil || !strings.Contains(err.Error(), "cannot be deleted") {
		t.Fatalf("admin delete error = %v, want deletion rejection", err)
	}
}

func TestBreakerStoreUnknownEndpoint(t *testing.T) {
	_, webhookDB, _ := registryTestDatabases(t)
	store := newStore(t, webhookDB)
	ctx := context.Background()
	tenant := randomTenant(t)

	missing, err := store.Breaker(ctx, tenant, uuid.NewString())
	if err != nil {
		t.Fatalf("Breaker(unknown) error = %v", err)
	}
	if missing.Version != 0 || missing.State.Status != webhook.BreakerClosed {
		t.Fatalf("unknown breaker = %+v, want closed version 0", missing)
	}

	if _, err := store.SaveBreaker(ctx, tenant, uuid.NewString(), 0, webhook.BreakerState{}); err == nil {
		t.Fatal("SaveBreaker(unknown endpoint) error = nil, want foreign-key rejection")
	}
}
