package postgres

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/sanskarpan/keel/internal/delivery/webhook"
	webhookpostgres "github.com/sanskarpan/keel/internal/delivery/webhook/postgres"
)

func TestPostgreSQLCreateFansOutToActiveEndpoints(t *testing.T) {
	db, tenant, repo := repositoryTestDB(t)
	adminDSN := os.Getenv("KEEL_TEST_ADMIN_DATABASE_URL")
	if adminDSN == "" {
		t.Skip("set KEEL_TEST_ADMIN_DATABASE_URL to verify webhook fanout")
	}
	admin := integrationDB(t, adminDSN, 4)
	registry, err := webhookpostgres.NewRegistry(db)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := registry.Register(context.Background(), tenant, webhookRegistration(), 0); err != nil {
			t.Fatalf("register endpoint: %v", err)
		}
	}

	result, err := repo.Create(context.Background(), tenant,
		testCreate("fanout-reference-"+nextUUID()), testMetadata(string(tenant), nextUUID()),
		"fanout-key-"+nextUUID(), "principal:requester-1")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	var delivered int
	if err := admin.QueryRowContext(context.Background(),
		`SELECT count(*) FROM keel_meta.webhook_deliveries d
		   JOIN keel_meta.event_outbox o ON o.tenant_id=d.tenant_id AND o.event_id=d.event_id::uuid
		  WHERE d.tenant_id=$1 AND o.aggregate_id=$2`,
		string(tenant), result.Snapshot.OrderID).Scan(&delivered); err != nil {
		t.Fatalf("read fanout deliveries: %v", err)
	}
	if delivered != 2 {
		t.Fatalf("create fanned out %d deliveries, want 2", delivered)
	}
}

func webhookRegistration() webhook.EndpointRegistration {
	return webhook.EndpointRegistration{
		ID:                  "ep_" + strings.ReplaceAll(uuid.NewString(), "-", ""),
		URL:                 "https://example.com/hooks/" + uuid.NewString(),
		KeyID:               "key_" + strings.ReplaceAll(uuid.NewString(), "-", ""),
		SubscriptionVersion: 1,
	}
}
