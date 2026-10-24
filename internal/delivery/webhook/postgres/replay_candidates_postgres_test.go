package postgres

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sanskarpan/keel/internal/delivery/webhook"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

func seedTerminalDelivery(t *testing.T, adminDB *sql.DB, tenant tenancy.TenantID, endpointID string, version int, state string) string {
	t.Helper()
	deliveryID := "whd_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := adminDB.ExecContext(context.Background(),
		`INSERT INTO keel_meta.webhook_deliveries
		 (tenant_id,event_id,endpoint_id,subscription_version,delivery_id)
		 VALUES ($1,$2,$3,$4,$5)`,
		string(tenant), uuid.NewString(), endpointID, version, deliveryID); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if _, err := adminDB.ExecContext(context.Background(),
		`UPDATE keel_meta.webhook_delivery_state
		    SET state='in_flight',next_attempt_at=NULL,lease_expires_at=$3,lease_epoch=1,
		        attempts=1,first_attempt_at=$4
		  WHERE tenant_id=$1 AND delivery_id=$2`,
		string(tenant), deliveryID, now.Add(time.Minute), now); err != nil {
		t.Fatal(err)
	}
	if _, err := adminDB.ExecContext(context.Background(),
		`UPDATE keel_meta.webhook_delivery_state
		    SET state=$3,lease_expires_at=NULL,finished_at=clock_timestamp()
		  WHERE tenant_id=$1 AND delivery_id=$2`,
		string(tenant), deliveryID, state); err != nil {
		t.Fatal(err)
	}
	return deliveryID
}

func TestPostgreSQLReplayCandidates(t *testing.T) {
	appDB, webhookDB, operatorDB, adminDB := reconciliationDatabases(t)
	store := newReconciliationStore(t, operatorDB)
	registry := newRegistry(t, appDB)
	tenant := payloadTenant(t)
	endpoint := registerFanoutEndpoint(t, registry, tenant, 1)
	failedID := seedTerminalDelivery(t, adminDB, tenant, endpoint.ID, 1, "failed")
	exhaustedID := seedTerminalDelivery(t, adminDB, tenant, endpoint.ID, 1, "exhausted")

	candidates, err := store.ReplayCandidates(context.Background(), tenant, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 2 {
		t.Fatalf("candidates = %d, want 2", len(candidates))
	}
	byID := make(map[string]ReplayCandidateRecord, len(candidates))
	for _, candidate := range candidates {
		byID[candidate.Delivery.ID] = candidate
	}
	for _, deliveryID := range []string{failedID, exhaustedID} {
		candidate, ok := byID[deliveryID]
		if !ok {
			t.Fatalf("missing candidate %s", deliveryID)
		}
		if candidate.Attempts != 1 || candidate.Replayed ||
			candidate.EndpointStatus != webhook.EndpointActive || candidate.KeyID != endpoint.KeyID {
			t.Fatalf("candidate %s = %+v", deliveryID, candidate)
		}
	}
	if byID[failedID].State != webhook.StateFailed || byID[exhaustedID].State != webhook.StateExhausted {
		t.Fatalf("candidate states = %+v", byID)
	}

	if _, err := store.RecordReplay(context.Background(), webhook.ReplayRequest{
		Tenant: tenant, ReplayID: "replay_" + strings.ReplaceAll(uuid.NewString(), "-", ""),
		DeliveryID: failedID, RequestedBy: "operator@example.com",
		Reason: "receiver requested a retry",
	}); err != nil {
		t.Fatal(err)
	}
	candidates, err = store.ReplayCandidates(context.Background(), tenant, 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range candidates {
		if candidate.Delivery.ID == failedID && !candidate.Replayed {
			t.Fatal("replayed candidate was not flagged")
		}
	}

	if _, err := registry.SetStatus(context.Background(), tenant, endpoint.ID, webhook.EndpointInactive, endpoint.Version); err != nil {
		t.Fatal(err)
	}
	candidates, err = store.ReplayCandidates(context.Background(), tenant, 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range candidates {
		if candidate.EndpointStatus != webhook.EndpointInactive {
			t.Fatalf("inactive endpoint candidate status = %s", candidate.EndpointStatus)
		}
	}

	for _, db := range []*sql.DB{appDB, webhookDB} {
		if _, err := db.ExecContext(context.Background(),
			`SELECT keel_meta.list_webhook_replay_candidates(10)`); err == nil {
			t.Fatal("candidate list executed without the operator capability")
		}
	}
	if _, err := store.ReplayCandidates(context.Background(), tenant, 0); !errors.Is(err, webhook.ErrInvalidReplay) {
		t.Fatalf("zero limit error = %v", err)
	}
	if _, err := store.ReplayCandidates(context.Background(), tenant, 5001); !errors.Is(err, webhook.ErrInvalidReplay) {
		t.Fatalf("large limit error = %v", err)
	}
}
