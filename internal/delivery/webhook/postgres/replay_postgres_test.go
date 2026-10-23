package postgres

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sanskarpan/keel/internal/delivery/webhook"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

func replayStoreDatabases(t *testing.T) (*sql.DB, *sql.DB, *sql.DB) {
	t.Helper()
	webhookDSN := os.Getenv("KEEL_TEST_WEBHOOK_DATABASE_URL")
	operatorDSN := os.Getenv("KEEL_TEST_OPERATOR_DATABASE_URL")
	adminDSN := os.Getenv("KEEL_TEST_ADMIN_DATABASE_URL")
	if webhookDSN == "" || operatorDSN == "" || adminDSN == "" {
		t.Skip("set KEEL_TEST_WEBHOOK_DATABASE_URL, KEEL_TEST_OPERATOR_DATABASE_URL and KEEL_TEST_ADMIN_DATABASE_URL for webhook replay integration coverage")
	}
	return webhookTestDB(t, webhookDSN), webhookTestDB(t, operatorDSN), webhookTestDB(t, adminDSN)
}

func replayRowCount(t *testing.T, admin *sql.DB, tenant tenancy.TenantID) int {
	t.Helper()
	var count int
	if err := admin.QueryRowContext(context.Background(),
		`SELECT count(*) FROM keel_meta.webhook_replays WHERE tenant_id=$1`,
		string(tenant)).Scan(&count); err != nil {
		t.Fatalf("count webhook replays: %v", err)
	}
	return count
}

func replayRequest(tenant tenancy.TenantID, deliveryID string) webhook.ReplayRequest {
	return webhook.ReplayRequest{
		Tenant:      tenant,
		ReplayID:    "replay_" + strings.ReplaceAll(uuid.NewString(), "-", ""),
		DeliveryID:  deliveryID,
		RequestedBy: "operator@example.com",
		Reason:      "receiver asked for a replay after acknowledging a timeout",
	}
}

func TestReplayStoreRecordsIdempotently(t *testing.T) {
	webhookDB, operatorDB, adminDB := replayStoreDatabases(t)
	deliveryStore := newStore(t, webhookDB)
	replayStore := newStore(t, operatorDB)
	ctx := context.Background()
	identity := randomIdentity(t)
	claim, err := deliveryStore.Ensure(ctx, identity)
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	otherIdentity := randomIdentity(t)
	otherIdentity.Tenant = identity.Tenant
	otherClaim, err := deliveryStore.Ensure(ctx, otherIdentity)
	if err != nil {
		t.Fatalf("Ensure(other): %v", err)
	}

	request := replayRequest(identity.Tenant, claim.Delivery.ID)
	before := time.Now().Add(-time.Second)
	record, err := replayStore.RecordReplay(ctx, request)
	if err != nil {
		t.Fatalf("RecordReplay: %v", err)
	}
	after := time.Now().Add(time.Second)
	if !record.Created {
		t.Fatal("expected the first replay request to create a record")
	}
	if record.ReplayID != request.ReplayID || record.DeliveryID != request.DeliveryID ||
		record.RequestedBy != request.RequestedBy || record.Reason != request.Reason {
		t.Fatalf("record = %+v, want %+v", record, request)
	}
	if record.RequestedAt.Location() != time.UTC {
		t.Fatalf("requested at location = %v, want UTC", record.RequestedAt.Location())
	}
	if record.RequestedAt.Before(before) || record.RequestedAt.After(after) {
		t.Fatalf("requested at %v is outside %v..%v", record.RequestedAt, before, after)
	}

	repeated, err := replayStore.RecordReplay(ctx, request)
	if err != nil {
		t.Fatalf("RecordReplay(repeat): %v", err)
	}
	if repeated.Created {
		t.Fatal("expected the repeated replay request to be idempotent")
	}
	if repeated.ReplayID != record.ReplayID || repeated.DeliveryID != record.DeliveryID ||
		repeated.RequestedBy != record.RequestedBy || repeated.Reason != record.Reason ||
		!repeated.RequestedAt.Equal(record.RequestedAt) {
		t.Fatalf("repeated record = %+v, want %+v", repeated, record)
	}
	if count := replayRowCount(t, adminDB, identity.Tenant); count != 1 {
		t.Fatalf("replay rows = %d, want 1", count)
	}

	for name, change := range map[string]func(*webhook.ReplayRequest){
		"different reason":   func(r *webhook.ReplayRequest) { r.Reason = "a different justification" },
		"different actor":    func(r *webhook.ReplayRequest) { r.RequestedBy = "other@example.com" },
		"different delivery": func(r *webhook.ReplayRequest) { r.DeliveryID = otherClaim.Delivery.ID },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := request
			change(&candidate)
			if _, err := replayStore.RecordReplay(ctx, candidate); !errors.Is(err, webhook.ErrReplayConflict) {
				t.Fatalf("RecordReplay() error = %v, want ErrReplayConflict", err)
			}
		})
	}

	secondReplay := replayRequest(identity.Tenant, claim.Delivery.ID)
	if _, err := replayStore.RecordReplay(ctx, secondReplay); !errors.Is(err, webhook.ErrReplayConflict) {
		t.Fatalf("RecordReplay(second replay) error = %v, want ErrReplayConflict", err)
	}
	if count := replayRowCount(t, adminDB, identity.Tenant); count != 1 {
		t.Fatalf("replay rows after conflicts = %d, want 1", count)
	}

	recorded, err := replayStore.ReplayRecorded(ctx, identity.Tenant, claim.Delivery.ID)
	if err != nil {
		t.Fatalf("ReplayRecorded(recorded): %v", err)
	}
	if !recorded {
		t.Fatal("expected the delivery to report a replay record")
	}
	recorded, err = replayStore.ReplayRecorded(ctx, identity.Tenant, otherClaim.Delivery.ID)
	if err != nil {
		t.Fatalf("ReplayRecorded(other): %v", err)
	}
	if recorded {
		t.Fatal("expected an unrelated delivery to report no replay record")
	}
	recorded, err = replayStore.ReplayRecorded(ctx, identity.Tenant, uuid.NewString())
	if err != nil {
		t.Fatalf("ReplayRecorded(unknown): %v", err)
	}
	if recorded {
		t.Fatal("expected an unknown delivery to report no replay record")
	}
}

func TestReplayStoreScopesReplayToTenant(t *testing.T) {
	webhookDB, operatorDB, adminDB := replayStoreDatabases(t)
	deliveryStore := newStore(t, webhookDB)
	replayStore := newStore(t, operatorDB)
	ctx := context.Background()
	identity := randomIdentity(t)
	claim, err := deliveryStore.Ensure(ctx, identity)
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	otherTenant := randomTenant(t)

	request := replayRequest(otherTenant, claim.Delivery.ID)
	if _, err := replayStore.RecordReplay(ctx, request); err == nil {
		t.Fatal("expected another tenant to be unable to replay the delivery")
	}
	if count := replayRowCount(t, adminDB, otherTenant); count != 0 {
		t.Fatalf("other tenant replay rows = %d, want 0", count)
	}
	recorded, err := replayStore.ReplayRecorded(ctx, otherTenant, claim.Delivery.ID)
	if err != nil {
		t.Fatalf("ReplayRecorded(other tenant): %v", err)
	}
	if recorded {
		t.Fatal("expected another tenant to see no replay record")
	}
}

func TestReplayStoreRejectsMutation(t *testing.T) {
	webhookDB, operatorDB, adminDB := replayStoreDatabases(t)
	deliveryStore := newStore(t, webhookDB)
	replayStore := newStore(t, operatorDB)
	ctx := context.Background()
	identity := randomIdentity(t)
	claim, err := deliveryStore.Ensure(ctx, identity)
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	request := replayRequest(identity.Tenant, claim.Delivery.ID)
	if _, err := replayStore.RecordReplay(ctx, request); err != nil {
		t.Fatalf("RecordReplay: %v", err)
	}

	if _, err := adminDB.ExecContext(ctx,
		`UPDATE keel_meta.webhook_replays SET reason='changed' WHERE tenant_id=$1`,
		string(identity.Tenant)); err == nil || !strings.Contains(err.Error(), "immutable") {
		t.Fatalf("admin update error = %v, want immutable rejection", err)
	}
	if _, err := adminDB.ExecContext(ctx,
		`DELETE FROM keel_meta.webhook_replays WHERE tenant_id=$1`,
		string(identity.Tenant)); err == nil || !strings.Contains(err.Error(), "immutable") {
		t.Fatalf("admin delete error = %v, want immutable rejection", err)
	}
	if count := replayRowCount(t, adminDB, identity.Tenant); count != 1 {
		t.Fatalf("replay rows after mutation attempts = %d, want 1", count)
	}
}

func TestReplayStoreRequiresOperatorCapability(t *testing.T) {
	webhookDB, _, _ := replayStoreDatabases(t)
	appDSN := os.Getenv("KEEL_TEST_DATABASE_URL")
	if appDSN == "" {
		t.Skip("set KEEL_TEST_DATABASE_URL for the webhook replay capability denial case")
	}
	appDB := webhookTestDB(t, appDSN)
	request := replayRequest(randomTenant(t), uuid.NewString())

	for role, db := range map[string]*sql.DB{"app": appDB, "webhook": webhookDB} {
		t.Run(role, func(t *testing.T) {
			ctx := context.Background()
			tx, err := db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback() }()
			if _, err := tx.ExecContext(ctx,
				"SELECT set_config('keel.tenant_id', $1, true)", string(request.Tenant)); err != nil {
				t.Fatal(err)
			}
			var replayID, deliveryID, requestedBy, reason string
			var requestedAt time.Time
			var created bool
			err = tx.QueryRowContext(ctx,
				`SELECT r_replay_id,r_delivery_id,r_requested_by,r_reason,r_requested_at,r_created
				   FROM keel_meta.record_webhook_replay($1,$2,$3,$4)`,
				request.ReplayID, request.DeliveryID, request.RequestedBy, request.Reason).
				Scan(&replayID, &deliveryID, &requestedBy, &reason, &requestedAt, &created)
			if err == nil {
				t.Fatalf("expected the %s role to be denied the replay capability", role)
			}
		})
	}
}
