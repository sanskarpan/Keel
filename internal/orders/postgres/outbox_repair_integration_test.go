package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/sanskarpan/keel/internal/orders"
	"github.com/sanskarpan/keel/internal/orders/outbox"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

type integrationRepairAuthorizer struct{ allow bool }

func (a integrationRepairAuthorizer) CanInspectOutbox(context.Context, outbox.RepairIdentity, string) (bool, error) {
	return a.allow, nil
}

func (a integrationRepairAuthorizer) CanRepairOutbox(context.Context, outbox.RepairIdentity, string, string) (bool, error) {
	return a.allow, nil
}

func TestPostgreSQLOutboxRepairIsTenantScopedAuditedAndOrdered(t *testing.T) {
	_, tenant, appRepo := repositoryTestDB(t)
	adminDSN := os.Getenv("KEEL_TEST_ADMIN_DATABASE_URL")
	workerDSN := os.Getenv("KEEL_TEST_WORKER_DATABASE_URL")
	operatorDSN := os.Getenv("KEEL_TEST_OPERATOR_DATABASE_URL")
	if adminDSN == "" || workerDSN == "" || operatorDSN == "" {
		t.Skip("set admin, worker, and operator database URLs for outbox repair integration coverage")
	}
	adminDB := integrationDB(t, adminDSN, 3)
	workerDB := integrationDB(t, workerDSN, 3)
	operatorDB := integrationDB(t, operatorDSN, 3)
	workerRepo, err := NewRepository(workerDB)
	if err != nil {
		t.Fatal(err)
	}
	operatorRepo, err := NewRepository(operatorDB)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	created, err := appRepo.Create(ctx, tenant, testCreate("outbox-repair-"+nextUUID()), testMetadata(string(tenant), nextUUID()), "outbox-repair-create-0001", "principal:requester-1")
	if err != nil {
		t.Fatal(err)
	}
	meta := testMetadata(string(tenant), created.Snapshot.OrderID)
	meta.ActorRef = "principal:requester-1"
	if _, err := appRepo.Submit(ctx, tenant, created.Snapshot.OrderID, 1, testSubmit(), meta, "outbox-repair-submit-0001", "principal:requester-1"); err != nil {
		t.Fatal(err)
	}
	var events []orders.Event
	events, err = appRepo.Events(ctx, tenant, created.Snapshot.OrderID)
	if err != nil || len(events) != 2 {
		t.Fatalf("canonical events=%d err=%v", len(events), err)
	}
	target := events[0]
	var canonicalEnvelope []byte
	if err := adminDB.QueryRowContext(ctx, `SELECT safe_envelope FROM keel_meta.event_outbox WHERE tenant_id=$1 AND event_id=$2`, string(tenant), target.Metadata.EventID).Scan(&canonicalEnvelope); err != nil {
		t.Fatal(err)
	}
	if _, err := adminDB.ExecContext(ctx, `UPDATE keel_meta.event_outbox SET safe_envelope='{}'::jsonb
		WHERE tenant_id=$1 AND event_id=$2`, string(tenant), target.Metadata.EventID); err != nil {
		t.Fatal(err)
	}
	if _, err := adminDB.ExecContext(ctx, `UPDATE keel_meta.outbox_delivery SET attempt_count=3
		WHERE tenant_id=$1 AND event_id=$2`, string(tenant), target.Metadata.EventID); err != nil {
		t.Fatal(err)
	}
	publisher, err := outbox.NewPublisher(workerRepo, &recordingBroker{}, outbox.Config{LeaseDuration: 5 * time.Second, PublishTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	blocked, err := publisher.RunOnce(ctx, string(tenant), "repair-test-worker")
	if !errors.Is(err, outbox.ErrPoisonEnvelope) || !blocked.Blocked {
		t.Fatalf("poison block result=%+v err=%v", blocked, err)
	}

	service, err := outbox.NewRepairService(operatorRepo, integrationRepairAuthorizer{allow: true})
	if err != nil {
		t.Fatal(err)
	}
	identity := outbox.RepairIdentity{TenantID: tenant, ActorRef: "principal:operator-1", RequestID: nextUUID()}
	operatorCtx := outbox.WithRepairIdentity(ctx, identity)
	blockedEvents, err := service.ListBlocked(operatorCtx, created.Snapshot.OrderID)
	if err != nil || len(blockedEvents) != 1 || blockedEvents[0].EventID != target.Metadata.EventID ||
		blockedEvents[0].Version != 1 || blockedEvents[0].ErrorCode != "outbox_corrupt" || blockedEvents[0].AttemptCount != 3 {
		t.Fatalf("safe blocked diagnostics=%+v err=%v", blockedEvents, err)
	}

	wrongTenant := mustTenant(t, nextUUID())
	wrongTenantCtx := outbox.WithRepairIdentity(ctx, outbox.RepairIdentity{TenantID: wrongTenant, ActorRef: identity.ActorRef, RequestID: nextUUID()})
	wrongTenantList, err := service.ListBlocked(wrongTenantCtx, created.Snapshot.OrderID)
	if err != nil || len(wrongTenantList) != 0 {
		t.Fatalf("cross-tenant diagnostics=%+v err=%v", wrongTenantList, err)
	}
	wrongTenantRequest := repairRequest(blockedEvents[0])
	if err := service.RepairBlocked(wrongTenantCtx, created.Snapshot.OrderID, wrongTenantRequest); !errors.Is(err, outbox.ErrRepairNotFound) {
		t.Fatalf("cross-tenant repair error=%v", err)
	}

	stale := repairRequest(blockedEvents[0])
	stale.ExpectedVersion++
	if err := service.RepairBlocked(operatorCtx, created.Snapshot.OrderID, stale); !errors.Is(err, outbox.ErrRepairStale) {
		t.Fatalf("stale repair error=%v", err)
	}
	repair := repairRequest(blockedEvents[0])
	if err := service.RepairBlocked(operatorCtx, created.Snapshot.OrderID, repair); !errors.Is(err, ErrCorruptState) {
		t.Fatalf("repair accepted an envelope that does not match its immutable source: %v", err)
	}
	var auditCount int
	if err := adminDB.QueryRowContext(ctx, `SELECT count(*) FROM keel_meta.outbox_repair_audit WHERE tenant_id=$1 AND aggregate_id=$2`, string(tenant), created.Snapshot.OrderID).Scan(&auditCount); err != nil || auditCount != 0 {
		t.Fatalf("stale request wrote %d audit rows, err=%v", auditCount, err)
	}
	if err := tenancy.WithTenantTx(ctx, operatorDB, tenant, nil, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE keel_meta.outbox_delivery SET delivery_state='pending'
			WHERE tenant_id=$1 AND aggregate_id=$2 AND event_id=$3`, string(tenant), created.Snapshot.OrderID, target.Metadata.EventID)
		return err
	}); err == nil {
		t.Fatal("operator SQL requeued a blocked event without an audit record")
	}
	// Simulate separately approved storage recovery from the verified immutable source. The
	// operator repair method itself never writes event_outbox or order_events.
	if _, err := adminDB.ExecContext(ctx, `UPDATE keel_meta.event_outbox SET safe_envelope=$1::jsonb WHERE tenant_id=$2 AND event_id=$3`, canonicalEnvelope, string(tenant), target.Metadata.EventID); err != nil {
		t.Fatal(err)
	}

	// An injected failure on the requeue update proves the audit insert and state change share
	// one transaction. Scope the trigger to this random event ID, then remove it before resuming.
	functionName := "fail_outbox_repair_" + strings.ReplaceAll(nextUUID(), "-", "")
	triggerName := "outbox_repair_failure_" + strings.ReplaceAll(nextUUID(), "-", "")
	functionSQL := fmt.Sprintf(`CREATE FUNCTION keel_meta.%s() RETURNS trigger LANGUAGE plpgsql AS $body$
		BEGIN IF NEW.event_id='%s'::uuid AND NEW.delivery_state='pending' THEN RAISE EXCEPTION 'injected repair transaction failure'; END IF; RETURN NEW; END $body$`, functionName, target.Metadata.EventID)
	if _, err := adminDB.ExecContext(ctx, functionSQL); err != nil {
		t.Fatal(err)
	}
	if _, err := adminDB.ExecContext(ctx, fmt.Sprintf(`CREATE TRIGGER %s BEFORE UPDATE ON keel_meta.outbox_delivery FOR EACH ROW EXECUTE FUNCTION keel_meta.%s()`, triggerName, functionName)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = adminDB.ExecContext(context.Background(), fmt.Sprintf(`DROP TRIGGER IF EXISTS %s ON keel_meta.outbox_delivery`, triggerName))
		_, _ = adminDB.ExecContext(context.Background(), fmt.Sprintf(`DROP FUNCTION IF EXISTS keel_meta.%s()`, functionName))
	})
	if err := service.RepairBlocked(operatorCtx, created.Snapshot.OrderID, repair); err == nil {
		t.Fatal("injected delivery update failure did not roll back repair")
	}
	if err := adminDB.QueryRowContext(ctx, `SELECT count(*) FROM keel_meta.outbox_repair_audit WHERE tenant_id=$1 AND event_id=$2`, string(tenant), target.Metadata.EventID).Scan(&auditCount); err != nil || auditCount != 0 {
		t.Fatalf("failed repair retained %d audit records, err=%v", auditCount, err)
	}
	var state string
	if err := adminDB.QueryRowContext(ctx, `SELECT delivery_state FROM keel_meta.outbox_delivery WHERE tenant_id=$1 AND event_id=$2`, string(tenant), target.Metadata.EventID).Scan(&state); err != nil || state != "blocked" {
		t.Fatalf("failed repair state=%q err=%v", state, err)
	}
	if _, err := adminDB.ExecContext(ctx, fmt.Sprintf(`DROP TRIGGER %s ON keel_meta.outbox_delivery`, triggerName)); err != nil {
		t.Fatal(err)
	}
	if _, err := adminDB.ExecContext(ctx, fmt.Sprintf(`DROP FUNCTION keel_meta.%s()`, functionName)); err != nil {
		t.Fatal(err)
	}
	if err := service.RepairBlocked(operatorCtx, created.Snapshot.OrderID, repair); err != nil {
		t.Fatalf("validated repair failed: %v", err)
	}
	if err := adminDB.QueryRowContext(ctx, `SELECT count(*) FROM keel_meta.outbox_repair_audit WHERE request_id=$1 AND tenant_id=$2 AND event_id=$3 AND actor_ref=$4 AND reason_code=$5 AND evidence_ref=$6 AND prior_attempt_count=3`, identity.RequestID, string(tenant), target.Metadata.EventID, identity.ActorRef, repair.ReasonCode, repair.EvidenceRef).Scan(&auditCount); err != nil || auditCount != 1 {
		t.Fatalf("repair audit count=%d err=%v", auditCount, err)
	}
	var attemptCount int
	if err := adminDB.QueryRowContext(ctx, `SELECT delivery_state,attempt_count FROM keel_meta.outbox_delivery WHERE tenant_id=$1 AND event_id=$2`, string(tenant), target.Metadata.EventID).Scan(&state, &attemptCount); err != nil || state != "pending" || attemptCount != 3 {
		t.Fatalf("repaired state=%q attempts=%d err=%v", state, attemptCount, err)
	}

	broker := &recordingBroker{}
	publisher, err = outbox.NewPublisher(workerRepo, broker, outbox.Config{LeaseDuration: 5 * time.Second, PublishTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	first, err := publisher.RunOnce(ctx, string(tenant), "repair-resume-worker")
	if err != nil || !first.Published || first.EventID != events[0].Metadata.EventID {
		t.Fatalf("repaired first version result=%+v err=%v", first, err)
	}
	second, err := publisher.RunOnce(ctx, string(tenant), "repair-resume-worker")
	if err != nil || !second.Published || second.EventID != events[1].Metadata.EventID {
		t.Fatalf("following version result=%+v err=%v", second, err)
	}
	if len(broker.messages) != 2 || broker.messages[0].EventID != target.Metadata.EventID || broker.messages[1].EventID != events[1].Metadata.EventID {
		t.Fatalf("resumed publish order=%+v", broker.messages)
	}
}

func repairRequest(blocked outbox.BlockedEvent) outbox.RepairRequest {
	return outbox.RepairRequest{
		EventID: blocked.EventID, ExpectedVersion: blocked.Version, ExpectedErrorCode: blocked.ErrorCode,
		ExpectedAttemptCount: blocked.AttemptCount, ReasonCode: "serializer_compatibility_fix", EvidenceRef: "CHG-2026ABC",
	}
}
