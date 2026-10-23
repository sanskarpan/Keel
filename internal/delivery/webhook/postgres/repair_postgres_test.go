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

func repairRequest(tenant tenancy.TenantID, runID string) webhook.RepairRequest {
	return webhook.RepairRequest{
		Tenant:      tenant,
		RepairID:    "rep_" + strings.ReplaceAll(uuid.NewString(), "-", ""),
		RunID:       runID,
		RequestedBy: "operator@example.com",
		EventLimit:  2,
	}
}

func TestPostgreSQLReconciliationRepairIsAuditedAndIdempotent(t *testing.T) {
	appDB, webhookDB, operatorDB, adminDB := reconciliationDatabases(t)
	store := newReconciliationStore(t, operatorDB)
	registry := newRegistry(t, appDB)
	tenant := payloadTenant(t)
	from := time.Now().Add(-time.Minute)
	endpoint := registerFanoutEndpoint(t, registry, tenant, 1)
	for range 2 {
		insertFanoutOutbox(t, adminDB, tenant, uuid.NewString())
	}
	plan := reconciliationRequest(tenant)
	plan.From = &from
	page, err := store.PlanReconciliation(context.Background(), plan)
	if err != nil || page.GapEvents != 2 {
		t.Fatalf("plan page=%+v err=%v", page, err)
	}

	request := repairRequest(tenant, plan.RunID)
	result, err := store.RepairReconciliation(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if result.GapEvents != 2 || result.InsertedDeliveries != 2 || result.RepairID != request.RepairID {
		t.Fatalf("repair result = %+v", result)
	}
	if count := countRepairDeliveries(t, adminDB, tenant); count != 2 {
		t.Fatalf("deliveries = %d, want 2", count)
	}
	var pending int
	if err := adminDB.QueryRowContext(context.Background(),
		`SELECT count(*) FROM keel_meta.webhook_delivery_state WHERE tenant_id=$1 AND state='pending'`,
		string(tenant)).Scan(&pending); err != nil {
		t.Fatal(err)
	}
	if pending != 2 {
		t.Fatalf("pending states = %d, want 2", pending)
	}
	var items int
	if err := adminDB.QueryRowContext(context.Background(),
		`SELECT count(*) FROM keel_meta.webhook_reconciliation_repair_items WHERE tenant_id=$1`,
		string(tenant)).Scan(&items); err != nil {
		t.Fatal(err)
	}
	if items != 2 {
		t.Fatalf("repair items = %d, want 2", items)
	}
	var deliveryEndpoint, deliveryID string
	var deliveryVersion int
	if err := adminDB.QueryRowContext(context.Background(),
		`SELECT endpoint_id,subscription_version,delivery_id FROM keel_meta.webhook_reconciliation_repair_items
		  WHERE tenant_id=$1 ORDER BY event_id LIMIT 1`, string(tenant)).
		Scan(&deliveryEndpoint, &deliveryVersion, &deliveryID); err != nil {
		t.Fatal(err)
	}
	if deliveryEndpoint != endpoint.ID || deliveryVersion != 1 || deliveryID == "" {
		t.Fatalf("repair item endpoint=%q version=%d delivery=%q", deliveryEndpoint, deliveryVersion, deliveryID)
	}

	second := repairRequest(tenant, plan.RunID)
	second.Tenant = tenant
	result, err = store.RepairReconciliation(context.Background(), second)
	if err != nil {
		t.Fatal(err)
	}
	if result.GapEvents != 2 || result.InsertedDeliveries != 0 {
		t.Fatalf("repeat repair result = %+v", result)
	}
	if count := countRepairDeliveries(t, adminDB, tenant); count != 2 {
		t.Fatalf("repeat repair changed delivery count to %d", count)
	}
	if _, err := store.RepairReconciliation(context.Background(), request); !errors.Is(err, webhook.ErrReconciliationConflict) {
		t.Fatalf("duplicate repair error = %v, want conflict", err)
	}

	for _, db := range []*sql.DB{appDB, webhookDB} {
		if _, err := db.ExecContext(context.Background(),
			`SELECT keel_meta.repair_webhook_reconciliation_run($1,$2,$3,$4)`,
			request.RepairID, request.RunID, request.RequestedBy, request.EventLimit); err == nil {
			t.Fatal("repair executed without the operator capability")
		}
	}
	if _, err := operatorDB.ExecContext(context.Background(),
		`SELECT count(*) FROM keel_meta.webhook_reconciliation_repair_runs`); err == nil {
		t.Fatal("operator read repair runs directly")
	}
	if _, err := adminDB.ExecContext(context.Background(),
		`UPDATE keel_meta.webhook_reconciliation_repair_runs SET requested_by='other' WHERE tenant_id=$1`,
		string(tenant)); err == nil {
		t.Fatal("repair run was mutable")
	}
}

func TestPostgreSQLReconciliationRepairHonorsEventLimit(t *testing.T) {
	appDB, _, operatorDB, adminDB := reconciliationDatabases(t)
	store := newReconciliationStore(t, operatorDB)
	registry := newRegistry(t, appDB)
	tenant := payloadTenant(t)
	from := time.Now().Add(-time.Minute)
	registerFanoutEndpoint(t, registry, tenant, 1)
	for range 2 {
		insertFanoutOutbox(t, adminDB, tenant, uuid.NewString())
	}
	plan := reconciliationRequest(tenant)
	plan.From = &from
	page, err := store.PlanReconciliation(context.Background(), plan)
	if err != nil || page.GapEvents != 2 {
		t.Fatalf("plan page=%+v err=%v", page, err)
	}
	request := repairRequest(tenant, plan.RunID)
	request.EventLimit = 1
	result, err := store.RepairReconciliation(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if result.GapEvents != 1 || result.InsertedDeliveries != 1 {
		t.Fatalf("limited repair result = %+v", result)
	}
	if count := countRepairDeliveries(t, adminDB, tenant); count != 1 {
		t.Fatalf("limited repair deliveries = %d, want 1", count)
	}
	second := repairRequest(tenant, plan.RunID)
	second.EventLimit = 2
	result, err = store.RepairReconciliation(context.Background(), second)
	if err != nil {
		t.Fatal(err)
	}
	if result.GapEvents != 2 || result.InsertedDeliveries != 1 {
		t.Fatalf("second limited repair result = %+v", result)
	}
	if count := countRepairDeliveries(t, adminDB, tenant); count != 2 {
		t.Fatalf("second limited repair deliveries = %d, want 2", count)
	}
}

func TestPostgreSQLReconciliationRepairRevalidatesGaps(t *testing.T) {
	appDB, _, operatorDB, adminDB := reconciliationDatabases(t)
	store := newReconciliationStore(t, operatorDB)
	registry := newRegistry(t, appDB)
	tenant := payloadTenant(t)
	from := time.Now().Add(-time.Minute)
	endpoint := registerFanoutEndpoint(t, registry, tenant, 1)
	eventIDs := []string{uuid.NewString(), uuid.NewString()}
	for _, eventID := range eventIDs {
		insertFanoutOutbox(t, adminDB, tenant, eventID)
	}
	plan := reconciliationRequest(tenant)
	plan.From = &from
	page, err := store.PlanReconciliation(context.Background(), plan)
	if err != nil || page.GapEvents != 2 {
		t.Fatalf("plan page=%+v err=%v", page, err)
	}
	if _, err := adminDB.ExecContext(context.Background(),
		`INSERT INTO keel_meta.webhook_deliveries
		 (tenant_id,event_id,endpoint_id,subscription_version,delivery_id)
		 VALUES ($1,$2,$3,1,$4)`,
		string(tenant), eventIDs[0], endpoint.ID, "whd_"+strings.ReplaceAll(uuid.NewString(), "-", "")); err != nil {
		t.Fatal(err)
	}
	request := repairRequest(tenant, plan.RunID)
	result, err := store.RepairReconciliation(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if result.GapEvents != 2 || result.InsertedDeliveries != 1 {
		t.Fatalf("revalidated repair result = %+v", result)
	}
	if count := countRepairDeliveries(t, adminDB, tenant); count != 2 {
		t.Fatalf("revalidated repair deliveries = %d, want 2", count)
	}
}

func TestPostgreSQLReconciliationRepairRejectsUnknownRun(t *testing.T) {
	_, _, operatorDB, _ := reconciliationDatabases(t)
	store := newReconciliationStore(t, operatorDB)
	tenant := payloadTenant(t)
	request := repairRequest(tenant, "rec_0123456789abcdef")
	if _, err := store.RepairReconciliation(context.Background(), request); !errors.Is(err, webhook.ErrInvalidReconciliation) {
		t.Fatalf("unknown run error = %v, want invalid reconciliation", err)
	}
}

func countRepairDeliveries(t *testing.T, adminDB *sql.DB, tenant tenancy.TenantID) int {
	t.Helper()
	var count int
	if err := adminDB.QueryRowContext(context.Background(),
		`SELECT count(*) FROM keel_meta.webhook_deliveries WHERE tenant_id=$1`, string(tenant)).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}
