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

func reconciliationDatabases(t *testing.T) (*sql.DB, *sql.DB, *sql.DB, *sql.DB) {
	t.Helper()
	appDSN := os.Getenv("KEEL_TEST_DATABASE_URL")
	webhookDSN := os.Getenv("KEEL_TEST_WEBHOOK_DATABASE_URL")
	operatorDSN := os.Getenv("KEEL_TEST_OPERATOR_DATABASE_URL")
	adminDSN := os.Getenv("KEEL_TEST_ADMIN_DATABASE_URL")
	if appDSN == "" || webhookDSN == "" || operatorDSN == "" || adminDSN == "" {
		t.Skip("set app, webhook, operator and admin DSNs for reconciliation coverage")
	}
	return webhookTestDB(t, appDSN), webhookTestDB(t, webhookDSN), webhookTestDB(t, operatorDSN), webhookTestDB(t, adminDSN)
}

func newReconciliationStore(t *testing.T, db *sql.DB) *Store {
	t.Helper()
	store, err := New(db)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func reconciliationRequest(tenant tenancy.TenantID) webhook.ReconciliationRequest {
	return webhook.ReconciliationRequest{
		Tenant:      tenant,
		RunID:       "rec_" + strings.ReplaceAll(uuid.NewString(), "-", ""),
		RequestedBy: "operator@example.com",
		PageSize:    2,
	}
}

func TestPostgreSQLReconciliationDryRunCursorAndGaps(t *testing.T) {
	appDB, _, operatorDB, adminDB := reconciliationDatabases(t)
	store := newReconciliationStore(t, operatorDB)
	registry := newRegistry(t, appDB)
	tenant := payloadTenant(t)
	from := time.Now().Add(-time.Minute)
	endpoint := registerFanoutEndpoint(t, registry, tenant, 1)
	eventIDs := []string{uuid.NewString(), uuid.NewString(), uuid.NewString()}
	for _, eventID := range eventIDs {
		insertFanoutOutbox(t, adminDB, tenant, eventID)
	}
	otherTenant := payloadTenant(t)
	otherEvent := uuid.NewString()
	insertFanoutOutbox(t, adminDB, otherTenant, otherEvent)

	first := reconciliationRequest(tenant)
	first.From = &from
	page, err := store.PlanReconciliation(context.Background(), first)
	if err != nil {
		t.Fatal(err)
	}
	if page.Scanned != 2 || page.GapEvents != 2 || page.Missing != 2 || len(page.Events) != 2 {
		t.Fatalf("first page = %+v", page)
	}
	if page.Events[0].Missing != 1 || page.Events[1].Missing != 1 {
		t.Fatalf("first page gaps = %+v", page.Events)
	}
	if page.Events[0].EventID != eventIDs[0] || page.Events[1].EventID != eventIDs[1] {
		t.Fatalf("first page order = %+v", page.Events)
	}
	for _, event := range page.Events {
		if event.EventID == otherEvent {
			t.Fatal("reconciliation crossed the tenant boundary")
		}
	}
	if count := countReconciliationDeliveries(t, adminDB, tenant); count != 0 {
		t.Fatalf("dry run created %d deliveries", count)
	}
	var scanned, gaps int
	var missing int64
	var cursorFromNull bool
	if err := adminDB.QueryRowContext(context.Background(),
		`SELECT events_scanned,gap_events,missing_deliveries,cursor_from_event_id IS NULL
		   FROM keel_meta.webhook_reconciliation_runs
		  WHERE tenant_id=$1 AND run_id=$2`, string(tenant), first.RunID).
		Scan(&scanned, &gaps, &missing, &cursorFromNull); err != nil {
		t.Fatal(err)
	}
	if scanned != 2 || gaps != 2 || missing != 2 || !cursorFromNull {
		t.Fatalf("run summary scanned=%d gaps=%d missing=%d first=%v", scanned, gaps, missing, cursorFromNull)
	}
	if last := reconciliationCursorEvent(t, adminDB, tenant); last != eventIDs[1] {
		t.Fatalf("cursor after first page = %q, want %q", last, eventIDs[1])
	}

	second := reconciliationRequest(tenant)
	page, err = store.PlanReconciliation(context.Background(), second)
	if err != nil {
		t.Fatal(err)
	}
	if page.Scanned != 1 || page.GapEvents != 1 || page.Missing != 1 || page.Events[0].EventID != eventIDs[2] {
		t.Fatalf("second page = %+v", page)
	}
	third := reconciliationRequest(tenant)
	page, err = store.PlanReconciliation(context.Background(), third)
	if err != nil {
		t.Fatal(err)
	}
	if page.Scanned != 0 || page.GapEvents != 0 || page.Missing != 0 || len(page.Events) != 0 {
		t.Fatalf("third page = %+v", page)
	}
	if last := reconciliationCursorEvent(t, adminDB, tenant); last != eventIDs[2] {
		t.Fatalf("cursor after second page = %q, want %q", last, eventIDs[2])
	}

	if _, err := store.PlanReconciliation(context.Background(), first); !errors.Is(err, webhook.ErrReconciliationConflict) {
		t.Fatalf("duplicate run error = %v, want conflict", err)
	}
	var gapRows int
	if err := adminDB.QueryRowContext(context.Background(),
		`SELECT count(*) FROM keel_meta.webhook_reconciliation_gaps WHERE tenant_id=$1`, string(tenant)).Scan(&gapRows); err != nil {
		t.Fatal(err)
	}
	if gapRows != 3 {
		t.Fatalf("gap rows = %d, want 3", gapRows)
	}
	if endpoint.ID == "" {
		t.Fatal("endpoint was not registered")
	}
}

func TestPostgreSQLReconciliationIgnoresExistingDeliveries(t *testing.T) {
	appDB, _, operatorDB, adminDB := reconciliationDatabases(t)
	store := newReconciliationStore(t, operatorDB)
	registry := newRegistry(t, appDB)
	tenant := payloadTenant(t)
	from := time.Now().Add(-time.Minute)
	endpoint := registerFanoutEndpoint(t, registry, tenant, 1)
	eventID := uuid.NewString()
	insertFanoutOutbox(t, adminDB, tenant, eventID)
	if _, err := adminDB.ExecContext(context.Background(),
		`INSERT INTO keel_meta.webhook_deliveries
		 (tenant_id,event_id,endpoint_id,subscription_version,delivery_id)
		 VALUES ($1,$2,$3,1,$4)`,
		string(tenant), eventID, endpoint.ID, "whd_"+strings.ReplaceAll(uuid.NewString(), "-", "")); err != nil {
		t.Fatal(err)
	}
	request := reconciliationRequest(tenant)
	request.From = &from
	page, err := store.PlanReconciliation(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if page.Scanned != 1 || page.GapEvents != 0 || page.Missing != 0 || page.Events[0].Missing != 0 {
		t.Fatalf("page with existing delivery = %+v", page)
	}
}

func TestPostgreSQLReconciliationRequiresFromWithoutCursor(t *testing.T) {
	_, _, operatorDB, _ := reconciliationDatabases(t)
	store := newReconciliationStore(t, operatorDB)
	request := reconciliationRequest(payloadTenant(t))
	if _, err := store.PlanReconciliation(context.Background(), request); !errors.Is(err, webhook.ErrInvalidReconciliation) {
		t.Fatalf("missing from error = %v, want invalid reconciliation", err)
	}
}

func TestPostgreSQLReconciliationRequiresOperatorCapabilityAndHidesTables(t *testing.T) {
	appDB, webhookDB, operatorDB, adminDB := reconciliationDatabases(t)
	tenant := payloadTenant(t)
	from := time.Now().Add(-time.Minute)
	request := reconciliationRequest(tenant)
	request.From = &from
	for _, db := range []*sql.DB{appDB, webhookDB} {
		if _, err := db.ExecContext(context.Background(),
			`SELECT keel_meta.plan_webhook_reconciliation($1,$2,$3,$4)`,
			request.RunID, request.RequestedBy, request.From, request.PageSize); err == nil {
			t.Fatal("reconciliation executed without the operator capability")
		}
	}
	store := newReconciliationStore(t, operatorDB)
	if _, err := store.PlanReconciliation(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if _, err := operatorDB.ExecContext(context.Background(),
		`SELECT count(*) FROM keel_meta.webhook_reconciliation_runs`); err == nil {
		t.Fatal("operator read reconciliation runs directly")
	}
	if _, err := adminDB.ExecContext(context.Background(),
		`UPDATE keel_meta.webhook_reconciliation_runs SET requested_by='other' WHERE tenant_id=$1`,
		string(tenant)); err == nil {
		t.Fatal("reconciliation run was mutable")
	}
}

func countReconciliationDeliveries(t *testing.T, adminDB *sql.DB, tenant tenancy.TenantID) int {
	t.Helper()
	var count int
	if err := adminDB.QueryRowContext(context.Background(),
		`SELECT count(*) FROM keel_meta.webhook_deliveries WHERE tenant_id=$1`, string(tenant)).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func reconciliationCursorEvent(t *testing.T, adminDB *sql.DB, tenant tenancy.TenantID) string {
	t.Helper()
	var eventID string
	if err := adminDB.QueryRowContext(context.Background(),
		`SELECT last_event_id::text FROM keel_meta.webhook_reconciliation_cursors WHERE tenant_id=$1`,
		string(tenant)).Scan(&eventID); err != nil {
		t.Fatal(err)
	}
	return eventID
}
