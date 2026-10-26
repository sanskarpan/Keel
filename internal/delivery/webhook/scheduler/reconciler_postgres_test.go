package scheduler

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/sanskarpan/keel/internal/delivery/webhook"
	"github.com/sanskarpan/keel/internal/delivery/webhook/postgres"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

// storeReconciler adapts one operator store to the scheduler Reconciler contract. It mints a
// unique run per call, resumes from each tenant's cursor after the configured start, and maps
// the recorded page to content-free counts. Production wiring would own this adapter alongside
// the operator credential; the scheduler itself stays capability-agnostic.
type storeReconciler struct {
	store    *postgres.Store
	pageSize int
	from     time.Time
}

func (r *storeReconciler) Plan(ctx context.Context, tenant tenancy.TenantID) (ReconPlan, error) {
	var plan ReconPlan
	if r == nil || r.store == nil {
		return plan, errors.New("webhook scheduler reconciler is not configured")
	}
	from := r.from
	page, err := r.store.PlanReconciliation(ctx, webhook.ReconciliationRequest{
		Tenant:      tenant,
		RunID:       "rec_sched_" + strings.ReplaceAll(uuid.NewString(), "-", ""),
		RequestedBy: "webhook-scheduler",
		From:        &from,
		PageSize:    r.pageSize,
	})
	if err != nil {
		return plan, err
	}
	return ReconPlan{Scanned: page.Scanned, GapEvents: page.GapEvents, Missing: int64(page.Missing)}, nil
}

func reconTestDatabases(t *testing.T) (*sql.DB, *sql.DB, *sql.DB) {
	t.Helper()
	appDSN := os.Getenv("KEEL_TEST_DATABASE_URL")
	operatorDSN := os.Getenv("KEEL_TEST_OPERATOR_DATABASE_URL")
	adminDSN := os.Getenv("KEEL_TEST_ADMIN_DATABASE_URL")
	if appDSN == "" || operatorDSN == "" || adminDSN == "" {
		t.Skip("set app, operator and admin DSNs for scheduler reconciliation coverage")
	}
	open := func(dsn string) *sql.DB {
		db, err := sql.Open("pgx", dsn)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		return db
	}
	return open(appDSN), open(operatorDSN), open(adminDSN)
}

func insertReconOutbox(t *testing.T, adminDB *sql.DB, tenant tenancy.TenantID, eventID string) {
	t.Helper()
	ctx := context.Background()
	orderID := uuid.NewString()
	hash := make([]byte, 32)
	if _, err := adminDB.ExecContext(ctx,
		`INSERT INTO keel_meta.order_heads
		 (tenant_id,order_id,external_reference,supplier_id,status,version,command_snapshot,snapshot_hash)
		 VALUES ($1,$2,$3,$4,'draft',1,'{}'::jsonb,$5)`,
		string(tenant), orderID, "ref-"+uuid.NewString(), uuid.NewString(), hash); err != nil {
		t.Fatalf("insert order head: %v", err)
	}
	if _, err := adminDB.ExecContext(ctx,
		`INSERT INTO keel_meta.order_events
		 (tenant_id,order_id,aggregate_version,event_id,event_type,event_data,event_hash,occurred_at)
		 VALUES ($1,$2,1,$3,'order.created','{}'::jsonb,$4,clock_timestamp())`,
		string(tenant), orderID, eventID, hash); err != nil {
		t.Fatalf("insert order event: %v", err)
	}
	if _, err := adminDB.ExecContext(ctx,
		`INSERT INTO keel_meta.event_outbox
		 (tenant_id,event_id,aggregate_id,aggregate_version,event_type,schema_version,safe_envelope)
		 VALUES ($1,$2,$3,1,'order.created',1,$4::jsonb)`,
		string(tenant), eventID, orderID, `{"event_id":"`+eventID+`"}`); err != nil {
		t.Fatalf("insert outbox event: %v", err)
	}
}

func TestSchedulerReconcilerScansThroughRunOnce(t *testing.T) {
	appDB, operatorDB, adminDB := reconTestDatabases(t)
	ctx := context.Background()
	tenant, err := tenancy.ParseTenantID(uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}

	registry, err := postgres.NewRegistry(appDB)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Register(ctx, tenant, webhook.EndpointRegistration{
		ID:                  "ep_" + strings.ReplaceAll(uuid.NewString(), "-", ""),
		URL:                 "https://example.com/hooks/" + uuid.NewString(),
		KeyID:               "key_" + strings.ReplaceAll(uuid.NewString(), "-", ""),
		SubscriptionVersion: 1,
	}, 0); err != nil {
		t.Fatalf("register endpoint: %v", err)
	}
	for range 2 {
		insertReconOutbox(t, adminDB, tenant, uuid.NewString())
	}

	operatorStore, err := postgres.New(operatorDB)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	source := &recordingSource{tenants: []webhook.DueTenant{
		{Tenant: tenant, DueAt: now.Add(-time.Minute), DueCount: 1},
	}}
	s, err := New(source, &recordingRunner{}, WithReconciler(&storeReconciler{
		store: operatorStore, pageSize: 10, from: now.Add(-time.Hour),
	}))
	if err != nil {
		t.Fatal(err)
	}

	report, err := s.RunOnce(ctx)
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if report.Tenants != 1 || report.ReconScanned != 2 || report.ReconGaps != 2 ||
		report.ReconMissing != 2 || report.ReconFailures != 0 {
		t.Fatalf("unexpected report: %+v", report)
	}

	var deliveries int
	if err := adminDB.QueryRowContext(ctx,
		`SELECT count(*) FROM keel_meta.webhook_deliveries WHERE tenant_id=$1`,
		string(tenant)).Scan(&deliveries); err != nil {
		t.Fatal(err)
	}
	if deliveries != 0 {
		t.Fatalf("background scan created %d deliveries", deliveries)
	}
}
