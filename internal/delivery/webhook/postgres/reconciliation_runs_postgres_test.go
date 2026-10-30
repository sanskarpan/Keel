package postgres

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sanskarpan/keel/internal/delivery/webhook"
)

type recordingReconObserver struct {
	mu             sync.Mutex
	pages          []webhook.ReconciliationPage
	results        []webhook.RepairResult
	planFailures   int
	repairFailures int
}

func (o *recordingReconObserver) ObserveReconciliationPlan(page webhook.ReconciliationPage) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.pages = append(o.pages, page)
}

func (o *recordingReconObserver) ObserveReconciliationRepair(result webhook.RepairResult) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.results = append(o.results, result)
}

func (o *recordingReconObserver) ObservePlanFailure() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.planFailures++
}

func (o *recordingReconObserver) ObserveRepairFailure() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.repairFailures++
}

func (o *recordingReconObserver) snapshot() ([]webhook.ReconciliationPage, []webhook.RepairResult) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]webhook.ReconciliationPage(nil), o.pages...),
		append([]webhook.RepairResult(nil), o.results...)
}

func TestPostgreSQLReconciliationRunsListsHistory(t *testing.T) {
	appDB, webhookDB, operatorDB, adminDB := reconciliationDatabases(t)
	store := newReconciliationStore(t, operatorDB)
	registry := newRegistry(t, appDB)
	ctx := context.Background()
	tenant := payloadTenant(t)
	from := time.Now().Add(-time.Minute)

	endpoint := registerFanoutEndpoint(t, registry, tenant, 1)
	eventIDs := []string{uuid.NewString(), uuid.NewString()}
	for _, eventID := range eventIDs {
		insertFanoutOutbox(t, adminDB, tenant, eventID)
	}
	plan := reconciliationRequest(tenant)
	plan.From = &from
	page, err := store.PlanReconciliation(ctx, plan)
	if err != nil || page.GapEvents != 2 {
		t.Fatalf("plan page=%+v err=%v", page, err)
	}
	repair := repairRequest(tenant, plan.RunID)
	if _, err := store.RepairReconciliation(ctx, repair); err != nil {
		t.Fatalf("repair run: %v", err)
	}

	runs, err := store.ReconciliationRuns(ctx, tenant, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 1 {
		t.Fatalf("runs = %+v, want 1", runs)
	}
	summary := runs[0]
	if summary.RunID != plan.RunID || summary.RequestedBy != "operator@example.com" {
		t.Fatalf("run identity = %+v", summary)
	}
	if summary.FromCreatedAt.IsZero() || summary.CreatedAt.IsZero() {
		t.Fatalf("run timestamps = %+v", summary)
	}
	if summary.CursorToEventID == "" || summary.CursorToEventID == "00000000-0000-0000-0000-000000000000" ||
		summary.CursorToCreatedAt.IsZero() {
		t.Fatalf("run cursor = %+v", summary)
	}
	if summary.EventsScanned != 2 || summary.GapEvents != 2 || summary.MissingDeliveries != 2 {
		t.Fatalf("plan counts = %+v", summary)
	}
	if summary.RepairedDeliveries != 2 || summary.SkippedIdentities != 0 {
		t.Fatalf("repair totals = %+v", summary)
	}
	if endpoint.ID == "" {
		t.Fatal("endpoint fixture was not registered")
	}

	second := reconciliationRequest(tenant)
	if _, err := store.PlanReconciliation(ctx, second); err != nil {
		t.Fatalf("second plan: %v", err)
	}
	runs, err = store.ReconciliationRuns(ctx, tenant, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 1 || runs[0].RunID != second.RunID {
		t.Fatalf("limited runs = %+v, want newest run only", runs)
	}
	runs, err = store.ReconciliationRuns(ctx, tenant, 100)
	if err != nil || len(runs) != 2 || runs[0].RunID != second.RunID || runs[1].RunID != plan.RunID {
		t.Fatalf("ordered runs = %+v err=%v", runs, err)
	}

	other := payloadTenant(t)
	runs, err = store.ReconciliationRuns(ctx, other, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 0 {
		t.Fatalf("other tenant runs = %+v, want none", runs)
	}

	for _, limit := range []int{0, -1, webhook.MaxReconciliationRunHistory + 1} {
		if _, err := store.ReconciliationRuns(ctx, tenant, limit); !errors.Is(err, webhook.ErrInvalidReconciliation) {
			t.Fatalf("limit %d error = %v, want invalid", limit, err)
		}
	}
	if _, err := store.ReconciliationRuns(nil, tenant, 10); err == nil {
		t.Fatal("nil context was accepted")
	}

	for _, db := range []*sql.DB{appDB, webhookDB} {
		if _, err := db.ExecContext(ctx,
			`SELECT keel_meta.list_webhook_reconciliation_runs(10)`); err == nil {
			t.Fatal("runs listed without the operator capability")
		}
	}
	if _, err := operatorDB.ExecContext(ctx,
		`SELECT count(*) FROM keel_meta.webhook_reconciliation_runs`); err == nil {
		t.Fatal("operator read reconciliation runs directly")
	}
}

func TestPostgreSQLReconciliationStoreFiresContentFreeObserver(t *testing.T) {
	appDB, _, operatorDB, adminDB := reconciliationDatabases(t)
	store := newReconciliationStore(t, operatorDB)
	registry := newRegistry(t, appDB)
	ctx := context.Background()
	tenant := payloadTenant(t)
	from := time.Now().Add(-time.Minute)

	registerFanoutEndpoint(t, registry, tenant, 1)
	for range 2 {
		insertFanoutOutbox(t, adminDB, tenant, uuid.NewString())
	}
	observer := &recordingReconObserver{}
	store.SetReconciliationObserver(observer)

	plan := reconciliationRequest(tenant)
	plan.From = &from
	if _, err := store.PlanReconciliation(ctx, plan); err != nil {
		t.Fatalf("plan run: %v", err)
	}
	repair := repairRequest(tenant, plan.RunID)
	if _, err := store.RepairReconciliation(ctx, repair); err != nil {
		t.Fatalf("repair run: %v", err)
	}

	pages, results := observer.snapshot()
	if len(pages) != 1 || pages[0].Scanned != 2 || pages[0].GapEvents != 2 || pages[0].Missing != 2 {
		t.Fatalf("observed pages = %+v", pages)
	}
	if len(results) != 1 || results[0].GapEvents != 2 || results[0].InsertedDeliveries != 2 {
		t.Fatalf("observed results = %+v", results)
	}

	store.SetReconciliationObserver(nil)
	second := reconciliationRequest(tenant)
	if _, err := store.PlanReconciliation(ctx, second); err != nil {
		t.Fatalf("second plan run: %v", err)
	}
	if pages, results := observer.snapshot(); len(pages) != 1 || len(results) != 1 {
		t.Fatalf("cleared observer fired: pages=%d results=%d", len(pages), len(results))
	}
}

func TestPostgreSQLReconciliationStoreObservesFailures(t *testing.T) {
	_, _, operatorDB, _ := reconciliationDatabases(t)
	store := newReconciliationStore(t, operatorDB)
	ctx := context.Background()
	tenant := payloadTenant(t)
	observer := &recordingReconObserver{}
	store.SetReconciliationObserver(observer)

	unknown := repairRequest(tenant, "rec_0123456789abcdef")
	if _, err := store.RepairReconciliation(ctx, unknown); err == nil {
		t.Fatal("repair of unknown run succeeded")
	}
	from := time.Now().Add(-time.Minute)
	plan := reconciliationRequest(tenant)
	plan.RunID = "rec_0123456789abcdef"
	plan.From = &from
	if _, err := store.PlanReconciliation(ctx, plan); err != nil {
		t.Fatalf("plan run: %v", err)
	}
	duplicate := reconciliationRequest(tenant)
	duplicate.RunID = plan.RunID
	if _, err := store.PlanReconciliation(ctx, duplicate); err == nil {
		t.Fatal("duplicate run succeeded")
	}

	observer.mu.Lock()
	defer observer.mu.Unlock()
	if len(observer.pages) != 1 || len(observer.results) != 0 {
		t.Fatalf("success observations pages=%d results=%d", len(observer.pages), len(observer.results))
	}
	if observer.planFailures != 1 || observer.repairFailures != 1 {
		t.Fatalf("failure observations plan=%d repair=%d, want 1/1",
			observer.planFailures, observer.repairFailures)
	}
}
