package postgres

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/sanskarpan/keel/internal/orders"
	"github.com/sanskarpan/keel/internal/orders/projector"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

func TestPostgreSQLAuthoritativeReadWatermarkAndBoundedHistory(t *testing.T) {
	appDB, tenant, appRepo := repositoryTestDB(t)
	projectorDSN, adminDSN := os.Getenv("KEEL_TEST_PROJECTOR_DATABASE_URL"), os.Getenv("KEEL_TEST_ADMIN_DATABASE_URL")
	if projectorDSN == "" || adminDSN == "" {
		t.Skip("set projector and test-admin database URLs for watermark and integrity coverage")
	}
	projectorDB := integrationDB(t, projectorDSN, 3)
	adminDB := integrationDB(t, adminDSN, 3)
	projectorRepo, err := NewRepository(projectorDB)
	if err != nil {
		t.Fatal(err)
	}
	processor, err := projector.New(projectorRepo, projector.DefaultConsumerID)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	created, err := appRepo.Create(ctx, tenant, testCreate("read-view-"+nextUUID()), testMetadata(string(tenant), nextUUID()), "read-view-create-"+nextUUID(), "principal:requester-1")
	if err != nil {
		t.Fatal(err)
	}
	view, err := appRepo.ReadOrder(ctx, tenant, created.Snapshot.OrderID)
	if err != nil || view.Snapshot.Status != orders.Draft || view.Snapshot.Version != 1 || view.ProjectionWatermark != 0 {
		t.Fatalf("unprojected read=%+v err=%v", view, err)
	}
	metadata := testMetadata(string(tenant), created.Snapshot.OrderID)
	metadata.ActorRef = "principal:requester-1"
	submitted, err := appRepo.Submit(ctx, tenant, created.Snapshot.OrderID, 1, testSubmit(), metadata, "read-view-submit-"+nextUUID(), "principal:requester-1")
	if err != nil {
		t.Fatal(err)
	}
	var envelopes [][]byte
	err = tenancy.WithTenantTx(ctx, appDB, tenant, &sql.TxOptions{ReadOnly: true}, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT safe_envelope FROM keel_meta.event_outbox WHERE tenant_id=$1 AND aggregate_id=$2 ORDER BY aggregate_version`, string(tenant), created.Snapshot.OrderID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var raw []byte
			if err := rows.Scan(&raw); err != nil {
				return err
			}
			envelopes = append(envelopes, raw)
		}
		return rows.Err()
	})
	if err != nil || len(envelopes) != 2 {
		t.Fatalf("canonical order envelopes=%d err=%v", len(envelopes), err)
	}
	first := projectionRecord(t, envelopes[0], time.Now().UnixNano())
	if result, err := processor.Process(ctx, string(tenant), first); err != nil || result.Disposition != projector.Applied {
		t.Fatalf("first projection result=%+v err=%v", result, err)
	}
	view, err = appRepo.ReadOrder(ctx, tenant, created.Snapshot.OrderID)
	if err != nil || view.Snapshot.Status != orders.Submitted || view.Snapshot.Version != submitted.Snapshot.Version || view.ProjectionWatermark != 1 {
		t.Fatalf("authoritative state during projection lag=%+v err=%v", view, err)
	}
	consistentView, page, err := appRepo.ReadOrderWithHistory(ctx, tenant, created.Snapshot.OrderID, 0, 1)
	if err != nil || consistentView.Snapshot.Version != 2 || consistentView.ProjectionWatermark != 1 || len(page.Items) != 1 || page.Items[0].Version != 2 || !page.HasMore || page.NextFrom != 2 {
		t.Fatalf("consistent detail/history snapshot view=%+v page=%+v err=%v", consistentView, page, err)
	}
	last, err := appRepo.PageEvents(ctx, tenant, created.Snapshot.OrderID, page.NextFrom, 1)
	if err != nil || len(last.Items) != 1 || last.Items[0].Version != 1 || last.HasMore || last.Items[0].Type != orders.OrderCreated {
		t.Fatalf("last bounded history page=%+v err=%v", last, err)
	}
	second := projectionRecord(t, envelopes[1], time.Now().UnixNano()+1)
	if result, err := processor.Process(ctx, string(tenant), second); err != nil || result.Disposition != projector.Applied {
		t.Fatalf("second projection result=%+v err=%v", result, err)
	}
	view, err = appRepo.ReadOrder(ctx, tenant, created.Snapshot.OrderID)
	if err != nil || view.ProjectionWatermark != view.Snapshot.Version || view.Snapshot.Status != orders.Submitted {
		t.Fatalf("current projection read=%+v err=%v", view, err)
	}
	otherTenant := mustTenant(t, nextUUID())
	if _, err := appRepo.ReadOrder(ctx, otherTenant, created.Snapshot.OrderID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant order read err=%v, want not found", err)
	}
	if _, err := appRepo.PageEvents(ctx, otherTenant, created.Snapshot.OrderID, 0, 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant history read err=%v, want not found", err)
	}
	if _, err := adminDB.ExecContext(ctx, `UPDATE keel_meta.order_projections SET status='draft' WHERE tenant_id=$1 AND aggregate_id=$2`, string(tenant), created.Snapshot.OrderID); err != nil {
		t.Fatal(err)
	}
	if _, err := appRepo.ReadOrder(ctx, tenant, created.Snapshot.OrderID); !errors.Is(err, ErrCorruptState) {
		t.Fatalf("mismatched current projection status error=%v, want corrupt state", err)
	}
	if _, err := adminDB.ExecContext(ctx, `UPDATE keel_meta.order_events SET event_data='{}'::jsonb WHERE tenant_id=$1 AND order_id=$2 AND aggregate_version=1`, string(tenant), created.Snapshot.OrderID); err != nil {
		t.Fatal(err)
	}
	if _, err := appRepo.PageEvents(ctx, tenant, created.Snapshot.OrderID, 0, 1); !errors.Is(err, ErrCorruptState) {
		t.Fatalf("corrupt history page error=%v, want corrupt state", err)
	}
}

func TestPostgreSQLStateFeedPagesDurableTenantSequenceAndHidesOtherTenants(t *testing.T) {
	_, tenant, repo := repositoryTestDB(t)
	ctx := context.Background()
	first, err := repo.Create(ctx, tenant, testCreate("state-feed-first-"+nextUUID()), testMetadata(string(tenant), nextUUID()), "state-feed-first-"+nextUUID(), "principal:requester-1")
	if err != nil {
		t.Fatal(err)
	}
	second, err := repo.Create(ctx, tenant, testCreate("state-feed-second-"+nextUUID()), testMetadata(string(tenant), nextUUID()), "state-feed-second-"+nextUUID(), "principal:requester-1")
	if err != nil {
		t.Fatal(err)
	}

	page, err := repo.ReadStateUpdates(ctx, tenant, 0, 1)
	if err != nil || page.Oldest != 1 || page.Latest != 2 || len(page.Updates) != 1 {
		t.Fatalf("first state feed page=%+v err=%v", page, err)
	}
	if page.Updates[0].Sequence != 1 || page.Updates[0].AggregateID != first.Snapshot.OrderID || page.Updates[0].Version != 1 || page.Updates[0].Kind != "order.changed" || page.Updates[0].Status != orders.Draft {
		t.Fatalf("first state feed DTO=%+v", page.Updates[0])
	}
	page, err = repo.ReadStateUpdates(ctx, tenant, 1, 100)
	if err != nil || len(page.Updates) != 1 || page.Updates[0].Sequence != 2 || page.Updates[0].AggregateID != second.Snapshot.OrderID {
		t.Fatalf("resumed state feed page=%+v err=%v", page, err)
	}

	otherTenant := mustTenant(t, nextUUID())
	isolated, err := repo.ReadStateUpdates(ctx, otherTenant, 0, 100)
	if err != nil || isolated.Latest != 0 || isolated.Oldest != 0 || len(isolated.Updates) != 0 {
		t.Fatalf("cross-tenant feed data visible: %+v err=%v", isolated, err)
	}
	if _, err := repo.ReadStateUpdates(ctx, tenant, 0, 101); err == nil {
		t.Fatal("oversized feed page limit was accepted")
	}
}

func TestPostgreSQLConcurrentCommandAndProjectorReadsShareOneSnapshot(t *testing.T) {
	appDB, tenant, appRepo := repositoryTestDB(t)
	projectorDSN := os.Getenv("KEEL_TEST_PROJECTOR_DATABASE_URL")
	if projectorDSN == "" {
		t.Skip("set projector database URL for concurrent command/projector coverage")
	}
	projectorDB := integrationDB(t, projectorDSN, 3)
	projectorRepo, err := NewRepository(projectorDB)
	if err != nil {
		t.Fatal(err)
	}
	processor, err := projector.New(projectorRepo, projector.DefaultConsumerID)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	created, err := appRepo.Create(ctx, tenant, testCreate("read-race-"+nextUUID()), testMetadata(string(tenant), nextUUID()), "read-race-create-"+nextUUID(), "principal:requester-1")
	if err != nil {
		t.Fatal(err)
	}
	var envelope []byte
	if err := tenancy.WithTenantTx(ctx, appDB, tenant, &sql.TxOptions{ReadOnly: true}, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT safe_envelope FROM keel_meta.event_outbox WHERE tenant_id=$1 AND aggregate_id=$2 AND aggregate_version=1`, string(tenant), created.Snapshot.OrderID).Scan(&envelope)
	}); err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	ready := make(chan struct{}, 2)
	results := make(chan error, 2)
	var workers sync.WaitGroup
	workers.Add(2)
	go func() {
		defer workers.Done()
		ready <- struct{}{}
		<-start
		_, err := appRepo.Submit(ctx, tenant, created.Snapshot.OrderID, 1, testSubmit(), testMetadata(string(tenant), created.Snapshot.OrderID), "read-race-submit-"+nextUUID(), "principal:requester-1")
		results <- err
	}()
	go func() {
		defer workers.Done()
		ready <- struct{}{}
		<-start
		_, err := processor.Process(ctx, string(tenant), projectionRecord(t, envelope, time.Now().UnixNano()))
		results <- err
	}()
	<-ready
	<-ready
	close(start)

	for i := 0; i < 40; i++ {
		view, page, err := appRepo.ReadOrderWithHistory(ctx, tenant, created.Snapshot.OrderID, 0, 100)
		if err != nil {
			t.Fatalf("concurrent authoritative/history read %d: %v", i, err)
		}
		if view.Snapshot.Version < 1 || view.Snapshot.Version > 2 || view.ProjectionWatermark > 1 || view.ProjectionWatermark > view.Snapshot.Version || uint64(len(page.Items)) != view.Snapshot.Version || len(page.Items) == 0 || page.Items[0].Version != view.Snapshot.Version || page.HasMore {
			t.Fatalf("read mixed command/projector snapshot: view=%+v page=%+v", view, page)
		}
		if view.Snapshot.Version == 1 && view.Snapshot.Status != orders.Draft || view.Snapshot.Version == 2 && view.Snapshot.Status != orders.Submitted {
			t.Fatalf("command snapshot version/status mismatch: %+v", view.Snapshot)
		}
	}
	workers.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatalf("concurrent command/projector operation: %v", err)
		}
	}
}
