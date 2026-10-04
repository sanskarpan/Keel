package postgres

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/sanskarpan/keel/internal/orders"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

var testSequence atomic.Uint64

func integrationDB(t *testing.T, dsn string, maxConnections int) *sql.DB {
	t.Helper()
	parsed, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("pgx", parsed.String())
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(maxConnections)
	db.SetMaxIdleConns(maxConnections)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		t.Fatalf("connect to PostgreSQL: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func nextUUID() string {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		panic(err)
	}
	value[6] = value[6]&0x0f | 0x40
	value[8] = value[8]&0x3f | 0x80
	// Keep a monotonic counter in the low bytes to make concurrent test IDs unique even if
	// a constrained test environment supplies a broken or deterministic random source.
	n := testSequence.Add(1)
	for i := 0; i < 6; i++ {
		value[15-i] ^= byte(n >> (8 * i))
	}
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		value[0:4], value[4:6], value[6:8], value[8:10], value[10:16])
}

func testMetadata(tenantID, orderID string) orders.EventMetadata {
	return orders.EventMetadata{
		EventID: nextUUID(), TenantID: tenantID, OrderID: orderID,
		OccurredAt: time.Now().UTC(), ActorRef: "principal:requester-1",
		CausationID: nextUUID(), CorrelationID: nextUUID(),
	}
}

func testCreate(externalRef string) orders.CreateOrder {
	return orders.CreateOrder{
		ExternalReference: externalRef, SupplierID: "80000000-0000-4000-8000-000000000001",
		Currency: "USD", AmountMinor: 1200,
		LineItems: []orders.LineItem{{Description: "Office supplies", Quantity: "1.00"}},
	}
}

func testSubmit() orders.SubmitOrder {
	return orders.SubmitOrder{Evidence: []orders.EvidenceRef{{DocumentID: "70000000-0000-4000-8000-000000000001", Version: 1}}}
}

func mustTenant(t *testing.T, value string) tenancy.TenantID {
	t.Helper()
	tenant, err := tenancy.ParseTenantID(value)
	if err != nil {
		t.Fatal(err)
	}
	return tenant
}

func repositoryTestDB(t *testing.T) (*sql.DB, tenancy.TenantID, *Repository) {
	t.Helper()
	dsn := os.Getenv("KEEL_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set KEEL_TEST_DATABASE_URL to a least-privilege Keel app database role")
	}
	db := integrationDB(t, dsn, 12)
	repo, err := NewRepository(db)
	if err != nil {
		t.Fatal(err)
	}
	return db, mustTenant(t, nextUUID()), repo
}

func TestPostgreSQLTransactionalIdempotencyAndAggregateLock(t *testing.T) {
	db, tenant, repo := repositoryTestDB(t)
	ctx := context.Background()
	_ = db
	const key = "create-same-key-0001"
	command := testCreate("same-external-reference-" + nextUUID())
	const principal = "principal:requester-1"

	// Parallel requests exercise the unique-key claim and confirm only one committed aggregate.
	const callers = 8
	results := make([]Result, callers)
	errs := make([]error, callers)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range callers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			metadata := testMetadata(string(tenant), nextUUID())
			results[i], errs[i] = repo.Create(ctx, tenant, command, metadata, key, principal)
		}(i)
	}
	close(start)
	wg.Wait()
	orderID := ""
	replays := 0
	for i, err := range errs {
		if err != nil {
			t.Fatalf("concurrent create %d: %v", i, err)
		}
		if orderID == "" {
			orderID = results[i].Snapshot.OrderID
		}
		if results[i].Snapshot.OrderID != orderID {
			t.Fatalf("concurrent create returned different orders: %q and %q", orderID, results[i].Snapshot.OrderID)
		}
		if results[i].Replayed {
			replays++
		}
	}
	if replays != callers-1 {
		t.Fatalf("concurrent create replay count=%d, want %d", replays, callers-1)
	}

	changed := command
	changed.AmountMinor++
	if _, err := repo.Create(ctx, tenant, changed, testMetadata(string(tenant), nextUUID()), key, principal); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("same key with changed payload error=%v, want idempotency conflict", err)
	}
	otherPrincipal := testMetadata(string(tenant), nextUUID())
	otherPrincipal.ActorRef = "principal:another-user"
	if _, err := repo.Create(ctx, tenant, command, otherPrincipal, key, "principal:another-user"); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("same key with changed principal error=%v, want idempotency conflict", err)
	}

	const naturalKey = "natural-reference-key-01"
	if _, err := repo.Create(ctx, tenant, testCreate(command.ExternalReference), testMetadata(string(tenant), nextUUID()), naturalKey, principal); !errors.Is(err, ErrNaturalReferenceConflict) {
		t.Fatalf("duplicate natural reference error=%v, want conflict", err)
	}
	if _, err := repo.Create(ctx, tenant, testCreate(command.ExternalReference), testMetadata(string(tenant), nextUUID()), naturalKey, principal); !errors.Is(err, ErrNaturalReferenceConflict) {
		t.Fatalf("replayed natural-reference rejection error=%v, want same conflict", err)
	}

	// Different keys racing on the same aggregate serialize through FOR UPDATE and version CAS.
	const submitCallers = 6
	submitResults := make([]Result, submitCallers)
	submitErrors := make([]error, submitCallers)
	start = make(chan struct{})
	for i := range submitCallers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			meta := testMetadata(string(tenant), orderID)
			meta.ActorRef = principal
			submitResults[i], submitErrors[i] = repo.Submit(ctx, tenant, orderID, 1, testSubmit(), meta, fmt.Sprintf("submit-distinct-key-%04d", i), principal)
		}(i)
	}
	close(start)
	wg.Wait()
	successes, conflicts := 0, 0
	for i, err := range submitErrors {
		switch {
		case err == nil:
			successes++
			if submitResults[i].Snapshot.Version != 2 || submitResults[i].Snapshot.Status != orders.Submitted {
				t.Fatalf("submit %d returned unexpected snapshot: %+v", i, submitResults[i].Snapshot)
			}
		case errors.Is(err, orders.ErrVersionConflict):
			conflicts++
		default:
			t.Fatalf("submit %d failed unexpectedly: %v", i, err)
		}
	}
	if successes != 1 || conflicts != submitCallers-1 {
		t.Fatalf("submit successes=%d conflicts=%d, want 1 and %d", successes, conflicts, submitCallers-1)
	}
	if _, err := repo.Load(ctx, mustTenant(t, "22222222-2222-4222-8222-222222222222"), orderID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant read error=%v, want not found", err)
	}
	events, err := repo.Events(ctx, tenant, orderID)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("event count=%d, want exactly create+submit", len(events))
	}

	// A late event uniqueness failure must roll back the newly claimed key and inserted head.
	rollbackKey := "rollback-event-collision-0001"
	rollbackMetadata := testMetadata(string(tenant), nextUUID())
	rollbackMetadata.EventID = events[0].Metadata.EventID
	rollbackCommand := testCreate("rollback-" + nextUUID())
	if _, err := repo.Create(ctx, tenant, rollbackCommand, rollbackMetadata, rollbackKey, principal); err == nil {
		t.Fatal("duplicate event ID unexpectedly committed")
	}
	committed, err := repo.Create(ctx, tenant, rollbackCommand, testMetadata(string(tenant), nextUUID()), rollbackKey, principal)
	if err != nil {
		t.Fatalf("retry after rolled-back transaction failed: %v", err)
	}
	if committed.Replayed || committed.Snapshot.ExternalReference != rollbackCommand.ExternalReference {
		t.Fatalf("rolled-back claim was not reusable: %+v", committed)
	}
}

func TestPostgreSQLExpiredDetailRetainsDedupTombstone(t *testing.T) {
	_, tenant, repo := repositoryTestDB(t)
	workerDSN := os.Getenv("KEEL_TEST_WORKER_DATABASE_URL")
	adminDSN := os.Getenv("KEEL_TEST_ADMIN_DATABASE_URL")
	if workerDSN == "" || adminDSN == "" {
		t.Skip("set worker and test-admin database URLs for the response-expiry integration test")
	}
	worker := integrationDB(t, workerDSN, 2)
	admin := integrationDB(t, adminDSN, 2)
	workerRepo, err := NewRepository(worker)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	key := "expiry-retry-key-0001"
	command := testCreate("expired-detail-" + nextUUID())
	principal := "principal:requester-1"
	created, err := repo.Create(ctx, tenant, command, testMetadata(string(tenant), nextUUID()), key, principal)
	if err != nil {
		t.Fatal(err)
	}
	meta := testMetadata(string(tenant), created.Snapshot.OrderID)
	meta.ActorRef = principal
	if _, err := repo.Submit(ctx, tenant, created.Snapshot.OrderID, 1, testSubmit(), meta, "expiry-submit-key-0001", principal); err != nil {
		t.Fatal(err)
	}
	keyHash, err := KeyDigest(key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin.ExecContext(ctx, `UPDATE keel_meta.idempotency_requests SET expires_at=clock_timestamp()-interval '8 days' WHERE tenant_id=$1 AND route=$2 AND key_digest=$3`, string(tenant), createRoute, keyHash); err != nil {
		t.Fatalf("age response detail using test admin connection: %v", err)
	}
	deleted, err := workerRepo.PruneExpiredResponses(ctx, tenant, 10)
	if err != nil {
		t.Fatal(err)
	}
	if deleted != 1 {
		t.Fatalf("pruned response details=%d, want 1", deleted)
	}
	replayed, err := repo.Create(ctx, tenant, command, testMetadata(string(tenant), nextUUID()), key, principal)
	if err != nil {
		t.Fatal(err)
	}
	if !replayed.Replayed || !replayed.DetailsExpired || replayed.Snapshot.OrderID != created.Snapshot.OrderID || replayed.Snapshot.Version != 2 {
		t.Fatalf("expired retry did not resolve latest original operation: %+v", replayed)
	}
	events, err := repo.Events(ctx, tenant, created.Snapshot.OrderID)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("retry after expiry produced %d events, want exactly 2", len(events))
	}
	var details, tombstones int
	if err := admin.QueryRowContext(ctx, `SELECT
		(SELECT count(*) FROM keel_meta.idempotency_requests WHERE tenant_id=$1 AND route=$2 AND key_digest=$3),
		(SELECT count(*) FROM keel_meta.idempotency_dedup WHERE tenant_id=$1 AND route=$2 AND key_digest=$3)`, string(tenant), createRoute, keyHash).Scan(&details, &tombstones); err != nil {
		t.Fatal(err)
	}
	if details != 0 || tombstones != 1 {
		t.Fatalf("expired registry state details=%d tombstones=%d, want 0 and 1", details, tombstones)
	}
}
