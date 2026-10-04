package postgres

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"reflect"
	"sort"
	"strings"
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

func TestPostgreSQLCommandOutboxAndStateFeedAreAtomicAndPrivate(t *testing.T) {
	appDB, tenant, repo := repositoryTestDB(t)
	adminDSN := os.Getenv("KEEL_TEST_ADMIN_DATABASE_URL")
	workerDSN := os.Getenv("KEEL_TEST_WORKER_DATABASE_URL")
	if adminDSN == "" || workerDSN == "" {
		t.Skip("set worker and test-admin database URLs for outbox/state-feed integration coverage")
	}
	admin := integrationDB(t, adminDSN, 2)
	worker := integrationDB(t, workerDSN, 2)
	ctx := context.Background()
	principal := "principal:requester-1"
	secretCanary := "ORDER-PII-CANARY-" + nextUUID()
	command := testCreate(secretCanary)
	command.LineItems[0].Description = "DESCRIPTION-CANARY-" + nextUUID()
	key := "outbox-atomicity-key-0001"
	created, err := repo.Create(ctx, tenant, command, testMetadata(string(tenant), nextUUID()), key, principal)
	if err != nil {
		t.Fatal(err)
	}
	keyHash, err := KeyDigest(key)
	if err != nil {
		t.Fatal(err)
	}
	var events, outboxRows, stateRows, resultRows int
	err = admin.QueryRowContext(ctx, `SELECT
		(SELECT count(*) FROM keel_meta.order_events WHERE tenant_id=$1 AND order_id=$2),
		(SELECT count(*) FROM keel_meta.event_outbox WHERE tenant_id=$1 AND aggregate_id=$2),
		(SELECT count(*) FROM keel_meta.state_updates WHERE tenant_id=$1 AND aggregate_id=$2),
		(SELECT count(*) FROM keel_meta.idempotency_requests WHERE tenant_id=$1 AND route=$3 AND key_digest=$4)`,
		string(tenant), created.Snapshot.OrderID, createRoute, keyHash).Scan(&events, &outboxRows, &stateRows, &resultRows)
	if err != nil {
		t.Fatal(err)
	}
	if events != 1 || outboxRows != 1 || stateRows != 1 || resultRows != 1 {
		t.Fatalf("created command records event/outbox/state/result=%d/%d/%d/%d, want one each", events, outboxRows, stateRows, resultRows)
	}
	var envelopeRaw, stateRaw []byte
	eventsInStream, err := repo.Events(ctx, tenant, created.Snapshot.OrderID)
	if err != nil {
		t.Fatal(err)
	}
	eventID := eventsInStream[0].Metadata.EventID
	if err := admin.QueryRowContext(ctx, `SELECT safe_envelope FROM keel_meta.event_outbox WHERE tenant_id=$1 AND event_id=$2`, string(tenant), eventID).Scan(&envelopeRaw); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRowContext(ctx, `SELECT safe_payload FROM keel_meta.state_updates WHERE tenant_id=$1 AND event_id=$2`, string(tenant), eventID).Scan(&stateRaw); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(envelopeRaw), secretCanary) || strings.Contains(string(envelopeRaw), command.LineItems[0].Description) || strings.Contains(string(stateRaw), secretCanary) || strings.Contains(string(stateRaw), command.LineItems[0].Description) {
		t.Fatal("safe outbox/state-feed payload leaked private order fields")
	}
	var envelopeFields, stateFields map[string]json.RawMessage
	if err := json.Unmarshal(envelopeRaw, &envelopeFields); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(stateRaw, &stateFields); err != nil {
		t.Fatal(err)
	}
	requireJSONKeys(t, envelopeFields, "aggregate_id", "aggregate_version", "event_id", "event_type", "occurred_at", "schema_version", "tenant_id")
	requireJSONKeys(t, stateFields, "aggregate_id", "aggregate_version", "event_id", "schema_version", "status")

	workerTxErr := tenancy.WithTenantTx(ctx, worker, tenant, &sql.TxOptions{ReadOnly: true}, func(tx *sql.Tx) error {
		var visible, visibleUpdates int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM keel_meta.event_outbox WHERE tenant_id=$1`, string(tenant)).Scan(&visible); err != nil {
			return err
		}
		if visible != 1 {
			return fmt.Errorf("worker sees %d outbox records, want one", visible)
		}
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM keel_meta.state_updates WHERE tenant_id=$1`, string(tenant)).Scan(&visibleUpdates); err != nil {
			return err
		}
		if visibleUpdates != 1 {
			return fmt.Errorf("worker sees %d state updates, want one", visibleUpdates)
		}
		return nil
	})
	if workerTxErr != nil {
		t.Fatalf("scoped worker cannot read safe outbox envelope: %v", workerTxErr)
	}
	statements := []string{
		`UPDATE keel_meta.order_events SET event_data=event_data WHERE tenant_id=$1 AND event_id=$2`,
		`DELETE FROM keel_meta.event_outbox WHERE tenant_id=$1 AND event_id=$2`,
	}
	for _, principalDB := range []*sql.DB{appDB, worker} {
		for _, statement := range statements {
			if _, err := principalDB.ExecContext(ctx, statement, string(tenant), eventID); err == nil {
				t.Fatalf("runtime role unexpectedly changed append-only record with %q", statement)
			}
		}
	}
	if _, err := appDB.ExecContext(ctx, `DELETE FROM keel_meta.state_updates WHERE tenant_id=$1 AND event_id=$2`, string(tenant), eventID); err == nil {
		t.Fatal("application role unexpectedly deleted a state-feed record")
	}

	meta := testMetadata(string(tenant), created.Snapshot.OrderID)
	meta.ActorRef = principal
	if _, err := repo.Submit(ctx, tenant, created.Snapshot.OrderID, 1, testSubmit(), meta, "outbox-submit-key-0001", principal); err != nil {
		t.Fatal(err)
	}
	const concurrentOrders = 4
	concurrentErrors := make([]error, concurrentOrders)
	var wg sync.WaitGroup
	for i := range concurrentOrders {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			orderCommand := testCreate("feed-concurrent-" + nextUUID())
			concurrentErrors[i] = func() error {
				_, err := repo.Create(ctx, tenant, orderCommand, testMetadata(string(tenant), nextUUID()), fmt.Sprintf("feed-concurrent-key-%04d", i), principal)
				return err
			}()
		}(i)
	}
	wg.Wait()
	for i, err := range concurrentErrors {
		if err != nil {
			t.Fatalf("concurrent state-feed create %d: %v", i, err)
		}
	}
	var counter int64
	var stateSequence []int64
	rows, err := admin.QueryContext(ctx, `SELECT sequence FROM keel_meta.state_updates WHERE tenant_id=$1 ORDER BY sequence`, string(tenant))
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var sequence int64
		if err := rows.Scan(&sequence); err != nil {
			_ = rows.Close()
			t.Fatal(err)
		}
		stateSequence = append(stateSequence, sequence)
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRowContext(ctx, `SELECT last_sequence FROM keel_meta.state_feed_counters WHERE tenant_id=$1`, string(tenant)).Scan(&counter); err != nil {
		t.Fatal(err)
	}
	if len(stateSequence) != 2+concurrentOrders || counter != int64(2+concurrentOrders) {
		t.Fatalf("tenant state-feed sequence=%v counter=%d, want %d consecutive records", stateSequence, counter, 2+concurrentOrders)
	}
	for i, sequence := range stateSequence {
		if sequence != int64(i+1) {
			t.Fatalf("tenant state-feed sequence=%v has a gap or reorder at position %d", stateSequence, i)
		}
	}
	workerRepo, err := NewRepository(worker)
	if err != nil {
		t.Fatal(err)
	}
	if err := tenancy.WithTenantTx(ctx, worker, tenant, nil, func(tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx, `DELETE FROM keel_meta.state_updates WHERE tenant_id=$1 AND sequence=1`, string(tenant))
		if err != nil {
			return err
		}
		deleted, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if deleted != 0 {
			return fmt.Errorf("worker deleted %d fresh state-feed rows", deleted)
		}
		return nil
	}); err != nil {
		t.Fatalf("worker fresh-row retention boundary: %v", err)
	}
	if _, err := admin.ExecContext(ctx, `UPDATE keel_meta.state_updates SET created_at=clock_timestamp()-interval '25 hours' WHERE tenant_id=$1`, string(tenant)); err != nil {
		t.Fatal(err)
	}
	firstBatch, err := workerRepo.PruneExpiredStateUpdates(ctx, tenant, 3)
	if err != nil {
		t.Fatal(err)
	}
	secondBatch, err := workerRepo.PruneExpiredStateUpdates(ctx, tenant, 10)
	if err != nil {
		t.Fatal(err)
	}
	if firstBatch != 3 || secondBatch != int64(len(stateSequence)-3) {
		t.Fatalf("state-feed prune batches=%d/%d, want 3/%d", firstBatch, secondBatch, len(stateSequence)-3)
	}
	if err := admin.QueryRowContext(ctx, `SELECT last_sequence FROM keel_meta.state_feed_counters WHERE tenant_id=$1`, string(tenant)).Scan(&counter); err != nil {
		t.Fatal(err)
	}
	if counter != int64(len(stateSequence)) {
		t.Fatalf("feed cursor reset after pruning: %d, want to retain %d", counter, len(stateSequence))
	}
	if _, err := repo.Create(ctx, tenant, testCreate("post-prune-"+nextUUID()), testMetadata(string(tenant), nextUUID()), "post-prune-create-key-0001", "principal:requester-1"); err != nil {
		t.Fatalf("create after state-feed pruning: %v", err)
	}
	var nextSequence int64
	if err := admin.QueryRowContext(ctx, `SELECT max(sequence) FROM keel_meta.state_updates WHERE tenant_id=$1`, string(tenant)).Scan(&nextSequence); err != nil {
		t.Fatal(err)
	}
	if nextSequence != int64(len(stateSequence)+1) {
		t.Fatalf("state-feed cursor after prune=%d, want %d", nextSequence, len(stateSequence)+1)
	}
}

func TestPostgreSQLLateStateFeedFailureRollsBackCommandAndCanRetry(t *testing.T) {
	_, tenant, repo := repositoryTestDB(t)
	adminDSN := os.Getenv("KEEL_TEST_ADMIN_DATABASE_URL")
	if adminDSN == "" {
		t.Skip("set KEEL_TEST_ADMIN_DATABASE_URL to verify rollback after the final transactional append")
	}
	admin := integrationDB(t, adminDSN, 2)
	ctx := context.Background()
	command := testCreate("late-feed-failure-" + nextUUID())
	key := "late-feed-failure-key-0001"
	orderID := nextUUID()
	constraint := "state_updates_test_reject_all"
	if _, err := admin.ExecContext(ctx, `ALTER TABLE keel_meta.state_updates ADD CONSTRAINT `+constraint+` CHECK (false) NOT VALID`); err != nil {
		t.Fatalf("install scoped failure constraint: %v", err)
	}
	dropped := false
	t.Cleanup(func() {
		if !dropped {
			_, _ = admin.ExecContext(context.Background(), `ALTER TABLE keel_meta.state_updates DROP CONSTRAINT IF EXISTS `+constraint)
		}
	})
	if _, err := repo.Create(ctx, tenant, command, testMetadata(string(tenant), orderID), key, "principal:requester-1"); err == nil {
		t.Fatal("state-feed insert failure unexpectedly committed the order")
	}
	if _, err := admin.ExecContext(ctx, `ALTER TABLE keel_meta.state_updates DROP CONSTRAINT `+constraint); err != nil {
		t.Fatalf("remove scoped failure constraint: %v", err)
	}
	dropped = true
	if _, err := repo.Load(ctx, tenant, orderID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("aggregate head survived failed state-feed append: %v", err)
	}
	created, err := repo.Create(ctx, tenant, command, testMetadata(string(tenant), nextUUID()), key, "principal:requester-1")
	if err != nil {
		t.Fatalf("same key could not retry after full transaction rollback: %v", err)
	}
	if created.Replayed || created.Snapshot.OrderID == orderID {
		t.Fatalf("failed command left an idempotency result behind: %+v", created)
	}
	var events, outboxRows, feedRows int
	if err := admin.QueryRowContext(ctx, `SELECT
		(SELECT count(*) FROM keel_meta.order_events WHERE tenant_id=$1 AND order_id=$2),
		(SELECT count(*) FROM keel_meta.event_outbox WHERE tenant_id=$1 AND aggregate_id=$2),
		(SELECT count(*) FROM keel_meta.state_updates WHERE tenant_id=$1 AND aggregate_id=$2)`,
		string(tenant), created.Snapshot.OrderID).Scan(&events, &outboxRows, &feedRows); err != nil {
		t.Fatal(err)
	}
	if events != 1 || outboxRows != 1 || feedRows != 1 {
		t.Fatalf("retry created event/outbox/feed=%d/%d/%d, want exactly one each", events, outboxRows, feedRows)
	}
}

func requireJSONKeys(t *testing.T, value map[string]json.RawMessage, want ...string) {
	t.Helper()
	got := make([]string, 0, len(value))
	for key := range value {
		got = append(got, key)
	}
	sort.Strings(got)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("JSON keys=%v, want exactly %v", got, want)
	}
}
