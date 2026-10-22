package callbackinbox

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

func callbackTestDB(t *testing.T, dsn string) *sql.DB {
	t.Helper()
	parsed, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("pgx", parsed.String())
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(8)
	db.SetMaxIdleConns(8)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err = db.PingContext(ctx); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func callbackTestDatabases(t *testing.T) (*sql.DB, *sql.DB) {
	t.Helper()
	callbackDSN, adminDSN := os.Getenv("KEEL_TEST_CALLBACK_DATABASE_URL"), os.Getenv("KEEL_TEST_ADMIN_DATABASE_URL")
	if callbackDSN == "" || adminDSN == "" {
		t.Skip("set KEEL_TEST_CALLBACK_DATABASE_URL and KEEL_TEST_ADMIN_DATABASE_URL for callback inbox integration coverage")
	}
	return callbackTestDB(t, callbackDSN), callbackTestDB(t, adminDSN)
}

func newInbox(t *testing.T, db *sql.DB, event VerifiedEvent) *Inbox {
	t.Helper()
	inbox, err := New(db, verifierFunc(func(context.Context, VerificationRequest) (VerifiedEvent, error) {
		return event, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	return inbox
}

type callbackFixture struct {
	tenant   tenancy.TenantID
	provider string
	eventID  string
	payload  []byte
	event    VerifiedEvent
}

func newCallbackFixture(t *testing.T) callbackFixture {
	t.Helper()
	tenantID := uuid.NewString()
	tenant, err := tenancy.ParseTenantID(tenantID)
	if err != nil {
		t.Fatal(err)
	}
	eventID := "evt_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	payload := []byte(`{"event":"` + eventID + `","status":"settled"}`)
	return callbackFixture{
		tenant:   tenant,
		provider: "provider_one",
		eventID:  eventID,
		payload:  payload,
		event: VerifiedEvent{
			Tenant:          tenant,
			Provider:        "provider_one",
			ProviderEventID: eventID,
			PayloadDigest:   DigestPayload(payload),
			EventType:       "payment.settled",
			KeyID:           "key_2026_01",
			OccurredAt:      time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond),
		},
	}
}

func (f callbackFixture) request() VerificationRequest {
	return VerificationRequest{
		Provider:        f.provider,
		ProviderEventID: f.eventID,
		Payload:         f.payload,
		Signature:       []byte("signature"),
		Timestamp:       "2026-01-01T00:00:00Z",
	}
}

func callbackRowCount(t *testing.T, admin *sql.DB, fixture callbackFixture) int {
	t.Helper()
	var count int
	if err := admin.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM keel_meta.callback_inbox
		WHERE tenant_id=$1 AND provider=$2 AND provider_event_id=$3`,
		string(fixture.tenant), fixture.provider, fixture.eventID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func callbackStoredState(t *testing.T, admin *sql.DB, fixture callbackFixture) (string, string, time.Time) {
	t.Helper()
	var state, digest string
	var appliedAt time.Time
	if err := admin.QueryRowContext(context.Background(), `SELECT state,payload_digest,applied_at
		FROM keel_meta.callback_inbox WHERE tenant_id=$1 AND provider=$2 AND provider_event_id=$3`,
		string(fixture.tenant), fixture.provider, fixture.eventID).Scan(&state, &digest, &appliedAt); err != nil {
		t.Fatal(err)
	}
	return state, digest, appliedAt
}

func callbackConflict(t *testing.T, admin *sql.DB, tenant tenancy.TenantID, fixture callbackFixture) (int, string, string) {
	t.Helper()
	var count int
	var reason, digest string
	if err := admin.QueryRowContext(context.Background(), `SELECT COUNT(*),COALESCE(MIN(conflict_reason),''),COALESCE(MIN(presented_digest),'')
		FROM keel_meta.callback_conflicts WHERE tenant_id=$1 AND provider=$2 AND provider_event_id=$3`,
		string(tenant), fixture.provider, fixture.eventID).Scan(&count, &reason, &digest); err != nil {
		t.Fatal(err)
	}
	return count, reason, digest
}

func TestPostgreSQLCallbackInboxAppliesExactlyOnce(t *testing.T) {
	app, admin := callbackTestDatabases(t)
	fixture := newCallbackFixture(t)
	inbox := newInbox(t, app, fixture.event)

	var applied int
	apply := func(ctx context.Context, tx *sql.Tx, event VerifiedEvent) error {
		applied++
		if event != fixture.event {
			return fmt.Errorf("applier received %+v, want %+v", event, fixture.event)
		}
		return nil
	}
	first, err := inbox.Accept(context.Background(), fixture.request(), apply)
	if err != nil {
		t.Fatalf("first delivery: %v", err)
	}
	if first.Duplicate {
		t.Fatal("first delivery was reported as a duplicate")
	}
	if first.AppliedAt.IsZero() {
		t.Fatal("first delivery has no database application time")
	}
	if first.PayloadDigest != fixture.event.PayloadDigest || first.EventType != fixture.event.EventType {
		t.Fatalf("receipt did not echo the recorded event: %+v", first)
	}

	second, err := inbox.Accept(context.Background(), fixture.request(), apply)
	if err != nil {
		t.Fatalf("redelivery: %v", err)
	}
	if !second.Duplicate {
		t.Fatal("exact redelivery was not reported as a duplicate")
	}
	if !second.AppliedAt.Equal(first.AppliedAt) {
		t.Fatalf("duplicate applied time %s, want recorded %s", second.AppliedAt, first.AppliedAt)
	}
	if applied != 1 {
		t.Fatalf("applier ran %d times, want exactly once", applied)
	}
	if count := callbackRowCount(t, admin, fixture); count != 1 {
		t.Fatalf("inbox row count was %d, want 1", count)
	}
	state, digest, storedAt := callbackStoredState(t, admin, fixture)
	if state != "applied" || digest != fixture.event.PayloadDigest {
		t.Fatalf("stored state %q digest %q, want applied and %q", state, digest, fixture.event.PayloadDigest)
	}
	if !storedAt.Equal(first.AppliedAt) {
		t.Fatalf("stored applied time %s, want receipt %s", storedAt, first.AppliedAt)
	}
	if count, _, _ := callbackConflict(t, admin, fixture.tenant, fixture); count != 0 {
		t.Fatalf("exact redelivery recorded %d conflicts, want 0", count)
	}
}

func TestPostgreSQLCallbackInboxRejectsPayloadConflict(t *testing.T) {
	app, admin := callbackTestDatabases(t)
	fixture := newCallbackFixture(t)
	applied := 0
	apply := func(context.Context, *sql.Tx, VerifiedEvent) error {
		applied++
		return nil
	}
	if _, err := newInbox(t, app, fixture.event).Accept(context.Background(), fixture.request(), apply); err != nil {
		t.Fatalf("first delivery: %v", err)
	}

	conflicting := fixture
	conflicting.payload = []byte(`{"event":"` + fixture.eventID + `","status":"refunded"}`)
	conflicting.event.PayloadDigest = DigestPayload(conflicting.payload)
	if _, err := newInbox(t, app, conflicting.event).Accept(context.Background(), conflicting.request(), apply); !errors.Is(err, ErrConflict) {
		t.Fatalf("payload conflict error was %v, want ErrConflict", err)
	}
	if applied != 1 {
		t.Fatalf("applier ran %d times, want 1", applied)
	}
	if count := callbackRowCount(t, admin, fixture); count != 1 {
		t.Fatalf("inbox row count was %d, want 1", count)
	}
	_, digest, _ := callbackStoredState(t, admin, fixture)
	if digest != fixture.event.PayloadDigest {
		t.Fatalf("stored digest changed to %q after a conflict", digest)
	}
	count, reason, presented := callbackConflict(t, admin, fixture.tenant, fixture)
	if count != 1 || reason != "payload_mismatch" {
		t.Fatalf("conflict evidence count %d reason %q, want 1 payload_mismatch", count, reason)
	}
	if presented != conflicting.event.PayloadDigest {
		t.Fatalf("conflict presented digest %q, want %q", presented, conflicting.event.PayloadDigest)
	}
}

func TestPostgreSQLCallbackInboxRejectsCrossTenantReplay(t *testing.T) {
	app, admin := callbackTestDatabases(t)
	fixture := newCallbackFixture(t)
	applied := 0
	apply := func(context.Context, *sql.Tx, VerifiedEvent) error {
		applied++
		return nil
	}
	if _, err := newInbox(t, app, fixture.event).Accept(context.Background(), fixture.request(), apply); err != nil {
		t.Fatalf("first delivery: %v", err)
	}

	other := fixture
	otherTenantID := uuid.NewString()
	otherTenant, err := tenancy.ParseTenantID(otherTenantID)
	if err != nil {
		t.Fatal(err)
	}
	other.tenant = otherTenant
	other.event.Tenant = otherTenant
	if _, err := newInbox(t, app, other.event).Accept(context.Background(), other.request(), apply); !errors.Is(err, ErrConflict) {
		t.Fatalf("cross-tenant replay error was %v, want ErrConflict", err)
	}
	if applied != 1 {
		t.Fatalf("applier ran %d times, want 1", applied)
	}
	if count := callbackRowCount(t, admin, fixture); count != 1 {
		t.Fatalf("original tenant row count was %d, want 1", count)
	}
	if count := callbackRowCount(t, admin, other); count != 0 {
		t.Fatalf("replaying tenant recorded %d inbox rows, want 0", count)
	}
	count, reason, _ := callbackConflict(t, admin, otherTenant, fixture)
	if count != 1 || reason != "tenant_mismatch" {
		t.Fatalf("conflict evidence count %d reason %q, want 1 tenant_mismatch", count, reason)
	}
	if count, _, _ := callbackConflict(t, admin, fixture.tenant, fixture); count != 0 {
		t.Fatalf("original tenant recorded %d conflicts, want 0", count)
	}
}

func TestPostgreSQLCallbackInboxRollsBackFailedApplication(t *testing.T) {
	app, admin := callbackTestDatabases(t)
	fixture := newCallbackFixture(t)
	inbox := newInbox(t, app, fixture.event)

	failure := errors.New("domain effect was rejected")
	_, err := inbox.Accept(context.Background(), fixture.request(), func(context.Context, *sql.Tx, VerifiedEvent) error {
		return failure
	})
	if !errors.Is(err, failure) {
		t.Fatalf("failed application error was %v, want the applier error", err)
	}
	if count := callbackRowCount(t, admin, fixture); count != 0 {
		t.Fatalf("a failed application left %d inbox rows, want 0", count)
	}

	applied := 0
	if _, err := inbox.Accept(context.Background(), fixture.request(), func(context.Context, *sql.Tx, VerifiedEvent) error {
		applied++
		return nil
	}); err != nil {
		t.Fatalf("retry after a failed application: %v", err)
	}
	if applied != 1 {
		t.Fatalf("retry applied %d times, want 1", applied)
	}
	if count := callbackRowCount(t, admin, fixture); count != 1 {
		t.Fatalf("retry left %d inbox rows, want 1", count)
	}
	if count, _, _ := callbackConflict(t, admin, fixture.tenant, fixture); count != 0 {
		t.Fatalf("retry recorded %d conflicts, want 0", count)
	}
}

func TestPostgreSQLCallbackInboxAppliesConcurrentDeliveryOnce(t *testing.T) {
	app, admin := callbackTestDatabases(t)
	fixture := newCallbackFixture(t)
	first, second := newInbox(t, app, fixture.event), newInbox(t, app, fixture.event)
	var applied atomic.Int32
	apply := func(context.Context, *sql.Tx, VerifiedEvent) error {
		applied.Add(1)
		time.Sleep(200 * time.Millisecond)
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	inboxes := []*Inbox{first, second}
	receipts := make([]Receipt, 2)
	errs := make([]error, 2)
	var wg sync.WaitGroup
	for i := range inboxes {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			receipts[index], errs[index] = inboxes[index].Accept(ctx, fixture.request(), apply)
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("concurrent delivery %d: %v", i, err)
		}
	}
	duplicates := 0
	if receipts[0].Duplicate {
		duplicates++
	}
	if receipts[1].Duplicate {
		duplicates++
	}
	if duplicates != 1 {
		t.Fatalf("concurrent deliveries reported %d duplicates, want exactly 1", duplicates)
	}
	if got := applied.Load(); got != 1 {
		t.Fatalf("applier ran %d times under concurrency, want 1", got)
	}
	if count := callbackRowCount(t, admin, fixture); count != 1 {
		t.Fatalf("concurrent delivery left %d inbox rows, want 1", count)
	}
}

func TestPostgreSQLCallbackInboxDeniesDirectAccessAndMutation(t *testing.T) {
	callbackDB, admin := callbackTestDatabases(t)
	fixture := newCallbackFixture(t)
	if _, err := newInbox(t, callbackDB, fixture.event).Accept(context.Background(), fixture.request(), func(context.Context, *sql.Tx, VerifiedEvent) error {
		return nil
	}); err != nil {
		t.Fatalf("seed callback: %v", err)
	}

	ctx := context.Background()
	var count int
	if err := callbackDB.QueryRowContext(ctx, `SELECT COUNT(*) FROM keel_meta.callback_inbox`).Scan(&count); err == nil {
		t.Fatal("callback capability could read the inbox table directly")
	}
	if err := callbackDB.QueryRowContext(ctx, `SELECT COUNT(*) FROM keel_meta.callback_conflicts`).Scan(&count); err == nil {
		t.Fatal("callback capability could read the conflict ledger directly")
	}
	if _, err := callbackDB.ExecContext(ctx, `INSERT INTO keel_meta.callback_inbox
		(tenant_id,provider,provider_event_id,payload_digest,event_type,key_id,occurred_at)
		VALUES($1,$2,$3,$4,$5,$6,now())`, string(fixture.tenant), fixture.provider, "evt_direct_insert",
		fixture.event.PayloadDigest, "payment.settled", "key_2026_01"); err == nil {
		t.Fatal("callback capability could insert into the inbox table directly")
	}

	if _, err := admin.ExecContext(ctx, `UPDATE keel_meta.callback_inbox SET payload_digest=$1
		WHERE tenant_id=$2 AND provider=$3 AND provider_event_id=$4`,
		strings.Repeat("0", 64), string(fixture.tenant), fixture.provider, fixture.eventID); err == nil {
		t.Fatal("direct update of a recorded callback was accepted")
	} else if !strings.Contains(err.Error(), "immutable") {
		t.Fatalf("direct update error was %v, want an immutability error", err)
	}
	if _, err := admin.ExecContext(ctx, `DELETE FROM keel_meta.callback_inbox
		WHERE tenant_id=$1 AND provider=$2 AND provider_event_id=$3`,
		string(fixture.tenant), fixture.provider, fixture.eventID); err == nil {
		t.Fatal("direct deletion of a recorded callback was accepted")
	} else if !strings.Contains(err.Error(), "immutable") {
		t.Fatalf("direct delete error was %v, want an immutability error", err)
	}
	if _, err := admin.ExecContext(ctx, `UPDATE keel_meta.callback_conflicts SET conflict_reason='payload_mismatch'`); err == nil {
		t.Fatal("direct update of the conflict ledger was accepted")
	} else if !strings.Contains(err.Error(), "append-only") {
		t.Fatalf("conflict update error was %v, want an append-only error", err)
	}

	_, digest, _ := callbackStoredState(t, admin, fixture)
	if digest != fixture.event.PayloadDigest {
		t.Fatalf("stored digest changed to %q", digest)
	}
}

func TestPostgreSQLCallbackInboxRejectsMissingCapability(t *testing.T) {
	appDSN := os.Getenv("KEEL_TEST_DATABASE_URL")
	adminDSN := os.Getenv("KEEL_TEST_ADMIN_DATABASE_URL")
	if adminDSN == "" || appDSN == "" {
		t.Skip("set KEEL_TEST_DATABASE_URL and KEEL_TEST_ADMIN_DATABASE_URL for callback capability coverage")
	}
	app := callbackTestDB(t, appDSN)
	fixture := newCallbackFixture(t)
	ctx := context.Background()
	tx, err := app.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, "SELECT set_config('keel.tenant_id', $1, true)", string(fixture.tenant)); err != nil {
		t.Fatal(err)
	}
	var outcome string
	var appliedAt sql.NullTime
	if err := tx.QueryRowContext(ctx, `SELECT outcome,applied_at FROM keel_meta.claim_provider_callback($1,$2,$3,$4,$5,$6)`,
		fixture.provider, fixture.eventID, fixture.event.PayloadDigest, fixture.event.EventType,
		fixture.event.KeyID, fixture.event.OccurredAt).Scan(&outcome, &appliedAt); err == nil {
		t.Fatal("an app role could claim a provider callback without the callback capability")
	}
}
