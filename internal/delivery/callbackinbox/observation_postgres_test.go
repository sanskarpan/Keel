package callbackinbox

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

var errSyntheticApplier = errors.New("synthetic application failed")

type observationRow struct {
	provider string
	eventID  string
	outcome  string
	delay    sql.NullInt64
}

func observationRows(t *testing.T, admin *sql.DB, fixture callbackFixture) []observationRow {
	t.Helper()
	rows, err := admin.QueryContext(context.Background(),
		`SELECT provider,provider_event_id,outcome,redelivery_delay_ms
		   FROM keel_meta.provider_callback_observations
		  WHERE tenant_id=$1 ORDER BY observation_id`,
		string(fixture.tenant))
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var observations []observationRow
	for rows.Next() {
		var row observationRow
		if err := rows.Scan(&row.provider, &row.eventID, &row.outcome, &row.delay); err != nil {
			t.Fatal(err)
		}
		observations = append(observations, row)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return observations
}

func acceptFixture(t *testing.T, inbox *Inbox, fixture callbackFixture, apply Applier) Receipt {
	t.Helper()
	receipt, err := inbox.Accept(context.Background(), fixture.request(), apply)
	if err != nil {
		t.Fatalf("accept callback: %v", err)
	}
	return receipt
}

func noopApplier(context.Context, *sql.Tx, VerifiedEvent) error { return nil }

func TestPostgreSQLProviderObservationsTrailDeliveries(t *testing.T) {
	callbackDB, admin := callbackTestDatabases(t)
	fixture := newCallbackFixture(t)
	inbox := newInbox(t, callbackDB, fixture.event)

	acceptFixture(t, inbox, fixture, noopApplier)
	observations := observationRows(t, admin, fixture)
	if len(observations) != 1 {
		t.Fatalf("observations = %+v, want 1", observations)
	}
	if observations[0].outcome != "applied" || observations[0].delay.Valid {
		t.Fatalf("first observation = %+v, want applied without delay", observations[0])
	}

	time.Sleep(10 * time.Millisecond)
	receipt := acceptFixture(t, inbox, fixture, noopApplier)
	if !receipt.Duplicate {
		t.Fatal("redelivery was not reported as duplicate")
	}
	observations = observationRows(t, admin, fixture)
	if len(observations) != 2 {
		t.Fatalf("observations = %+v, want 2", observations)
	}
	second := observations[1]
	if second.outcome != "duplicate" || !second.delay.Valid || second.delay.Int64 < 0 {
		t.Fatalf("second observation = %+v, want duplicate with delay", second)
	}
}

func TestPostgreSQLProviderObservationsRecordConflicts(t *testing.T) {
	callbackDB, admin := callbackTestDatabases(t)
	fixture := newCallbackFixture(t)
	inbox := newInbox(t, callbackDB, fixture.event)
	acceptFixture(t, inbox, fixture, noopApplier)

	conflicting := fixture
	conflicting.event.PayloadDigest = strings.Repeat("1", 64)
	conflictInbox := newInbox(t, callbackDB, conflicting.event)
	if _, err := conflictInbox.Accept(context.Background(), conflicting.request(), noopApplier); err == nil {
		t.Fatal("conflicting callback was accepted")
	}
	observations := observationRows(t, admin, fixture)
	if len(observations) != 2 {
		t.Fatalf("observations = %+v, want applied plus conflict", observations)
	}
	if observations[1].outcome != "conflict" || observations[1].delay.Valid {
		t.Fatalf("conflict observation = %+v", observations[1])
	}
}

func TestPostgreSQLProviderObservationsRollBackWithApplication(t *testing.T) {
	callbackDB, admin := callbackTestDatabases(t)
	fixture := newCallbackFixture(t)
	inbox := newInbox(t, callbackDB, fixture.event)
	if _, err := inbox.Accept(context.Background(), fixture.request(), func(context.Context, *sql.Tx, VerifiedEvent) error {
		return errSyntheticApplier
	}); err == nil {
		t.Fatal("failing application was accepted")
	}
	if observations := observationRows(t, admin, fixture); len(observations) != 0 {
		t.Fatalf("rolled-back application left %+v", observations)
	}
}

func TestPostgreSQLProviderObservationsDenyDirectAccess(t *testing.T) {
	callbackDB, admin := callbackTestDatabases(t)
	fixture := newCallbackFixture(t)
	acceptFixture(t, newInbox(t, callbackDB, fixture.event), fixture, noopApplier)
	ctx := context.Background()

	var count int
	if err := callbackDB.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM keel_meta.provider_callback_observations`).Scan(&count); err == nil {
		t.Fatal("callback capability could read the observation ledger directly")
	}
	if _, err := admin.ExecContext(ctx,
		`UPDATE keel_meta.provider_callback_observations SET outcome='duplicate'
		  WHERE tenant_id=$1`, string(fixture.tenant)); err == nil {
		t.Fatal("direct update of an observation was accepted")
	} else if !strings.Contains(err.Error(), "immutable") {
		t.Fatalf("observation update error was %v, want an immutability error", err)
	}
	if _, err := admin.ExecContext(ctx,
		`DELETE FROM keel_meta.provider_callback_observations WHERE tenant_id=$1`,
		string(fixture.tenant)); err == nil {
		t.Fatal("direct deletion of an observation was accepted")
	}
}

func TestPostgreSQLProviderObservationsRejectMissingCapability(t *testing.T) {
	appDSN := os.Getenv("KEEL_TEST_DATABASE_URL")
	if appDSN == "" {
		t.Skip("set KEEL_TEST_DATABASE_URL for observation capability coverage")
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
	var observation int64
	if err := tx.QueryRowContext(ctx,
		`SELECT r_observation_id FROM keel_meta.record_provider_callback_observation($1,$2,$3,$4)`,
		fixture.provider, fixture.eventID, "applied", nil).Scan(&observation); err == nil {
		t.Fatal("an app role recorded a provider observation without the callback capability")
	}
}
