package dbquery

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/sanskarpan/keel/internal/platform/observability"
)

// recordingObserver captures emitted events so statement observation can be asserted directly.
type recordingObserver struct {
	events []observability.Event
}

func (o *recordingObserver) Observe(event observability.Event) {
	o.events = append(o.events, event)
}

func testDatabase(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("KEEL_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set KEEL_TEST_DATABASE_URL to a least-privilege Keel app database role")
	}
	parsed, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("pgx", parsed.String())
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(2)
	db.SetMaxIdleConns(2)
	if err := db.PingContext(context.Background()); err != nil {
		_ = db.Close()
		t.Fatalf("connect to the test database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestStatementHelpersRecordReadAndWriteClasses(t *testing.T) {
	db := testDatabase(t)
	observer := &recordingObserver{}
	recorder := observability.NewStatementRecorder(observer, context.Background())
	ctx := observability.WithStatementRecorder(context.Background(), recorder)

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	var marker string
	if err := ReadRow(ctx, tx, `SELECT 'dbquery-read'::text`).Scan(&marker); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if marker != "dbquery-read" {
		_ = tx.Rollback()
		t.Fatalf("unexpected read value %q", marker)
	}
	if _, err := Write(ctx, tx, `SELECT 1`); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	recorder.Flush()

	if len(observer.events) != 2 {
		t.Fatalf("expected two statement events, got %d: %+v", len(observer.events), observer.events)
	}
	if observer.events[0].Operation != "query.read" || observer.events[0].Outcome != "ok" {
		t.Fatalf("read statement was not classified: %+v", observer.events[0])
	}
	if observer.events[1].Operation != "query.write" || observer.events[1].Outcome != "ok" {
		t.Fatalf("write statement was not classified: %+v", observer.events[1])
	}
}

func TestStatementHelpersReportFailedStatements(t *testing.T) {
	db := testDatabase(t)
	observer := &recordingObserver{}
	recorder := observability.NewStatementRecorder(observer, context.Background())
	ctx := observability.WithStatementRecorder(context.Background(), recorder)

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Write(ctx, tx, `SELECT missing_column FROM keel_meta.schema_migrations`); err == nil {
		_ = tx.Rollback()
		t.Fatal("an invalid statement unexpectedly succeeded")
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	recorder.Flush()

	if len(observer.events) != 1 || observer.events[0].Outcome != "error" {
		t.Fatalf("a failed statement was not reported as an error: %+v", observer.events)
	}
}

func TestStatementHelpersReportMissingRowAsSuccessfulStatement(t *testing.T) {
	db := testDatabase(t)
	observer := &recordingObserver{}
	recorder := observability.NewStatementRecorder(observer, context.Background())
	ctx := observability.WithStatementRecorder(context.Background(), recorder)

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	var missing string
	err = ReadRow(ctx, tx, `SELECT 'missing'::text WHERE false`).Scan(&missing)
	if !errors.Is(err, sql.ErrNoRows) {
		_ = tx.Rollback()
		t.Fatalf("expected a missing row, got %v", err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	recorder.Flush()

	if len(observer.events) != 1 || observer.events[0].Outcome != "ok" {
		t.Fatalf("a missing row was not reported as a successful statement: %+v", observer.events)
	}
}

func TestStatementHelpersCarryNoStatementContent(t *testing.T) {
	db := testDatabase(t)
	observer := &recordingObserver{}
	recorder := observability.NewStatementRecorder(observer, context.Background())
	ctx := observability.WithStatementRecorder(context.Background(), recorder)

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	var secret string
	if err := ReadRow(ctx, tx, `SELECT 'sensitive-value'::text`).Scan(&secret); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	recorder.Flush()

	if len(observer.events) != 1 {
		t.Fatalf("expected one statement event, got %+v", observer.events)
	}
	event := observer.events[0]
	if event.Operation != "query.read" || event.Outcome != "ok" {
		t.Fatalf("unexpected statement event: %+v", event)
	}
	if event.SchemaVersion != 0 || event.RetryCount != 0 {
		t.Fatalf("messaging-only fields were populated: %+v", event)
	}
	if event.Duration < 0 || event.Duration > time.Hour {
		t.Fatalf("statement duration was not bounded: %+v", event)
	}
}

func TestStatementHelpersWithoutRecorderStaySilent(t *testing.T) {
	db := testDatabase(t)
	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	var marker string
	if err := ReadRow(ctx, tx, `SELECT 'dbquery-plain'::text`).Scan(&marker); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
}
