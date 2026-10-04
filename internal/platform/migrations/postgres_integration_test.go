package migrations

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

const localMigrationLockID int64 = 772691034

func TestPostgreSQLMigrationSerializationAndChecksum(t *testing.T) {
	db, table := migrationTestDB(t)
	ctx := context.Background()
	body := fmt.Sprintf("CREATE TABLE tenant_data.%s (value integer NOT NULL); INSERT INTO tenant_data.%s VALUES (1); SELECT pg_catalog.pg_sleep(0.15);", quoteIdentifier(table), quoteIdentifier(table))
	source := migrationSource("0001_create_marker.up.sql", body)
	options := Options{LedgerTable: "schema_migrations_" + strings.TrimPrefix(table, "keel_migration_"), LockID: localMigrationLockID}
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- Apply(ctx, db, source, options)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	conn := asSchemaOwner(t, db)
	defer conn.Close()
	var markerCount, ledgerCount int
	if err := conn.QueryRowContext(ctx, `SELECT count(*) FROM tenant_data.`+quoteIdentifier(table)).Scan(&markerCount); err != nil {
		t.Fatal(err)
	}
	if err := conn.QueryRowContext(ctx, `SELECT count(*) FROM keel_meta.`+quoteIdentifier(options.LedgerTable)).Scan(&ledgerCount); err != nil {
		t.Fatal(err)
	}
	if markerCount != 1 || ledgerCount != 1 {
		t.Fatalf("after two serialized runners: marker rows=%d ledger rows=%d; want one each", markerCount, ledgerCount)
	}
	if err := Apply(ctx, db, migrationSource("0001_create_marker.up.sql", strings.ReplaceAll(body, "VALUES (1)", "VALUES (2)")), options); err == nil || !strings.Contains(err.Error(), "drift") {
		t.Fatalf("changed applied migration was accepted; error=%v", err)
	}
	if err := Apply(ctx, db, fstest.MapFS{}, options); err == nil || !strings.Contains(err.Error(), "absent from this binary") {
		t.Fatalf("binary missing an applied migration was accepted; error=%v", err)
	}
}

func TestPostgreSQLMigrationRejectsBackfillBehindAppliedVersion(t *testing.T) {
	db, table := migrationTestDB(t)
	ctx := context.Background()
	options := Options{LedgerTable: "schema_migrations_" + strings.TrimPrefix(table, "keel_migration_"), LockID: localMigrationLockID}
	newer := fmt.Sprintf("CREATE TABLE tenant_data.%s (value integer NOT NULL);", quoteIdentifier(table))
	if err := Apply(ctx, db, migrationSource("0002_newer.up.sql", newer), options); err != nil {
		t.Fatal(err)
	}
	older := "CREATE TABLE keel_meta.k0_migration_backfill_test (value integer);"
	withBackfill := fstest.MapFS{
		"0001_older.up.sql": {Data: []byte(older)},
		"0002_newer.up.sql": {Data: []byte(newer)},
	}
	if err := Apply(ctx, db, withBackfill, options); err == nil || !strings.Contains(err.Error(), "sorts before") {
		t.Fatalf("out-of-order backfill was accepted; error=%v", err)
	}
}

func TestPostgreSQLMigrationFailureRollsBackAndAllowsForwardRepair(t *testing.T) {
	db, table := migrationTestDB(t)
	ctx := context.Background()
	options := Options{LedgerTable: "schema_migrations_" + strings.TrimPrefix(table, "keel_migration_"), LockID: localMigrationLockID}
	broken := fmt.Sprintf("CREATE TABLE tenant_data.%s (value integer NOT NULL); SELECT 1 / 0;", quoteIdentifier(table))
	if err := Apply(ctx, db, migrationSource("0001_create_marker.up.sql", broken), options); err == nil {
		t.Fatal("failing migration unexpectedly succeeded")
	}
	conn := asSchemaOwner(t, db)
	var markerPresent bool
	if err := conn.QueryRowContext(ctx, `SELECT pg_catalog.to_regclass($1) IS NOT NULL`, "tenant_data."+table).Scan(&markerPresent); err != nil {
		t.Fatal(err)
	}
	if markerPresent {
		t.Fatal("DDL from a failed transaction was not rolled back")
	}
	var recorded int
	if err := conn.QueryRowContext(ctx, `SELECT count(*) FROM keel_meta.`+quoteIdentifier(options.LedgerTable)).Scan(&recorded); err != nil {
		t.Fatal(err)
	}
	if recorded != 0 {
		t.Fatalf("failed migration left %d ledger rows", recorded)
	}
	fixed := fmt.Sprintf("CREATE TABLE tenant_data.%s (value integer NOT NULL);", quoteIdentifier(table))
	if err := Apply(ctx, db, migrationSource("0001_create_marker.up.sql", fixed), options); err != nil {
		t.Fatalf("corrected migration could not be applied as a forward repair: %v", err)
	}
	_ = conn.Close()
}

func TestPostgreSQLMigrationRejectsTransactionControlBeforeMutation(t *testing.T) {
	db, table := migrationTestDB(t)
	ctx := context.Background()
	options := Options{LedgerTable: "schema_migrations_" + strings.TrimPrefix(table, "keel_migration_"), LockID: localMigrationLockID}
	body := fmt.Sprintf("CREATE TABLE tenant_data.%s (value integer NOT NULL); COMMIT;", quoteIdentifier(table))
	if err := Apply(ctx, db, migrationSource("0001_unsafe_commit.up.sql", body), options); err == nil || !strings.Contains(err.Error(), "transaction control") {
		t.Fatalf("transaction-control migration was not rejected: %v", err)
	}
	conn := asSchemaOwner(t, db)
	defer conn.Close()
	var objectPresent bool
	if err := conn.QueryRowContext(ctx, `SELECT pg_catalog.to_regclass($1) IS NOT NULL`, "tenant_data."+table).Scan(&objectPresent); err != nil {
		t.Fatal(err)
	}
	if objectPresent {
		t.Fatal("rejected transaction-control migration left schema changes behind")
	}
}

func migrationTestDB(t *testing.T) (*sql.DB, string) {
	t.Helper()
	rawURL := os.Getenv("KEEL_TEST_MIGRATION_DATABASE_URL")
	if rawURL == "" {
		t.Skip("set KEEL_TEST_MIGRATION_DATABASE_URL to a database with the local migration roles installed")
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("pgx", parsed.String())
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(4)
	if err := db.PingContext(context.Background()); err != nil {
		_ = db.Close()
		t.Fatalf("connect to migration test database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	table := fmt.Sprintf("keel_migration_%x", time.Now().UnixNano())
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn, err := db.Conn(cleanupCtx)
		if err != nil {
			return
		}
		defer conn.Close()
		if _, err := conn.ExecContext(cleanupCtx, `SET ROLE keel_schema_owner`); err != nil {
			return
		}
		_, _ = conn.ExecContext(cleanupCtx, `DROP TABLE IF EXISTS tenant_data.`+quoteIdentifier(table)+` CASCADE`)
		_, _ = conn.ExecContext(cleanupCtx, `DROP TABLE IF EXISTS keel_meta.`+quoteIdentifier("schema_migrations_"+strings.TrimPrefix(table, "keel_migration_"))+` CASCADE`)
	})
	return db, table
}

func asSchemaOwner(t *testing.T, db *sql.DB) *sql.Conn {
	t.Helper()
	conn, err := db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ExecContext(context.Background(), `SET ROLE keel_schema_owner`); err != nil {
		_ = conn.Close()
		t.Fatalf("assume schema owner for assertion: %v", err)
	}
	t.Cleanup(func() {
		_, _ = conn.ExecContext(context.Background(), `RESET ROLE`)
		_ = conn.Close()
	})
	return conn
}

func migrationSource(name, body string) fstest.MapFS {
	return fstest.MapFS{name: &fstest.MapFile{Data: []byte(body)}}
}
