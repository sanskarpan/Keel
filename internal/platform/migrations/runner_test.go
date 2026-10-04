package migrations

import (
	"testing"
	"testing/fstest"
)

func TestReadMigrationsOrdersAndChecksFiles(t *testing.T) {
	source := fstest.MapFS{
		"0002_add_index.up.sql":    {Data: []byte("CREATE INDEX x ON y (z);\n")},
		"0001_create_table.up.sql": {Data: []byte("CREATE TABLE x (z integer);\n")},
		"README.md":                {Data: []byte("not a migration")},
	}
	got, err := readMigrations(source)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].version != 1 || got[1].version != 2 {
		t.Fatalf("migration order = %#v", got)
	}
	if len(got[0].checksum) != 64 {
		t.Fatalf("SHA-256 checksum length = %d, want 64", len(got[0].checksum))
	}
}

func TestReadMigrationsRejectsDuplicateVersionAndInvalidSQLFile(t *testing.T) {
	for name, source := range map[string]fstest.MapFS{
		"duplicate version": {
			"0001_first.up.sql":  {Data: []byte("SELECT 1")},
			"0001_second.up.sql": {Data: []byte("SELECT 2")},
		},
		"invalid name": {"seed.sql": {Data: []byte("SELECT 1")}},
		"empty body":   {"0001_empty.up.sql": {Data: []byte(" \n\t")}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := readMigrations(source); err == nil {
				t.Fatal("expected migration source validation error")
			}
		})
	}
}

func TestTransactionControlRejectsCommandsButIgnoresQuotedTextAndComments(t *testing.T) {
	for _, sql := range []string{
		"COMMIT;",
		"-- header\nROLLBACK WORK;",
		"START TRANSACTION;",
		"PREPARE TRANSACTION 'migration';",
		"END;",
	} {
		if command, found := transactionControl([]byte(sql)); !found {
			t.Errorf("transaction command %q was accepted", sql)
		} else {
			t.Logf("rejected %s", command)
		}
	}
	for _, sql := range []string{
		"-- COMMIT;\nCREATE TABLE sample (id integer);",
		"/* ROLLBACK; /* nested COMMIT; */ */ CREATE TABLE sample (id integer);",
		"SELECT 'COMMIT; ROLLBACK';",
		`CREATE FUNCTION sample() RETURNS text LANGUAGE sql AS $$ SELECT 'COMMIT'; $$;`,
		`DO $body$ BEGIN RAISE NOTICE 'COMMIT'; END $body$;`,
		`CREATE TABLE "commit" ("rollback" text);`,
	} {
		if command, found := transactionControl([]byte(sql)); found {
			t.Errorf("quoted/commented transaction word %q was treated as command %s", sql, command)
		}
	}
}
