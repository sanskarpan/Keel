// Package migrations applies immutable, ordered PostgreSQL migrations under a session advisory lock.
package migrations

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const defaultSchema = "keel_meta"

//go:embed sql
var embeddedMigrations embed.FS

// Embedded returns this release's immutable SQL migration bundle.
func Embedded() fs.FS {
	files, err := fs.Sub(embeddedMigrations, "sql")
	if err != nil {
		panic("embedded migration directory is missing: " + err.Error())
	}
	return files
}

var (
	fileNamePattern = regexp.MustCompile(`^([0-9]{4,})_([a-z0-9_]+)\.up\.sql$`)
	schemaPattern   = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)
)

// Options controls the ledger schema and the globally reserved PostgreSQL advisory-lock key.
// Keep LockID stable for every process that can migrate the same database.
type Options struct {
	Schema      string
	LedgerTable string
	LockID      int64
}

type migration struct {
	version  uint64
	name     string
	body     []byte
	checksum string
}

// Apply validates the complete migration set, serializes runners for this database, rejects
// checksum drift and applies each pending migration with its ledger row in one transaction.
// Migrations must be transactional PostgreSQL DDL/DML; commands such as CREATE INDEX CONCURRENTLY
// need a separately designed online-migration mechanism.
func Apply(ctx context.Context, db *sql.DB, source fs.FS, options Options) (err error) {
	if ctx == nil {
		return errors.New("migration context is required")
	}
	if db == nil || source == nil {
		return errors.New("migration database and source are required")
	}
	schema := options.Schema
	if schema == "" {
		schema = defaultSchema
	}
	if !schemaPattern.MatchString(schema) {
		return fmt.Errorf("invalid migration ledger schema %q", schema)
	}
	ledgerTable := options.LedgerTable
	if ledgerTable == "" {
		ledgerTable = "schema_migrations"
	}
	if !schemaPattern.MatchString(ledgerTable) {
		return fmt.Errorf("invalid migration ledger table %q", ledgerTable)
	}
	if options.LockID == 0 {
		return errors.New("a stable non-zero migration advisory lock ID is required")
	}

	all, err := readMigrations(source)
	if err != nil {
		return err
	}
	conn, err := db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("acquire migration connection: %w", err)
	}
	defer func() {
		if closeErr := conn.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("return migration connection: %w", closeErr)
		}
	}()

	if _, err = conn.ExecContext(ctx, `SET ROLE keel_schema_owner`); err != nil {
		return fmt.Errorf("assume migration schema-owner role: %w", err)
	}
	roleSet := true
	locked := false
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if locked {
			var released bool
			if unlockErr := conn.QueryRowContext(cleanupCtx, `SELECT pg_catalog.pg_advisory_unlock($1)`, options.LockID).Scan(&released); unlockErr != nil && err == nil {
				err = fmt.Errorf("release migration advisory lock: %w", unlockErr)
			} else if unlockErr == nil && !released && err == nil {
				err = errors.New("migration advisory lock was not held at release")
			}
		}
		if roleSet {
			if _, resetErr := conn.ExecContext(cleanupCtx, `RESET ROLE`); resetErr != nil && err == nil {
				err = fmt.Errorf("reset migration connection role: %w", resetErr)
			}
		}
	}()

	if _, err = conn.ExecContext(ctx, `SELECT pg_catalog.pg_advisory_lock($1)`, options.LockID); err != nil {
		return fmt.Errorf("acquire migration advisory lock: %w", err)
	}
	locked = true

	ledger := quoteIdentifier(schema) + `.` + quoteIdentifier(ledgerTable)
	createLedger := `CREATE TABLE IF NOT EXISTS ` + ledger + ` (
		version bigint PRIMARY KEY,
		name text NOT NULL UNIQUE,
		sha256 char(64) NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
		applied_at timestamptz NOT NULL DEFAULT clock_timestamp()
	)`
	if _, err = conn.ExecContext(ctx, createLedger); err != nil {
		return fmt.Errorf("create migration ledger: %w", err)
	}

	rows, err := conn.QueryContext(ctx, `SELECT version, name, sha256 FROM `+ledger+` ORDER BY version`)
	if err != nil {
		return fmt.Errorf("read migration ledger: %w", err)
	}
	applied := make(map[uint64]migration, len(all))
	var maxApplied uint64
	for rows.Next() {
		var version uint64
		var name, checksum string
		if scanErr := rows.Scan(&version, &name, &checksum); scanErr != nil {
			_ = rows.Close()
			return fmt.Errorf("scan migration ledger: %w", scanErr)
		}
		applied[version] = migration{version: version, name: name, checksum: strings.TrimSpace(checksum)}
		if version > maxApplied {
			maxApplied = version
		}
	}
	if rowsErr := rows.Err(); rowsErr != nil {
		_ = rows.Close()
		return fmt.Errorf("iterate migration ledger: %w", rowsErr)
	}
	if err = rows.Close(); err != nil {
		return fmt.Errorf("close migration ledger rows: %w", err)
	}

	known := make(map[uint64]migration, len(all))
	for _, item := range all {
		known[item.version] = item
	}
	for version, recorded := range applied {
		item, exists := known[version]
		if !exists {
			return fmt.Errorf("database has migration %d (%s) absent from this binary", version, recorded.name)
		}
		if item.name != recorded.name || item.checksum != recorded.checksum {
			return fmt.Errorf("migration %d checksum/name drift: database=%s/%s binary=%s/%s", version, recorded.name, recorded.checksum, item.name, item.checksum)
		}
	}
	for _, item := range all {
		if _, exists := applied[item.version]; exists {
			continue
		}
		if item.version <= maxApplied {
			return fmt.Errorf("pending migration %d sorts before an already applied migration; add a forward repair instead", item.version)
		}
		tx, beginErr := conn.BeginTx(ctx, nil)
		if beginErr != nil {
			return fmt.Errorf("begin migration %d: %w", item.version, beginErr)
		}
		if _, execErr := tx.ExecContext(ctx, string(item.body)); execErr != nil {
			_ = tx.Rollback()
			return fmt.Errorf("execute migration %d (%s): %w", item.version, item.name, execErr)
		}
		if _, execErr := tx.ExecContext(ctx, `INSERT INTO `+ledger+` (version, name, sha256) VALUES ($1, $2, $3)`, item.version, item.name, item.checksum); execErr != nil {
			_ = tx.Rollback()
			return fmt.Errorf("record migration %d (%s): %w", item.version, item.name, execErr)
		}
		if commitErr := tx.Commit(); commitErr != nil {
			return fmt.Errorf("commit migration %d (%s): %w", item.version, item.name, commitErr)
		}
		maxApplied = item.version
	}
	return nil
}

func readMigrations(source fs.FS) ([]migration, error) {
	entries, err := fs.ReadDir(source, ".")
	if err != nil {
		return nil, fmt.Errorf("read migration source: %w", err)
	}
	var migrations []migration
	seen := make(map[uint64]string)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		match := fileNamePattern.FindStringSubmatch(entry.Name())
		if match == nil {
			return nil, fmt.Errorf("invalid migration filename %q; expected NNNN_name.up.sql", entry.Name())
		}
		version, parseErr := strconv.ParseUint(match[1], 10, 63)
		if parseErr != nil || version == 0 {
			return nil, fmt.Errorf("invalid migration version in %q", entry.Name())
		}
		if previous, ok := seen[version]; ok {
			return nil, fmt.Errorf("duplicate migration version %d in %q and %q", version, previous, entry.Name())
		}
		body, readErr := fs.ReadFile(source, path.Clean(entry.Name()))
		if readErr != nil {
			return nil, fmt.Errorf("read migration %q: %w", entry.Name(), readErr)
		}
		if len(bytesTrimSpace(body)) == 0 {
			return nil, fmt.Errorf("migration %q is empty", entry.Name())
		}
		if command, found := transactionControl(body); found {
			return nil, fmt.Errorf("migration %q contains transaction control command %s; migrations must remain inside the runner transaction", entry.Name(), command)
		}
		digest := sha256.Sum256(body)
		seen[version] = entry.Name()
		migrations = append(migrations, migration{version: version, name: entry.Name(), body: body, checksum: hex.EncodeToString(digest[:])})
	}
	sort.Slice(migrations, func(i, j int) bool { return migrations[i].version < migrations[j].version })
	return migrations, nil
}

// transactionControl lexes top-level statement-leading keywords while ignoring strings,
// quoted identifiers, dollar-quoted bodies, and nested/block/line comments. PostgreSQL
// functions and procedures may mention transaction keywords in their bodies; only executable
// top-level transaction commands can break the runner's per-file atomicity.
func transactionControl(body []byte) (string, bool) {
	var statement []string
	flush := func() (string, bool) {
		command := ""
		if len(statement) > 0 {
			switch statement[0] {
			case "COMMIT", "END", "ROLLBACK", "ABORT", "BEGIN":
				command = statement[0]
			case "START":
				if len(statement) > 1 && statement[1] == "TRANSACTION" {
					command = "START TRANSACTION"
				}
			case "PREPARE":
				if len(statement) > 1 && statement[1] == "TRANSACTION" {
					command = "PREPARE TRANSACTION"
				}
			}
		}
		statement = statement[:0]
		return command, command != ""
	}

	for i := 0; i < len(body); {
		c := body[i]
		switch {
		case c == '-' && i+1 < len(body) && body[i+1] == '-':
			i += 2
			for i < len(body) && body[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < len(body) && body[i+1] == '*':
			i += 2
			depth := 1
			for i < len(body) && depth > 0 {
				if i+1 < len(body) && body[i] == '/' && body[i+1] == '*' {
					depth++
					i += 2
				} else if i+1 < len(body) && body[i] == '*' && body[i+1] == '/' {
					depth--
					i += 2
				} else {
					i++
				}
			}
		case c == '\'' || c == '"':
			quote := c
			// E'...' strings use backslash escapes; ordinary PostgreSQL strings follow
			// the server's standard_conforming_strings setting and use doubled quotes.
			escape := quote == '\'' && i > 0 && (body[i-1] == 'e' || body[i-1] == 'E') && (i == 1 || !isSQLIdent(body[i-2]))
			i++
			for i < len(body) {
				if escape && body[i] == '\\' && i+1 < len(body) {
					i += 2
				} else if body[i] == quote {
					if i+1 < len(body) && body[i+1] == quote {
						i += 2
					} else {
						i++
						break
					}
				} else {
					i++
				}
			}
		case c == '$':
			if end := dollarQuoteStart(body, i); end > i {
				tag := body[i:end]
				i = end
				for i < len(body) {
					if i+len(tag) <= len(body) && string(body[i:i+len(tag)]) == string(tag) {
						i += len(tag)
						break
					}
					i++
				}
			} else {
				i++
			}
		case c == ';':
			if command, found := flush(); found {
				return command, true
			}
			i++
		case isSQLIdentStart(c):
			start := i
			i++
			for i < len(body) && isSQLIdent(body[i]) {
				i++
			}
			if len(statement) < 2 {
				statement = append(statement, strings.ToUpper(string(body[start:i])))
			}
		default:
			i++
		}
	}
	return flush()
}

func dollarQuoteStart(body []byte, start int) int {
	for i := start + 1; i < len(body); i++ {
		if body[i] == '$' {
			return i + 1
		}
		if !isSQLIdent(body[i]) {
			return start
		}
	}
	return start
}

func isSQLIdentStart(c byte) bool { return c == '_' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' }
func isSQLIdent(c byte) bool      { return isSQLIdentStart(c) || c >= '0' && c <= '9' || c == '$' }

func bytesTrimSpace(value []byte) []byte {
	return []byte(strings.TrimSpace(string(value)))
}

func quoteIdentifier(identifier string) string {
	return `"` + strings.ReplaceAll(identifier, `"`, `""`) + `"`
}
