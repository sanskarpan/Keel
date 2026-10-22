// Package dbquery executes database statements and records bounded, privacy-safe timings.
//
// The helpers are thin wrappers around database/sql. They add no retry, no timeout, no
// statement rewriting, and no error translation: a statement that succeeds here succeeds in
// the database, and a statement that fails here fails the same way. The only addition is
// optional observation of how long a statement took and whether it failed.
//
// The recorded event carries a statement class and an outcome. It never carries the
// statement text, its arguments, the rows it returned, the identifiers it touched, or the
// database error text, because none of those values are accepted by the recorder.
package dbquery

import (
	"context"
	"database/sql"
	"time"

	"github.com/sanskarpan/keel/internal/platform/observability"
)

// Read runs a read statement. The recorded duration covers statement execution up to the
// first returned row; row iteration time is not included.
func Read(ctx context.Context, tx *sql.Tx, query string, args ...any) (*sql.Rows, error) {
	started := time.Now()
	rows, err := tx.QueryContext(ctx, query, args...)
	record(ctx, observability.StatementRead, started, err)
	return rows, err
}

// ReadRow runs a read statement that returns at most one row. The statement outcome is
// recorded when the row is scanned, because that is where the database reports the result.
func ReadRow(ctx context.Context, tx *sql.Tx, query string, args ...any) *Row {
	started := time.Now()
	return &Row{row: tx.QueryRowContext(ctx, query, args...), record: func(err error) {
		record(ctx, observability.StatementRead, started, err)
	}}
}

// Write runs a statement that can change durable state.
func Write(ctx context.Context, tx *sql.Tx, query string, args ...any) (sql.Result, error) {
	started := time.Now()
	result, err := tx.ExecContext(ctx, query, args...)
	record(ctx, observability.StatementWrite, started, err)
	return result, err
}

// WriteRow runs a state-changing statement that returns a row, such as an insert with a
// returning clause. The statement outcome is recorded when the row is scanned.
func WriteRow(ctx context.Context, tx *sql.Tx, query string, args ...any) *Row {
	started := time.Now()
	return &Row{row: tx.QueryRowContext(ctx, query, args...), record: func(err error) {
		record(ctx, observability.StatementWrite, started, err)
	}}
}

// Row is a single-row statement result whose outcome is recorded once it is scanned.
type Row struct {
	row    *sql.Row
	record func(error)
}

// Scan reads the row values and records the statement outcome.
func (r *Row) Scan(dest ...any) error {
	err := r.row.Scan(dest...)
	r.record(err)
	return err
}

func record(ctx context.Context, kind observability.StatementKind, started time.Time, err error) {
	recorder, ok := observability.StatementRecorderFromContext(ctx)
	if !ok {
		return
	}
	recorder.Record(kind, time.Since(started), err)
}
