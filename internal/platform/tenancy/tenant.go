// Package tenancy provides transaction-scoped tenant context for trusted Keel services.
// Never construct a TenantID directly from an unverified header, prompt or request body.
package tenancy

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
)

var canonicalUUID = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// TenantID is a validated canonical UUID that should come from authenticated server-side authorization.
type TenantID string

// ParseTenantID validates the canonical UUID representation expected by Keel's PostgreSQL keys.
func ParseTenantID(value string) (TenantID, error) {
	if !canonicalUUID.MatchString(value) {
		return "", errors.New("tenant ID must be a canonical UUID")
	}
	return TenantID(value), nil
}

// WithTenantTx starts a transaction, installs a transaction-local tenant context, and commits only
// when work succeeds. The passed tenant identity must already be authorized by trusted service code.
// App/worker roles rely on this broker-set GUC. Agent logins are additionally bound by PostgreSQL
// session_user mapping; RLS ignores this GUC for any login in keel_agent.
func WithTenantTx(ctx context.Context, db *sql.DB, tenant TenantID, options *sql.TxOptions, work func(*sql.Tx) error) (err error) {
	if ctx == nil {
		return errors.New("transaction context is required")
	}
	if db == nil {
		return errors.New("database is required")
	}
	if !canonicalUUID.MatchString(string(tenant)) {
		return errors.New("validated tenant ID is required")
	}
	if work == nil {
		return errors.New("tenant transaction work is required")
	}

	tx, err := db.BeginTx(ctx, options)
	if err != nil {
		return fmt.Errorf("begin tenant transaction: %w", err)
	}
	defer func() {
		if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) && err == nil {
			err = fmt.Errorf("rollback tenant transaction: %w", rollbackErr)
		}
	}()

	if _, err = tx.ExecContext(ctx, "SELECT set_config('keel.tenant_id', $1, true)", string(tenant)); err != nil {
		return fmt.Errorf("set transaction tenant context: %w", err)
	}
	if err = work(tx); err != nil {
		return fmt.Errorf("tenant transaction work: %w", err)
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("commit tenant transaction: %w", err)
	}
	return nil
}
