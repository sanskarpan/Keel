package postgres

import (
	"context"
	"database/sql"
	"errors"

	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

const maxErasureBatch = 100

// ErasureStore exposes only the atomic expired-record deletion function. Its database
// handle must use the dedicated context-erasure capability, not the vault role.
type ErasureStore struct{ db *sql.DB }

func NewErasureStore(db *sql.DB) (*ErasureStore, error) {
	if db == nil {
		return nil, errors.New("context erasure database is required")
	}
	return &ErasureStore{db: db}, nil
}

// DeleteExpiredBatch erases at most limit expired records for the authorized tenant.
// PostgreSQL derives the tenant from the transaction context and returns only a count.
func (s *ErasureStore) DeleteExpiredBatch(ctx context.Context, tenant tenancy.TenantID, limit int) (int, error) {
	if s == nil || s.db == nil || ctx == nil || limit < 1 || limit > maxErasureBatch {
		return 0, ErrInvalid
	}
	deleted := 0
	err := tenancy.WithTenantTx(ctx, s.db, tenant, nil, func(tx *sql.Tx) error {
		var err error
		deleted, err = s.DeleteExpiredBatchTx(ctx, tx, limit)
		return err
	})
	if err != nil {
		return 0, err
	}
	return deleted, nil
}

// DeleteExpiredBatchTx composes the controlled erasure transition with a caller transaction.
func (s *ErasureStore) DeleteExpiredBatchTx(ctx context.Context, tx *sql.Tx, limit int) (int, error) {
	if s == nil || tx == nil || ctx == nil || limit < 1 || limit > maxErasureBatch {
		return 0, ErrInvalid
	}
	var deleted int
	if err := tx.QueryRowContext(ctx, `SELECT keel_meta.erase_expired_context_vault($1)`, limit).Scan(&deleted); err != nil {
		return 0, err
	}
	return deleted, nil
}
