// Package postgres persists encrypted context envelopes with transaction-scoped tenant RLS.
package postgres

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/sanskarpan/keel/internal/ai/contextvault"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

var (
	ErrInvalid  = errors.New("invalid context vault record")
	ErrConflict = errors.New("context vault record version conflicts with stored data")
	ErrNotFound = errors.New("context vault record not found")
)

const maxVersion = uint64(1<<63 - 1)

type Store struct{ db *sql.DB }

type Record struct {
	Scope     contextvault.Scope
	Envelope  contextvault.Envelope
	CreatedAt time.Time
	ExpiresAt time.Time
}

func NewStore(db *sql.DB) (*Store, error) {
	if db == nil {
		return nil, errors.New("context vault database is required")
	}
	return &Store{db: db}, nil
}

// Put inserts an immutable encrypted record version or accepts an exact unexpired replay.
func (s *Store) Put(ctx context.Context, tenant tenancy.TenantID, scope contextvault.Scope, envelope contextvault.Envelope, expiresAt time.Time) error {
	if s == nil || s.db == nil {
		return ErrInvalid
	}
	return tenancy.WithTenantTx(ctx, s.db, tenant, nil, func(tx *sql.Tx) error {
		return s.PutTx(ctx, tx, tenant, scope, envelope, expiresAt)
	})
}

// PutTx lets a caller include encrypted context metadata in its existing tenant transaction.
func (s *Store) PutTx(ctx context.Context, tx *sql.Tx, tenant tenancy.TenantID, scope contextvault.Scope, envelope contextvault.Envelope, expiresAt time.Time) error {
	if s == nil || tx == nil || ctx == nil || scope.Version == 0 || scope.Version > maxVersion ||
		!sameUUID(scope.TenantID, string(tenant)) || contextvault.ValidateEnvelope(scope, envelope) != nil {
		return ErrInvalid
	}
	canonicalTenant, err := tenancy.ParseTenantID(string(tenant))
	if err != nil {
		return ErrInvalid
	}
	canonicalRecord, err := tenancy.ParseTenantID(scope.RecordID)
	if err != nil {
		return ErrInvalid
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO keel_meta.context_vault_records
		(tenant_id,record_id,version,policy_digest,algorithm,key_id,wrapped_dek,nonce,ciphertext,expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		ON CONFLICT (tenant_id,record_id,version) DO NOTHING`,
		strings.ToLower(string(canonicalTenant)), strings.ToLower(string(canonicalRecord)), int64(scope.Version), scope.PolicyDigest,
		envelope.Algorithm, envelope.KeyID, envelope.WrappedDEK, envelope.Nonce, envelope.Ciphertext,
		expiresAt.UTC().Truncate(time.Microsecond)); err != nil {
		return fmt.Errorf("insert encrypted context record: %w", err)
	}
	stored, err := readRecordTx(ctx, tx, tenancy.TenantID(strings.ToLower(string(canonicalTenant))), strings.ToLower(string(canonicalRecord)), scope.Version)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrConflict
	}
	if err != nil {
		return fmt.Errorf("read encrypted context record: %w", err)
	}
	if sameRecord(stored, scope, envelope, expiresAt) {
		return nil
	}
	return ErrConflict
}

// Get reads one exact, unexpired tenant/record/version. RLS independently constrains tenant scope.
func (s *Store) Get(ctx context.Context, tenant tenancy.TenantID, recordID string, version uint64) (Record, error) {
	if s == nil || s.db == nil || ctx == nil || version == 0 || version > maxVersion {
		return Record{}, ErrInvalid
	}
	canonicalTenant, err := tenancy.ParseTenantID(string(tenant))
	if err != nil {
		return Record{}, ErrInvalid
	}
	canonicalRecord, err := tenancy.ParseTenantID(recordID)
	if err != nil {
		return Record{}, ErrInvalid
	}
	canonicalTenant = tenancy.TenantID(strings.ToLower(string(canonicalTenant)))
	var record Record
	err = tenancy.WithTenantTx(ctx, s.db, canonicalTenant, &sql.TxOptions{ReadOnly: true}, func(tx *sql.Tx) error {
		var err error
		record, err = readRecordTx(ctx, tx, canonicalTenant, strings.ToLower(string(canonicalRecord)), version)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	})
	if err != nil {
		return Record{}, err
	}
	return record, nil
}

func readRecordTx(ctx context.Context, tx *sql.Tx, tenant tenancy.TenantID, recordID string, version uint64) (Record, error) {
	var record Record
	record.Scope.TenantID = string(tenant)
	err := tx.QueryRowContext(ctx, `SELECT record_id::text,version,policy_digest,algorithm,key_id,
		wrapped_dek,nonce,ciphertext,created_at,expires_at
		FROM keel_meta.context_vault_records
		WHERE tenant_id=$1 AND record_id=$2 AND version=$3 AND expires_at>statement_timestamp()`,
		string(tenant), recordID, int64(version)).Scan(&record.Scope.RecordID, &record.Scope.Version,
		&record.Scope.PolicyDigest, &record.Envelope.Algorithm, &record.Envelope.KeyID,
		&record.Envelope.WrappedDEK, &record.Envelope.Nonce, &record.Envelope.Ciphertext,
		&record.CreatedAt, &record.ExpiresAt)
	if err != nil {
		return Record{}, err
	}
	return record, nil
}

func sameRecord(record Record, scope contextvault.Scope, envelope contextvault.Envelope, expiresAt time.Time) bool {
	return sameUUID(record.Scope.RecordID, scope.RecordID) && record.Scope.Version == scope.Version &&
		record.Scope.PolicyDigest == scope.PolicyDigest && record.Envelope.Algorithm == envelope.Algorithm &&
		record.Envelope.KeyID == envelope.KeyID && bytes.Equal(record.Envelope.WrappedDEK, envelope.WrappedDEK) &&
		bytes.Equal(record.Envelope.Nonce, envelope.Nonce) && bytes.Equal(record.Envelope.Ciphertext, envelope.Ciphertext) &&
		record.ExpiresAt.Equal(expiresAt.UTC().Truncate(time.Microsecond))
}

func sameUUID(left, right string) bool {
	leftID, leftErr := tenancy.ParseTenantID(left)
	rightID, rightErr := tenancy.ParseTenantID(right)
	return leftErr == nil && rightErr == nil && strings.EqualFold(string(leftID), string(rightID))
}
