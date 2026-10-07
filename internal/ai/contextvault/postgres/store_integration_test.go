package postgres

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/sanskarpan/keel/internal/ai/contextvault"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

func TestPostgreSQLContextVaultTenantScopedImmutableAndAtomic(t *testing.T) {
	vaultDSN := os.Getenv("KEEL_TEST_CONTEXT_VAULT_DATABASE_URL")
	appDSN := os.Getenv("KEEL_TEST_DATABASE_URL")
	if vaultDSN == "" || appDSN == "" {
		t.Skip("set context-vault and app database URLs for PostgreSQL/RLS integration coverage")
	}
	vaultDB := openTestDB(t, vaultDSN)
	appDB := openTestDB(t, appDSN)
	store, err := NewStore(vaultDB)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	tenantA := mustTenant(t, uuid.NewString())
	tenantB := mustTenant(t, uuid.NewString())
	scope := testScope(string(tenantA), uuid.NewString(), 1)
	envelope := testEnvelope()
	expiresAt := time.Now().UTC().Add(10 * time.Minute)

	if err := store.Put(ctx, tenantA, scope, envelope, expiresAt); err != nil {
		t.Fatalf("store encrypted context: %v", err)
	}
	if err := store.Put(ctx, tenantA, scope, envelope, expiresAt); err != nil {
		t.Fatalf("exact retry was not idempotent: %v", err)
	}
	stored, err := store.Get(ctx, tenantA, scope.RecordID, scope.Version)
	if err != nil || stored.Scope.PolicyDigest != scope.PolicyDigest || !equalEnvelope(stored.Envelope, envelope) {
		t.Fatalf("stored record=%+v err=%v", stored, err)
	}
	if _, err := store.Get(ctx, tenantB, scope.RecordID, scope.Version); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant read error=%v, want not found", err)
	}
	conflict := envelope
	conflict.Ciphertext = append([]byte(nil), envelope.Ciphertext...)
	conflict.Ciphertext[0] ^= 0xff
	if err := store.Put(ctx, tenantA, scope, conflict, expiresAt); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflicting version write error=%v", err)
	}

	appErr := tenancy.WithTenantTx(ctx, appDB, tenantA, &sql.TxOptions{ReadOnly: true}, func(tx *sql.Tx) error {
		var count int
		return tx.QueryRowContext(ctx, `SELECT count(*) FROM keel_meta.context_vault_records WHERE tenant_id=$1`, string(tenantA)).Scan(&count)
	})
	if appErr == nil {
		t.Fatal("app role could read protected context ciphertext")
	}
	vaultErr := tenancy.WithTenantTx(ctx, vaultDB, tenantA, nil, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE keel_meta.context_vault_records SET key_id='changed'
			WHERE tenant_id=$1 AND record_id=$2 AND version=$3`, string(tenantA), scope.RecordID, scope.Version)
		return err
	})
	if vaultErr == nil {
		t.Fatal("context-vault role could mutate an immutable record version")
	}

	rollbackScope := testScope(string(tenantA), uuid.NewString(), 1)
	rollbackErr := errors.New("force rollback")
	err = tenancy.WithTenantTx(ctx, vaultDB, tenantA, nil, func(tx *sql.Tx) error {
		if err := store.PutTx(ctx, tx, tenantA, rollbackScope, testEnvelope(), expiresAt); err != nil {
			return err
		}
		return rollbackErr
	})
	if !errors.Is(err, rollbackErr) {
		t.Fatalf("transaction rollback cause=%v", err)
	}
	if _, err := store.Get(ctx, tenantA, rollbackScope.RecordID, rollbackScope.Version); !errors.Is(err, ErrNotFound) {
		t.Fatalf("rolled-back context record error=%v, want not found", err)
	}

	expiringScope := testScope(string(tenantA), uuid.NewString(), 1)
	if err := store.Put(ctx, tenantA, expiringScope, testEnvelope(), time.Now().UTC().Add(2*time.Second)); err != nil {
		t.Fatalf("insert short-lived context record: %v", err)
	}
	time.Sleep(2200 * time.Millisecond)
	if _, err := store.Get(ctx, tenantA, expiringScope.RecordID, expiringScope.Version); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired context record error=%v, want not found", err)
	}
}

func openTestDB(t *testing.T, dsn string) *sql.DB {
	t.Helper()
	parsed, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("pgx", parsed.String())
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(4)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		t.Fatalf("connect to PostgreSQL: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func mustTenant(t *testing.T, value string) tenancy.TenantID {
	t.Helper()
	tenant, err := tenancy.ParseTenantID(value)
	if err != nil {
		t.Fatal(err)
	}
	return tenant
}

func testScope(tenantID, recordID string, version uint64) contextvault.Scope {
	return contextvault.Scope{
		TenantID: tenantID, RecordID: recordID, Version: version,
		PolicyDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
}

func testEnvelope() contextvault.Envelope {
	ciphertext := make([]byte, 32)
	for index := range ciphertext {
		ciphertext[index] = byte(index + 1)
	}
	return contextvault.Envelope{
		Algorithm: contextvault.Algorithm, KeyID: "kms://test/context-v1",
		WrappedDEK: []byte("wrapped-test-key-material"), Nonce: []byte("123456789012"), Ciphertext: ciphertext,
	}
}

func equalEnvelope(left, right contextvault.Envelope) bool {
	return left.Algorithm == right.Algorithm && left.KeyID == right.KeyID &&
		bytes.Equal(left.WrappedDEK, right.WrappedDEK) && bytes.Equal(left.Nonce, right.Nonce) &&
		bytes.Equal(left.Ciphertext, right.Ciphertext)
}
