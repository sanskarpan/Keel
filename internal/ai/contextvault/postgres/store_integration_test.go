package postgres

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/sanskarpan/keel/internal/ai/contextvault"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

func TestPostgreSQLContextVaultTenantScopedImmutableAndAtomic(t *testing.T) {
	vaultDSN := os.Getenv("KEEL_TEST_CONTEXT_VAULT_DATABASE_URL")
	policyDSN := os.Getenv("KEEL_TEST_CONTEXT_POLICY_DATABASE_URL")
	erasureDSN := os.Getenv("KEEL_TEST_CONTEXT_ERASURE_DATABASE_URL")
	appDSN := os.Getenv("KEEL_TEST_DATABASE_URL")
	adminDSN := os.Getenv("KEEL_TEST_ADMIN_DATABASE_URL")
	if vaultDSN == "" || policyDSN == "" || erasureDSN == "" || appDSN == "" || adminDSN == "" {
		t.Skip("set context-vault, context-policy, context-erasure, app, and admin database URLs for PostgreSQL/RLS integration coverage")
	}
	vaultDB := openTestDB(t, vaultDSN)
	policyDB := openTestDB(t, policyDSN)
	erasureDB := openTestDB(t, erasureDSN)
	appDB := openTestDB(t, appDSN)
	adminDB := openTestDB(t, adminDSN)
	store, err := NewStore(vaultDB)
	if err != nil {
		t.Fatal(err)
	}
	erasureStore, err := NewErasureStore(erasureDB)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	tenantA := mustTenant(t, uuid.NewString())
	tenantB := mustTenant(t, uuid.NewString())
	scope := testScope(string(tenantA), uuid.NewString(), 1)
	envelope := testEnvelope()
	setRetentionPolicy(t, policyDB, tenantA, PurposeReadOnlyReplay, 1, false, 0, "")
	if err := store.Put(ctx, tenantA, scope, envelope, RetentionPolicy{Purpose: PurposeReadOnlyReplay, Version: 1}); err == nil {
		t.Fatal("default-off context retention policy accepted a write")
	}
	setRetentionPolicy(t, policyDB, tenantA, PurposeReadOnlyReplay, 2, true, 600, uuid.NewString())
	retention := RetentionPolicy{Purpose: PurposeReadOnlyReplay, Version: 2}
	immutableErr := tenancy.WithTenantTx(ctx, policyDB, tenantA, nil, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE keel_meta.context_retention_policies
			SET retention_seconds=1200 WHERE tenant_id=$1 AND purpose=$2 AND policy_version=2`, string(tenantA), PurposeReadOnlyReplay)
		return err
	})
	if immutableErr == nil {
		t.Fatal("context-policy role could mutate an immutable retention snapshot")
	}
	boundedErr := tenancy.WithTenantTx(ctx, policyDB, tenantA, nil, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO keel_meta.context_retention_policies
			(tenant_id,purpose,policy_version,enabled,retention_seconds,consent_id)
			VALUES ($1,$2,4,true,31536001,$3)`, string(tenantA), PurposeReadOnlyReplay, uuid.NewString())
		return err
	})
	if boundedErr == nil {
		t.Fatal("context retention policy accepted an interval over one year")
	}
	missingIntervalErr := tenancy.WithTenantTx(ctx, policyDB, tenantA, nil, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO keel_meta.context_retention_policies
			(tenant_id,purpose,policy_version,enabled,retention_seconds,consent_id)
			VALUES ($1,$2,5,true,NULL,$3)`, string(tenantA), PurposeReadOnlyReplay, uuid.NewString())
		return err
	})
	if missingIntervalErr == nil {
		t.Fatal("enabled context retention policy accepted a missing interval")
	}

	if err := store.Put(ctx, tenantA, scope, envelope, retention); err != nil {
		t.Fatalf("store encrypted context: %v", err)
	}
	if err := store.Put(ctx, tenantA, scope, envelope, retention); err != nil {
		t.Fatalf("exact retry was not idempotent: %v", err)
	}
	stored, err := store.Get(ctx, tenantA, scope.RecordID, scope.Version)
	if err != nil || stored.Scope.PolicyDigest != scope.PolicyDigest || !equalEnvelope(stored.Envelope, envelope) ||
		stored.Purpose != retention.Purpose || stored.RetentionPolicyVersion != retention.Version ||
		stored.ConsentID == "" || time.Until(stored.ExpiresAt) > 10*time.Minute || time.Until(stored.ExpiresAt) <= 0 {
		t.Fatalf("stored record=%+v err=%v", stored, err)
	}
	if _, err := store.Get(ctx, tenantB, scope.RecordID, scope.Version); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant read error=%v, want not found", err)
	}
	conflict := envelope
	conflict.Ciphertext = append([]byte(nil), envelope.Ciphertext...)
	conflict.Ciphertext[0] ^= 0xff
	if err := store.Put(ctx, tenantA, scope, conflict, retention); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflicting version write error=%v", err)
	}
	staleScope := testScope(string(tenantA), uuid.NewString(), 1)
	if err := store.Put(ctx, tenantA, staleScope, testEnvelope(), RetentionPolicy{Purpose: PurposeReadOnlyReplay, Version: 1}); err == nil {
		t.Fatal("stale retention policy version accepted a new record")
	}

	appErr := tenancy.WithTenantTx(ctx, appDB, tenantA, &sql.TxOptions{ReadOnly: true}, func(tx *sql.Tx) error {
		var count int
		return tx.QueryRowContext(ctx, `SELECT count(*) FROM keel_meta.context_vault_records WHERE tenant_id=$1`, string(tenantA)).Scan(&count)
	})
	if appErr == nil {
		t.Fatal("app role could read protected context ciphertext")
	}
	policyErr := tenancy.WithTenantTx(ctx, policyDB, tenantA, &sql.TxOptions{ReadOnly: true}, func(tx *sql.Tx) error {
		var count int
		return tx.QueryRowContext(ctx, `SELECT count(*) FROM keel_meta.context_vault_records`).Scan(&count)
	})
	if policyErr == nil {
		t.Fatal("context-policy role could read protected context ciphertext")
	}
	vaultPolicyErr := tenancy.WithTenantTx(ctx, vaultDB, tenantA, nil, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO keel_meta.context_retention_policies
			(tenant_id,purpose,policy_version,enabled,retention_seconds,consent_id)
			VALUES ($1,'incident_review',1,false,NULL,NULL)`, string(tenantA))
		return err
	})
	if vaultPolicyErr == nil {
		t.Fatal("context-vault role could author retention policy")
	}
	vaultErr := tenancy.WithTenantTx(ctx, vaultDB, tenantA, nil, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE keel_meta.context_vault_records SET key_id='changed'
			WHERE tenant_id=$1 AND record_id=$2 AND version=$3`, string(tenantA), scope.RecordID, scope.Version)
		return err
	})
	if vaultErr == nil {
		t.Fatal("context-vault role could mutate an immutable record version")
	}
	vaultDeleteErr := tenancy.WithTenantTx(ctx, vaultDB, tenantA, nil, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `DELETE FROM keel_meta.context_vault_records
			WHERE tenant_id=$1 AND record_id=$2 AND version=$3`, string(tenantA), scope.RecordID, scope.Version)
		return err
	})
	if vaultDeleteErr == nil {
		t.Fatal("context-vault role could directly delete an immutable record")
	}

	rollbackScope := testScope(string(tenantA), uuid.NewString(), 1)
	rollbackErr := errors.New("force rollback")
	err = tenancy.WithTenantTx(ctx, vaultDB, tenantA, nil, func(tx *sql.Tx) error {
		if err := store.PutTx(ctx, tx, tenantA, rollbackScope, testEnvelope(), retention); err != nil {
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
	setRetentionPolicy(t, policyDB, tenantA, PurposeReadOnlyReplay, 3, true, 2, uuid.NewString())
	if err := store.Put(ctx, tenantA, scope, envelope, retention); err != nil {
		t.Fatalf("policy rotation broke exact retry of existing record: %v", err)
	}
	unchanged, err := store.Get(ctx, tenantA, scope.RecordID, scope.Version)
	if err != nil || unchanged.RetentionPolicyVersion != retention.Version || !unchanged.ExpiresAt.Equal(stored.ExpiresAt) {
		t.Fatalf("policy update changed an existing record snapshot: record=%+v err=%v", unchanged, err)
	}
	if err := store.Put(ctx, tenantA, expiringScope, testEnvelope(), RetentionPolicy{Purpose: PurposeReadOnlyReplay, Version: 3}); err != nil {
		t.Fatalf("insert short-lived context record: %v", err)
	}
	time.Sleep(2200 * time.Millisecond)
	if _, err := store.Get(ctx, tenantA, expiringScope.RecordID, expiringScope.Version); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired context record error=%v, want not found", err)
	}
	if count, err := erasureStore.DeleteExpiredBatch(ctx, tenantB, 10); err != nil || count != 0 {
		t.Fatalf("cross-tenant erasure count=%d err=%v, want zero", count, err)
	}
	if _, err := erasureStore.DeleteExpiredBatch(ctx, tenantA, maxErasureBatch+1); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unbounded erasure batch error=%v, want invalid", err)
	}
	directErasureReadErr := tenancy.WithTenantTx(ctx, erasureDB, tenantA, nil, func(tx *sql.Tx) error {
		var count int
		return tx.QueryRowContext(ctx, `SELECT count(*) FROM keel_meta.context_vault_records`).Scan(&count)
	})
	if directErasureReadErr == nil {
		t.Fatal("erasure role directly read live vault records")
	}
	directErasureDeleteErr := tenancy.WithTenantTx(ctx, erasureDB, tenantA, nil, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `DELETE FROM keel_meta.context_vault_records WHERE tenant_id=$1`, string(tenantA))
		return err
	})
	if directErasureDeleteErr == nil {
		t.Fatal("erasure role directly deleted vault records")
	}
	directReceiptReadErr := tenancy.WithTenantTx(ctx, erasureDB, tenantA, &sql.TxOptions{ReadOnly: true}, func(tx *sql.Tx) error {
		var count int
		return tx.QueryRowContext(ctx, `SELECT count(*) FROM keel_meta.context_vault_erasure_receipts`).Scan(&count)
	})
	if directReceiptReadErr == nil {
		t.Fatal("erasure role directly read tombstones")
	}
	databaseBatchErr := tenancy.WithTenantTx(ctx, erasureDB, tenantA, nil, func(tx *sql.Tx) error {
		var count int
		return tx.QueryRowContext(ctx, `SELECT keel_meta.erase_expired_context_vault($1)`, maxErasureBatch+1).Scan(&count)
	})
	if databaseBatchErr == nil {
		t.Fatal("database erasure function accepted an oversized batch")
	}
	erasureRollbackErr := errors.New("force erasure rollback")
	err = tenancy.WithTenantTx(ctx, erasureDB, tenantA, nil, func(tx *sql.Tx) error {
		deleted, err := erasureStore.DeleteExpiredBatchTx(ctx, tx, 1)
		if err != nil {
			return err
		}
		if deleted != 1 {
			return errors.New("erasure rollback test did not claim its expired record")
		}
		return erasureRollbackErr
	})
	if !errors.Is(err, erasureRollbackErr) {
		t.Fatalf("erasure rollback cause=%v", err)
	}
	var receiptCount int
	if err := adminDB.QueryRowContext(ctx, `SELECT count(*) FROM keel_meta.context_vault_erasure_receipts
		WHERE tenant_id=$1 AND record_id=$2 AND version=$3`, string(tenantA), expiringScope.RecordID, expiringScope.Version).Scan(&receiptCount); err != nil {
		t.Fatal(err)
	}
	if receiptCount != 0 {
		t.Fatalf("rollback left %d erasure receipts", receiptCount)
	}
	if deleted, err := erasureStore.DeleteExpiredBatch(ctx, tenantA, 1); err != nil || deleted != 1 {
		t.Fatalf("erase expired context record count=%d err=%v", deleted, err)
	}
	if deleted, err := erasureStore.DeleteExpiredBatch(ctx, tenantA, 1); err != nil || deleted != 0 {
		t.Fatalf("erasure retry count=%d err=%v, want idempotent zero", deleted, err)
	}
	var purpose, digest string
	var policyVersion int64
	var expiry, deletedAt time.Time
	if err := adminDB.QueryRowContext(ctx, `SELECT purpose,retention_policy_version,envelope_sha256,expires_at,deleted_at
		FROM keel_meta.context_vault_erasure_receipts WHERE tenant_id=$1 AND record_id=$2 AND version=$3`,
		string(tenantA), expiringScope.RecordID, expiringScope.Version).Scan(&purpose, &policyVersion, &digest, &expiry, &deletedAt); err != nil {
		t.Fatal(err)
	}
	if purpose != retention.Purpose || policyVersion != 3 || len(digest) != len("sha256:")+64 || !strings.HasPrefix(digest, "sha256:") ||
		!expiry.Before(deletedAt) {
		t.Fatalf("invalid content-free erasure receipt: purpose=%q version=%d digest=%q expiry=%s deleted=%s", purpose, policyVersion, digest, expiry, deletedAt)
	}
}

func setRetentionPolicy(t *testing.T, db *sql.DB, tenant tenancy.TenantID, purpose string, version uint64, enabled bool, seconds int, consentID string) {
	t.Helper()
	var retentionSeconds any
	var consent any
	if enabled {
		retentionSeconds = seconds
		consent = consentID
	}
	err := tenancy.WithTenantTx(context.Background(), db, tenant, nil, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(context.Background(), `INSERT INTO keel_meta.context_retention_policies
			(tenant_id,purpose,policy_version,enabled,retention_seconds,consent_id)
			VALUES ($1,$2,$3,$4,$5,$6)`, string(tenant), purpose, int64(version), enabled, retentionSeconds, consent); err != nil {
			return err
		}
		if version == 1 {
			_, err := tx.ExecContext(context.Background(), `INSERT INTO keel_meta.context_retention_policy_heads
				(tenant_id,purpose,policy_version) VALUES ($1,$2,$3)`, string(tenant), purpose, int64(version))
			return err
		}
		_, err := tx.ExecContext(context.Background(), `UPDATE keel_meta.context_retention_policy_heads
			SET policy_version=$3 WHERE tenant_id=$1 AND purpose=$2`, string(tenant), purpose, int64(version))
		return err
	})
	if err != nil {
		t.Fatalf("write context retention policy: %v", err)
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
