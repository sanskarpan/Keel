package postgres

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/sanskarpan/keel/internal/auth"
)

// TestPostgreSQLIdentityBootstrapAndSessionLifecycle runs against real PostgreSQL
// through the capability-gated identity functions. It skips unless
// KEEL_TEST_IDENTITY_DATABASE_URL (as the keel_local_identity login) and
// KEEL_TEST_ADMIN_DATABASE_URL (as postgres, for cross-role denial checks) are set.
func TestPostgreSQLIdentityBootstrapAndSessionLifecycle(t *testing.T) {
	identityDSN := os.Getenv("KEEL_TEST_IDENTITY_DATABASE_URL")
	adminDSN := os.Getenv("KEEL_TEST_ADMIN_DATABASE_URL")
	if identityDSN == "" || adminDSN == "" {
		t.Skip("set identity and admin PostgreSQL URLs to run identity integration tests")
	}
	ctx := context.Background()
	now := time.Now().UTC()

	identityDB := openRoleDB(t, identityDSN)
	repo, err := New(identityDB)
	if err != nil {
		t.Fatalf("repository: %v", err)
	}

	pepper := []byte("keel-integration-pepper-keel-integration-pepper-32")
	adminDB := openRoleDB(t, adminDSN)

	email := "owner-" + uuid.NewString() + "@example.test"
	password := "integration-pass-phrase"
	hash, err := auth.HashPassword(password, auth.TestArgonParams())
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	principalID := uuid.New()
	tenantID := uuid.MustParse("11111111-1111-4111-8111-111111111111")
	outcome, err := repo.BootstrapPrincipal(ctx, principalID, email, pepper, hash, &tenantID)
	if err != nil || outcome != "created" {
		t.Fatalf("bootstrap: %v (outcome %q)", err, outcome)
	}

	// A repeated email digest is a conflict, not a re-registration.
	if _, err := repo.BootstrapPrincipal(ctx, uuid.New(), email, pepper, hash, &tenantID); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate email accepted: %v", err)
	}

	// Unknown and malformed addresses are one branch the caller treats as a miss.
	if _, _, _, err := repo.CredentialForEmail(ctx, "missing-"+uuid.NewString()+"@example.test", pepper); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown email: %v", err)
	}
	if _, _, _, err := repo.CredentialForEmail(ctx, "not-an-email", pepper); err == nil {
		t.Fatal("malformed email accepted")
	}

	id, state, stored, err := repo.CredentialForEmail(ctx, email, pepper)
	if err != nil || id != principalID || state != auth.PrincipalPending || stored != hash {
		t.Fatalf("credential lookup: principal=%v state=%q err=%v", id, state, err)
	}
	if ok, err := auth.VerifyPassword("wrong-horse-battery!", stored); err != nil || ok {
		t.Fatalf("wrong-password verification: %v %v", ok, err)
	}
	if ok, err := auth.VerifyPassword(password, stored); err != nil || !ok {
		t.Fatalf("correct-password verification: %v %v", ok, err)
	}

	// Pending principals have no verification and cannot mint sessions.
	token, err := auth.NewSecret(nil)
	if err != nil {
		t.Fatalf("secret: %v", err)
	}
	if _, err := repo.RecordEmailVerification(ctx, principalID, token, pepper, now, now.Add(time.Minute)); err == nil {
		t.Fatal("under-min verification TTL accepted")
	}
	if _, err := repo.RecordEmailVerification(ctx, principalID, token, pepper, now, now.Add(time.Hour)); err != nil {
		t.Fatalf("record verification: %v", err)
	}
	if _, err := repo.RecordSession(ctx, uuid.New(), principalID, token, pepper, now, now.Add(time.Hour)); !errors.Is(err, ErrNotVerified) {
		t.Fatalf("session before verification: %v", err)
	}

	// Deterministic consumption outcomes.
	if outcome, _, err := repo.ConsumeEmailVerification(ctx, token, pepper); err != nil || outcome != "verified" {
		t.Fatalf("consume: %v (outcome %q)", err, outcome)
	}
	if outcome, consumedID, err := repo.ConsumeEmailVerification(ctx, token, pepper); err != nil || outcome != "duplicate" || consumedID != principalID {
		t.Fatalf("repeat consume: %v (outcome %q id %v)", err, outcome, consumedID)
	}
	// An unrecorded but well-formed secret resolves to the database's unknown
	// outcome; the caller treats it as an ordinary credential miss.
	unrecorded, err := auth.NewSecret(nil)
	if err != nil {
		t.Fatalf("unrecorded secret: %v", err)
	}
	if outcome, _, err := repo.ConsumeEmailVerification(ctx, unrecorded, pepper); err != nil || outcome != "unknown" {
		t.Fatalf("unknown token consume: %v (outcome %q)", err, outcome)
	}
	// A verified principal is now active and can sign in.
	_, state, _, err = repo.CredentialForEmail(ctx, email, pepper)
	if err != nil || state != auth.PrincipalActive {
		t.Fatalf("post-verification state: %q err=%v", state, err)
	}

	sessionID := uuid.New()
	sessionToken, err := auth.NewSecret(nil)
	if err != nil {
		t.Fatalf("session secret: %v", err)
	}
	if outcome, err := repo.RecordSession(ctx, sessionID, principalID, sessionToken, pepper, now, now.Add(30*24*time.Hour)); err != nil || outcome != "created" {
		t.Fatalf("record session: %v (outcome %q)", err, outcome)
	}
	session, err := repo.SessionForToken(ctx, sessionToken, pepper)
	if err != nil || session.SessionID != sessionID.String() || session.PrincipalID != principalID.String() {
		t.Fatalf("session lookup: %v (session %+v)", err, session)
	}
	if !session.Valid(now) {
		t.Fatalf("fresh session invalid: %+v at %v", session, now)
	}
	if outcome, err := repo.RevokeSession(ctx, sessionID); err != nil || outcome != "revoked" {
		t.Fatalf("revoke: %v (outcome %q)", err, outcome)
	}
	if _, err := repo.RevokeSession(ctx, sessionID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("repeat revoke: %v", err)
	}
	session, err = repo.SessionForToken(ctx, sessionToken, pepper)
	if err != nil {
		t.Fatalf("revoked lookup: %v", err)
	}
	if session.Valid(now) {
		t.Fatal("revoked session judged valid")
	}
	if _, err := repo.SessionForToken(ctx, unrecorded, pepper); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown session: %v", err)
	}

	// Token reuse across principals is refused at the database boundary.
	otherPrincipal := uuid.New()
	otherEmail := "owner-two-" + uuid.NewString() + "@example.test"
	if outcome, err := repo.BootstrapPrincipal(ctx, otherPrincipal, otherEmail, pepper, hash, &tenantID); err != nil || outcome != "created" {
		t.Fatalf("second bootstrap: %v (outcome %q)", err, outcome)
	}
	verificationToken, err := auth.NewSecret(nil)
	if err != nil {
		t.Fatalf("verification secret: %v", err)
	}
	if _, err := repo.RecordEmailVerification(ctx, otherPrincipal, verificationToken, pepper, now, now.Add(time.Hour)); err != nil {
		t.Fatalf("second verification: %v", err)
	}
	if _, err := repo.RecordEmailVerification(ctx, otherPrincipal, verificationToken, pepper, now, now.Add(time.Hour)); !errors.Is(err, ErrTokenReuse) {
		t.Fatalf("token reuse accepted: %v", err)
	}

	// Structural lockdown: the postgres superuser login (outside the capability
	// system) verifies FORCE RLS is set and the four tables carry no grants at
	// all - access exists only through the SECURITY DEFINER functions.
	var forced bool
	if err := adminDB.QueryRowContext(ctx,
		`SELECT relforcerowsecurity FROM pg_class
		  WHERE oid='keel_meta.identity_principals'::regclass`).Scan(&forced); err != nil || !forced {
		t.Fatalf("identity principals is not FORCE RLS: %v", err)
	}
	grantRows, err := adminDB.QueryContext(ctx,
		`SELECT c.relname FROM pg_class c
		  JOIN pg_namespace n ON n.oid=c.relnamespace
		 WHERE n.nspname='keel_meta'
		   AND c.relname IN ('identity_principals','identity_credentials',
		                     'identity_email_verifications','identity_sessions')
		   AND EXISTS (SELECT 1 FROM aclexplode(c.relacl) a
		                WHERE a.grantee<>c.relowner)`)
	if err != nil {
		t.Fatalf("grant check: %v", err)
	}
	defer grantRows.Close()
	if grantRows.Next() {
		grantTable := ""
		if err := grantRows.Scan(&grantTable); err != nil || grantTable != "" {
			t.Fatalf("identity table %q carries direct grants", grantTable)
		}
	}
	appDB := openRoleDB(t, "postgres://keel_local_app:keel-app-local-only@127.0.0.1:5432/postgres?sslmode=disable")
	if _, err := appDB.QueryContext(ctx,
		`SELECT keel_meta.create_identity_principal(gen_random_uuid(),'39a3a5946e1a08eecd0a9b4a8dc0e19c1a4c1bdb9369a45d1e547547e5b4d1ca'::bytea,'x',NULL)`); err == nil {
		t.Fatal("app capability executed identity function")
	} else if !isPrivilegeDenial(err) {
		t.Fatalf("unexpected app denial error: %v", err)
	}
	if _, err := identityDB.QueryContext(ctx, `SELECT password_hash FROM keel_meta.identity_credentials LIMIT 1`); err == nil {
		t.Fatal("identity login read credentials directly")
	} else if !isPrivilegeDenial(err) {
		t.Fatalf("unexpected identity denial error: %v", err)
	}
}

func isPrivilegeDenial(err error) bool {
	message := err.Error()
	return strings.Contains(message, "permission denied") ||
		strings.Contains(message, "capability is required")
}

func openRoleDB(t *testing.T, dsn string) *sql.DB {
	t.Helper()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open %s: %v", dsn, err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("ping %s: %v", dsn, err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}
