package postgres

import (
	"bytes"
	"context"
	"crypto/rand"
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
		                     'identity_email_verifications','identity_sessions',
		                     'identity_password_resets','identity_login_throttle',
		                     'identity_webauthn_credentials','identity_webauthn_challenges',
		                     'identity_organizations','identity_memberships',
		                     'identity_invites','identity_service_principals',
		                     'identity_api_keys')
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

// TestPostgreSQLIdentityRecoveryAndRotation proves the takeover boundary: a
// reset for an active principal rotates the credential and revokes every live
// session, the token is single-use, pending principals cannot start recovery,
// and revoke-all supports owner lockout.
func TestPostgreSQLIdentityRecoveryAndRotation(t *testing.T) {
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
	_ = adminDB

	// Bootstrap then verify a principal so recovery is eligible.
	email := "recover-" + uuid.NewString() + "@example.test"
	oldPassword := "old-recovery-phrase"
	oldHash, err := auth.HashPassword(oldPassword, auth.TestArgonParams())
	if err != nil {
		t.Fatalf("hash old: %v", err)
	}
	principalID := uuid.New()
	tenantID := uuid.MustParse("22222222-2222-4222-8222-222222222222")
	if outcome, err := repo.BootstrapPrincipal(ctx, principalID, email, pepper, oldHash, &tenantID); err != nil || outcome != "created" {
		t.Fatalf("bootstrap: %v (outcome %q)", err, outcome)
	}
	// Pending principals cannot start recovery.
	pendingToken, err := auth.NewSecret(nil)
	if err != nil {
		t.Fatalf("secret: %v", err)
	}
	if _, err := repo.RecordPasswordReset(ctx, principalID, pendingToken, pepper, now, now.Add(time.Hour)); !errors.Is(err, ErrNotVerified) {
		t.Fatalf("pending reset accepted: %v", err)
	}
	verifyToken, err := auth.NewSecret(nil)
	if err != nil {
		t.Fatalf("secret: %v", err)
	}
	if _, err := repo.RecordEmailVerification(ctx, principalID, verifyToken, pepper, now, now.Add(time.Hour)); err != nil {
		t.Fatalf("record verification: %v", err)
	}
	if outcome, _, err := repo.ConsumeEmailVerification(ctx, verifyToken, pepper); err != nil || outcome != "verified" {
		t.Fatalf("consume: %v (outcome %q)", err, outcome)
	}

	// Mint two live sessions before rotation.
	sessionOne, tokenOne := uuid.New(), mustSecret(t)
	if outcome, err := repo.RecordSession(ctx, sessionOne, principalID, tokenOne, pepper, now, now.Add(time.Hour)); err != nil || outcome != "created" {
		t.Fatalf("record session one: %v (outcome %q)", err, outcome)
	}
	sessionTwo, tokenTwo := uuid.New(), mustSecret(t)
	if outcome, err := repo.RecordSession(ctx, sessionTwo, principalID, tokenTwo, pepper, now, now.Add(time.Hour)); err != nil || outcome != "created" {
		t.Fatalf("record session two: %v (outcome %q)", err, outcome)
	}

	// Under-min reset TTL is rejected before the database.
	resetToken, err := auth.NewSecret(nil)
	if err != nil {
		t.Fatalf("secret: %v", err)
	}
	if _, err := repo.RecordPasswordReset(ctx, principalID, resetToken, pepper, now, now.Add(time.Minute)); err == nil {
		t.Fatal("under-min reset TTL accepted")
	}
	if outcome, err := repo.RecordPasswordReset(ctx, principalID, resetToken, pepper, now, now.Add(time.Hour)); err != nil || outcome != "recorded" {
		t.Fatalf("record reset: %v (outcome %q)", err, outcome)
	}
	// Token reuse across a second principal is refused.
	otherPrincipal := uuid.New()
	otherEmail := "recover-other-" + uuid.NewString() + "@example.test"
	if outcome, err := repo.BootstrapPrincipal(ctx, otherPrincipal, otherEmail, pepper, oldHash, &tenantID); err != nil || outcome != "created" {
		t.Fatalf("second bootstrap: %v (outcome %q)", err, outcome)
	}
	otherVerify, err := auth.NewSecret(nil)
	if err != nil {
		t.Fatalf("secret: %v", err)
	}
	if _, err := repo.RecordEmailVerification(ctx, otherPrincipal, otherVerify, pepper, now, now.Add(time.Hour)); err != nil {
		t.Fatalf("other verification: %v", err)
	}
	if outcome, _, err := repo.ConsumeEmailVerification(ctx, otherVerify, pepper); err != nil || outcome != "verified" {
		t.Fatalf("other consume: %v (outcome %q)", err, outcome)
	}
	if _, err := repo.RecordPasswordReset(ctx, otherPrincipal, resetToken, pepper, now, now.Add(time.Hour)); !errors.Is(err, ErrTokenReuse) {
		t.Fatalf("reset token reuse accepted: %v", err)
	}

	// Rotation consumes the token, replaces the hash and revokes both sessions.
	newPassword := "new-recovery-phrase"
	newHash, err := auth.HashPassword(newPassword, auth.TestArgonParams())
	if err != nil {
		t.Fatalf("hash new: %v", err)
	}
	if outcome, rotatedID, err := repo.RotateCredential(ctx, resetToken, pepper, newHash); err != nil || outcome != "rotated" || rotatedID != principalID {
		t.Fatalf("rotate: %v (outcome %q id %v)", err, outcome, rotatedID)
	}
	// Single-use: the same token is now a duplicate.
	if outcome, _, err := repo.RotateCredential(ctx, resetToken, pepper, newHash); err != nil || outcome != "duplicate" {
		t.Fatalf("repeat rotate: %v (outcome %q)", err, outcome)
	}
	// Unknown reset digests resolve to unknown.
	if outcome, _, err := repo.RotateCredential(ctx, mustSecret(t), pepper, newHash); err != nil || outcome != "unknown" {
		t.Fatalf("unknown rotate: %v (outcome %q)", err, outcome)
	}
	// Expired resets are consumed but refuse rotation. Backdate one request
	// through the superuser by parking the guard trigger, then restore it.
	expiredToken, err := auth.NewSecret(nil)
	if err != nil {
		t.Fatalf("secret: %v", err)
	}
	if outcome, err := repo.RecordPasswordReset(ctx, principalID, expiredToken, pepper, now, now.Add(time.Hour)); err != nil || outcome != "recorded" {
		t.Fatalf("record expired-candidate: %v (outcome %q)", err, outcome)
	}
	expiredDigest, err := auth.TokenDigest(expiredToken, auth.PurposePasswordReset)
	if err != nil {
		t.Fatalf("expired digest: %v", err)
	}
	if _, err := adminDB.ExecContext(ctx, `ALTER TABLE keel_meta.identity_password_resets DISABLE TRIGGER identity_password_resets_guard`); err != nil {
		t.Fatalf("disable reset guard: %v", err)
	}
	if _, err := adminDB.ExecContext(ctx, `UPDATE keel_meta.identity_password_resets SET requested_at=clock_timestamp()-INTERVAL '2 hours',expires_at=clock_timestamp()-INTERVAL '1 minute' WHERE token_digest=$1`, expiredDigest[:]); err != nil {
		t.Fatalf("backdate reset: %v", err)
	}
	if _, err := adminDB.ExecContext(ctx, `ALTER TABLE keel_meta.identity_password_resets ENABLE TRIGGER identity_password_resets_guard`); err != nil {
		t.Fatalf("enable reset guard: %v", err)
	}
	if outcome, _, err := repo.RotateCredential(ctx, expiredToken, pepper, newHash); err != nil || outcome != "expired" {
		t.Fatalf("expired rotate: %v (outcome %q)", err, outcome)
	}
	// Credential version advanced exactly once through rotation.
	var credentialVersion int
	if err := adminDB.QueryRowContext(ctx, `SELECT version FROM keel_meta.identity_credentials WHERE principal_id=$1`, principalID).Scan(&credentialVersion); err != nil || credentialVersion != 2 {
		t.Fatalf("credential version: %d err=%v", credentialVersion, err)
	}
	// Old password fails, new password verifies.
	_, _, stored, err := repo.CredentialForEmail(ctx, email, pepper)
	if err != nil {
		t.Fatalf("credential lookup: %v", err)
	}
	if ok, err := auth.VerifyPassword(oldPassword, stored); err != nil || ok {
		t.Fatalf("old password still verifies: %v %v", ok, err)
	}
	if ok, err := auth.VerifyPassword(newPassword, stored); err != nil || !ok {
		t.Fatalf("new password rejected: %v %v", ok, err)
	}
	// Both pre-rotation sessions are revoked and judge invalid.
	for i, tok := range []string{tokenOne, tokenTwo} {
		session, err := repo.SessionForToken(ctx, tok, pepper)
		if err != nil {
			t.Fatalf("revoked lookup %d: %v", i, err)
		}
		if session.Valid(now) {
			t.Fatalf("post-rotation session %d judged valid", i)
		}
	}
	// Revoke-all on a principal with no live sessions reports zero.
	if n, err := repo.RevokeAllSessions(ctx, principalID); err != nil || n != 0 {
		t.Fatalf("revoke-all empty: %v (n=%d)", err, n)
	}
	// A fresh session after rotation works, then revoke-all locks it out.
	freshID, freshToken := uuid.New(), mustSecret(t)
	if outcome, err := repo.RecordSession(ctx, freshID, principalID, freshToken, pepper, now, now.Add(time.Hour)); err != nil || outcome != "created" {
		t.Fatalf("fresh session: %v (outcome %q)", err, outcome)
	}
	secondID, secondToken := uuid.New(), mustSecret(t)
	if outcome, err := repo.RecordSession(ctx, secondID, principalID, secondToken, pepper, now, now.Add(time.Hour)); err != nil || outcome != "created" {
		t.Fatalf("second session: %v (outcome %q)", err, outcome)
	}
	if n, err := repo.RevokeAllSessions(ctx, principalID); err != nil || n != 2 {
		t.Fatalf("revoke-all: %v (n=%d)", err, n)
	}
	for i, tok := range []string{freshToken, secondToken} {
		session, err := repo.SessionForToken(ctx, tok, pepper)
		if err != nil {
			t.Fatalf("lockout lookup %d: %v", i, err)
		}
		if session.Valid(now) {
			t.Fatalf("lockout session %d judged valid", i)
		}
	}
	// Capability isolation for the new functions.
	var resetsForced bool
	if err := adminDB.QueryRowContext(ctx,
		`SELECT relforcerowsecurity FROM pg_class
		  WHERE oid='keel_meta.identity_password_resets'::regclass`).Scan(&resetsForced); err != nil || !resetsForced {
		t.Fatalf("identity resets is not FORCE RLS: %v", err)
	}
	appDB := openRoleDB(t, "postgres://keel_local_app:keel-app-local-only@127.0.0.1:5432/postgres?sslmode=disable")
	if _, err := appDB.QueryContext(ctx, `SELECT keel_meta.record_identity_password_reset(gen_random_uuid(),'00'::bytea,now())`); err == nil {
		t.Fatal("app capability executed reset function")
	} else if !isPrivilegeDenial(err) {
		t.Fatalf("unexpected app denial: %v", err)
	}
	if _, err := identityDB.QueryContext(ctx, `SELECT token_digest FROM keel_meta.identity_password_resets LIMIT 1`); err == nil {
		t.Fatal("identity login read resets directly")
	} else if !isPrivilegeDenial(err) {
		t.Fatalf("unexpected identity denial: %v", err)
	}
}

func mustSecret(t *testing.T) string {
	t.Helper()
	secret, err := auth.NewSecret(nil)
	if err != nil {
		t.Fatalf("secret: %v", err)
	}
	return secret
}

// TestPostgreSQLIdentityLockout proves the bounded lockout: four failures
// count, the fifth locks for 15 minutes without stretching on further
// attempts, success clears the count, stale failures decay, and unknown
// principals are never counted.
func TestPostgreSQLIdentityLockout(t *testing.T) {
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

	email := "lockout-" + uuid.NewString() + "@example.test"
	hash, err := auth.HashPassword("lockout-pass-phrase", auth.TestArgonParams())
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	principalID := uuid.New()
	tenantID := uuid.MustParse("33333333-3333-4333-8333-333333333333")
	if outcome, err := repo.BootstrapPrincipal(ctx, principalID, email, pepper, hash, &tenantID); err != nil || outcome != "created" {
		t.Fatalf("bootstrap: %v (outcome %q)", err, outcome)
	}
	verifyToken := mustSecret(t)
	if _, err := repo.RecordEmailVerification(ctx, principalID, verifyToken, pepper, now, now.Add(time.Hour)); err != nil {
		t.Fatalf("record verification: %v", err)
	}
	if outcome, _, err := repo.ConsumeEmailVerification(ctx, verifyToken, pepper); err != nil || outcome != "verified" {
		t.Fatalf("consume: %v (outcome %q)", err, outcome)
	}

	for i := 0; i < 4; i++ {
		if outcome, err := repo.RecordLoginFailure(ctx, principalID); err != nil || outcome != "counted" {
			t.Fatalf("failure %d: %v (outcome %q)", i+1, err, outcome)
		}
	}
	if outcome, err := repo.RecordLoginFailure(ctx, principalID); err != nil || outcome != "locked" {
		t.Fatalf("fifth failure: %v (outcome %q)", err, outcome)
	}
	count, lockedUntil, err := repo.ThrottleFor(ctx, principalID)
	if err != nil || count != 5 || !lockedUntil.After(now) {
		t.Fatalf("throttle: count=%d locked=%v err=%v", count, lockedUntil, err)
	}
	// Attempts while locked change nothing: same outcome, same expiry.
	if outcome, err := repo.RecordLoginFailure(ctx, principalID); err != nil || outcome != "locked" {
		t.Fatalf("locked attempt: %v (outcome %q)", err, outcome)
	}
	_, lockedAgain, err := repo.ThrottleFor(ctx, principalID)
	if err != nil || !lockedAgain.Equal(lockedUntil) {
		t.Fatalf("lock stretched: %v vs %v err=%v", lockedAgain, lockedUntil, err)
	}
	// Success clears the count.
	if n, err := repo.ResetLoginThrottle(ctx, principalID); err != nil || n != 1 {
		t.Fatalf("reset: %v (n=%d)", err, n)
	}
	if count, lockedUntil, err := repo.ThrottleFor(ctx, principalID); err != nil || count != 0 || !lockedUntil.IsZero() {
		t.Fatalf("post-reset: count=%d locked=%v err=%v", count, lockedUntil, err)
	}
	if n, err := repo.ResetLoginThrottle(ctx, principalID); err != nil || n != 0 {
		t.Fatalf("empty reset: %v (n=%d)", err, n)
	}
	// Unknown principals are never counted.
	if _, err := repo.RecordLoginFailure(ctx, uuid.New()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown principal: %v", err)
	}
	// Stale failures decay: a failure older than 15 minutes restarts at one.
	if outcome, err := repo.RecordLoginFailure(ctx, principalID); err != nil || outcome != "counted" {
		t.Fatalf("fresh failure: %v (outcome %q)", err, outcome)
	}
	if _, err := adminDB.ExecContext(ctx, `ALTER TABLE keel_meta.identity_login_throttle DISABLE TRIGGER identity_login_throttle_guard`); err != nil {
		t.Fatalf("disable throttle guard: %v", err)
	}
	if _, err := adminDB.ExecContext(ctx, `UPDATE keel_meta.identity_login_throttle SET first_failure_at=clock_timestamp()-INTERVAL '1 hour',last_failure_at=clock_timestamp()-INTERVAL '1 hour' WHERE principal_id=$1`, principalID); err != nil {
		t.Fatalf("backdate throttle: %v", err)
	}
	if _, err := adminDB.ExecContext(ctx, `ALTER TABLE keel_meta.identity_login_throttle ENABLE TRIGGER identity_login_throttle_guard`); err != nil {
		t.Fatalf("enable throttle guard: %v", err)
	}
	if outcome, err := repo.RecordLoginFailure(ctx, principalID); err != nil || outcome != "counted" {
		t.Fatalf("decayed failure: %v (outcome %q)", err, outcome)
	}
	if count, lockedUntil, err := repo.ThrottleFor(ctx, principalID); err != nil || count != 1 || !lockedUntil.IsZero() {
		t.Fatalf("decayed throttle: count=%d locked=%v err=%v", count, lockedUntil, err)
	}
	// Structural lockdown for the throttle table.
	var forced bool
	if err := adminDB.QueryRowContext(ctx,
		`SELECT relforcerowsecurity FROM pg_class
		  WHERE oid='keel_meta.identity_login_throttle'::regclass`).Scan(&forced); err != nil || !forced {
		t.Fatalf("throttle is not FORCE RLS: %v", err)
	}
	appDB := openRoleDB(t, "postgres://keel_local_app:keel-app-local-only@127.0.0.1:5432/postgres?sslmode=disable")
	if _, err := appDB.QueryContext(ctx, `SELECT keel_meta.record_identity_login_failure(gen_random_uuid())`); err == nil {
		t.Fatal("app capability executed throttle function")
	} else if !isPrivilegeDenial(err) {
		t.Fatalf("unexpected app denial: %v", err)
	}
	if _, err := identityDB.QueryContext(ctx, `SELECT consecutive_failures FROM keel_meta.identity_login_throttle LIMIT 1`); err == nil {
		t.Fatal("identity login read throttle directly")
	} else if !isPrivilegeDenial(err) {
		t.Fatalf("unexpected identity denial: %v", err)
	}
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

// activeTestPrincipal bootstraps and verifies one principal for tests that
// need an eligible actor or member. A nil tenant leaves the principal
// unbound so organization tests can prove first binding.
func activeTestPrincipal(t *testing.T, ctx context.Context, repo *Repository, pepper []byte, email string, tenantID *uuid.UUID) uuid.UUID {
	t.Helper()
	passwordHash, err := auth.HashPassword("org-member-pass-phrase", auth.TestArgonParams())
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	principalID := uuid.New()
	if outcome, err := repo.BootstrapPrincipal(ctx, principalID, email, pepper, passwordHash, tenantID); err != nil || outcome != "created" {
		t.Fatalf("bootstrap: %v (outcome %q)", err, outcome)
	}
	token := mustSecret(t)
	now := time.Now().UTC()
	if _, err := repo.RecordEmailVerification(ctx, principalID, token, pepper, now, now.Add(time.Hour)); err != nil {
		t.Fatalf("record verification: %v", err)
	}
	if outcome, _, err := repo.ConsumeEmailVerification(ctx, token, pepper); err != nil || outcome != "verified" {
		t.Fatalf("consume: %v (outcome %q)", err, outcome)
	}
	return principalID
}

func boundTenant(t *testing.T, adminDB *sql.DB, ctx context.Context, principalID uuid.UUID) *uuid.UUID {
	t.Helper()
	var tenant uuid.NullUUID
	if err := adminDB.QueryRowContext(ctx, `SELECT tenant_id FROM keel_meta.identity_principals WHERE principal_id=$1`, principalID).Scan(&tenant); err != nil {
		t.Fatalf("tenant lookup: %v", err)
	}
	if !tenant.Valid {
		return nil
	}
	id := tenant.UUID
	return &id
}

// TestPostgreSQLIdentityOrganizations proves first binding: creating seats an
// owner and binds the tenant, owners/admins seat members with tenant
// convergence, and cross-org principals, strangers and bad input fail closed.
func TestPostgreSQLIdentityOrganizations(t *testing.T) {
	identityDSN := os.Getenv("KEEL_TEST_IDENTITY_DATABASE_URL")
	adminDSN := os.Getenv("KEEL_TEST_ADMIN_DATABASE_URL")
	if identityDSN == "" || adminDSN == "" {
		t.Skip("set identity and admin PostgreSQL URLs to run identity integration tests")
	}
	ctx := context.Background()

	identityDB := openRoleDB(t, identityDSN)
	repo, err := New(identityDB)
	if err != nil {
		t.Fatalf("repository: %v", err)
	}
	pepper := []byte("keel-integration-pepper-keel-integration-pepper-32")
	adminDB := openRoleDB(t, adminDSN)

	owner := activeTestPrincipal(t, ctx, repo, pepper, "org-owner-"+uuid.NewString()+"@example.test", nil)
	orgID := uuid.New()
	if outcome, err := repo.CreateOrganization(ctx, orgID, owner, "acme-"+uuid.NewString()[:8], "Acme Corporation", "home"); err != nil || outcome != "created" {
		t.Fatalf("create: %v (outcome %q)", err, outcome)
	}
	if bound := boundTenant(t, adminDB, ctx, owner); bound == nil || *bound != orgID {
		t.Fatalf("owner tenant not bound: %v", bound)
	}
	orgs, err := repo.OrganizationsFor(ctx, owner)
	if err != nil || len(orgs) != 1 || orgs[0].OrgID != orgID || orgs[0].Role != auth.OrgRoleOwner {
		t.Fatalf("owner orgs: %v err=%v", orgs, err)
	}
	// Founders keep founding: the tenant stays first-bound (primary).
	secondOrgID := uuid.New()
	if outcome, err := repo.CreateOrganization(ctx, secondOrgID, owner, "second-"+uuid.NewString()[:8], "Second", "home"); err != nil || outcome != "created" {
		t.Fatalf("second org: %v (outcome %q)", err, outcome)
	}
	if bound := boundTenant(t, adminDB, ctx, owner); bound == nil || *bound != orgID {
		t.Fatalf("owner tenant moved: %v", bound)
	}
	orgs, err = repo.OrganizationsFor(ctx, owner)
	if err != nil || len(orgs) != 2 {
		t.Fatalf("owner orgs: %v err=%v", orgs, err)
	}
	// Slugs are globally unique.
	other := activeTestPrincipal(t, ctx, repo, pepper, "org-other-"+uuid.NewString()+"@example.test", nil)
	if _, err := repo.CreateOrganization(ctx, uuid.New(), other, orgs[0].Slug, "Clone", "home"); !errors.Is(err, ErrConflict) {
		t.Fatalf("slug reuse: %v", err)
	}
	// Pending principals cannot found organizations.
	pendingHash, err := auth.HashPassword("pending-pass-phrase", auth.TestArgonParams())
	if err != nil {
		t.Fatal(err)
	}
	pending := uuid.New()
	if outcome, err := repo.BootstrapPrincipal(ctx, pending, "org-pending-"+uuid.NewString()+"@example.test", pepper, pendingHash, nil); err != nil || outcome != "created" {
		t.Fatalf("pending bootstrap: %v", err)
	}
	if _, err := repo.CreateOrganization(ctx, uuid.New(), pending, "pending-"+uuid.NewString()[:8], "Pending", "home"); !errors.Is(err, ErrNotVerified) {
		t.Fatalf("pending create: %v", err)
	}
	// Owners seat members; membership binds the tenant.
	member := activeTestPrincipal(t, ctx, repo, pepper, "org-member-"+uuid.NewString()+"@example.test", nil)
	if outcome, err := repo.AddOrganizationMember(ctx, owner, orgID, member, auth.OrgRoleMember); err != nil || outcome != "added" {
		t.Fatalf("add member: %v (outcome %q)", err, outcome)
	}
	if bound := boundTenant(t, adminDB, ctx, member); bound == nil || *bound != orgID {
		t.Fatalf("member tenant not bound: %v", bound)
	}
	// Members cannot seat others; admins can.
	stranger := activeTestPrincipal(t, ctx, repo, pepper, "org-stranger-"+uuid.NewString()+"@example.test", nil)
	if _, err := repo.AddOrganizationMember(ctx, member, orgID, stranger, auth.OrgRoleMember); !errors.Is(err, ErrNotAuthorized) {
		t.Fatalf("member add: %v", err)
	}
	if outcome, err := repo.AddOrganizationMember(ctx, owner, orgID, stranger, auth.OrgRoleAdmin); err != nil || outcome != "added" {
		t.Fatalf("add admin: %v (outcome %q)", err, outcome)
	}
	third := activeTestPrincipal(t, ctx, repo, pepper, "org-third-"+uuid.NewString()+"@example.test", nil)
	if outcome, err := repo.AddOrganizationMember(ctx, stranger, orgID, third, auth.OrgRoleMember); err != nil || outcome != "added" {
		t.Fatalf("admin add: %v (outcome %q)", err, outcome)
	}
	// Re-adding to the same org conflicts; joining a second org is allowed
	// and never moves the first-bound tenant.
	if _, err := repo.AddOrganizationMember(ctx, owner, orgID, member, auth.OrgRoleMember); !errors.Is(err, ErrConflict) {
		t.Fatalf("re-add: %v", err)
	}
	otherOrgOwner := activeTestPrincipal(t, ctx, repo, pepper, "org-rival-"+uuid.NewString()+"@example.test", nil)
	otherOrgID := uuid.New()
	if outcome, err := repo.CreateOrganization(ctx, otherOrgID, otherOrgOwner, "rival-"+uuid.NewString()[:8], "Rival", "home"); err != nil || outcome != "created" {
		t.Fatalf("rival create: %v (outcome %q)", err, outcome)
	}
	if outcome, err := repo.AddOrganizationMember(ctx, owner, orgID, otherOrgOwner, auth.OrgRoleMember); err != nil || outcome != "added" {
		t.Fatalf("cross-org add: %v (outcome %q)", err, outcome)
	}
	if bound := boundTenant(t, adminDB, ctx, otherOrgOwner); bound == nil || *bound != otherOrgID {
		t.Fatalf("rival tenant moved: %v", bound)
	}
	rivalOrgs, err := repo.OrganizationsFor(ctx, otherOrgOwner)
	if err != nil || len(rivalOrgs) != 2 {
		t.Fatalf("rival orgs: %v err=%v", rivalOrgs, err)
	}
	// Per-session active-org switch follows membership, never tenancy.
	now := time.Now().UTC()
	sessionID := uuid.New()
	sessionToken := mustSecret(t)
	if outcome, err := repo.RecordSession(ctx, sessionID, member, sessionToken, pepper, now, now.Add(time.Hour)); err != nil || outcome != "created" {
		t.Fatalf("record session: %v (outcome %q)", err, outcome)
	}
	session, err := repo.SessionForToken(ctx, sessionToken, pepper)
	if err != nil || session.OrgID != "" {
		t.Fatalf("fresh session org: %q err=%v", session.OrgID, err)
	}
	if outcome, err := repo.SwitchSessionOrg(ctx, sessionID, orgID); err != nil || outcome != "switched" {
		t.Fatalf("switch: %v (outcome %q)", err, outcome)
	}
	session, err = repo.SessionForToken(ctx, sessionToken, pepper)
	if err != nil || session.OrgID != orgID.String() || !session.Valid(now) {
		t.Fatalf("switched session: %+v err=%v", session, err)
	}
	// Switching to a second membership works; strangers and dead sessions fail.
	if outcome, err := repo.AddOrganizationMember(ctx, otherOrgOwner, otherOrgID, member, auth.OrgRoleMember); err != nil || outcome != "added" {
		t.Fatalf("member joins rival: %v (outcome %q)", err, outcome)
	}
	if outcome, err := repo.SwitchSessionOrg(ctx, sessionID, otherOrgID); err != nil || outcome != "switched" {
		t.Fatalf("second switch: %v (outcome %q)", err, outcome)
	}
	thirdOrgID := uuid.New()
	thirdOrgOwner := activeTestPrincipal(t, ctx, repo, pepper, "org-third-owner-"+uuid.NewString()+"@example.test", nil)
	if outcome, err := repo.CreateOrganization(ctx, thirdOrgID, thirdOrgOwner, "third-"+uuid.NewString()[:8], "Third", "home"); err != nil || outcome != "created" {
		t.Fatalf("third create: %v (outcome %q)", err, outcome)
	}
	if outcome, err := repo.SwitchSessionOrg(ctx, sessionID, thirdOrgID); err != nil || outcome != "not_member" {
		t.Fatalf("stranger switch: %v (outcome %q)", err, outcome)
	}
	if _, err := repo.SwitchSessionOrg(ctx, uuid.New(), orgID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown session switch: %v", err)
	}
	if _, err := repo.RevokeSession(ctx, sessionID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := repo.SwitchSessionOrg(ctx, sessionID, orgID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoked switch: %v", err)
	}
	// Expired sessions do not switch either.
	expirySession := uuid.New()
	expiryToken := mustSecret(t)
	if outcome, err := repo.RecordSession(ctx, expirySession, member, expiryToken, pepper, now, now.Add(time.Hour)); err != nil || outcome != "created" {
		t.Fatalf("expiry session: %v (outcome %q)", err, outcome)
	}
	if _, err := adminDB.ExecContext(ctx, `ALTER TABLE keel_meta.identity_sessions DISABLE TRIGGER identity_sessions_guard`); err != nil {
		t.Fatalf("disable sessions guard: %v", err)
	}
	if _, err := adminDB.ExecContext(ctx, `UPDATE keel_meta.identity_sessions SET created_at=clock_timestamp()-INTERVAL '2 hours',expires_at=clock_timestamp()-INTERVAL '1 hour' WHERE session_id=$1`, expirySession); err != nil {
		t.Fatalf("backdate session: %v", err)
	}
	if _, err := adminDB.ExecContext(ctx, `ALTER TABLE keel_meta.identity_sessions ENABLE TRIGGER identity_sessions_guard`); err != nil {
		t.Fatalf("enable sessions guard: %v", err)
	}
	if _, err := repo.SwitchSessionOrg(ctx, expirySession, orgID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired switch: %v", err)
	}
	// Owner seats are never granted through the member path, and bad input
	// fails before the database.
	if _, err := repo.AddOrganizationMember(ctx, owner, orgID, third, auth.OrgRoleOwner); !errors.Is(err, ErrInvalidRecord) {
		t.Fatalf("owner grant: %v", err)
	}
	strangerOrgs, err := repo.OrganizationsFor(ctx, stranger)
	if err != nil || len(strangerOrgs) != 1 || strangerOrgs[0].Role != auth.OrgRoleAdmin {
		t.Fatalf("admin orgs: %v err=%v", strangerOrgs, err)
	}
	if _, err := repo.CreateOrganization(ctx, uuid.New(), owner, "Bad Slug!", "Bad", "home"); err == nil {
		t.Fatal("bad slug accepted")
	}
	// Structural lockdown for both new tables.
	for _, table := range []string{"identity_organizations", "identity_memberships"} {
		var forced bool
		if err := adminDB.QueryRowContext(ctx,
			`SELECT relforcerowsecurity FROM pg_class WHERE oid=('keel_meta.'||$1)::regclass`, table).Scan(&forced); err != nil || !forced {
			t.Fatalf("%s is not FORCE RLS: %v", table, err)
		}
	}
	appDB := openRoleDB(t, "postgres://keel_local_app:keel-app-local-only@127.0.0.1:5432/postgres?sslmode=disable")
	if _, err := appDB.QueryContext(ctx, `SELECT keel_meta.create_identity_organization(gen_random_uuid(),gen_random_uuid(),'s','n','home')`); err == nil {
		t.Fatal("app capability executed org function")
	} else if !isPrivilegeDenial(err) {
		t.Fatalf("unexpected app denial: %v", err)
	}
	if _, err := identityDB.QueryContext(ctx, `SELECT slug FROM keel_meta.identity_organizations LIMIT 1`); err == nil {
		t.Fatal("identity login read organizations directly")
	} else if !isPrivilegeDenial(err) {
		t.Fatalf("unexpected identity denial: %v", err)
	}
}

// TestPostgreSQLIdentityInvitesAndTransfer proves token invites and the
// immediate owner handoff: invites name an email that needs no account yet,
// acceptance seats the matching principal and binds an unbound tenant, and
// transfer swaps owner/admin atomically without orphaning the org.
func TestPostgreSQLIdentityInvitesAndTransfer(t *testing.T) {
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

	owner := activeTestPrincipal(t, ctx, repo, pepper, "invite-owner-"+uuid.NewString()+"@example.test", nil)
	orgID := uuid.New()
	if outcome, err := repo.CreateOrganization(ctx, orgID, owner, "invite-"+uuid.NewString()[:8], "Invite Org", "home"); err != nil || outcome != "created" {
		t.Fatalf("create: %v (outcome %q)", err, outcome)
	}
	// Owners and admins invite; strangers are refused.
	inviteeEmail := "invitee-" + uuid.NewString() + "@example.test"
	inviteToken := mustSecret(t)
	if outcome, err := repo.InviteMember(ctx, uuid.New(), owner, orgID, inviteeEmail, pepper, inviteToken, auth.OrgRoleMember, now, now.Add(24*time.Hour)); err != nil || outcome != "invited" {
		t.Fatalf("invite: %v (outcome %q)", err, outcome)
	}
	stranger := activeTestPrincipal(t, ctx, repo, pepper, "invite-stranger-"+uuid.NewString()+"@example.test", nil)
	if _, err := repo.InviteMember(ctx, uuid.New(), stranger, orgID, "x-"+uuid.NewString()+"@example.test", pepper, mustSecret(t), auth.OrgRoleMember, now, now.Add(24*time.Hour)); !errors.Is(err, ErrNotAuthorized) {
		t.Fatalf("stranger invite: %v", err)
	}
	// Tokens are single-use across invites; members are not re-invited.
	if _, err := repo.InviteMember(ctx, uuid.New(), owner, orgID, "fresh-"+uuid.NewString()+"@example.test", pepper, inviteToken, auth.OrgRoleMember, now, now.Add(24*time.Hour)); !errors.Is(err, ErrTokenReuse) {
		t.Fatalf("token reuse: %v", err)
	}
	if _, err := repo.InviteMember(ctx, uuid.New(), owner, orgID, "ttl-"+uuid.NewString()+"@example.test", pepper, mustSecret(t), auth.OrgRoleMember, now, now.Add(30*time.Minute)); err == nil {
		t.Fatal("under-min invite TTL accepted")
	}
	// Acceptance seats the matching principal and binds an unbound tenant.
	invitee := activeTestPrincipal(t, ctx, repo, pepper, inviteeEmail, nil)
	if outcome, acceptedOrg, err := repo.AcceptInvite(ctx, inviteToken, invitee); err != nil || outcome != "accepted" || acceptedOrg != orgID {
		t.Fatalf("accept: %v (outcome %q org %v)", err, outcome, acceptedOrg)
	}
	if bound := boundTenant(t, adminDB, ctx, invitee); bound == nil || *bound != orgID {
		t.Fatalf("invitee tenant not bound: %v", bound)
	}
	if outcome, _, err := repo.AcceptInvite(ctx, inviteToken, invitee); err != nil || outcome != "duplicate" {
		t.Fatalf("repeat accept: %v (outcome %q)", err, outcome)
	}
	// A different principal cannot consume the invite.
	otherEmail := "invitee-other-" + uuid.NewString() + "@example.test"
	otherToken := mustSecret(t)
	if outcome, err := repo.InviteMember(ctx, uuid.New(), owner, orgID, otherEmail, pepper, otherToken, auth.OrgRoleAdmin, now, now.Add(24*time.Hour)); err != nil || outcome != "invited" {
		t.Fatalf("second invite: %v (outcome %q)", err, outcome)
	}
	other := activeTestPrincipal(t, ctx, repo, pepper, "wrong-principal-"+uuid.NewString()+"@example.test", nil)
	if outcome, _, err := repo.AcceptInvite(ctx, otherToken, other); err != nil || outcome != "email_mismatch" {
		t.Fatalf("mismatch accept: %v (outcome %q)", err, outcome)
	}
	// Members are not re-invited.
	if _, err := repo.InviteMember(ctx, uuid.New(), owner, orgID, inviteeEmail, pepper, mustSecret(t), auth.OrgRoleMember, now, now.Add(24*time.Hour)); !errors.Is(err, ErrConflict) {
		t.Fatalf("member re-invite: %v", err)
	}
	// Expired invites consume as expired.
	expiryEmail := "expiry-" + uuid.NewString() + "@example.test"
	expiryToken := mustSecret(t)
	if outcome, err := repo.InviteMember(ctx, uuid.New(), owner, orgID, expiryEmail, pepper, expiryToken, auth.OrgRoleMember, now, now.Add(24*time.Hour)); err != nil || outcome != "invited" {
		t.Fatalf("expiry invite: %v (outcome %q)", err, outcome)
	}
	if _, err := adminDB.ExecContext(ctx, `ALTER TABLE keel_meta.identity_invites DISABLE TRIGGER identity_invites_guard`); err != nil {
		t.Fatalf("disable invite guard: %v", err)
	}
	expiryDigest, err := auth.TokenDigest(expiryToken, auth.PurposeOrganizationInvite)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adminDB.ExecContext(ctx, `UPDATE keel_meta.identity_invites SET requested_at=clock_timestamp()-INTERVAL '2 hours',expires_at=clock_timestamp()-INTERVAL '1 minute' WHERE token_digest=$1`, expiryDigest[:]); err != nil {
		t.Fatalf("backdate invite: %v", err)
	}
	if _, err := adminDB.ExecContext(ctx, `ALTER TABLE keel_meta.identity_invites ENABLE TRIGGER identity_invites_guard`); err != nil {
		t.Fatalf("enable invite guard: %v", err)
	}
	expiryPrincipal := activeTestPrincipal(t, ctx, repo, pepper, expiryEmail, nil)
	if outcome, _, err := repo.AcceptInvite(ctx, expiryToken, expiryPrincipal); err != nil || outcome != "expired" {
		t.Fatalf("expired accept: %v (outcome %q)", err, outcome)
	}
	// Immediate transfer swaps owner and admin atomically.
	if outcome, err := repo.TransferOwnership(ctx, owner, orgID, invitee); err != nil || outcome != "transferred" {
		t.Fatalf("transfer: %v (outcome %q)", err, outcome)
	}
	ownerOrgs, err := repo.OrganizationsFor(ctx, owner)
	if err != nil || len(ownerOrgs) != 1 || ownerOrgs[0].Role != auth.OrgRoleAdmin {
		t.Fatalf("old owner orgs: %v err=%v", ownerOrgs, err)
	}
	inviteeOrgs, err := repo.OrganizationsFor(ctx, invitee)
	if err != nil || len(inviteeOrgs) != 1 || inviteeOrgs[0].Role != auth.OrgRoleOwner {
		t.Fatalf("new owner orgs: %v err=%v", inviteeOrgs, err)
	}
	// Demoted owners cannot transfer; outsiders are not members.
	if _, err := repo.TransferOwnership(ctx, owner, orgID, invitee); !errors.Is(err, ErrNotAuthorized) {
		t.Fatalf("demoted transfer: %v", err)
	}
	if _, err := repo.TransferOwnership(ctx, invitee, orgID, stranger); !errors.Is(err, ErrNotFound) {
		t.Fatalf("outsider transfer: %v", err)
	}
	// Self-transfer is a no-op success.
	if outcome, err := repo.TransferOwnership(ctx, invitee, orgID, invitee); err != nil || outcome != "transferred" {
		t.Fatalf("self transfer: %v (outcome %q)", err, outcome)
	}
	// Structural lockdown for the invites table.
	var forced bool
	if err := adminDB.QueryRowContext(ctx,
		`SELECT relforcerowsecurity FROM pg_class WHERE oid='keel_meta.identity_invites'::regclass`).Scan(&forced); err != nil || !forced {
		t.Fatalf("invites is not FORCE RLS: %v", err)
	}
	appDB := openRoleDB(t, "postgres://keel_local_app:keel-app-local-only@127.0.0.1:5432/postgres?sslmode=disable")
	if _, err := appDB.QueryContext(ctx, `SELECT keel_meta.invite_organization_member(gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),'00'::bytea,'00'::bytea,'member',now())`); err == nil {
		t.Fatal("app capability executed invite function")
	} else if !isPrivilegeDenial(err) {
		t.Fatalf("unexpected app denial: %v", err)
	}
	if _, err := identityDB.QueryContext(ctx, `SELECT token_digest FROM keel_meta.identity_invites LIMIT 1`); err == nil {
		t.Fatal("identity login read invites directly")
	} else if !isPrivilegeDenial(err) {
		t.Fatalf("unexpected identity denial: %v", err)
	}
}

// TestPostgreSQLIdentityAPIKeys proves the machine-identity lifecycle: an
// owner/admin registers a service principal, issues bearer keys shown once,
// verifies against digests only, rotates with overlap, and revocation plus
// disable fail closed.
func TestPostgreSQLIdentityAPIKeys(t *testing.T) {
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

	owner := activeTestPrincipal(t, ctx, repo, pepper, "svc-owner-"+uuid.NewString()+"@example.test", nil)
	orgID := uuid.New()
	if outcome, err := repo.CreateOrganization(ctx, orgID, owner, "svc-"+uuid.NewString()[:8], "Services", "home"); err != nil || outcome != "created" {
		t.Fatalf("create: %v (outcome %q)", err, outcome)
	}
	stranger := activeTestPrincipal(t, ctx, repo, pepper, "svc-stranger-"+uuid.NewString()+"@example.test", nil)
	svcID := uuid.New()
	if outcome, err := repo.CreateServicePrincipal(ctx, svcID, owner, orgID, "etl-worker"); err != nil || outcome != "created" {
		t.Fatalf("create service: %v (outcome %q)", err, outcome)
	}
	if _, err := repo.CreateServicePrincipal(ctx, uuid.New(), stranger, orgID, "intruder"); !errors.Is(err, ErrNotAuthorized) {
		t.Fatalf("stranger create: %v", err)
	}
	// Issue shows the wire form once; verification resolves the identity.
	keyID := uuid.New()
	wire, err := repo.IssueAPIKey(ctx, keyID, svcID, now, time.Time{})
	if err != nil || wire == "" {
		t.Fatalf("issue: %v", err)
	}
	if prefix, _, err := auth.ParseAPIKey(wire); err != nil || prefix == "" {
		t.Fatalf("wire form: %v", err)
	}
	outcome, identity, err := repo.VerifyAPIKey(ctx, wire)
	if err != nil || outcome != "valid" || identity.KeyID != keyID || identity.ServicePrincipalID != svcID || identity.OrgID != orgID {
		t.Fatalf("verify: %v (outcome %q identity %+v)", err, outcome, identity)
	}
	if outcome, _, err := repo.VerifyAPIKey(ctx, wire[:len(wire)-2]+"xx"); err != nil || outcome != "unknown" {
		t.Fatalf("tampered key: %v (outcome %q)", err, outcome)
	}
	// Rotation overlaps: the predecessor stays valid until revoked.
	rotatedID := uuid.New()
	rotated, err := repo.IssueAPIKey(ctx, rotatedID, svcID, now, now.Add(24*time.Hour))
	if err != nil || rotated == "" {
		t.Fatalf("rotate issue: %v", err)
	}
	if outcome, _, err := repo.VerifyAPIKey(ctx, wire); err != nil || outcome != "valid" {
		t.Fatalf("predecessor during overlap: %v (outcome %q)", err, outcome)
	}
	if outcome, err := repo.RevokeAPIKey(ctx, keyID); err != nil || outcome != "revoked" {
		t.Fatalf("revoke: %v (outcome %q)", err, outcome)
	}
	if _, err := repo.RevokeAPIKey(ctx, keyID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("repeat revoke: %v", err)
	}
	if outcome, _, err := repo.VerifyAPIKey(ctx, wire); err != nil || outcome != "revoked" {
		t.Fatalf("revoked verify: %v (outcome %q)", err, outcome)
	}
	if outcome, _, err := repo.VerifyAPIKey(ctx, rotated); err != nil || outcome != "valid" {
		t.Fatalf("rotated verify: %v (outcome %q)", err, outcome)
	}
	// Expiry is enforced on the database clock.
	if _, err := adminDB.ExecContext(ctx, `ALTER TABLE keel_meta.identity_api_keys DISABLE TRIGGER identity_api_keys_guard`); err != nil {
		t.Fatalf("disable key guard: %v", err)
	}
	expiryDigest, err := auth.APIKeyDigest(mustAPIKeySecret(t, rotated))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adminDB.ExecContext(ctx, `UPDATE keel_meta.identity_api_keys SET created_at=clock_timestamp()-INTERVAL '2 hours',expires_at=clock_timestamp()-INTERVAL '1 minute' WHERE key_digest=$1`, expiryDigest[:]); err != nil {
		t.Fatalf("backdate key: %v", err)
	}
	if _, err := adminDB.ExecContext(ctx, `ALTER TABLE keel_meta.identity_api_keys ENABLE TRIGGER identity_api_keys_guard`); err != nil {
		t.Fatalf("enable key guard: %v", err)
	}
	if outcome, _, err := repo.VerifyAPIKey(ctx, rotated); err != nil || outcome != "expired" {
		t.Fatalf("expired verify: %v (outcome %q)", err, outcome)
	}
	// Disabling the principal revokes every live key.
	liveID := uuid.New()
	live, err := repo.IssueAPIKey(ctx, liveID, svcID, now, time.Time{})
	if err != nil {
		t.Fatalf("live issue: %v", err)
	}
	if outcome, err := repo.DisableServicePrincipal(ctx, svcID); err != nil || outcome != "disabled" {
		t.Fatalf("disable: %v (outcome %q)", err, outcome)
	}
	if outcome, _, err := repo.VerifyAPIKey(ctx, live); err != nil || outcome != "revoked" {
		t.Fatalf("disabled verify: %v (outcome %q)", err, outcome)
	}
	if _, err := repo.DisableServicePrincipal(ctx, svcID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("repeat disable: %v", err)
	}
	// Structural lockdown for both new tables.
	for _, table := range []string{"identity_service_principals", "identity_api_keys"} {
		var forced bool
		if err := adminDB.QueryRowContext(ctx,
			`SELECT relforcerowsecurity FROM pg_class WHERE oid=('keel_meta.'||$1)::regclass`, table).Scan(&forced); err != nil || !forced {
			t.Fatalf("%s is not FORCE RLS: %v", table, err)
		}
	}
	appDB := openRoleDB(t, "postgres://keel_local_app:keel-app-local-only@127.0.0.1:5432/postgres?sslmode=disable")
	if _, err := appDB.QueryContext(ctx, `SELECT keel_meta.issue_identity_api_key(gen_random_uuid(),gen_random_uuid(),'abcdefgh','00'::bytea,NULL)`); err == nil {
		t.Fatal("app capability executed key function")
	} else if !isPrivilegeDenial(err) {
		t.Fatalf("unexpected app denial: %v", err)
	}
	if _, err := identityDB.QueryContext(ctx, `SELECT key_digest FROM keel_meta.identity_api_keys LIMIT 1`); err == nil {
		t.Fatal("identity login read keys directly")
	} else if !isPrivilegeDenial(err) {
		t.Fatalf("unexpected identity denial: %v", err)
	}
}

func mustAPIKeySecret(t *testing.T, wire string) string {
	t.Helper()
	_, secret, err := auth.ParseAPIKey(wire)
	if err != nil {
		t.Fatal(err)
	}
	return secret
}

// TestPostgreSQLIdentityWebAuthn proves the key lifecycle: active-only
// challenges with resend replacement, single-use consume, atomic registration
// bound to a registration challenge, monotonic sign counts with clone
// reporting, and the same capability isolation as every identity table.
func TestPostgreSQLIdentityWebAuthn(t *testing.T) {
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

	email := "webauthn-" + uuid.NewString() + "@example.test"
	hash, err := auth.HashPassword("webauthn-pass-phrase", auth.TestArgonParams())
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	principalID := uuid.New()
	tenantID := uuid.MustParse("44444444-4444-4444-8444-444444444444")
	if outcome, err := repo.BootstrapPrincipal(ctx, principalID, email, pepper, hash, &tenantID); err != nil || outcome != "created" {
		t.Fatalf("bootstrap: %v (outcome %q)", err, outcome)
	}
	// Pending principals cannot start ceremonies.
	pendingChallenge := make([]byte, auth.WebAuthnChallengeBytes)
	if _, err := repo.RecordWebAuthnChallenge(ctx, uuid.New(), principalID, auth.PurposeWebAuthnRegistration, pendingChallenge, now, now.Add(5*time.Minute)); !errors.Is(err, ErrNotVerified) {
		t.Fatalf("pending challenge accepted: %v", err)
	}
	verifyToken := mustSecret(t)
	if _, err := repo.RecordEmailVerification(ctx, principalID, verifyToken, pepper, now, now.Add(time.Hour)); err != nil {
		t.Fatalf("record verification: %v", err)
	}
	if outcome, _, err := repo.ConsumeEmailVerification(ctx, verifyToken, pepper); err != nil || outcome != "verified" {
		t.Fatalf("consume: %v (outcome %q)", err, outcome)
	}

	nonce := func() []byte {
		out := make([]byte, auth.WebAuthnChallengeBytes)
		if _, err := rand.Read(out); err != nil {
			t.Fatalf("nonce: %v", err)
		}
		return out
	}
	n1, n2, n3, n4, n5, n6 := nonce(), nonce(), nonce(), nonce(), nonce(), nonce()
	// Under-min ceremony windows are rejected before the database.
	if _, err := repo.RecordWebAuthnChallenge(ctx, uuid.New(), principalID, auth.PurposeWebAuthnRegistration, nonce(), now, now.Add(30*time.Second)); err == nil {
		t.Fatal("under-min challenge TTL accepted")
	}
	firstID := uuid.New()
	if outcome, err := repo.RecordWebAuthnChallenge(ctx, firstID, principalID, auth.PurposeWebAuthnRegistration, n1, now, now.Add(5*time.Minute)); err != nil || outcome != "recorded" {
		t.Fatalf("record challenge: %v (outcome %q)", err, outcome)
	}
	// Resend replaces the pending challenge for the same purpose.
	secondID := uuid.New()
	if outcome, err := repo.RecordWebAuthnChallenge(ctx, secondID, principalID, auth.PurposeWebAuthnRegistration, n2, now, now.Add(5*time.Minute)); err != nil || outcome != "recorded" {
		t.Fatalf("resend challenge: %v (outcome %q)", err, outcome)
	}
	// The replaced challenge is gone; the live one consumes exactly once.
	if outcome, _, _, _, err := repo.ConsumeWebAuthnChallenge(ctx, firstID); err != nil || outcome != "unknown" {
		t.Fatalf("replaced consume: %v (outcome %q)", err, outcome)
	}
	outcome, consumedPrincipal, purpose, consumedNonce, err := repo.ConsumeWebAuthnChallenge(ctx, secondID)
	if err != nil || outcome != "ready" || consumedPrincipal != principalID || purpose != auth.PurposeWebAuthnRegistration {
		t.Fatalf("consume: %v (outcome %q purpose %q)", err, outcome, purpose)
	}
	if string(consumedNonce) != string(n2) {
		t.Fatal("consumed nonce mismatch")
	}
	if outcome, _, _, _, err := repo.ConsumeWebAuthnChallenge(ctx, secondID); err != nil || outcome != "duplicate" {
		t.Fatalf("repeat consume: %v (outcome %q)", err, outcome)
	}
	// Challenge bytes are globally unique: reuse across principals refused.
	otherPrincipal := uuid.New()
	otherEmail := "webauthn-other-" + uuid.NewString() + "@example.test"
	if outcome, err := repo.BootstrapPrincipal(ctx, otherPrincipal, otherEmail, pepper, hash, &tenantID); err != nil || outcome != "created" {
		t.Fatalf("second bootstrap: %v (outcome %q)", err, outcome)
	}
	otherVerify := mustSecret(t)
	if _, err := repo.RecordEmailVerification(ctx, otherPrincipal, otherVerify, pepper, now, now.Add(time.Hour)); err != nil {
		t.Fatalf("other verification: %v", err)
	}
	if outcome, _, err := repo.ConsumeEmailVerification(ctx, otherVerify, pepper); err != nil || outcome != "verified" {
		t.Fatalf("other consume: %v (outcome %q)", err, outcome)
	}
	if _, err := repo.RecordWebAuthnChallenge(ctx, uuid.New(), otherPrincipal, auth.PurposeWebAuthnAuthentication, n2, now, now.Add(5*time.Minute)); !errors.Is(err, ErrTokenReuse) {
		t.Fatalf("challenge reuse accepted: %v", err)
	}
	// Registration binds exactly one key through a fresh ceremony.
	regID := uuid.New()
	if outcome, err := repo.RecordWebAuthnChallenge(ctx, regID, principalID, auth.PurposeWebAuthnRegistration, n3, now, now.Add(5*time.Minute)); err != nil || outcome != "recorded" {
		t.Fatalf("registration challenge: %v (outcome %q)", err, outcome)
	}
	credentialID := []byte("webauthn-cred-" + uuid.NewString())
	publicKey := bytes.Repeat([]byte{0x04}, 77)
	if outcome, registeredID, err := repo.RegisterWebAuthnCredential(ctx, regID, credentialID, publicKey, "usb", true, false); err != nil || outcome != "registered" || registeredID != principalID {
		t.Fatalf("register: %v (outcome %q id %v)", err, outcome, registeredID)
	}
	// The ceremony challenge is spent: registration is single-use.
	if outcome, _, err := repo.RegisterWebAuthnCredential(ctx, regID, []byte("other-credential"), publicKey, "", false, false); err != nil || outcome != "duplicate" {
		t.Fatalf("repeat register: %v (outcome %q)", err, outcome)
	}
	// An authentication-purpose challenge cannot mint a key.
	authCID := uuid.New()
	if outcome, err := repo.RecordWebAuthnChallenge(ctx, authCID, principalID, auth.PurposeWebAuthnAuthentication, n4, now, now.Add(5*time.Minute)); err != nil || outcome != "recorded" {
		t.Fatalf("auth challenge: %v (outcome %q)", err, outcome)
	}
	if outcome, _, err := repo.RegisterWebAuthnCredential(ctx, authCID, []byte("auth-credential"), publicKey, "", false, false); err != nil || outcome != "wrong_purpose" {
		t.Fatalf("wrong-purpose register: %v (outcome %q)", err, outcome)
	}
	// Credential identifiers are globally unique.
	dupCID := uuid.New()
	if outcome, err := repo.RecordWebAuthnChallenge(ctx, dupCID, otherPrincipal, auth.PurposeWebAuthnRegistration, n5, now, now.Add(5*time.Minute)); err != nil || outcome != "recorded" {
		t.Fatalf("other challenge: %v (outcome %q)", err, outcome)
	}
	if outcome, _, err := repo.RegisterWebAuthnCredential(ctx, dupCID, credentialID, publicKey, "", false, false); err != nil || outcome != "credential_reuse" {
		t.Fatalf("credential reuse: %v (outcome %q)", err, outcome)
	}
	// Key listing exposes exactly the bound key for ceremony verification.
	keys, err := repo.KeysFor(ctx, principalID)
	if err != nil || len(keys) != 1 {
		t.Fatalf("keys: %v (%d)", err, len(keys))
	}
	if string(keys[0].CredentialID) != string(credentialID) || string(keys[0].PublicKey) != string(publicKey) ||
		keys[0].SignCount != 0 || keys[0].Transports != "usb" || !keys[0].BackupEligible || keys[0].BackupState {
		t.Fatalf("key mismatch: %+v", keys[0])
	}
	if keys, err := repo.KeysFor(ctx, otherPrincipal); err != nil || len(keys) != 0 {
		t.Fatalf("other keys: %v (%d)", err, len(keys))
	}
	// Sign counts advance monotonically; replays are reported, not applied.
	if outcome, _, err := repo.AdvanceSignCount(ctx, credentialID, 1); err != nil || outcome != "advanced" {
		t.Fatalf("advance: %v (outcome %q)", err, outcome)
	}
	if outcome, _, err := repo.AdvanceSignCount(ctx, credentialID, 1); err != nil || outcome != "cloned" {
		t.Fatalf("replay: %v (outcome %q)", err, outcome)
	}
	if outcome, _, err := repo.AdvanceSignCount(ctx, credentialID, 0); err != nil || outcome != "cloned" {
		t.Fatalf("regressed: %v (outcome %q)", err, outcome)
	}
	if outcome, _, err := repo.AdvanceSignCount(ctx, credentialID, 41); err != nil || outcome != "advanced" {
		t.Fatalf("second advance: %v (outcome %q)", err, outcome)
	}
	if outcome, _, err := repo.AdvanceSignCount(ctx, []byte("missing-credential"), 1); err != nil || outcome != "unknown" {
		t.Fatalf("unknown advance: %v (outcome %q)", err, outcome)
	}
	// Expired challenges consume as expired.
	expiredID := uuid.New()
	if outcome, err := repo.RecordWebAuthnChallenge(ctx, expiredID, principalID, auth.PurposeWebAuthnAuthentication, n6, now, now.Add(5*time.Minute)); err != nil || outcome != "recorded" {
		t.Fatalf("expiry candidate: %v (outcome %q)", err, outcome)
	}
	if _, err := adminDB.ExecContext(ctx, `ALTER TABLE keel_meta.identity_webauthn_challenges DISABLE TRIGGER identity_webauthn_challenges_guard`); err != nil {
		t.Fatalf("disable challenge guard: %v", err)
	}
	if _, err := adminDB.ExecContext(ctx, `UPDATE keel_meta.identity_webauthn_challenges SET requested_at=clock_timestamp()-INTERVAL '1 hour',expires_at=clock_timestamp()-INTERVAL '1 minute' WHERE challenge_id=$1`, expiredID); err != nil {
		t.Fatalf("backdate challenge: %v", err)
	}
	if _, err := adminDB.ExecContext(ctx, `ALTER TABLE keel_meta.identity_webauthn_challenges ENABLE TRIGGER identity_webauthn_challenges_guard`); err != nil {
		t.Fatalf("enable challenge guard: %v", err)
	}
	if outcome, _, _, _, err := repo.ConsumeWebAuthnChallenge(ctx, expiredID); err != nil || outcome != "expired" {
		t.Fatalf("expired consume: %v (outcome %q)", err, outcome)
	}
	// Structural lockdown for both new tables.
	for _, table := range []string{"identity_webauthn_credentials", "identity_webauthn_challenges"} {
		var forced bool
		if err := adminDB.QueryRowContext(ctx,
			`SELECT relforcerowsecurity FROM pg_class WHERE oid=('keel_meta.'||$1)::regclass`, table).Scan(&forced); err != nil || !forced {
			t.Fatalf("%s is not FORCE RLS: %v", table, err)
		}
	}
	appDB := openRoleDB(t, "postgres://keel_local_app:keel-app-local-only@127.0.0.1:5432/postgres?sslmode=disable")
	if _, err := appDB.QueryContext(ctx, `SELECT keel_meta.record_identity_webauthn_challenge(gen_random_uuid(),gen_random_uuid(),'identity-webauthn-registration-v1','00'::bytea,now())`); err == nil {
		t.Fatal("app capability executed challenge function")
	} else if !isPrivilegeDenial(err) {
		t.Fatalf("unexpected app denial: %v", err)
	}
	if _, err := identityDB.QueryContext(ctx, `SELECT public_key FROM keel_meta.identity_webauthn_credentials LIMIT 1`); err == nil {
		t.Fatal("identity login read keys directly")
	} else if !isPrivilegeDenial(err) {
		t.Fatalf("unexpected identity denial: %v", err)
	}
	// Direct store outcomes: inactive principals refuse, reuse conflicts.
	pendingPrincipal := uuid.New()
	pendingEmail := "webauthn-pending-" + uuid.NewString() + "@example.test"
	if outcome, err := repo.BootstrapPrincipal(ctx, pendingPrincipal, pendingEmail, pepper, hash, &tenantID); err != nil || outcome != "created" {
		t.Fatalf("pending bootstrap: %v (outcome %q)", err, outcome)
	}
	freshCred := []byte("webauthn-direct-" + uuid.NewString())
	freshKey := bytes.Repeat([]byte{0x05}, 77)
	if outcome, err := repo.StoreWebAuthnCredential(ctx, pendingPrincipal, freshCred, freshKey, "usb", false, false, 0); err != nil || outcome != "principal_inactive" {
		t.Fatalf("pending store: %v (outcome %q)", err, outcome)
	}
	if outcome, err := repo.StoreWebAuthnCredential(ctx, principalID, freshCred, freshKey, "usb", true, false, 7); err != nil || outcome != "stored" {
		t.Fatalf("direct store: %v (outcome %q)", err, outcome)
	}
	if outcome, err := repo.StoreWebAuthnCredential(ctx, otherPrincipal, freshCred, freshKey, "", false, false, 0); err != nil || outcome != "credential_reuse" {
		t.Fatalf("direct reuse: %v (outcome %q)", err, outcome)
	}
}
