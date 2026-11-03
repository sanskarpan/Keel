// Package postgres stores first-party identity principals, credentials,
// verifications, password resets and sessions behind the keel_identity
// capability. Identity access is pre-tenant: these functions are global and
// tenant binding is a later K8.1/K8.2 concern, so no RLS tenant context is used here.
package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/sanskarpan/keel/internal/auth"
)

var (
	// ErrNotFound reports an unknown email digest or session token.
	ErrNotFound = errors.New("identity record not found")
	// ErrConflict reports a duplicated email digest or reused token.
	ErrConflict = errors.New("identity record conflicts with an existing principal")
	// ErrTokenReuse reports a session/verification token digest already recorded.
	ErrTokenReuse = errors.New("identity token is already recorded")
	// ErrNotVerified reports a sign-in attempt before email verification.
	ErrNotVerified = errors.New("identity principal is not verified")
	// ErrInvalidRecord reports an argument that fails bounded validation.
	ErrInvalidRecord = errors.New("identity record is invalid")
	// ErrCapabilityDenied reports a caller without the keel_identity capability.
	ErrCapabilityDenied = errors.New("identity capability is required")
)

// Repository is the PostgreSQL-backed identity store.
type Repository struct{ db *sql.DB }

// New validates the injected DB handle.
func New(db *sql.DB) (*Repository, error) {
	if db == nil {
		return nil, errors.New("identity database is required")
	}
	return &Repository{db: db}, nil
}

// BootstrapPrincipal creates a pending principal with its credential in one
// transaction. A repeated email digest is a conflict, not a re-registration.
func (r *Repository) BootstrapPrincipal(ctx context.Context, principalID uuid.UUID, email string, pepper []byte, passwordHash string, tenant *uuid.UUID) (string, error) {
	if r == nil || r.db == nil || principalID == uuid.Nil || passwordHash == "" || len(passwordHash) > auth.MaxHashLen {
		return "", ErrInvalidRecord
	}
	digest, err := auth.EmailDigest(email, pepper)
	if err != nil {
		return "", err
	}
	var outcome string
	err = r.withTx(ctx, func(tx *sql.Tx) error {
		rowErr := tx.QueryRowContext(ctx,
			`SELECT keel_meta.create_identity_principal($1,$2,$3,$4)`,
			principalID, digest[:], passwordHash, tenant,
		).Scan(&outcome)
		return rowErr
	})
	if err == nil && outcome == "duplicate_email" {
		return "", ErrConflict
	}
	if err == nil && outcome != "created" {
		return "", fmt.Errorf("%w: unexpected bootstrap outcome %q", ErrInvalidRecord, outcome)
	}
	return outcome, err
}

// CredentialForEmail returns the credential row for one canonical email digest.
// Unknown addresses and wrong addresses are indistinguishable use-cases: the
// caller must not reveal which part failed.
func (r *Repository) CredentialForEmail(ctx context.Context, email string, pepper []byte) (principalID uuid.UUID, state string, storedHash string, err error) {
	if r == nil || r.db == nil {
		return uuid.Nil, "", "", ErrInvalidRecord
	}
	digest, err := auth.EmailDigest(email, pepper)
	if err != nil {
		return uuid.Nil, "", "", err
	}
	err = r.withTx(ctx, func(tx *sql.Tx) error {
		rowErr := tx.QueryRowContext(ctx,
			`SELECT out_principal_id,out_state,out_password_hash
			   FROM keel_meta.identity_password_credential($1)`,
			digest[:],
		).Scan(&principalID, &state, &storedHash)
		if errors.Is(rowErr, sql.ErrNoRows) {
			return ErrNotFound
		}
		return rowErr
	})
	return principalID, state, storedHash, err
}

// RecordEmailVerification stores one bounded verification request, replacing
// any earlier pending request for the same principal.
func (r *Repository) RecordEmailVerification(ctx context.Context, principalID uuid.UUID, token string, pepper []byte, now, expires time.Time) (string, error) {
	if r == nil || r.db == nil {
		return "", ErrInvalidRecord
	}
	if err := auth.ValidateVerificationTTL(now, expires); err != nil {
		return "", err
	}
	digest, err := auth.TokenDigest(token, auth.PurposeEmailVerification)
	if err != nil {
		return "", err
	}
	var outcome string
	err = r.withTx(ctx, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx,
			`SELECT keel_meta.record_identity_verification($1,$2,$3)`,
			principalID, digest[:], expires.UTC(),
		).Scan(&outcome)
	})
	if err == nil && outcome == "not_pending" {
		return "", ErrNotVerified
	}
	if err == nil && outcome == "token_reuse" {
		return "", ErrTokenReuse
	}
	return outcome, err
}

// ConsumeEmailVerification marks one token consumed and activates its principal.
func (r *Repository) ConsumeEmailVerification(ctx context.Context, token string, pepper []byte) (string, uuid.UUID, error) {
	if r == nil || r.db == nil {
		return "", uuid.Nil, ErrInvalidRecord
	}
	digest, err := auth.TokenDigest(token, auth.PurposeEmailVerification)
	if err != nil {
		return "", uuid.Nil, err
	}
	var outcome string
	var principalID uuid.UUID
	err = r.withTx(ctx, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx,
			`SELECT outcome,out_principal_id FROM keel_meta.consume_identity_verification($1)`,
			digest[:],
		).Scan(&outcome, &principalID)
	})
	// A zero principal id is part of the unknown/expired outcomes; the caller
	// judges by outcome, and a nil principal with unknown must not authenticate.
	if err != nil || outcome != "verified" {
		return outcome, principalID, err
	}
	if principalID == uuid.Nil {
		return "", uuid.Nil, fmt.Errorf("%w: verification verified with empty principal", ErrInvalidRecord)
	}
	return outcome, principalID, err
}

// RecordSession stores one bounded session row; the principal must be active.
func (r *Repository) RecordSession(ctx context.Context, sessionID, principalID uuid.UUID, token string, pepper []byte, now, expires time.Time) (string, error) {
	if r == nil || r.db == nil {
		return "", ErrInvalidRecord
	}
	if sessionID == uuid.Nil {
		return "", ErrInvalidRecord
	}
	if err := auth.ValidateSessionTTL(now, expires); err != nil {
		return "", err
	}
	digest, err := auth.TokenDigest(token, auth.PurposeSession)
	if err != nil {
		return "", err
	}
	var outcome string
	err = r.withTx(ctx, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx,
			`SELECT keel_meta.record_identity_session($1,$2,$3,$4)`,
			sessionID, principalID, digest[:], expires.UTC(),
		).Scan(&outcome)
	})
	if err == nil && outcome == "principal_inactive" {
		return "", ErrNotVerified
	}
	return outcome, err
}

// SessionForToken resolves one session by its digest; validity is judged by
// the domain using the caller's clock.
func (r *Repository) SessionForToken(ctx context.Context, token string, pepper []byte) (auth.Session, error) {
	if r == nil || r.db == nil {
		return auth.Session{}, ErrInvalidRecord
	}
	digest, err := auth.TokenDigest(token, auth.PurposeSession)
	if err != nil {
		return auth.Session{}, err
	}
	var session auth.Session
	err = r.withTx(ctx, func(tx *sql.Tx) error {
		var revoked, expires, created sql.NullTime
		var sessionID, principalID uuid.UUID
		rowErr := tx.QueryRowContext(ctx,
			`SELECT out_session_id,out_principal_id,out_principal_state,
			        out_created_at,out_expires_at,out_revoked_at
			   FROM keel_meta.identity_session_for($1)`,
			digest[:],
		).Scan(&sessionID, &principalID, &session.PrincipalState,
			&created, &expires, &revoked)
		if errors.Is(rowErr, sql.ErrNoRows) {
			return ErrNotFound
		}
		session.SessionID, session.PrincipalID = sessionID.String(), principalID.String()
		session.CreatedAt, session.ExpiresAt = created.Time, expires.Time
		if revoked.Valid {
			session.RevokedAt = revoked.Time
		}
		return rowErr
	})
	return session, err
}

// RevokeSession revokes one session exactly once; an unknown id is a distinct
// outcome rather than an error because repeated logouts converge.
func (r *Repository) RevokeSession(ctx context.Context, sessionID uuid.UUID) (string, error) {
	if r == nil || r.db == nil || sessionID == uuid.Nil {
		return "", ErrInvalidRecord
	}
	var outcome string
	err := r.withTx(ctx, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx,
			`SELECT keel_meta.revoke_identity_session($1)`, sessionID,
		).Scan(&outcome)
	})
	if err == nil && outcome == "unknown_session" {
		return "", ErrNotFound
	}
	return outcome, err
}

// RecordPasswordReset stores one bounded reset request for an active principal,
// replacing any pending request. Inactive principals cannot start recovery.
func (r *Repository) RecordPasswordReset(ctx context.Context, principalID uuid.UUID, token string, pepper []byte, now, expires time.Time) (string, error) {
	if r == nil || r.db == nil {
		return "", ErrInvalidRecord
	}
	_ = pepper
	if err := auth.ValidateResetTTL(now, expires); err != nil {
		return "", err
	}
	digest, err := auth.TokenDigest(token, auth.PurposePasswordReset)
	if err != nil {
		return "", err
	}
	var outcome string
	err = r.withTx(ctx, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx,
			`SELECT keel_meta.record_identity_password_reset($1,$2,$3)`,
			principalID, digest[:], expires.UTC(),
		).Scan(&outcome)
	})
	if err == nil && outcome == "not_active" {
		return "", ErrNotVerified
	}
	if err == nil && outcome == "token_reuse" {
		return "", ErrTokenReuse
	}
	return outcome, err
}

// RotateCredential atomically consumes one reset token, replaces the Argon2id
// hash (versioned) and revokes every live session for the principal. The
// caller judges the outcome: only "rotated" changes credentials.
func (r *Repository) RotateCredential(ctx context.Context, token string, pepper []byte, newHash string) (string, uuid.UUID, error) {
	if r == nil || r.db == nil {
		return "", uuid.Nil, ErrInvalidRecord
	}
	_ = pepper
	if newHash == "" || len(newHash) > auth.MaxHashLen {
		return "", uuid.Nil, ErrInvalidRecord
	}
	digest, err := auth.TokenDigest(token, auth.PurposePasswordReset)
	if err != nil {
		return "", uuid.Nil, err
	}
	var outcome string
	var principalID uuid.UUID
	err = r.withTx(ctx, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx,
			`SELECT outcome,out_principal_id FROM keel_meta.rotate_identity_credential($1,$2)`,
			digest[:], newHash,
		).Scan(&outcome, &principalID)
	})
	if err != nil || outcome != "rotated" {
		return outcome, principalID, err
	}
	if principalID == uuid.Nil {
		return "", uuid.Nil, fmt.Errorf("%w: rotation completed with empty principal", ErrInvalidRecord)
	}
	return outcome, principalID, err
}

// RevokeAllSessions revokes every live session for one principal and reports
// the count. Zero is a valid outcome when no sessions are live.
func (r *Repository) RevokeAllSessions(ctx context.Context, principalID uuid.UUID) (int, error) {
	if r == nil || r.db == nil || principalID == uuid.Nil {
		return 0, ErrInvalidRecord
	}
	var revoked int
	err := r.withTx(ctx, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx,
			`SELECT keel_meta.revoke_all_identity_sessions($1)`, principalID,
		).Scan(&revoked)
	})
	return revoked, err
}

// RecordLoginFailure counts one failed password login. Five consecutive
// failures lock the principal for 15 minutes; attempts while locked change
// nothing. Unknown principals are not counted.
func (r *Repository) RecordLoginFailure(ctx context.Context, principalID uuid.UUID) (string, error) {
	if r == nil || r.db == nil || principalID == uuid.Nil {
		return "", ErrInvalidRecord
	}
	var outcome string
	err := r.withTx(ctx, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx,
			`SELECT keel_meta.record_identity_login_failure($1)`, principalID,
		).Scan(&outcome)
	})
	if err == nil && outcome == "unknown_principal" {
		return "", ErrNotFound
	}
	return outcome, err
}

// ResetLoginThrottle clears the failure count after a successful login.
// Zero is valid when nothing was recorded.
func (r *Repository) ResetLoginThrottle(ctx context.Context, principalID uuid.UUID) (int, error) {
	if r == nil || r.db == nil || principalID == uuid.Nil {
		return 0, ErrInvalidRecord
	}
	var removed int
	err := r.withTx(ctx, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx,
			`SELECT keel_meta.reset_identity_login_throttle($1)`, principalID,
		).Scan(&removed)
	})
	return removed, err
}

// ThrottleFor reports the current failure count and lock expiry. Zero values
// mean no throttle is recorded; a locked_until in the future means the
// principal is locked as of the database clock.
func (r *Repository) ThrottleFor(ctx context.Context, principalID uuid.UUID) (int, time.Time, error) {
	if r == nil || r.db == nil || principalID == uuid.Nil {
		return 0, time.Time{}, ErrInvalidRecord
	}
	var consecutive int
	var lockedUntil sql.NullTime
	err := r.withTx(ctx, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx,
			`SELECT out_consecutive,out_locked_until FROM keel_meta.identity_throttle_for($1)`,
			principalID,
		).Scan(&consecutive, &lockedUntil)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return 0, time.Time{}, nil
	}
	if err != nil {
		return 0, time.Time{}, err
	}
	if lockedUntil.Valid {
		return consecutive, lockedUntil.Time, nil
	}
	return consecutive, time.Time{}, nil
}

// WebAuthnKey is one stored credential public key with its clone-detection
// counter and authenticator flags.
type WebAuthnKey struct {
	CredentialID   []byte
	PublicKey      []byte
	SignCount      uint32
	Transports     string
	BackupEligible bool
	BackupState    bool
}

// RecordWebAuthnChallenge stores one bounded ceremony challenge for an active
// principal, replacing any pending challenge for the same purpose.
func (r *Repository) RecordWebAuthnChallenge(ctx context.Context, challengeID, principalID uuid.UUID, purpose string, challenge []byte, now, expires time.Time) (string, error) {
	if r == nil || r.db == nil || challengeID == uuid.Nil {
		return "", ErrInvalidRecord
	}
	if purpose != auth.PurposeWebAuthnRegistration && purpose != auth.PurposeWebAuthnAuthentication {
		return "", ErrInvalidRecord
	}
	if err := auth.ValidateChallengeBytes(challenge); err != nil {
		return "", err
	}
	if err := auth.ValidateWebAuthnChallengeTTL(now, expires); err != nil {
		return "", err
	}
	var outcome string
	err := r.withTx(ctx, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx,
			`SELECT keel_meta.record_identity_webauthn_challenge($1,$2,$3,$4,$5)`,
			challengeID, principalID, purpose, challenge, expires.UTC(),
		).Scan(&outcome)
	})
	if err == nil && outcome == "not_active" {
		return "", ErrNotVerified
	}
	if err == nil && outcome == "challenge_reuse" {
		return "", ErrTokenReuse
	}
	return outcome, err
}

// ConsumeWebAuthnChallenge marks one challenge consumed and returns its
// principal, purpose and nonce. Only "ready" challenges feed a ceremony.
func (r *Repository) ConsumeWebAuthnChallenge(ctx context.Context, challengeID uuid.UUID) (string, uuid.UUID, string, []byte, error) {
	if r == nil || r.db == nil || challengeID == uuid.Nil {
		return "", uuid.Nil, "", nil, ErrInvalidRecord
	}
	var outcome, purpose string
	var principalID uuid.UUID
	var nonce []byte
	err := r.withTx(ctx, func(tx *sql.Tx) error {
		var purposeNull sql.NullString
		rowErr := tx.QueryRowContext(ctx,
			`SELECT outcome,out_principal_id,out_purpose,out_challenge FROM keel_meta.consume_identity_webauthn_challenge($1)`,
			challengeID,
		).Scan(&outcome, &principalID, &purposeNull, &nonce)
		if purposeNull.Valid {
			purpose = purposeNull.String
		}
		return rowErr
	})
	return outcome, principalID, purpose, nonce, err
}

// RegisterWebAuthnCredential atomically consumes one registration challenge
// and stores the credential public key. Only "registered" binds a key.
func (r *Repository) RegisterWebAuthnCredential(ctx context.Context, challengeID uuid.UUID, credentialID, publicKey []byte, transports string, backupEligible, backupState bool) (string, uuid.UUID, error) {
	if r == nil || r.db == nil || challengeID == uuid.Nil {
		return "", uuid.Nil, ErrInvalidRecord
	}
	if err := auth.ValidateCredentialID(credentialID); err != nil {
		return "", uuid.Nil, err
	}
	if err := auth.ValidatePublicKey(publicKey); err != nil {
		return "", uuid.Nil, err
	}
	if err := auth.ValidateTransports(transports); err != nil {
		return "", uuid.Nil, err
	}
	var outcome string
	var principalID uuid.UUID
	err := r.withTx(ctx, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx,
			`SELECT outcome,out_principal_id FROM keel_meta.register_identity_webauthn_credential($1,$2,$3,$4,$5,$6)`,
			challengeID, credentialID, publicKey, transports, backupEligible, backupState,
		).Scan(&outcome, &principalID)
	})
	return outcome, principalID, err
}

// KeysFor lists every credential public key for one principal. Empty (not an
// error) means the principal enrolled nothing.
func (r *Repository) KeysFor(ctx context.Context, principalID uuid.UUID) ([]WebAuthnKey, error) {
	if r == nil || r.db == nil || principalID == uuid.Nil {
		return nil, ErrInvalidRecord
	}
	var keys []WebAuthnKey
	err := r.withTx(ctx, func(tx *sql.Tx) error {
		rows, rowsErr := tx.QueryContext(ctx,
			`SELECT out_credential_id,out_public_key,out_sign_count,out_transports,out_backup_eligible,out_backup_state
			   FROM keel_meta.identity_webauthn_keys_for($1)`,
			principalID,
		)
		if rowsErr != nil {
			return rowsErr
		}
		defer rows.Close()
		for rows.Next() {
			var key WebAuthnKey
			var signCount int64
			if scanErr := rows.Scan(&key.CredentialID, &key.PublicKey, &signCount, &key.Transports, &key.BackupEligible, &key.BackupState); scanErr != nil {
				return scanErr
			}
			if signCount < 0 || signCount > 4294967295 {
				return fmt.Errorf("%w: stored sign count out of range", ErrInvalidRecord)
			}
			key.SignCount = uint32(signCount)
			keys = append(keys, key)
		}
		return rows.Err()
	})
	return keys, err
}

// AdvanceSignCount applies one presented counter. "advanced" moves the stored
// value; "cloned" reports a non-advancing counter while one was expected and
// changes nothing, so the caller must fail the ceremony closed.
func (r *Repository) AdvanceSignCount(ctx context.Context, credentialID []byte, presented uint32) (string, uuid.UUID, error) {
	if r == nil || r.db == nil {
		return "", uuid.Nil, ErrInvalidRecord
	}
	if err := auth.ValidateCredentialID(credentialID); err != nil {
		return "", uuid.Nil, err
	}
	var outcome string
	var principalID uuid.UUID
	err := r.withTx(ctx, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx,
			`SELECT outcome,out_principal_id FROM keel_meta.advance_identity_webauthn_sign_count($1,$2)`,
			credentialID, int64(presented),
		).Scan(&outcome, &principalID)
	})
	return outcome, principalID, err
}

// StoreWebAuthnCredential inserts one verified ceremony key. The caller must
// have consumed a single-use challenge and verified the attestation first;
// only "stored" binds the key.
func (r *Repository) StoreWebAuthnCredential(ctx context.Context, principalID uuid.UUID, credentialID, publicKey []byte, transports string, backupEligible, backupState bool, signCount uint32) (string, error) {
	if r == nil || r.db == nil || principalID == uuid.Nil {
		return "", ErrInvalidRecord
	}
	if err := auth.ValidateCredentialID(credentialID); err != nil {
		return "", err
	}
	if err := auth.ValidatePublicKey(publicKey); err != nil {
		return "", err
	}
	if err := auth.ValidateTransports(transports); err != nil {
		return "", err
	}
	var outcome string
	err := r.withTx(ctx, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx,
			`SELECT keel_meta.store_identity_webauthn_credential($1,$2,$3,$4,$5,$6,$7)`,
			principalID, credentialID, publicKey, transports, backupEligible, backupState, int64(signCount),
		).Scan(&outcome)
	})
	return outcome, err
}

func (r *Repository) withTx(ctx context.Context, work func(*sql.Tx) error) error {
	tx, tranErr := r.db.BeginTx(ctx, nil)
	if tranErr != nil {
		return fmt.Errorf("identity transaction failed: %w", tranErr)
	}
	workErr := work(tx)
	if workErr == nil {
		return tx.Commit()
	}
	if rollErr := tx.Rollback(); rollErr != nil {
		return fmt.Errorf("identity work failed (%v) and rollback failed: %w", workErr, rollErr)
	}
	return workErr
}
