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
	// ErrNotAuthorized reports an actor without owner/admin membership.
	ErrNotAuthorized = errors.New("identity actor is not authorized")
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
		var orgID uuid.NullUUID
		rowErr := tx.QueryRowContext(ctx,
			`SELECT out_session_id,out_principal_id,out_principal_state,
			        out_created_at,out_expires_at,out_revoked_at,out_org_id
			   FROM keel_meta.identity_session_for($1)`,
			digest[:],
		).Scan(&sessionID, &principalID, &session.PrincipalState,
			&created, &expires, &revoked, &orgID)
		if errors.Is(rowErr, sql.ErrNoRows) {
			return ErrNotFound
		}
		session.SessionID, session.PrincipalID = sessionID.String(), principalID.String()
		session.CreatedAt, session.ExpiresAt = created.Time, expires.Time
		if revoked.Valid {
			session.RevokedAt = revoked.Time
		}
		if orgID.Valid {
			session.OrgID = orgID.UUID.String()
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

// Organization is one organization row with the caller's membership role.
type Organization struct {
	OrgID       uuid.UUID
	Slug        string
	DisplayName string
	Region      string
	Role        string
}

// CreateOrganization creates one organization with the caller as owner.
// Founding never refuses a principal that already belongs elsewhere: the
// tenant stays first-bound (primary) and only an unbound founder binds.
// A taken slug is a conflict.
func (r *Repository) CreateOrganization(ctx context.Context, orgID, principalID uuid.UUID, slug, displayName, region string) (string, error) {
	if r == nil || r.db == nil || orgID == uuid.Nil || principalID == uuid.Nil {
		return "", ErrInvalidRecord
	}
	if err := auth.ValidateOrgSlug(slug); err != nil {
		return "", err
	}
	if err := auth.ValidateOrgName(displayName); err != nil {
		return "", err
	}
	if err := auth.ValidateOrgRegion(region); err != nil {
		return "", err
	}
	var outcome string
	err := r.withTx(ctx, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx,
			`SELECT keel_meta.create_identity_organization($1,$2,$3,$4,$5)`,
			orgID, principalID, slug, displayName, region,
		).Scan(&outcome)
	})
	if err == nil && outcome == "not_active" {
		return "", ErrNotVerified
	}
	if err == nil && outcome == "slug_conflict" {
		return "", ErrConflict
	}
	return outcome, err
}

// AddOrganizationMember seats an active principal as admin or member. The
// actor must hold owner/admin membership. Joining never refuses a principal
// that already belongs elsewhere: the tenant stays first-bound (primary)
// and only an unbound member binds.
func (r *Repository) AddOrganizationMember(ctx context.Context, actorID, orgID, memberID uuid.UUID, role string) (string, error) {
	if r == nil || r.db == nil || actorID == uuid.Nil || orgID == uuid.Nil || memberID == uuid.Nil {
		return "", ErrInvalidRecord
	}
	if err := auth.ValidateOrgRole(role); err != nil {
		return "", err
	}
	if role == auth.OrgRoleOwner {
		return "", ErrInvalidRecord
	}
	var outcome string
	err := r.withTx(ctx, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx,
			`SELECT keel_meta.add_organization_member($1,$2,$3,$4)`,
			actorID, orgID, memberID, role,
		).Scan(&outcome)
	})
	if err == nil && outcome == "not_authorized" {
		return "", ErrNotAuthorized
	}
	if err == nil && outcome == "not_active" {
		return "", ErrNotVerified
	}
	if err == nil && outcome == "already_member" {
		return "", ErrConflict
	}
	return outcome, err
}

// SwitchSessionOrg moves one live session to an organization its principal
// belongs to. Revoked, expired and unknown sessions do not switch.
func (r *Repository) SwitchSessionOrg(ctx context.Context, sessionID, orgID uuid.UUID) (string, error) {
	if r == nil || r.db == nil || sessionID == uuid.Nil || orgID == uuid.Nil {
		return "", ErrInvalidRecord
	}
	var outcome string
	err := r.withTx(ctx, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx,
			`SELECT keel_meta.switch_identity_session_org($1,$2)`,
			sessionID, orgID,
		).Scan(&outcome)
	})
	if err == nil && outcome == "unknown_session" {
		return "", ErrNotFound
	}
	return outcome, err
}

// InviteMember records one bounded email invite for an admin/member seat.
// The invitee needs no account yet; acceptance binds a matching principal.
func (r *Repository) InviteMember(ctx context.Context, inviteID, actorID, orgID uuid.UUID, email string, pepper []byte, token string, role string, now, expires time.Time) (string, error) {
	if r == nil || r.db == nil || inviteID == uuid.Nil || actorID == uuid.Nil || orgID == uuid.Nil {
		return "", ErrInvalidRecord
	}
	if role != auth.OrgRoleAdmin && role != auth.OrgRoleMember {
		return "", ErrInvalidRecord
	}
	if err := auth.ValidateInviteTTL(now, expires); err != nil {
		return "", err
	}
	emailDigest, err := auth.EmailDigest(email, pepper)
	if err != nil {
		return "", err
	}
	tokenDigest, err := auth.TokenDigest(token, auth.PurposeOrganizationInvite)
	if err != nil {
		return "", err
	}
	var outcome string
	err = r.withTx(ctx, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx,
			`SELECT keel_meta.invite_organization_member($1,$2,$3,$4,$5,$6,$7)`,
			inviteID, actorID, orgID, emailDigest[:], tokenDigest[:], role, expires.UTC(),
		).Scan(&outcome)
	})
	if err == nil && outcome == "not_authorized" {
		return "", ErrNotAuthorized
	}
	if err == nil && outcome == "already_member" {
		return "", ErrConflict
	}
	if err == nil && outcome == "token_reuse" {
		return "", ErrTokenReuse
	}
	return outcome, err
}

// AcceptInvite consumes one invite for the matching active principal,
// seating them with the invited role and binding an unbound tenant.
func (r *Repository) AcceptInvite(ctx context.Context, token string, principalID uuid.UUID) (string, uuid.UUID, error) {
	if r == nil || r.db == nil || principalID == uuid.Nil {
		return "", uuid.Nil, ErrInvalidRecord
	}
	tokenDigest, err := auth.TokenDigest(token, auth.PurposeOrganizationInvite)
	if err != nil {
		return "", uuid.Nil, err
	}
	var outcome string
	var orgID uuid.UUID
	err = r.withTx(ctx, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx,
			`SELECT outcome,out_org_id FROM keel_meta.accept_organization_invite($1,$2)`,
			tokenDigest[:], principalID,
		).Scan(&outcome, &orgID)
	})
	return outcome, orgID, err
}

// TransferOwnership moves the owner seat to an admin/member immediately: the
// actor becomes admin and the target becomes owner in one transaction.
// Self-transfer is a no-op success.
func (r *Repository) TransferOwnership(ctx context.Context, actorID, orgID, newOwnerID uuid.UUID) (string, error) {
	if r == nil || r.db == nil || actorID == uuid.Nil || orgID == uuid.Nil || newOwnerID == uuid.Nil {
		return "", ErrInvalidRecord
	}
	var outcome string
	err := r.withTx(ctx, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx,
			`SELECT keel_meta.transfer_organization_ownership($1,$2,$3)`,
			actorID, orgID, newOwnerID,
		).Scan(&outcome)
	})
	if err == nil && outcome == "not_authorized" {
		return "", ErrNotAuthorized
	}
	if err == nil && outcome == "not_member" {
		return "", ErrNotFound
	}
	return outcome, err
}

// APIKeyIdentity is the verified identity behind one bearer key.
type APIKeyIdentity struct {
	KeyID              uuid.UUID
	ServicePrincipalID uuid.UUID
	OrgID              uuid.UUID
}

// CreateServicePrincipal registers one machine identity under an
// organization. The actor must hold owner/admin membership.
func (r *Repository) CreateServicePrincipal(ctx context.Context, servicePrincipalID, actorID, orgID uuid.UUID, name string) (string, error) {
	if r == nil || r.db == nil || servicePrincipalID == uuid.Nil || actorID == uuid.Nil || orgID == uuid.Nil {
		return "", ErrInvalidRecord
	}
	if err := auth.ValidateServiceName(name); err != nil {
		return "", err
	}
	var outcome string
	err := r.withTx(ctx, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx,
			`SELECT keel_meta.create_identity_service_principal($1,$2,$3,$4)`,
			servicePrincipalID, actorID, orgID, name,
		).Scan(&outcome)
	})
	if err == nil && outcome == "not_authorized" {
		return "", ErrNotAuthorized
	}
	return outcome, err
}

// IssueAPIKey mints one bearer key and returns the wire form exactly once.
// The actor must hold owner/admin membership in the service principal's
// organization. Only the purpose-bound digest is stored; rotation is a fresh
// issue plus a revoke of the predecessor.
func (r *Repository) IssueAPIKey(ctx context.Context, keyID, actorID, servicePrincipalID uuid.UUID, now, expires time.Time) (string, error) {
	if r == nil || r.db == nil || keyID == uuid.Nil || actorID == uuid.Nil || servicePrincipalID == uuid.Nil {
		return "", ErrInvalidRecord
	}
	if err := auth.ValidateAPIKeyTTL(now, expires); err != nil {
		return "", err
	}
	secret, prefix, err := auth.NewAPIKeySecret()
	if err != nil {
		return "", err
	}
	digest, err := auth.APIKeyDigest(secret)
	if err != nil {
		return "", err
	}
	var expiry any
	if !expires.IsZero() {
		expiry = expires.UTC()
	}
	var outcome string
	err = r.withTx(ctx, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx,
			`SELECT keel_meta.issue_identity_api_key($1,$2,$3,$4,$5,$6)`,
			keyID, actorID, servicePrincipalID, prefix, digest[:], expiry,
		).Scan(&outcome)
	})
	if err == nil && outcome == "unknown_principal" {
		return "", ErrNotFound
	}
	if err == nil && outcome == "not_authorized" {
		return "", ErrNotAuthorized
	}
	if err == nil && outcome == "key_reuse" {
		return "", ErrTokenReuse
	}
	if err != nil || outcome != "issued" {
		return "", err
	}
	formatted, err := auth.FormatAPIKey(secret)
	if err != nil {
		return "", err
	}
	return formatted, nil
}

// VerifyAPIKey resolves one bearer key to its service identity. Only
// "valid" authenticates; revocation, expiry and unknown keys fail closed
// with distinct outcomes and no identity.
func (r *Repository) VerifyAPIKey(ctx context.Context, formattedKey string) (string, APIKeyIdentity, error) {
	if r == nil || r.db == nil {
		return "", APIKeyIdentity{}, ErrInvalidRecord
	}
	_, secret, err := auth.ParseAPIKey(formattedKey)
	if err != nil {
		return "", APIKeyIdentity{}, err
	}
	digest, err := auth.APIKeyDigest(secret)
	if err != nil {
		return "", APIKeyIdentity{}, err
	}
	var outcome string
	var identity APIKeyIdentity
	err = r.withTx(ctx, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx,
			`SELECT outcome,out_key_id,out_service_principal_id,out_org_id FROM keel_meta.verify_identity_api_key($1)`,
			digest[:],
		).Scan(&outcome, &identity.KeyID, &identity.ServicePrincipalID, &identity.OrgID)
	})
	return outcome, identity, err
}

// RevokeAPIKey terminates one key exactly once; repeat revokes converge.
// The actor must hold owner/admin membership in the key's organization.
func (r *Repository) RevokeAPIKey(ctx context.Context, actorID, keyID uuid.UUID) (string, error) {
	if r == nil || r.db == nil || actorID == uuid.Nil || keyID == uuid.Nil {
		return "", ErrInvalidRecord
	}
	var outcome string
	err := r.withTx(ctx, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx,
			`SELECT keel_meta.revoke_identity_api_key($1,$2)`, actorID, keyID,
		).Scan(&outcome)
	})
	if err == nil && outcome == "unknown_key" {
		return "", ErrNotFound
	}
	if err == nil && outcome == "not_authorized" {
		return "", ErrNotAuthorized
	}
	return outcome, err
}

// DisableServicePrincipal disables one machine identity and revokes every
// live key it holds. The actor must hold owner/admin membership.
func (r *Repository) DisableServicePrincipal(ctx context.Context, actorID, servicePrincipalID uuid.UUID) (string, error) {
	if r == nil || r.db == nil || actorID == uuid.Nil || servicePrincipalID == uuid.Nil {
		return "", ErrInvalidRecord
	}
	var outcome string
	err := r.withTx(ctx, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx,
			`SELECT keel_meta.disable_identity_service_principal($1,$2)`, actorID, servicePrincipalID,
		).Scan(&outcome)
	})
	if err == nil && outcome == "unknown_principal" {
		return "", ErrNotFound
	}
	if err == nil && outcome == "not_authorized" {
		return "", ErrNotAuthorized
	}
	return outcome, err
}

// Membership is one org seat as seen by an owner/admin directory read.
type Membership struct {
	PrincipalID uuid.UUID
	Role        string
	CreatedAt   time.Time
}

// MembersFor lists every seat in an organization. Actor authorization is
// enforced by the caller comparing against OrganizationsFor; the function
// itself returns rows only to keel_identity holders.
func (r *Repository) MembersFor(ctx context.Context, actorID, orgID uuid.UUID) ([]Membership, error) {
	if r == nil || r.db == nil || actorID == uuid.Nil || orgID == uuid.Nil {
		return nil, ErrInvalidRecord
	}
	var members []Membership
	err := r.withTx(ctx, func(tx *sql.Tx) error {
		rows, rowsErr := tx.QueryContext(ctx,
			`SELECT out_principal_id,out_role,out_created_at FROM keel_meta.members_for_organization($1,$2)`,
			actorID, orgID,
		)
		if rowsErr != nil {
			return rowsErr
		}
		defer rows.Close()
		for rows.Next() {
			var member Membership
			if scanErr := rows.Scan(&member.PrincipalID, &member.Role, &member.CreatedAt); scanErr != nil {
				return scanErr
			}
			members = append(members, member)
		}
		return rows.Err()
	})
	return members, err
}

// Invite is one pending invitation as seen by an owner/admin directory read.
// The email digest is opaque hex: matchable by inviter tooling, never an
// address.
type Invite struct {
	InviteID    uuid.UUID
	EmailDigest []byte
	Role        string
	RequestedAt time.Time
	ExpiresAt   time.Time
}

// InvitesFor lists every pending invite in an organization. Actor
// authorization is enforced by the caller comparing against
// OrganizationsFor.
func (r *Repository) InvitesFor(ctx context.Context, actorID, orgID uuid.UUID) ([]Invite, error) {
	if r == nil || r.db == nil || actorID == uuid.Nil || orgID == uuid.Nil {
		return nil, ErrInvalidRecord
	}
	var invites []Invite
	err := r.withTx(ctx, func(tx *sql.Tx) error {
		rows, rowsErr := tx.QueryContext(ctx,
			`SELECT out_invite_id,out_email_digest,out_role,out_requested_at,out_expires_at FROM keel_meta.invites_for_organization($1,$2)`,
			actorID, orgID,
		)
		if rowsErr != nil {
			return rowsErr
		}
		defer rows.Close()
		for rows.Next() {
			var invite Invite
			if scanErr := rows.Scan(&invite.InviteID, &invite.EmailDigest, &invite.Role, &invite.RequestedAt, &invite.ExpiresAt); scanErr != nil {
				return scanErr
			}
			invites = append(invites, invite)
		}
		return rows.Err()
	})
	return invites, err
}

// RevokeInvite cancels one pending invite before acceptance; consumed
// invites are immutable history and report unknown.
func (r *Repository) RevokeInvite(ctx context.Context, actorID, inviteID uuid.UUID) (string, error) {
	if r == nil || r.db == nil || actorID == uuid.Nil || inviteID == uuid.Nil {
		return "", ErrInvalidRecord
	}
	var outcome string
	err := r.withTx(ctx, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx,
			`SELECT keel_meta.revoke_organization_invite($1,$2)`, actorID, inviteID,
		).Scan(&outcome)
	})
	if err == nil && outcome == "unknown_invite" {
		return "", ErrNotFound
	}
	if err == nil && outcome == "not_authorized" {
		return "", ErrNotAuthorized
	}
	return outcome, err
}

// OrganizationsFor lists every organization one principal belongs to.
func (r *Repository) OrganizationsFor(ctx context.Context, principalID uuid.UUID) ([]Organization, error) {
	if r == nil || r.db == nil || principalID == uuid.Nil {
		return nil, ErrInvalidRecord
	}
	var orgs []Organization
	err := r.withTx(ctx, func(tx *sql.Tx) error {
		rows, rowsErr := tx.QueryContext(ctx,
			`SELECT out_org_id,out_slug,out_display_name,out_region,out_role
			   FROM keel_meta.organizations_for($1)`,
			principalID,
		)
		if rowsErr != nil {
			return rowsErr
		}
		defer rows.Close()
		for rows.Next() {
			var org Organization
			if scanErr := rows.Scan(&org.OrgID, &org.Slug, &org.DisplayName, &org.Region, &org.Role); scanErr != nil {
				return scanErr
			}
			orgs = append(orgs, org)
		}
		return rows.Err()
	})
	return orgs, err
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
