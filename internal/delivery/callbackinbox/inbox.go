// Package callbackinbox records one authenticated provider callback exactly once and applies its
// effect in the same tenant transaction that records it.
//
// The package is a trust boundary, not a provider adapter: it never verifies a signature itself.
// It accepts only a VerifiedEvent produced by an injected Verifier, so signature algorithms, key
// rotation and provider-specific payload parsing stay outside this package. A callback that
// conflicts with an already recorded provider event ID is recorded in an append-only conflict
// ledger and is not applied.
package callbackinbox

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

// MaxPayloadBytes bounds the raw payload one callback may present. The inbox never stores the
// payload, so the bound exists only to keep verification work finite.
const MaxPayloadBytes = 1 << 20

var (
	// ErrUnauthenticated means the verifier rejected the callback or there was nothing to verify.
	ErrUnauthenticated = errors.New("provider callback could not be authenticated")
	// ErrInvalidCallback means the request or the verified event violates a bounded input rule.
	ErrInvalidCallback = errors.New("provider callback is invalid")
	// ErrConflict means the provider event ID is already recorded with different content or under
	// another tenant. The specific reason is recorded in the conflict ledger, not returned.
	ErrConflict = errors.New("provider callback conflicts with a recorded event")
	// ErrUnavailable means the verifier could not decide. The inbox fails closed and applies nothing.
	ErrUnavailable = errors.New("provider callback verification is unavailable")
)

var (
	providerPattern  = regexp.MustCompile(`^[a-z][a-z0-9_-]{1,31}$`)
	eventIDPattern   = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)
	digestPattern    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	eventTypePattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,63}$`)
	keyIDPattern     = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,64}$`)
	zeroTenant       = "00000000-0000-0000-0000-000000000000"
)

// VerificationRequest is the untrusted input one provider delivery presents. The verifier owns the
// meaning of Signature and Timestamp; the inbox only requires that a signature is present.
type VerificationRequest struct {
	Provider        string
	ProviderEventID string
	Payload         []byte
	Signature       []byte
	Timestamp       string
}

// Verifier authenticates one inbound callback. Only its VerifiedEvent output may reach the inbox,
// so an implementation must bind the signature to the exact payload and must not invent a tenant.
type Verifier interface {
	Verify(ctx context.Context, request VerificationRequest) (VerifiedEvent, error)
}

// VerifiedEvent is a callback that a trusted verifier authenticated. The tenant is authoritative:
// it is derived from the authenticated integration identity, never from the payload.
type VerifiedEvent struct {
	Tenant          tenancy.TenantID
	Provider        string
	ProviderEventID string
	PayloadDigest   string
	EventType       string
	KeyID           string
	OccurredAt      time.Time
}

// Applier applies one verified callback inside the tenant transaction that records it. It must use
// the provided transaction, must not commit, roll back or begin another transaction, and must be
// safe to run again after a rollback. Returning an error rolls the recorded event back.
type Applier func(ctx context.Context, tx *sql.Tx, event VerifiedEvent) error

// Receipt is the durable outcome of one callback delivery. Duplicate reports that the event was
// already applied and the applier did not run again.
type Receipt struct {
	Provider        string
	ProviderEventID string
	PayloadDigest   string
	EventType       string
	Duplicate       bool
	AppliedAt       time.Time
}

// Inbox records verified callbacks and applies their effects at most once.
type Inbox struct {
	db       *sql.DB
	verifier Verifier
}

// New creates an inbox over the callback capability's database connection. The verifier is
// required: an inbox that cannot authenticate a callback must not accept one.
func New(db *sql.DB, verifier Verifier) (*Inbox, error) {
	if db == nil {
		return nil, errors.New("callback inbox database is required")
	}
	if verifier == nil {
		return nil, errors.New("callback verifier is required")
	}
	return &Inbox{db: db, verifier: verifier}, nil
}

// Accept authenticates one callback and applies its effect exactly once. A first delivery records
// the event and applies the effect in one tenant transaction, so a failed application leaves no
// deduplication state behind. An exact redelivery returns a duplicate receipt without applying
// again. A conflicting delivery returns ErrConflict and records the conflict.
func (i *Inbox) Accept(ctx context.Context, request VerificationRequest, apply Applier) (Receipt, error) {
	if i == nil || i.db == nil {
		return Receipt{}, errors.New("callback inbox database is required")
	}
	if i.verifier == nil {
		return Receipt{}, errors.New("callback verifier is required")
	}
	if ctx == nil {
		return Receipt{}, errors.New("callback context is required")
	}
	if apply == nil {
		return Receipt{}, errors.New("callback applier is required")
	}
	if err := validateRequest(request); err != nil {
		return Receipt{}, err
	}
	event, err := i.verifier.Verify(ctx, request)
	if err != nil {
		if errors.Is(err, ErrUnauthenticated) {
			return Receipt{}, ErrUnauthenticated
		}
		return Receipt{}, ErrUnavailable
	}
	if err := validateEvent(request, event); err != nil {
		return Receipt{}, err
	}

	receipt := Receipt{
		Provider:        event.Provider,
		ProviderEventID: event.ProviderEventID,
		PayloadDigest:   event.PayloadDigest,
		EventType:       event.EventType,
	}
	tx, err := i.db.BeginTx(ctx, nil)
	if err != nil {
		return Receipt{}, fmt.Errorf("begin callback transaction: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	if _, err := tx.ExecContext(ctx, "SELECT set_config('keel.tenant_id', $1, true)", string(event.Tenant)); err != nil {
		return Receipt{}, fmt.Errorf("set callback tenant context: %w", err)
	}
	var outcome string
	var recordedAt sql.NullTime
	err = tx.QueryRowContext(ctx, `SELECT outcome,applied_at FROM keel_meta.claim_provider_callback($1,$2,$3,$4,$5,$6)`,
		event.Provider, event.ProviderEventID, event.PayloadDigest, event.EventType, event.KeyID, event.OccurredAt.UTC()).Scan(&outcome, &recordedAt)
	if err != nil {
		return Receipt{}, fmt.Errorf("claim provider callback: %w", err)
	}
	switch outcome {
	case "inserted":
		if err := apply(ctx, tx, event); err != nil {
			return Receipt{}, fmt.Errorf("apply provider callback: %w", err)
		}
		var appliedAt time.Time
		if err := tx.QueryRowContext(ctx, `SELECT keel_meta.confirm_provider_callback($1,$2)`,
			event.Provider, event.ProviderEventID).Scan(&appliedAt); err != nil {
			return Receipt{}, fmt.Errorf("confirm provider callback: %w", err)
		}
		receipt.AppliedAt = appliedAt.UTC()
	case "duplicate":
		if !recordedAt.Valid {
			return Receipt{}, errors.New("duplicate callback has no recorded application")
		}
		receipt.Duplicate = true
		receipt.AppliedAt = recordedAt.Time.UTC()
	case "conflict", "tenant_mismatch":
		if err := tx.Commit(); err != nil {
			return Receipt{}, fmt.Errorf("commit callback conflict: %w", err)
		}
		committed = true
		return Receipt{}, ErrConflict
	default:
		return Receipt{}, fmt.Errorf("callback claim returned an unknown outcome %q", outcome)
	}
	if err := tx.Commit(); err != nil {
		return Receipt{}, fmt.Errorf("commit callback transaction: %w", err)
	}
	committed = true
	return receipt, nil
}

// DigestPayload returns the canonical lowercase hex SHA-256 digest a verifier should bind to a
// callback payload. A verifier that canonicalizes provider-specific content must return the digest
// of its canonical form instead.
func DigestPayload(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func validateRequest(request VerificationRequest) error {
	if !providerPattern.MatchString(request.Provider) {
		return ErrInvalidCallback
	}
	if !eventIDPattern.MatchString(request.ProviderEventID) {
		return ErrInvalidCallback
	}
	if len(request.Payload) == 0 || len(request.Payload) > MaxPayloadBytes {
		return ErrInvalidCallback
	}
	if len(request.Signature) == 0 {
		return ErrUnauthenticated
	}
	return nil
}

func validateEvent(request VerificationRequest, event VerifiedEvent) error {
	if event.Provider != request.Provider || event.ProviderEventID != request.ProviderEventID {
		return ErrInvalidCallback
	}
	if !providerPattern.MatchString(event.Provider) {
		return ErrInvalidCallback
	}
	if !eventIDPattern.MatchString(event.ProviderEventID) {
		return ErrInvalidCallback
	}
	if !digestPattern.MatchString(event.PayloadDigest) {
		return ErrInvalidCallback
	}
	if !eventTypePattern.MatchString(event.EventType) {
		return ErrInvalidCallback
	}
	if !keyIDPattern.MatchString(event.KeyID) {
		return ErrInvalidCallback
	}
	if event.OccurredAt.IsZero() {
		return ErrInvalidCallback
	}
	if string(event.Tenant) == "" || string(event.Tenant) == zeroTenant {
		return ErrInvalidCallback
	}
	if _, err := tenancy.ParseTenantID(string(event.Tenant)); err != nil {
		return ErrInvalidCallback
	}
	return nil
}
