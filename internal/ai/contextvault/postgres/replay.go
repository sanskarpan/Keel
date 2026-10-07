package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/sanskarpan/keel/internal/ai/contextvault"
	"github.com/sanskarpan/keel/internal/ai/contextvault/replay"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

// ReplayStore uses only the dedicated replay capability. Its SQL surface is
// limited to begin/finish functions; it has no direct table access.
type ReplayStore struct{ db *sql.DB }

func NewReplayStore(db *sql.DB) (*ReplayStore, error) {
	if db == nil {
		return nil, errors.New("context replay database is required")
	}
	return &ReplayStore{db: db}, nil
}

// RecordDenied appends a content-free authorization denial without reading the
// context record or invoking a key provider.
func (s *ReplayStore) RecordDenied(ctx context.Context, request replay.Request) error {
	if s == nil || s.db == nil || ctx == nil || !validReplayRequest(request) {
		return ErrInvalid
	}
	tenant, err := tenancy.ParseTenantID(request.TenantID)
	if err != nil {
		return ErrInvalid
	}
	tenant = tenancy.TenantID(strings.ToLower(string(tenant)))
	return tenancy.WithTenantTx(ctx, s.db, tenant, nil, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `SELECT keel_meta.record_denied_context_vault_replay($1,$2,$3,$4,$5,$6)`,
			request.RequestID, request.ActorID, request.RecordID, int64(request.Version), request.Purpose, request.Reason)
		return err
	})
}

func (s *ReplayStore) BeginReplay(ctx context.Context, request replay.Request) (contextvault.Scope, contextvault.Envelope, error) {
	if s == nil || s.db == nil || ctx == nil || !validReplayRequest(request) {
		return contextvault.Scope{}, contextvault.Envelope{}, ErrInvalid
	}
	tenant, err := tenancy.ParseTenantID(request.TenantID)
	if err != nil {
		return contextvault.Scope{}, contextvault.Envelope{}, ErrInvalid
	}
	tenant = tenancy.TenantID(strings.ToLower(string(tenant)))
	var status string
	var scope contextvault.Scope
	var envelope contextvault.Envelope
	err = tenancy.WithTenantTx(ctx, s.db, tenant, nil, func(tx *sql.Tx) error {
		var storedRecordID sql.NullString
		var storedVersion sql.NullInt64
		var policyDigest, algorithm, keyID sql.NullString
		var wrapped, nonce, ciphertext []byte
		if err := tx.QueryRowContext(ctx, `SELECT status,record_id::text,version,policy_digest,algorithm,key_id,
			wrapped_dek,nonce,ciphertext FROM keel_meta.begin_context_vault_replay($1,$2,$3,$4,$5,$6)`,
			request.RequestID, request.ActorID, request.RecordID, int64(request.Version), request.Purpose, request.Reason).Scan(
			&status, &storedRecordID, &storedVersion, &policyDigest, &algorithm, &keyID, &wrapped, &nonce, &ciphertext); err != nil {
			return err
		}
		if status != "started" {
			return nil // Commit the content-free denied attempt.
		}
		if !storedRecordID.Valid || !storedVersion.Valid || !policyDigest.Valid || !algorithm.Valid || !keyID.Valid {
			return errors.New("context replay returned an incomplete record")
		}
		scope = contextvault.Scope{TenantID: string(tenant), RecordID: storedRecordID.String,
			Version: uint64(storedVersion.Int64), PolicyDigest: policyDigest.String}
		envelope = contextvault.Envelope{Algorithm: algorithm.String, KeyID: keyID.String,
			WrappedDEK: wrapped, Nonce: nonce, Ciphertext: ciphertext}
		return nil
	})
	if err != nil {
		return contextvault.Scope{}, contextvault.Envelope{}, fmt.Errorf("begin context replay: %w", err)
	}
	if status != "started" {
		return contextvault.Scope{}, contextvault.Envelope{}, ErrNotFound
	}
	return scope, envelope, nil
}

func (s *ReplayStore) FinishReplay(ctx context.Context, request replay.Request, outcome replay.Outcome) error {
	if s == nil || s.db == nil || ctx == nil || !validReplayRequest(request) ||
		(outcome != replay.OutcomeComplete && outcome != replay.OutcomeIntegrityError && outcome != replay.OutcomeKeyUnavailable &&
			outcome != replay.OutcomeDeliveryError && outcome != replay.OutcomeCancelled) {
		return ErrInvalid
	}
	tenant, err := tenancy.ParseTenantID(request.TenantID)
	if err != nil {
		return ErrInvalid
	}
	tenant = tenancy.TenantID(strings.ToLower(string(tenant)))
	return tenancy.WithTenantTx(ctx, s.db, tenant, nil, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `SELECT keel_meta.finish_context_vault_replay($1,$2,$3)`,
			request.RequestID, request.ActorID, string(outcome))
		return err
	})
}

// DeliverReplay holds a shared lock on the exact live record while the trusted
// consumer receives plaintext. Hold placement and erasure take an exclusive
// lock on this row, so the final eligibility check is serialized with release.
func (s *ReplayStore) DeliverReplay(ctx context.Context, request replay.Request, deliver func() replay.Outcome) error {
	if s == nil || s.db == nil || ctx == nil || !validReplayRequest(request) || deliver == nil {
		return ErrInvalid
	}
	tenant, err := tenancy.ParseTenantID(request.TenantID)
	if err != nil {
		return ErrInvalid
	}
	tenant = tenancy.TenantID(strings.ToLower(string(tenant)))
	eligible := false
	var outcome replay.Outcome
	err = tenancy.WithTenantTx(ctx, s.db, tenant, nil, func(tx *sql.Tx) error {
		if err := tx.QueryRowContext(ctx, `SELECT keel_meta.prepare_context_vault_replay_release($1,$2)`,
			request.RequestID, request.ActorID).Scan(&eligible); err != nil {
			return err
		}
		if !eligible {
			return nil // Commit the content-free terminal denial.
		}
		outcome = deliver()
		if outcome != replay.OutcomeComplete && outcome != replay.OutcomeIntegrityError &&
			outcome != replay.OutcomeKeyUnavailable && outcome != replay.OutcomeDeliveryError && outcome != replay.OutcomeCancelled {
			return ErrInvalid
		}
		_, err := tx.ExecContext(ctx, `SELECT keel_meta.finish_context_vault_replay($1,$2,$3)`,
			request.RequestID, request.ActorID, string(outcome))
		return err
	})
	if err != nil {
		return fmt.Errorf("deliver context replay: %w", err)
	}
	if !eligible || outcome != replay.OutcomeComplete {
		return ErrNotFound
	}
	return nil
}

func validReplayRequest(request replay.Request) bool {
	return request.TenantID != "" && request.ActorID != "" && request.RecordID != "" && request.Version > 0 && request.Version <= maxVersion &&
		request.RequestID != "" && (request.Purpose == PurposeReadOnlyReplay || request.Purpose == PurposeIncidentReview) &&
		(request.Reason == "support_diagnostic" || request.Reason == "security_investigation" || request.Reason == "customer_requested")
}
