package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

const (
	MinLegalHoldReviewInterval = time.Second
	MaxLegalHoldReviewInterval = 90 * 24 * time.Hour
)

type LegalHoldReason string

const (
	LegalHoldLitigation        LegalHoldReason = "litigation"
	LegalHoldRegulatory        LegalHoldReason = "regulatory"
	LegalHoldInvestigation     LegalHoldReason = "investigation"
	LegalHoldPreservationOrder LegalHoldReason = "preservation_order"
	LegalHoldOtherAuthorized   LegalHoldReason = "other_authorized"
)

type LegalHoldDecision string

const (
	LegalHoldExtend  LegalHoldDecision = "extend"
	LegalHoldRelease LegalHoldDecision = "release"
)

// LegalHold contains only opaque identifiers and lifecycle timestamps.
type LegalHold struct {
	ID          string
	RecordID    string
	Version     uint64
	Revision    int
	ReviewDueAt time.Time
	Released    bool
}

// LegalHoldStore calls only the audited hold lifecycle functions with a dedicated authority connection.
type LegalHoldStore struct{ db *sql.DB }

func NewLegalHoldStore(db *sql.DB) (*LegalHoldStore, error) {
	if db == nil {
		return nil, errors.New("context legal hold database is required")
	}
	return &LegalHoldStore{db: db}, nil
}

func (s *LegalHoldStore) Create(ctx context.Context, tenant tenancy.TenantID, recordID string, version uint64,
	actorID string, reason LegalHoldReason, reviewInterval time.Duration) (LegalHold, error) {
	if s == nil || s.db == nil || ctx == nil || version == 0 || version > maxVersion ||
		!validLegalHoldReason(reason) || !validLegalHoldActor(actorID) ||
		reviewInterval < MinLegalHoldReviewInterval || reviewInterval > MaxLegalHoldReviewInterval {
		return LegalHold{}, ErrInvalid
	}
	canonicalTenant, err := tenancy.ParseTenantID(string(tenant))
	if err != nil {
		return LegalHold{}, ErrInvalid
	}
	canonicalRecord, err := tenancy.ParseTenantID(recordID)
	if err != nil {
		return LegalHold{}, ErrInvalid
	}
	var hold LegalHold
	hold.RecordID = string(canonicalRecord)
	hold.Version = version
	err = tenancy.WithTenantTx(ctx, s.db, canonicalTenant, nil, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT hold_id::text,revision,review_due_at
			FROM keel_meta.create_context_vault_legal_hold($1,$2,$3,$4,$5)`,
			hold.RecordID, int64(version), actorID, string(reason), reviewInterval.Milliseconds()).Scan(
			&hold.ID, &hold.Revision, &hold.ReviewDueAt)
	})
	if err != nil {
		return LegalHold{}, fmt.Errorf("create context legal hold: %w", err)
	}
	return hold, nil
}

func (s *LegalHoldStore) Review(ctx context.Context, tenant tenancy.TenantID, holdID, actorID string,
	decision LegalHoldDecision, reason LegalHoldReason, reviewInterval time.Duration) (LegalHold, error) {
	if s == nil || s.db == nil || ctx == nil || !validLegalHoldID(holdID) || !validLegalHoldActor(actorID) ||
		!validLegalHoldReason(reason) || (decision != LegalHoldExtend && decision != LegalHoldRelease) ||
		(decision == LegalHoldExtend && (reviewInterval < MinLegalHoldReviewInterval || reviewInterval > MaxLegalHoldReviewInterval)) ||
		(decision == LegalHoldRelease && reviewInterval != 0) {
		return LegalHold{}, ErrInvalid
	}
	canonicalTenant, err := tenancy.ParseTenantID(string(tenant))
	if err != nil {
		return LegalHold{}, ErrInvalid
	}
	var intervalArg any
	if decision == LegalHoldExtend {
		intervalArg = reviewInterval.Milliseconds()
	}
	var hold LegalHold
	err = tenancy.WithTenantTx(ctx, s.db, canonicalTenant, nil, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT revision,review_due_at,released
			FROM keel_meta.review_context_vault_legal_hold($1,$2,$3,$4,$5)`,
			holdID, actorID, string(decision), string(reason), intervalArg).Scan(
			&hold.Revision, &hold.ReviewDueAt, &hold.Released)
	})
	if err != nil {
		return LegalHold{}, fmt.Errorf("review context legal hold: %w", err)
	}
	hold.ID = holdID
	return hold, nil
}

func (s *LegalHoldStore) Extend(ctx context.Context, tenant tenancy.TenantID, holdID, actorID string,
	reason LegalHoldReason, reviewInterval time.Duration) (LegalHold, error) {
	if s == nil || s.db == nil || ctx == nil || !validLegalHoldID(holdID) || !validLegalHoldActor(actorID) ||
		!validLegalHoldReason(reason) || reviewInterval < MinLegalHoldReviewInterval || reviewInterval > MaxLegalHoldReviewInterval {
		return LegalHold{}, ErrInvalid
	}
	canonicalTenant, err := tenancy.ParseTenantID(string(tenant))
	if err != nil {
		return LegalHold{}, ErrInvalid
	}
	var hold LegalHold
	err = tenancy.WithTenantTx(ctx, s.db, canonicalTenant, nil, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT revision,review_due_at,released
			FROM keel_meta.extend_context_vault_legal_hold($1,$2,$3,$4)`,
			holdID, actorID, string(reason), reviewInterval.Milliseconds()).Scan(
			&hold.Revision, &hold.ReviewDueAt, &hold.Released)
	})
	if err != nil {
		return LegalHold{}, fmt.Errorf("extend context legal hold: %w", err)
	}
	hold.ID = holdID
	return hold, nil
}

func (s *LegalHoldStore) Release(ctx context.Context, tenant tenancy.TenantID, holdID, actorID string,
	reason LegalHoldReason) (LegalHold, error) {
	if s == nil || s.db == nil || ctx == nil || !validLegalHoldID(holdID) || !validLegalHoldActor(actorID) || !validLegalHoldReason(reason) {
		return LegalHold{}, ErrInvalid
	}
	canonicalTenant, err := tenancy.ParseTenantID(string(tenant))
	if err != nil {
		return LegalHold{}, ErrInvalid
	}
	var hold LegalHold
	err = tenancy.WithTenantTx(ctx, s.db, canonicalTenant, nil, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT revision,review_due_at,released
			FROM keel_meta.release_context_vault_legal_hold($1,$2,$3)`,
			holdID, actorID, string(reason)).Scan(&hold.Revision, &hold.ReviewDueAt, &hold.Released)
	})
	if err != nil {
		return LegalHold{}, fmt.Errorf("release context legal hold: %w", err)
	}
	hold.ID = holdID
	return hold, nil
}

func validLegalHoldReason(reason LegalHoldReason) bool {
	switch reason {
	case LegalHoldLitigation, LegalHoldRegulatory, LegalHoldInvestigation, LegalHoldPreservationOrder, LegalHoldOtherAuthorized:
		return true
	default:
		return false
	}
}

func validLegalHoldActor(value string) bool { return validLegalHoldID(value) }

func validLegalHoldID(value string) bool {
	id, err := tenancy.ParseTenantID(value)
	return err == nil && id != tenancy.TenantID("00000000-0000-0000-0000-000000000000")
}
