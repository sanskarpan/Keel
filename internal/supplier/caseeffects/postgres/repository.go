// Package postgres implements fenced delivery for durable supplier-case effects.
package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

const MaxAttempts = 12

var idPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
var ErrInvalidLease = errors.New("invalid supplier case effect lease")
var ErrStaleLease = errors.New("supplier case effect lease is stale")

type Repository struct{ db *sql.DB }
type Lease struct {
	TenantID                                                           tenancy.TenantID
	EffectID, CaseID, EffectKey, EffectType, Occurrence, Digest, Owner string
	Attempt                                                            uint32
	Epoch                                                              uint64
	ExpiresAt                                                          time.Time
}
type Context struct {
	CaseState, EffectType string
	DeadlineAt            time.Time
	Recipients            []string
}

func New(db *sql.DB) (*Repository, error) {
	if db == nil {
		return nil, errors.New("case effect database is required")
	}
	return &Repository{db: db}, nil
}

func (r *Repository) Claim(ctx context.Context, tenant tenancy.TenantID, owner string, ttl time.Duration) (Lease, bool, error) {
	if r == nil || r.db == nil || ctx == nil || !idPattern.MatchString(string(tenant)) || !idPattern.MatchString(owner) || ttl < 10*time.Second || ttl > 5*time.Minute {
		return Lease{}, false, ErrInvalidLease
	}
	var lease Lease
	lease.TenantID = tenant
	found := false
	err := tenancy.WithTenantTx(ctx, r.db, tenant, nil, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE keel_meta.supplier_case_activity_effects SET effect_state='dead',lease_owner=NULL,lease_expires_at=NULL,last_error_code='unknown',updated_at=clock_timestamp() WHERE tenant_id=$1 AND effect_state='leased' AND lease_expires_at<=clock_timestamp() AND attempt_count >= $2`, string(tenant), MaxAttempts); err != nil {
			return err
		}
		err := tx.QueryRowContext(ctx, `WITH candidate AS (
			SELECT tenant_id,effect_id FROM keel_meta.supplier_case_activity_effects
			WHERE tenant_id=$1 AND due_at<=clock_timestamp() AND available_at<=clock_timestamp() AND attempt_count<$3
			  AND (effect_state='pending' OR (effect_state='leased' AND lease_expires_at<=clock_timestamp()))
			ORDER BY due_at,effect_id FOR UPDATE SKIP LOCKED LIMIT 1
		) UPDATE keel_meta.supplier_case_activity_effects e SET effect_state='leased',attempt_count=e.attempt_count+1,
			lease_owner=$2,lease_epoch=e.lease_epoch+1,lease_expires_at=clock_timestamp()+($4*interval '1 millisecond'),updated_at=clock_timestamp()
		FROM candidate c WHERE e.tenant_id=c.tenant_id AND e.effect_id=c.effect_id
		RETURNING e.effect_id,e.case_id,e.effect_key,e.effect_type,e.occurrence,encode(e.payload_digest,'hex'),e.attempt_count,e.lease_owner,e.lease_epoch,e.lease_expires_at`, string(tenant), owner, MaxAttempts, ttl.Milliseconds()).
			Scan(&lease.EffectID, &lease.CaseID, &lease.EffectKey, &lease.EffectType, &lease.Occurrence, &lease.Digest, &lease.Attempt, &lease.Owner, &lease.Epoch, &lease.ExpiresAt)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("claim supplier case activity effect: %w", err)
		}
		found = true
		return nil
	})
	return lease, found, err
}

// LoadContext rechecks lifecycle state and current reviewer grants immediately before
// delivery. The SECURITY DEFINER query exposes only principal refs and timing metadata.
func (r *Repository) LoadContext(ctx context.Context, lease Lease) (Context, bool, error) {
	if r == nil || r.db == nil || !validLease(lease) {
		return Context{}, false, ErrInvalidLease
	}
	var value Context
	err := tenancy.WithTenantTx(ctx, r.db, lease.TenantID, nil, func(tx *sql.Tx) error {
		err := tx.QueryRowContext(ctx, `SELECT case_state,deadline_at,recipient_refs,effect_type FROM keel_meta.load_supplier_case_reminder_context($1,$2,$3,$4,$5)`, string(lease.TenantID), lease.CaseID, lease.EffectID, lease.Owner, lease.Epoch).
			Scan(&value.CaseState, &value.DeadlineAt, &value.Recipients, &value.EffectType)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		return err
	})
	if err != nil {
		return Context{}, false, fmt.Errorf("load current reminder authorization context: %w", err)
	}
	return value, !value.DeadlineAt.IsZero(), nil
}

func (r *Repository) Complete(ctx context.Context, l Lease) error {
	return r.finish(ctx, l, `UPDATE keel_meta.supplier_case_activity_effects SET effect_state='delivered',delivered_at=clock_timestamp(),lease_owner=NULL,lease_expires_at=NULL,last_error_code=NULL,updated_at=clock_timestamp() WHERE tenant_id=$1 AND effect_id=$2 AND effect_state='leased' AND lease_owner=$3 AND lease_epoch=$4 AND lease_expires_at>clock_timestamp()`, nil)
}
func (r *Repository) CompleteNoop(ctx context.Context, l Lease) error {
	return r.finish(ctx, l, `UPDATE keel_meta.supplier_case_activity_effects SET effect_state='canceled',lease_owner=NULL,lease_expires_at=NULL,updated_at=clock_timestamp() WHERE tenant_id=$1 AND effect_id=$2 AND effect_state='leased' AND lease_owner=$3 AND lease_epoch=$4 AND lease_expires_at>clock_timestamp()`, []string{"canceled"})
}

func (r *Repository) Fail(ctx context.Context, l Lease, retryAfter time.Duration, code string) error {
	if retryAfter < 0 || retryAfter > 24*time.Hour || !allowedError(code) {
		return ErrInvalidLease
	}
	return r.finish(ctx, l, `UPDATE keel_meta.supplier_case_activity_effects SET effect_state=CASE WHEN $5 OR attempt_count >= $6 THEN 'dead' ELSE 'pending' END,
		available_at=clock_timestamp()+($7*interval '1 millisecond'),lease_owner=NULL,lease_expires_at=NULL,last_error_code=$8,updated_at=clock_timestamp()
		WHERE tenant_id=$1 AND effect_id=$2 AND effect_state='leased' AND lease_owner=$3 AND lease_epoch=$4 AND lease_expires_at>clock_timestamp()`, nil, code == "permanent_rejection", MaxAttempts, retryAfter.Milliseconds(), code)
}

func (r *Repository) finish(ctx context.Context, l Lease, query string, idempotentStates []string, args ...any) error {
	if r == nil || r.db == nil || ctx == nil || !validLease(l) {
		return ErrInvalidLease
	}
	values := []any{string(l.TenantID), l.EffectID, l.Owner, l.Epoch}
	values = append(values, args...)
	var rows int64
	err := tenancy.WithTenantTx(ctx, r.db, l.TenantID, nil, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, query, values...)
		if err != nil {
			return err
		}
		rows, err = res.RowsAffected()
		return err
	})
	if err != nil {
		return fmt.Errorf("finish supplier case effect: %w", err)
	}
	if rows == 1 {
		return nil
	}
	if len(idempotentStates) > 0 {
		var state string
		err := tenancy.WithTenantTx(ctx, r.db, l.TenantID, nil, func(tx *sql.Tx) error {
			return tx.QueryRowContext(ctx, `SELECT effect_state FROM keel_meta.supplier_case_activity_effects WHERE tenant_id=$1 AND effect_id=$2`, string(l.TenantID), l.EffectID).Scan(&state)
		})
		if err == nil && state == idempotentStates[0] {
			return nil
		}
	}
	return ErrStaleLease
}

func validLease(l Lease) bool {
	return idPattern.MatchString(string(l.TenantID)) && idPattern.MatchString(l.EffectID) && idPattern.MatchString(l.CaseID) && idPattern.MatchString(l.Owner) && l.Epoch > 0 && l.EffectKey != "" && (l.EffectType == "case_reminder" || l.EffectType == "case_expiry") && l.Digest != ""
}
func allowedError(code string) bool {
	return code == "sink_unavailable" || code == "sink_timeout" || code == "permanent_rejection" || code == "unknown"
}
