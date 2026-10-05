// Package postgres persists retryable delivery state separately from immutable workflow intents.
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

var (
	ErrInvalidLease = errors.New("invalid workflow dispatch lease")
	ErrStaleLease   = errors.New("workflow dispatch lease is stale")
	ErrNoLease      = errors.New("workflow dispatch lease not found")
	uuidPattern     = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
)

const MaxAttempts = 12

type Lease struct {
	TenantID  tenancy.TenantID
	IntentID  string
	CaseID    string
	Version   uint64
	EventType string
	EventHash string
	Attempt   uint32
	Owner     string
	Epoch     uint64
	ExpiresAt time.Time
}

type Repository struct{ db *sql.DB }

func New(db *sql.DB) (*Repository, error) {
	if db == nil {
		return nil, errors.New("workflow dispatch database is required")
	}
	return &Repository{db: db}, nil
}

// Claim reserves one case's earliest outstanding event. Earlier dead-lettered events
// intentionally block later versions; operators must repair the chain explicitly.
func (r *Repository) Claim(ctx context.Context, tenant tenancy.TenantID, owner string, ttl time.Duration) (Lease, bool, error) {
	if r == nil || r.db == nil || ctx == nil || !uuidPattern.MatchString(string(tenant)) || !uuidPattern.MatchString(owner) || ttl < 10*time.Second || ttl > 5*time.Minute {
		return Lease{}, false, ErrInvalidLease
	}
	var lease Lease
	lease.TenantID = tenant
	found := false
	err := tenancy.WithTenantTx(ctx, r.db, tenant, nil, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE keel_meta.supplier_workflow_dispatch
			SET dispatch_state='dead',lease_owner=NULL,lease_expires_at=NULL,
				last_error_code='unknown',updated_at=clock_timestamp()
			WHERE tenant_id=$1 AND dispatch_state='leased' AND lease_expires_at<=clock_timestamp() AND attempt_count >= $2`, string(tenant), MaxAttempts); err != nil {
			return err
		}
		err := tx.QueryRowContext(ctx, `WITH candidate AS (
			SELECT d.tenant_id,d.intent_id FROM keel_meta.supplier_workflow_dispatch AS d
			WHERE d.tenant_id=$1 AND d.attempt_count < $3 AND d.available_at<=clock_timestamp()
			  AND (d.dispatch_state='pending' OR (d.dispatch_state='leased' AND d.lease_expires_at<=clock_timestamp()))
			  AND NOT EXISTS (
				SELECT 1 FROM keel_meta.supplier_workflow_dispatch AS earlier
				WHERE earlier.tenant_id=d.tenant_id AND earlier.case_id=d.case_id
				  AND earlier.aggregate_version<d.aggregate_version AND earlier.dispatch_state<>'delivered'
			  )
			ORDER BY d.available_at,d.case_id,d.aggregate_version
			FOR UPDATE OF d SKIP LOCKED LIMIT 1
		)
		UPDATE keel_meta.supplier_workflow_dispatch AS d
		SET dispatch_state='leased',attempt_count=d.attempt_count+1,
			lease_owner=$2,lease_epoch=d.lease_epoch+1,
			lease_expires_at=clock_timestamp()+($4 * interval '1 millisecond'),
			updated_at=clock_timestamp()
		FROM candidate AS c
		WHERE d.tenant_id=c.tenant_id AND d.intent_id=c.intent_id
		RETURNING d.intent_id,d.case_id,d.aggregate_version,d.intent_type,
			encode(d.event_hash,'hex'),d.attempt_count,d.lease_owner,d.lease_epoch,d.lease_expires_at`, string(tenant), owner, MaxAttempts, ttl.Milliseconds()).Scan(
			&lease.IntentID, &lease.CaseID, &lease.Version, &lease.EventType,
			&lease.EventHash, &lease.Attempt, &lease.Owner, &lease.Epoch, &lease.ExpiresAt)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("claim supplier workflow intent: %w", err)
		}
		found = true
		return nil
	})
	return lease, found, err
}

func (r *Repository) Complete(ctx context.Context, lease Lease) error {
	return r.finish(ctx, lease, `UPDATE keel_meta.supplier_workflow_dispatch
		SET dispatch_state='delivered',delivered_at=clock_timestamp(),lease_owner=NULL,
			lease_expires_at=NULL,last_error_code=NULL,updated_at=clock_timestamp()
		WHERE tenant_id=$1 AND intent_id=$2 AND dispatch_state='leased'
		  AND lease_owner=$3 AND lease_epoch=$4 AND lease_expires_at>clock_timestamp()`, lease.TenantID, lease.IntentID, lease.Owner, lease.Epoch)
}

// Fail stores only a bounded code, never the remote error text or request payload.
func (r *Repository) Fail(ctx context.Context, lease Lease, retryAfter time.Duration, errorCode string) error {
	if retryAfter < 0 || retryAfter > 24*time.Hour || !allowedError(errorCode) {
		return ErrInvalidLease
	}
	return r.finish(ctx, lease, `UPDATE keel_meta.supplier_workflow_dispatch
		SET dispatch_state=CASE WHEN $5 OR attempt_count >= $6 THEN 'dead' ELSE 'pending' END,
			available_at=clock_timestamp()+($7 * interval '1 millisecond'),
			lease_owner=NULL,lease_expires_at=NULL,last_error_code=$8,updated_at=clock_timestamp()
		WHERE tenant_id=$1 AND intent_id=$2 AND dispatch_state='leased'
		  AND lease_owner=$3 AND lease_epoch=$4 AND lease_expires_at>clock_timestamp()`,
		lease.TenantID, lease.IntentID, lease.Owner, lease.Epoch, errorCode == "invalid_intent" || errorCode == "workflow_conflict", MaxAttempts, retryAfter.Milliseconds(), errorCode)
}

func (r *Repository) finish(ctx context.Context, lease Lease, query string, args ...any) error {
	if r == nil || r.db == nil || ctx == nil || !uuidPattern.MatchString(string(lease.TenantID)) ||
		!uuidPattern.MatchString(lease.IntentID) || !uuidPattern.MatchString(lease.Owner) || lease.Epoch == 0 {
		return ErrInvalidLease
	}
	var updated int64
	err := tenancy.WithTenantTx(ctx, r.db, lease.TenantID, nil, func(tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx, query, args...)
		if err != nil {
			return err
		}
		updated, err = result.RowsAffected()
		return err
	})
	if err != nil {
		return fmt.Errorf("finish supplier workflow dispatch: %w", err)
	}
	if updated != 1 {
		return ErrStaleLease
	}
	return nil
}

func allowedError(code string) bool {
	switch code {
	case "temporal_unavailable", "temporal_timeout", "invalid_intent", "workflow_conflict", "unknown":
		return true
	default:
		return false
	}
}
