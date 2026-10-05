package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

var ErrSourceNotRegistered = errors.New("retrieval source version is not registered in this cohort")

var (
	ErrErasureActionReceiptConflict    = errors.New("erasure action already has a different immutable receipt")
	ErrErasureActionManifestIncomplete = errors.New("erasure job cannot complete until every required action has a receipt")
)

const (
	ErasureActionLegalHoldCheck       = "legal_hold_check"
	ErasureActionSupplierSourceObject = "supplier_source_objects"
	ErasureActionDerivedIndex         = "derived_index"
	ErasureActionCacheRevocation      = "cache_revocation"
	ErasureActionQueuedWorkRevocation = "queued_work_revocation"
	ErasureActionBackupExpiry         = "backup_expiry"
	ErasureReceiptComplete            = "complete"
	ErasureReceiptNotApplicable       = "not_applicable"
)

// ErasureActionReceipt is an immutable acknowledgement for one action in a
// job's database-seeded manifest. It records a digest of external evidence,
// never the evidence payload itself, which may contain source data.
type ErasureActionReceipt struct {
	ActionKey       string
	LeaseOwner      string
	LeaseEpoch      int64
	Disposition     string
	DecisionActorID uuid.UUID
	DecisionReason  sql.NullString
	ReceiptSHA256   [32]byte
	RecordedAt      time.Time
}

// ErasureJob is a durable request to suppress one immutable source version.
// Its lease state records cleanup orchestration; complete is only valid after
// the caller has finished its configured actions. The repository itself does
// not claim physical or backup erasure.
type ErasureJob struct {
	ID                    uuid.UUID
	RequestedBy           uuid.UUID
	DocumentVersionID     uuid.UUID
	EligibilityGeneration int64
	State                 string
	RequestedAt           string
	AttemptCount          int
	LastErrorCode         sql.NullString
	AvailableAt           time.Time
	LeaseOwner            sql.NullString
	LeaseEpoch            int64
	LeaseUntil            sql.NullTime
	BlockedAt             sql.NullTime
	CompletedAt           sql.NullTime
}

// RecordErasureActionReceipt appends one result for a manifest action. A live
// owner/epoch is required for a new receipt; replaying an identical receipt is
// idempotent even after lease expiry. Conflicting replays are rejected.
func (r *Repository) RecordErasureActionReceipt(ctx context.Context, tenant tenancy.TenantID, visibility, workerID string,
	jobID uuid.UUID, epoch int64, actionKey string, disposition string, actorID uuid.UUID, reason string, receiptSHA256 [32]byte) (ErasureActionReceipt, error) {
	if err := validateErasureWorkerRepository(r, ctx); err != nil {
		return ErasureActionReceipt{}, err
	}
	s, err := newScope(tenant, visibility)
	if err != nil {
		return ErasureActionReceipt{}, err
	}
	if !erasureWorkerIDPattern.MatchString(workerID) || jobID == uuid.Nil || epoch < 1 || actorID == uuid.Nil ||
		!validErasureAction(actionKey) || (disposition != ErasureReceiptComplete && disposition != ErasureReceiptNotApplicable) {
		return ErasureActionReceipt{}, errors.New("erasure receipt identity or decision is invalid")
	}
	if disposition == ErasureReceiptComplete {
		if reason != "" {
			return ErasureActionReceipt{}, errors.New("completed erasure action must not include a not-applicable reason")
		}
	} else {
		reason = strings.TrimSpace(reason)
		if actionKey == ErasureActionLegalHoldCheck || len(reason) == 0 || len(reason) > 512 {
			return ErasureActionReceipt{}, errors.New("not-applicable decision requires an allowed action and a reason of at most 512 bytes")
		}
	}
	var receipt ErasureActionReceipt
	err = withScope(ctx, r.db, s, nil, func(tx *sql.Tx) error {
		var existing ErasureActionReceipt
		var existingReason sql.NullString
		var existingDigest []byte
		err := tx.QueryRowContext(ctx, `SELECT action_key,lease_owner,lease_epoch,disposition,decision_actor_id,decision_reason,receipt_sha256,recorded_at
			FROM keel_meta.retrieval_erasure_action_receipts
			WHERE tenant_id=$1 AND visibility_key=$2 AND job_id=$3 AND action_key=$4`,
			string(s.tenant), s.visibility, jobID, actionKey).
			Scan(&existing.ActionKey, &existing.LeaseOwner, &existing.LeaseEpoch, &existing.Disposition, &existing.DecisionActorID,
				&existingReason, &existingDigest, &existing.RecordedAt)
		if err == nil {
			if len(existingDigest) != len(existing.ReceiptSHA256) {
				return errors.New("stored erasure receipt digest has invalid length")
			}
			copy(existing.ReceiptSHA256[:], existingDigest)
			existing.DecisionReason = existingReason
			if existing.Disposition != disposition || existing.DecisionActorID != actorID ||
				existing.DecisionReason.String != reason || existing.ReceiptSHA256 != receiptSHA256 {
				return ErrErasureActionReceiptConflict
			}
			receipt = existing
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("read existing erasure action receipt: %w", err)
		}
		var reasonValue any
		if disposition == ErasureReceiptNotApplicable {
			reasonValue = reason
		}
		var insertedDigest []byte
		err = tx.QueryRowContext(ctx, `INSERT INTO keel_meta.retrieval_erasure_action_receipts
			(tenant_id,visibility_key,job_id,action_key,lease_owner,lease_epoch,disposition,decision_actor_id,decision_reason,receipt_sha256)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
			ON CONFLICT (tenant_id,visibility_key,job_id,action_key) DO NOTHING
			RETURNING action_key,lease_owner,lease_epoch,disposition,decision_actor_id,decision_reason,receipt_sha256,recorded_at`,
			string(s.tenant), s.visibility, jobID, actionKey, workerID, epoch, disposition, actorID, reasonValue, receiptSHA256[:]).
			Scan(&receipt.ActionKey, &receipt.LeaseOwner, &receipt.LeaseEpoch, &receipt.Disposition, &receipt.DecisionActorID,
				&receipt.DecisionReason, &insertedDigest, &receipt.RecordedAt)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrErasureActionReceiptConflict
		}
		if err != nil {
			return fmt.Errorf("record erasure action receipt: %w", err)
		}
		if len(insertedDigest) != len(receipt.ReceiptSHA256) {
			return errors.New("stored erasure receipt digest has invalid length")
		}
		copy(receipt.ReceiptSHA256[:], insertedDigest)
		return nil
	})
	return receipt, err
}

func validErasureAction(action string) bool {
	switch action {
	case ErasureActionLegalHoldCheck, ErasureActionSupplierSourceObject, ErasureActionDerivedIndex,
		ErasureActionCacheRevocation, ErasureActionQueuedWorkRevocation, ErasureActionBackupExpiry:
		return true
	default:
		return false
	}
}

// WithdrawSource atomically installs a monotonic query-time tombstone and a
// durable idempotent erasure request. The app role cannot reactivate a source.
func (r *Repository) WithdrawSource(ctx context.Context, tenant tenancy.TenantID, visibility string, requestedBy, documentVersionID, jobID uuid.UUID) (ErasureJob, error) {
	s, err := newScope(tenant, visibility)
	if err != nil {
		return ErasureJob{}, err
	}
	if requestedBy == uuid.Nil || documentVersionID == uuid.Nil || jobID == uuid.Nil {
		return ErasureJob{}, errors.New("request actor, document version and erasure job IDs are required")
	}
	var job ErasureJob
	err = withScope(ctx, r.db, s, nil, func(tx *sql.Tx) error {
		var state string
		var generation int64
		if err := tx.QueryRowContext(ctx, `SELECT state,generation FROM keel_meta.retrieval_source_eligibility
			WHERE tenant_id=$1 AND visibility_key=$2 AND document_version_id=$3 FOR UPDATE`, string(s.tenant), s.visibility, documentVersionID).
			Scan(&state, &generation); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrSourceNotRegistered
			}
			return fmt.Errorf("lock source eligibility for withdrawal: %w", err)
		}
		if state == "active" {
			if err := tx.QueryRowContext(ctx, `UPDATE keel_meta.retrieval_source_eligibility
				SET state='withdrawn',generation=generation+1,changed_at=clock_timestamp()
				WHERE tenant_id=$1 AND visibility_key=$2 AND document_version_id=$3
				RETURNING generation`, string(s.tenant), s.visibility, documentVersionID).Scan(&generation); err != nil {
				return fmt.Errorf("install source withdrawal fence: %w", err)
			}
		} else if state != "withdrawn" {
			return errors.New("unknown source eligibility state")
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO keel_meta.retrieval_erasure_jobs
			(tenant_id,visibility_key,job_id,requested_by,document_version_id,eligibility_generation)
			VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING`, string(s.tenant), s.visibility, jobID, requestedBy, documentVersionID, generation)
		if err != nil {
			return fmt.Errorf("persist source erasure job: %w", err)
		}
		if err := tx.QueryRowContext(ctx, `SELECT job_id,requested_by,document_version_id,eligibility_generation,state,requested_at::text,attempt_count,last_error_code,
			available_at,lease_owner,lease_epoch,lease_until,blocked_at,completed_at
			FROM keel_meta.retrieval_erasure_jobs WHERE tenant_id=$1 AND visibility_key=$2 AND job_id=$3`, string(s.tenant), s.visibility, jobID).
			Scan(&job.ID, &job.RequestedBy, &job.DocumentVersionID, &job.EligibilityGeneration, &job.State, &job.RequestedAt, &job.AttemptCount, &job.LastErrorCode,
				&job.AvailableAt, &job.LeaseOwner, &job.LeaseEpoch, &job.LeaseUntil, &job.BlockedAt, &job.CompletedAt); err != nil {
			return fmt.Errorf("read durable source erasure job: %w", err)
		}
		if job.RequestedBy != requestedBy || job.DocumentVersionID != documentVersionID || job.EligibilityGeneration != generation {
			return errors.New("erasure job ID already belongs to a different source fence")
		}
		return nil
	})
	return job, err
}

// ErasureJob returns the tenant/cohort-scoped durable state for a request.
func (r *Repository) ErasureJob(ctx context.Context, tenant tenancy.TenantID, visibility string, jobID uuid.UUID) (ErasureJob, error) {
	s, err := newScope(tenant, visibility)
	if err != nil {
		return ErasureJob{}, err
	}
	if jobID == uuid.Nil {
		return ErasureJob{}, errors.New("erasure job ID is required")
	}
	var job ErasureJob
	err = withScope(ctx, r.db, s, &sql.TxOptions{ReadOnly: true}, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT job_id,requested_by,document_version_id,eligibility_generation,state,requested_at::text,attempt_count,last_error_code,
			available_at,lease_owner,lease_epoch,lease_until,blocked_at,completed_at
			FROM keel_meta.retrieval_erasure_jobs WHERE tenant_id=$1 AND visibility_key=$2 AND job_id=$3`, string(s.tenant), s.visibility, jobID).
			Scan(&job.ID, &job.RequestedBy, &job.DocumentVersionID, &job.EligibilityGeneration, &job.State, &job.RequestedAt, &job.AttemptCount, &job.LastErrorCode,
				&job.AvailableAt, &job.LeaseOwner, &job.LeaseEpoch, &job.LeaseUntil, &job.BlockedAt, &job.CompletedAt)
	})
	return job, err
}
