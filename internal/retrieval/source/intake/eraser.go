package intake

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"regexp"

	"github.com/google/uuid"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
	"github.com/sanskarpan/keel/internal/retrieval/index"
)

var ErrSourceErasureNotAuthorized = errors.New("source erasure requires the matching withdrawal fence")

var sourceErasureWorkerIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]{1,63}$`)

// ObjectDeleter is the narrow storage operation required by Eraser.
type ObjectDeleter interface {
	Delete(context.Context, string) error
}

// ErasureFence identifies the exact currently claimed source-erasure action.
type ErasureFence struct {
	Tenant                tenancy.TenantID
	Visibility            string
	WorkerID              string
	JobID                 uuid.UUID
	DocumentVersionID     uuid.UUID
	EligibilityGeneration int64
	LeaseEpoch            int64
}

// HoldClearance is a provider decision that serializes legal-hold changes
// against destructive work until Release returns. Implementations must fail
// closed for active, unknown, stale or unavailable policy state.
type HoldClearance struct {
	DecisionActorID uuid.UUID
	EvidenceSHA256  [32]byte
	Release         func() error
}

// LegalHoldAuthority acquires a clearance permit for one fenced deletion.
// A read-only check without serialization is insufficient because a hold
// could become active between the check and object deletion.
type LegalHoldAuthority interface {
	AcquireClearance(context.Context, ErasureFence) (HoldClearance, error)
}

// SourceErasureReceiptWriter stores content-free evidence using the same live
// lease that performed the deletion. Implementations must reject stale leases.
type SourceErasureReceiptWriter interface {
	RecordSourceObjects(context.Context, ErasureFence, uuid.UUID, [32]byte) error
}

type SourceErasureReceiptWriterFunc func(context.Context, ErasureFence, uuid.UUID, [32]byte) error

func (f SourceErasureReceiptWriterFunc) RecordSourceObjects(ctx context.Context, fence ErasureFence, actorID uuid.UUID, digest [32]byte) error {
	return f(ctx, fence, actorID, digest)
}

// Eraser removes the raw and extracted supplier upload objects for one
// withdrawn source and records that action's receipt. It is not the complete
// erasure processor; callers must not complete the durable job based on this
// action alone because every other manifest action remains required.
type Eraser struct {
	db            *sql.DB
	objects       ObjectDeleter
	holdAuthority LegalHoldAuthority
	receipts      SourceErasureReceiptWriter
}

func NewEraser(db *sql.DB, objects ObjectDeleter, holdAuthority LegalHoldAuthority, receipts SourceErasureReceiptWriter) (*Eraser, error) {
	if db == nil || objects == nil || holdAuthority == nil || receipts == nil {
		return nil, errors.New("erasure database, object deleter, legal-hold authority and receipt writer are required")
	}
	return &Eraser{db: db, objects: objects, holdAuthority: holdAuthority, receipts: receipts}, nil
}

// EraseClaimed deletes both supplier objects for the source resolved from the
// exact live erasure lease. It checks the lease and hold-clearance receipt
// before reading object IDs and immediately before each external deletion. A
// partial delete is retried by the same durable job on a later lease.
//
// A prior database receipt is only a prerequisite. The injected hold authority
// must independently acquire current clearance and serialize hold changes
// until both deletions return.
func (e *Eraser) EraseClaimed(ctx context.Context, tenant tenancy.TenantID, visibility, workerID string, jobID uuid.UUID, epoch int64) error {
	if ctx == nil || e == nil || e.db == nil || e.objects == nil || jobID == uuid.Nil || epoch < 1 || !sourceErasureWorkerIDPattern.MatchString(workerID) {
		return errors.New("source erasure arguments are invalid")
	}
	tenantID, err := tenancy.ParseTenantID(string(tenant))
	if err != nil {
		return errors.New("source erasure tenant is invalid")
	}
	visibility, err = index.ParseVisibilityKey(visibility)
	if err != nil {
		return errors.New("source erasure visibility is invalid")
	}
	rawKey, extractedKey, documentVersionID, generation, alreadyRecorded, err := e.authorizedObjectKeys(ctx, tenantID, visibility, workerID, jobID, epoch)
	if err != nil {
		return err
	}
	if alreadyRecorded {
		return nil
	}
	if _, err := uuid.Parse(rawKey); err != nil {
		return errors.New("supplier raw object identity is invalid")
	}
	if _, err := uuid.Parse(extractedKey); err != nil {
		return errors.New("supplier extracted object identity is invalid")
	}
	fence := ErasureFence{Tenant: tenantID, Visibility: visibility,
		WorkerID: workerID, JobID: jobID, DocumentVersionID: documentVersionID,
		EligibilityGeneration: generation, LeaseEpoch: epoch}
	clearance, err := e.holdAuthority.AcquireClearance(ctx, fence)
	if err != nil {
		return ErrSourceErasureNotAuthorized
	}
	if clearance.Release == nil {
		return ErrSourceErasureNotAuthorized
	}
	if clearance.DecisionActorID == uuid.Nil || clearance.EvidenceSHA256 == ([32]byte{}) {
		_ = clearance.Release()
		return ErrSourceErasureNotAuthorized
	}
	released := false
	defer func() {
		if !released {
			_ = clearance.Release()
		}
	}()
	if _, _, _, _, _, err := e.authorizedObjectKeys(ctx, tenantID, visibility, workerID, jobID, epoch); err != nil {
		return err
	}
	if err := e.objects.Delete(ctx, extractedKey); err != nil {
		return errors.New("supplier extracted source object could not be erased")
	}
	if _, _, _, _, _, err := e.authorizedObjectKeys(ctx, tenantID, visibility, workerID, jobID, epoch); err != nil {
		return err
	}
	if err := e.objects.Delete(ctx, rawKey); err != nil {
		return errors.New("supplier raw source object could not be erased")
	}
	if _, _, _, _, _, err := e.authorizedObjectKeys(ctx, tenantID, visibility, workerID, jobID, epoch); err != nil {
		return err
	}
	// The receipt digest binds the immutable job/source identity, object IDs,
	// and hold-authority evidence without persisting source content or keys.
	receiptDigest := sha256.Sum256([]byte(fmt.Sprintf("keel-supplier-erasure-v1\x00%s\x00%s\x00%s\x00%s\x00%d\x00%x\x00%s\x00%s",
		tenantID, visibility, jobID, documentVersionID, generation, clearance.EvidenceSHA256, rawKey, extractedKey)))
	if err := e.receipts.RecordSourceObjects(ctx, fence, clearance.DecisionActorID, receiptDigest); err != nil {
		return errors.New("supplier source erasure receipt could not be recorded")
	}
	if err := clearance.Release(); err != nil {
		return errors.New("legal-hold clearance could not be released after source erasure")
	}
	released = true
	return nil
}

func (e *Eraser) authorizedObjectKeys(ctx context.Context, tenant tenancy.TenantID, visibility, workerID string, jobID uuid.UUID, epoch int64) (string, string, uuid.UUID, int64, bool, error) {
	var rawKey, extractedKey string
	var documentVersionID uuid.UUID
	var generation int64
	var alreadyRecorded bool
	err := tenancy.WithTenantTx(ctx, e.db, tenant, &sql.TxOptions{Isolation: sql.LevelReadCommitted}, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `SELECT set_config('keel.visibility_key',$1,true)`, visibility); err != nil {
			return fmt.Errorf("set source erasure visibility scope: %w", err)
		}
		err := tx.QueryRowContext(ctx, `SELECT j.document_version_id,j.eligibility_generation,EXISTS (
				SELECT 1 FROM keel_meta.retrieval_erasure_action_receipts source_receipt
				WHERE source_receipt.tenant_id=j.tenant_id AND source_receipt.visibility_key=j.visibility_key
				  AND source_receipt.job_id=j.job_id AND source_receipt.action_key='supplier_source_objects'
				  AND source_receipt.disposition='complete'
			)
			FROM keel_meta.retrieval_erasure_jobs j
			JOIN keel_meta.retrieval_source_eligibility e
			  ON e.tenant_id=j.tenant_id AND e.visibility_key=j.visibility_key AND e.document_version_id=j.document_version_id
			WHERE j.tenant_id=$1 AND j.visibility_key=$2 AND j.job_id=$3 AND j.state='cleanup_pending'
			  AND j.lease_owner=$4 AND j.lease_epoch=$5 AND j.lease_until>clock_timestamp()
			  AND e.state='withdrawn' AND e.generation=j.eligibility_generation
			  AND EXISTS (
			    SELECT 1 FROM keel_meta.retrieval_erasure_action_receipts r
			    WHERE r.tenant_id=j.tenant_id AND r.visibility_key=j.visibility_key AND r.job_id=j.job_id
			      AND r.action_key='legal_hold_check' AND r.disposition='complete' AND r.lease_epoch<=$5
			  )`, string(tenant), visibility, jobID, workerID, epoch).Scan(&documentVersionID, &generation, &alreadyRecorded)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrSourceErasureNotAuthorized
		}
		if err != nil {
			return fmt.Errorf("validate source erasure lease and hold receipt: %w", err)
		}
		err = tx.QueryRowContext(ctx, `SELECT object_key::text,extracted_object_key::text
			FROM keel_meta.supplier_uploads
			WHERE tenant_id=$1 AND upload_id=$2 AND upload_state='extracted'`,
			string(tenant), documentVersionID).Scan(&rawKey, &extractedKey)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrSourceErasureNotAuthorized
		}
		if err != nil {
			return fmt.Errorf("read supplier source object identities: %w", err)
		}
		return nil
	})
	if err != nil {
		return "", "", uuid.Nil, 0, false, err
	}
	return rawKey, extractedKey, documentVersionID, generation, alreadyRecorded, nil
}
