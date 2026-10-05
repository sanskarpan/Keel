package intake

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
	"github.com/sanskarpan/keel/internal/retrieval/index"
	retrievalpostgres "github.com/sanskarpan/keel/internal/retrieval/postgres"
)

// DerivedIndexEraser executes one bounded unpublished-index cleanup pass. It
// holds serialized legal-hold clearance until either the pass has safely
// completed and its receipt is durable, or the pass exits for retry.
type DerivedIndexEraser struct {
	repository    *retrievalpostgres.Repository
	holdAuthority LegalHoldAuthority
}

var _ retrievalpostgres.ClaimedDerivedIndexEraser = (*DerivedIndexEraser)(nil)

func NewDerivedIndexEraser(repository *retrievalpostgres.Repository, authority LegalHoldAuthority) (*DerivedIndexEraser, error) {
	if repository == nil || authority == nil {
		return nil, errors.New("derived-index repository and legal-hold authority are required")
	}
	return &DerivedIndexEraser{repository: repository, holdAuthority: authority}, nil
}

func (e *DerivedIndexEraser) CleanupClaimed(ctx context.Context, tenant tenancy.TenantID, visibility, workerID string, jobID uuid.UUID, epoch int64) error {
	if ctx == nil || e == nil || e.repository == nil || e.holdAuthority == nil || jobID == uuid.Nil || epoch < 1 {
		return errors.New("derived-index cleanup arguments are invalid")
	}
	tenantID, err := tenancy.ParseTenantID(string(tenant))
	if err != nil {
		return errors.New("derived-index cleanup tenant is invalid")
	}
	visibility, err = index.ParseVisibilityKey(visibility)
	if err != nil {
		return errors.New("derived-index cleanup visibility is invalid")
	}
	job, err := e.repository.ErasureJob(ctx, tenantID, visibility, jobID)
	if err != nil || job.State != "cleanup_pending" || !job.LeaseOwner.Valid || job.LeaseOwner.String != workerID ||
		job.LeaseEpoch != epoch || job.DocumentVersionID == uuid.Nil || job.EligibilityGeneration < 1 {
		return retrievalpostgres.ErrErasureLeaseLost
	}
	fence := ErasureFence{Tenant: tenantID, Visibility: visibility, WorkerID: workerID, JobID: jobID,
		DocumentVersionID: job.DocumentVersionID, EligibilityGeneration: job.EligibilityGeneration, LeaseEpoch: epoch}
	clearance, err := e.holdAuthority.AcquireClearance(ctx, fence)
	if err != nil {
		return ErrSourceErasureNotAuthorized
	}
	if clearance.Release == nil || clearance.DecisionActorID == uuid.Nil || clearance.EvidenceSHA256 == ([32]byte{}) {
		if clearance.Release != nil {
			_ = clearance.Release()
		}
		return ErrSourceErasureNotAuthorized
	}
	released := false
	defer func() {
		if !released {
			_ = clearance.Release()
		}
	}()
	result, err := e.repository.CleanupUnpublishedErasureIndexBatch(ctx, tenantID, visibility, workerID, jobID, epoch,
		retrievalpostgres.MaxErasureIndexBatchRows)
	if err != nil {
		return err
	}
	if !result.ReadyForReceipt() {
		return errors.New("derived-index cleanup remains pending retention or bounded progress")
	}
	// Bind the content-free receipt to this job/source generation, pass result,
	// and serialized hold decision. The repository rechecks the live lease.
	digest := sha256.Sum256([]byte(fmt.Sprintf("keel-derived-index-erasure-v1\x00%s\x00%s\x00%s\x00%s\x00%d\x00%d\x00%t\x00%t\x00%x",
		tenantID, visibility, jobID, job.DocumentVersionID, job.EligibilityGeneration, result.RowsDeleted,
		result.RemainingUnpublished, result.RetainedPublishedBuilds, clearance.EvidenceSHA256)))
	if _, err := e.repository.RecordErasureActionReceipt(ctx, tenantID, visibility, workerID, jobID, epoch,
		retrievalpostgres.ErasureActionDerivedIndex, retrievalpostgres.ErasureReceiptComplete,
		clearance.DecisionActorID, "", digest); err != nil {
		return fmt.Errorf("record derived-index erasure receipt: %w", err)
	}
	if err := clearance.Release(); err != nil {
		return errors.New("legal-hold clearance could not be released after derived-index cleanup")
	}
	released = true
	return nil
}
