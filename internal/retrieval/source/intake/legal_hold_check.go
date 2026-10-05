package intake

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
	"github.com/sanskarpan/keel/internal/retrieval/index"
	retrievalpostgres "github.com/sanskarpan/keel/internal/retrieval/postgres"
)

const (
	legalHoldBlockActive  = "legal_hold_active"
	legalHoldBlockUnknown = "legal_hold_unknown"
)

// LegalHoldCheckExecutor records the authoritative hold decision as the first
// erasure manifest action. Destructive executors still acquire their own
// serialized clearance immediately before external effects.
type LegalHoldCheckExecutor struct {
	repository    *retrievalpostgres.Repository
	holdAuthority LegalHoldAuthority
}

var _ retrievalpostgres.ErasureActionExecutor = (*LegalHoldCheckExecutor)(nil)

func NewLegalHoldCheckExecutor(repository *retrievalpostgres.Repository, authority LegalHoldAuthority) (*LegalHoldCheckExecutor, error) {
	if repository == nil || authority == nil {
		return nil, errors.New("legal-hold repository and authority are required")
	}
	return &LegalHoldCheckExecutor{repository: repository, holdAuthority: authority}, nil
}

func (e *LegalHoldCheckExecutor) Execute(ctx context.Context, job retrievalpostgres.ErasureJob, tenant, visibility string) (retrievalpostgres.ErasureActionExecution, error) {
	if ctx == nil || e == nil || e.repository == nil || e.holdAuthority == nil || job.ID == uuid.Nil ||
		job.State != "cleanup_pending" || !job.LeaseOwner.Valid || job.LeaseEpoch < 1 {
		return retrievalpostgres.ErasureActionExecution{}, errors.New("legal-hold check requires the current claimed erasure job")
	}
	tenantID, err := tenancy.ParseTenantID(tenant)
	if err != nil {
		return retrievalpostgres.ErasureActionExecution{}, errors.New("legal-hold check tenant is invalid")
	}
	visibility, err = index.ParseVisibilityKey(visibility)
	if err != nil {
		return retrievalpostgres.ErasureActionExecution{}, errors.New("legal-hold check visibility is invalid")
	}
	current, err := e.repository.ErasureJob(ctx, tenantID, visibility, job.ID)
	if err != nil || current.State != "cleanup_pending" || !current.LeaseOwner.Valid ||
		current.LeaseOwner.String != job.LeaseOwner.String || current.LeaseEpoch != job.LeaseEpoch ||
		!current.LeaseUntil.Valid || current.DocumentVersionID != job.DocumentVersionID ||
		current.EligibilityGeneration != job.EligibilityGeneration {
		return retrievalpostgres.ErasureActionExecution{}, retrievalpostgres.ErrErasureLeaseLost
	}
	fence := ErasureFence{Tenant: tenantID, Visibility: visibility, WorkerID: current.LeaseOwner.String,
		JobID: current.ID, DocumentVersionID: current.DocumentVersionID,
		EligibilityGeneration: current.EligibilityGeneration, LeaseEpoch: current.LeaseEpoch}
	clearance, err := e.holdAuthority.AcquireClearance(ctx, fence)
	if err != nil {
		return retrievalpostgres.ErasureActionExecution{}, legalHoldBlockError(err)
	}
	if clearance.Release == nil || clearance.DecisionActorID == uuid.Nil || clearance.EvidenceSHA256 == ([32]byte{}) {
		if clearance.Release != nil {
			_ = clearance.Release()
		}
		return retrievalpostgres.ErasureActionExecution{}, legalHoldBlockError(errors.New("incomplete hold decision"))
	}
	if err := clearance.Release(); err != nil {
		return retrievalpostgres.ErasureActionExecution{}, legalHoldBlockError(err)
	}
	return retrievalpostgres.ErasureActionExecution{Disposition: retrievalpostgres.ErasureReceiptComplete,
		ActorID: clearance.DecisionActorID, ReceiptSHA256: clearance.EvidenceSHA256}, nil
}

// Any unsuccessful clearance is unknown unless the provider explicitly
// identifies an active hold. The error text is never persisted or returned.
func legalHoldBlockError(cause error) error {
	code := legalHoldBlockUnknown
	var decision *LegalHoldDecisionError
	if errors.As(cause, &decision) && decision != nil && decision.Decision == LegalHoldActive {
		code = legalHoldBlockActive
	}
	blocked, err := retrievalpostgres.NewErasureActionBlockError(code)
	if err != nil {
		return fmt.Errorf("create legal-hold block outcome: %w", err)
	}
	return blocked
}
