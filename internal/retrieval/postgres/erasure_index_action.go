package postgres

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

// ClaimedDerivedIndexEraser performs one bounded cleanup pass for a currently
// leased job. A pass that is not ready for a receipt must return an error so
// ProcessOne retries the job without marking the action complete.
type ClaimedDerivedIndexEraser interface {
	CleanupClaimed(context.Context, tenancy.TenantID, string, string, uuid.UUID, int64) error
}

// DerivedIndexCleanupExecutor adapts a fenced index eraser to the manifest
// processor. The eraser owns hold-permit and receipt ordering around deletion.
type DerivedIndexCleanupExecutor struct {
	eraser ClaimedDerivedIndexEraser
}

func NewDerivedIndexCleanupExecutor(eraser ClaimedDerivedIndexEraser) (*DerivedIndexCleanupExecutor, error) {
	if eraser == nil {
		return nil, errors.New("claimed derived-index eraser is required")
	}
	return &DerivedIndexCleanupExecutor{eraser: eraser}, nil
}

func (e *DerivedIndexCleanupExecutor) Execute(ctx context.Context, job ErasureJob, tenant, visibility string) (ErasureActionExecution, error) {
	if ctx == nil || e == nil || e.eraser == nil || job.ID == uuid.Nil || job.LeaseEpoch < 1 ||
		job.State != "cleanup_pending" || !job.LeaseOwner.Valid || !erasureWorkerIDPattern.MatchString(job.LeaseOwner.String) {
		return ErasureActionExecution{}, errors.New("derived-index action requires a claimed erasure job")
	}
	tenantID, err := tenancy.ParseTenantID(tenant)
	if err != nil {
		return ErasureActionExecution{}, errors.New("derived-index action tenant is invalid")
	}
	if err := e.eraser.CleanupClaimed(ctx, tenantID, visibility, job.LeaseOwner.String, job.ID, job.LeaseEpoch); err != nil {
		return ErasureActionExecution{}, err
	}
	return ErasureActionExecution{}, nil
}
