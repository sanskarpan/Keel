package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

// ClaimedDerivedIndexEraser performs one bounded cleanup pass for a currently
// leased job. A pass that needs more work returns progress without a receipt;
// ProcessOne yields the lease and continues from the durable database cursor.
type ClaimedDerivedIndexEraser interface {
	CleanupClaimed(context.Context, tenancy.TenantID, string, string, uuid.UUID, int64) (bool, time.Duration, error)
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
	progress, delay, err := e.eraser.CleanupClaimed(ctx, tenantID, visibility, job.LeaseOwner.String, job.ID, job.LeaseEpoch)
	if err != nil {
		return ErasureActionExecution{}, err
	}
	if progress {
		return ErasureActionExecution{Progress: true, ProgressDelay: delay}, nil
	}
	return ErasureActionExecution{}, nil
}
