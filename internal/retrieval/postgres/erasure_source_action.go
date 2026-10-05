package postgres

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

// ClaimedSupplierSourceEraser is implemented by an object-store eraser that
// resolves its source from a live job and writes the immutable action receipt
// only after deletion succeeds.
type ClaimedSupplierSourceEraser interface {
	EraseClaimed(context.Context, tenancy.TenantID, string, string, uuid.UUID, int64) error
}

// SupplierSourceObjectsExecutor adapts the concrete supplier source eraser to
// the manifest processor. The eraser writes its own receipt while it holds the
// legal-hold permit; ProcessOne observes that receipt after execution and does
// not attempt a second insert.
type SupplierSourceObjectsExecutor struct {
	eraser ClaimedSupplierSourceEraser
}

func NewSupplierSourceObjectsExecutor(eraser ClaimedSupplierSourceEraser) (*SupplierSourceObjectsExecutor, error) {
	if eraser == nil {
		return nil, errors.New("claimed supplier source eraser is required")
	}
	return &SupplierSourceObjectsExecutor{eraser: eraser}, nil
}

func (e *SupplierSourceObjectsExecutor) Execute(ctx context.Context, job ErasureJob, tenant, visibility string) (ErasureActionExecution, error) {
	if ctx == nil || e == nil || e.eraser == nil || job.ID == uuid.Nil || job.LeaseEpoch < 1 ||
		job.State != "cleanup_pending" || !job.LeaseOwner.Valid || !erasureWorkerIDPattern.MatchString(job.LeaseOwner.String) {
		return ErasureActionExecution{}, errors.New("supplier source action requires a claimed erasure job")
	}
	tenantID, err := tenancy.ParseTenantID(tenant)
	if err != nil {
		return ErasureActionExecution{}, errors.New("supplier source action tenant is invalid")
	}
	if err := e.eraser.EraseClaimed(ctx, tenantID, visibility, job.LeaseOwner.String, job.ID, job.LeaseEpoch); err != nil {
		return ErasureActionExecution{}, err
	}
	return ErasureActionExecution{}, nil
}
