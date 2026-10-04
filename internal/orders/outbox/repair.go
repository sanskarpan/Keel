package outbox

import (
	"context"
	"errors"
	"regexp"

	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

var (
	ErrRepairUnauthorized = errors.New("outbox repair is not authorized")
	ErrRepairNotFound     = errors.New("blocked outbox event not found")
	ErrRepairStale        = errors.New("blocked outbox repair request is stale")
	ErrRepairInvalid      = errors.New("outbox repair request is invalid")
	repairActorPattern    = regexp.MustCompile(`^(principal|service-principal):[A-Za-z0-9._~-]{1,120}$`)
	repairUUIDPattern     = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	repairEvidencePattern = regexp.MustCompile(`^(INC|CHG|OPS)-[A-Z0-9]{4,20}$`)
)

type repairIdentityKey struct{}

// RepairIdentity is installed only by trusted authentication/authorization middleware.
// A request body, query parameter, tenant header, or CLI flag must never construct it.
type RepairIdentity struct {
	TenantID  tenancy.TenantID
	ActorRef  string
	RequestID string
}

func WithRepairIdentity(ctx context.Context, identity RepairIdentity) context.Context {
	return context.WithValue(ctx, repairIdentityKey{}, identity)
}

type BlockedEvent struct {
	TenantID     string
	AggregateID  string
	EventID      string
	Version      int64
	ErrorCode    string
	AttemptCount int
}

type RepairRequest struct {
	EventID              string
	ExpectedVersion      int64
	ExpectedErrorCode    string
	ExpectedAttemptCount int
	ReasonCode           string
	EvidenceRef          string
}

type RepairStore interface {
	ListBlocked(context.Context, tenancy.TenantID, string) ([]BlockedEvent, error)
	RepairBlocked(context.Context, tenancy.TenantID, string, RepairIdentity, RepairRequest) error
}

type RepairAuthorizer interface {
	CanInspectOutbox(context.Context, RepairIdentity, string) (bool, error)
	CanRepairOutbox(context.Context, RepairIdentity, string, string) (bool, error)
}

// RepairService binds every operation to a trusted identity and requires an explicit
// authorization decision. The store separately uses a least-privilege operator DB role.
type RepairService struct {
	store      RepairStore
	authorizer RepairAuthorizer
}

func NewRepairService(store RepairStore, authorizer RepairAuthorizer) (*RepairService, error) {
	if store == nil || authorizer == nil {
		return nil, errors.New("outbox repair store and authorizer are required")
	}
	return &RepairService{store: store, authorizer: authorizer}, nil
}

func (s *RepairService) ListBlocked(ctx context.Context, aggregateID string) ([]BlockedEvent, error) {
	identity, err := repairIdentity(ctx)
	if err != nil {
		return nil, err
	}
	if !repairUUIDPattern.MatchString(aggregateID) {
		return nil, ErrRepairInvalid
	}
	allowed, err := s.authorizer.CanInspectOutbox(ctx, identity, aggregateID)
	if err != nil {
		return nil, err
	}
	if !allowed {
		return nil, ErrRepairUnauthorized
	}
	return s.store.ListBlocked(ctx, identity.TenantID, aggregateID)
}

func (s *RepairService) RepairBlocked(ctx context.Context, aggregateID string, request RepairRequest) error {
	identity, err := repairIdentity(ctx)
	if err != nil {
		return err
	}
	if !repairUUIDPattern.MatchString(aggregateID) || !repairUUIDPattern.MatchString(request.EventID) ||
		request.ExpectedVersion < 1 || request.ExpectedAttemptCount < 0 || request.ExpectedErrorCode != "outbox_corrupt" ||
		!validRepairReason(request.ReasonCode) || !repairEvidencePattern.MatchString(request.EvidenceRef) {
		return ErrRepairInvalid
	}
	allowed, err := s.authorizer.CanRepairOutbox(ctx, identity, aggregateID, request.EventID)
	if err != nil {
		return err
	}
	if !allowed {
		return ErrRepairUnauthorized
	}
	return s.store.RepairBlocked(ctx, identity.TenantID, aggregateID, identity, request)
}

func repairIdentity(ctx context.Context) (RepairIdentity, error) {
	if ctx == nil {
		return RepairIdentity{}, ErrRepairUnauthorized
	}
	identity, ok := ctx.Value(repairIdentityKey{}).(RepairIdentity)
	_, tenantErr := tenancy.ParseTenantID(string(identity.TenantID))
	if !ok || tenantErr != nil || !repairActorPattern.MatchString(identity.ActorRef) || !repairUUIDPattern.MatchString(identity.RequestID) {
		return RepairIdentity{}, ErrRepairUnauthorized
	}
	return identity, nil
}

func validRepairReason(code string) bool {
	switch code {
	case "serializer_compatibility_fix", "verified_storage_recovery", "other_approved_change":
		return true
	default:
		return false
	}
}
