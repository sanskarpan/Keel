package outbox

import (
	"context"
	"errors"
	"testing"

	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

const (
	repairTestTenant = "11111111-1111-4111-8111-111111111111"
	repairTestOrder  = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	repairTestEvent  = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	repairTestReq    = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
)

type fakeRepairStore struct {
	listedTenant tenancy.TenantID
	repaired     bool
	request      RepairRequest
}

func (s *fakeRepairStore) ListBlocked(_ context.Context, tenant tenancy.TenantID, _ string) ([]BlockedEvent, error) {
	s.listedTenant = tenant
	return []BlockedEvent{}, nil
}

func (s *fakeRepairStore) RepairBlocked(_ context.Context, tenant tenancy.TenantID, _ string, _ RepairIdentity, request RepairRequest) error {
	s.listedTenant, s.repaired, s.request = tenant, true, request
	return nil
}

type fakeRepairAuthorizer struct {
	inspectAllowed bool
	repairAllowed  bool
}

func (a fakeRepairAuthorizer) CanInspectOutbox(context.Context, RepairIdentity, string) (bool, error) {
	return a.inspectAllowed, nil
}

func (a fakeRepairAuthorizer) CanRepairOutbox(context.Context, RepairIdentity, string, string) (bool, error) {
	return a.repairAllowed, nil
}

func TestRepairServiceRequiresTrustedIdentityAndAuthorization(t *testing.T) {
	store := &fakeRepairStore{}
	service, err := NewRepairService(store, fakeRepairAuthorizer{inspectAllowed: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.ListBlocked(context.Background(), repairTestOrder); !errors.Is(err, ErrRepairUnauthorized) {
		t.Fatalf("missing trusted identity error=%v", err)
	}
	ctx := repairContext(repairTestTenant)
	if err := service.RepairBlocked(ctx, repairTestOrder, validRepairRequest()); !errors.Is(err, ErrRepairUnauthorized) {
		t.Fatalf("unauthorized repair error=%v", err)
	}
	if store.repaired {
		t.Fatal("store was called before authorization succeeded")
	}
}

func TestRepairServiceBindsTenantAndValidatesEvidence(t *testing.T) {
	store := &fakeRepairStore{}
	service, err := NewRepairService(store, fakeRepairAuthorizer{inspectAllowed: true, repairAllowed: true})
	if err != nil {
		t.Fatal(err)
	}
	ctx := repairContext(repairTestTenant)
	if _, err := service.ListBlocked(ctx, repairTestOrder); err != nil {
		t.Fatal(err)
	}
	if store.listedTenant != tenancy.TenantID(repairTestTenant) {
		t.Fatalf("diagnostics tenant=%q", store.listedTenant)
	}
	request := validRepairRequest()
	request.EvidenceRef = "free-form payload"
	if err := service.RepairBlocked(ctx, repairTestOrder, request); !errors.Is(err, ErrRepairInvalid) {
		t.Fatalf("invalid evidence ref error=%v", err)
	}
	if store.repaired {
		t.Fatal("invalid evidence ref reached store")
	}
	request = validRepairRequest()
	if err := service.RepairBlocked(ctx, repairTestOrder, request); err != nil {
		t.Fatal(err)
	}
	if !store.repaired || store.listedTenant != tenancy.TenantID(repairTestTenant) || store.request != request {
		t.Fatalf("repair tenant=%q request=%+v repaired=%t", store.listedTenant, store.request, store.repaired)
	}
}

func repairContext(tenant string) context.Context {
	id, _ := tenancy.ParseTenantID(tenant)
	return WithRepairIdentity(context.Background(), RepairIdentity{
		TenantID: id, ActorRef: "principal:operator-1", RequestID: repairTestReq,
	})
}

func validRepairRequest() RepairRequest {
	return RepairRequest{
		EventID: repairTestEvent, ExpectedVersion: 1, ExpectedErrorCode: "outbox_corrupt",
		ExpectedAttemptCount: 3, ReasonCode: "serializer_compatibility_fix", EvidenceRef: "CHG-2026ABC",
	}
}
