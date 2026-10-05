package caseworkflow

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

const testCaseID = "11111111-1111-4111-8111-111111111111"
const testTenantID = "22222222-2222-4222-8222-222222222222"

func signal(version uint64, kind, intent, hash string) EventSignal {
	return EventSignal{CaseID: testCaseID, IntentID: intent, Version: version, EventType: kind, EventHash: hash}
}

func TestWorkflowIDIsDeterministicAndValidatesCaseID(t *testing.T) {
	tenant, _ := tenancy.ParseTenantID(testTenantID)
	want, err := WorkflowID(tenant, testCaseID)
	if err != nil || len(want) != len("keel.supplier-case.v1.")+64 {
		t.Fatalf("opaque workflow ID invalid: (%q,%v)", want, err)
	}
	for range 2 {
		got, err := WorkflowID(tenant, testCaseID)
		if err != nil || got != want {
			t.Fatalf("WorkflowID()=(%q,%v), want (%q,nil)", got, err, want)
		}
	}
	if _, err := WorkflowID(tenant, "not-a-uuid"); !errors.Is(err, ErrInvalidSignal) {
		t.Fatalf("invalid case ID accepted: %v", err)
	}
}

func TestPersistedTemporalV1NamesRemainStable(t *testing.T) {
	if WorkflowName != "SupplierCaseWorkflowV1" || TaskQueue != "keel-supplier-case-v1" ||
		SignalName != "supplier-case-event-v1" || StateQuery != "supplier-case-state-v1" {
		t.Fatalf("persisted Temporal contract changed without a rollout: workflow=%q queue=%q signal=%q query=%q", WorkflowName, TaskQueue, SignalName, StateQuery)
	}
	tenant, _ := tenancy.ParseTenantID(testTenantID)
	id, err := WorkflowID(tenant, testCaseID)
	if err != nil || !strings.HasPrefix(id, "keel.supplier-case.v1.") {
		t.Fatalf("persisted workflow ID version changed: id=%q err=%v", id, err)
	}
}

func TestApplyAcceptsExactRetriesAndRejectsConflictsAndGaps(t *testing.T) {
	created := signal(1, "supplier.case.created", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", strings.Repeat("a", 64))
	state, err := Apply(State{CaseID: testCaseID}, created)
	if err != nil || state.LastVersion != 1 {
		t.Fatalf("apply create: state=%+v err=%v", state, err)
	}
	retry, err := Apply(state, created)
	if err != nil || retry.LastVersion != 1 || len(retry.Events) != 1 {
		t.Fatalf("exact retry changed state: state=%+v err=%v", retry, err)
	}
	conflict := created
	conflict.EventHash = strings.Repeat("b", 64)
	if _, err := Apply(state, conflict); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflicting duplicate accepted: %v", err)
	}
	reusedIntent := signal(2, "supplier.case.evidence-added", created.IntentID, strings.Repeat("d", 64))
	if _, err := Apply(state, reusedIntent); !errors.Is(err, ErrConflict) {
		t.Fatalf("one intent ID reused at a different version: %v", err)
	}
	gap := signal(3, "supplier.case.evidence-added", "cccccccc-cccc-4ccc-8ccc-cccccccccccc", strings.Repeat("c", 64))
	if _, err := Apply(state, gap); !errors.Is(err, ErrVersionGap) {
		t.Fatalf("sequence gap accepted: %v", err)
	}
}

func TestApplyRejectsMalformedOrCrossCaseSignals(t *testing.T) {
	valid := signal(1, "supplier.case.created", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", strings.Repeat("a", 64))
	bad := valid
	bad.EventType = "supplier.case.approved"
	if _, err := Apply(State{CaseID: testCaseID}, bad); !errors.Is(err, ErrInvalidSignal) {
		t.Fatalf("unknown event type accepted: %v", err)
	}
	bad = valid
	bad.EventHash = "short"
	if _, err := Apply(State{CaseID: testCaseID}, bad); !errors.Is(err, ErrInvalidSignal) {
		t.Fatalf("invalid event hash accepted: %v", err)
	}
	other := State{CaseID: "22222222-2222-4222-8222-222222222222"}
	if _, err := Apply(other, valid); !errors.Is(err, ErrCaseMismatch) {
		t.Fatalf("cross-case signal accepted: %v", err)
	}
}

func TestWorkflowEventEnvelopeCoversBoundedApprovalLifecycleAndRejectsBeyondIt(t *testing.T) {
	state := State{CaseID: testCaseID}
	for version := uint64(1); version <= MaxEvents; version++ {
		kind := "supplier.case.approval-decided"
		if version == 1 {
			kind = "supplier.case.created"
		} else if version <= 101 {
			kind = "supplier.case.evidence-added"
		} else if version == 102 {
			kind = "supplier.case.submitted"
		} else if version == MaxEvents {
			kind = "supplier.case.expired"
		}
		intent := fmt.Sprintf("aaaaaaaa-aaaa-4aaa-8aaa-%012x", version)
		var err error
		state, err = Apply(state, signal(version, kind, intent, strings.Repeat("a", 64)))
		if err != nil {
			t.Fatalf("version %d rejected within bounded lifecycle: %v", version, err)
		}
	}
	if state.LastVersion != MaxEvents || len(state.Events) != MaxEvents {
		t.Fatalf("bounded state mismatch: last=%d events=%d", state.LastVersion, len(state.Events))
	}
	tooLarge := signal(MaxEvents+1, "supplier.case.approval-decided", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", strings.Repeat("b", 64))
	if _, err := Apply(state, tooLarge); !errors.Is(err, ErrInvalidSignal) {
		t.Fatalf("event beyond explicit lifecycle bound accepted: %v", err)
	}
}
