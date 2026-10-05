package cases

import (
	"errors"
	"strings"
	"testing"
	"time"
)

var (
	tenantID   = "11111111-1111-4111-8111-111111111111"
	caseID     = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	supplierID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	policyID   = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	uploadID   = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
)

func validPolicy() Policy {
	return Policy{TenantID: tenantID, PolicyID: policyID, Version: 1, Name: "Standard supplier review", Deadline: 48 * time.Hour,
		RequiredEvidence: []string{"insurance", "tax"},
		Steps:            []ReviewStep{{Key: "risk", Role: "risk:reviewer"}, {Key: "procurement", Role: "procurement:reviewer", DependsOn: []string{"risk"}}},
		PublishedAt:      time.Date(2026, 10, 4, 10, 0, 0, 0, time.UTC)}
}

func TestPolicyCanonicalDigestIsStableAndRejectsCycles(t *testing.T) {
	a := validPolicy()
	b := validPolicy()
	b.RequiredEvidence = []string{"tax", "insurance"}
	b.Steps[0], b.Steps[1] = b.Steps[1], b.Steps[0]
	canonicalA, _, err := a.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	canonicalB, _, err := b.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if b.RequiredEvidence[0] != "tax" || b.RequiredEvidence[1] != "insurance" || b.Steps[0].Key != "procurement" || b.Steps[1].Key != "risk" {
		t.Fatal("canonicalization mutated the caller's policy slices")
	}
	if canonicalA.Digest != canonicalB.Digest {
		t.Fatal("equivalent policies must have the same digest")
	}

	cyclic := validPolicy()
	cyclic.Steps[0].DependsOn = []string{"procurement"}
	if _, _, err := cyclic.Canonical(); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("cycle error = %v", err)
	}
}

func TestCaseEvidenceRevisionAndSubmissionBindFrozenVersions(t *testing.T) {
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	policy, _, err := validPolicy().Canonical()
	if err != nil {
		t.Fatal(err)
	}
	current, created, err := NewCase(tenantID, caseID, supplierID, "principal:buyer-1", policy, now)
	if err != nil {
		t.Fatal(err)
	}
	if !created.Verify() || current.LastEventHash != created.Hash || current.DeadlineAt.Sub(now) != 48*time.Hour {
		t.Fatal("case creation failed to freeze policy, deadline, or history")
	}

	first := Evidence{EvidenceID: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", Slot: "tax", Kind: "tax", UploadID: uploadID, Version: 1, MediaType: "application/pdf", Bytes: 17, SHA256: strings.Repeat("a", 64)}
	current, event1, err := AddEvidence(current, nil, first, "principal:buyer-1", now.Add(time.Hour), created.Hash)
	if err != nil {
		t.Fatal(err)
	}
	if !event1.Verify() || current.Version != 2 || current.EvidenceEpoch != 1 {
		t.Fatal("first evidence revision not recorded")
	}

	second := Evidence{EvidenceID: "ffffffff-ffff-4fff-8fff-ffffffffffff", Slot: "insurance", Kind: "insurance", UploadID: "99999999-9999-4999-8999-999999999999", Version: 1, MediaType: "text/plain", Bytes: 23, SHA256: strings.Repeat("b", 64)}
	current, event2, err := AddEvidence(current, []Evidence{first}, second, "principal:buyer-1", now.Add(2*time.Hour), event1.Hash)
	if err != nil {
		t.Fatal(err)
	}
	if !event2.Verify() || event2.PrevHash != event1.Hash || current.EvidenceEpoch != 2 {
		t.Fatal("evidence event hash chain is invalid")
	}

	updated, submitted, err := Submit(current, []Evidence{first, second}, policy, "principal:risk-1", now.Add(3*time.Hour), event2.Hash)
	if err != nil {
		t.Fatal(err)
	}
	if !submitted.Verify() || updated.Status != Submitted || submitted.PrevHash != event2.Hash {
		t.Fatal("submission did not freeze evidence and policy")
	}
	if _, _, err := Submit(updated, []Evidence{first, second}, policy, "principal:risk-2", now.Add(4*time.Hour), submitted.Hash); !errors.Is(err, ErrConflict) {
		t.Fatalf("repeat submit error = %v", err)
	}
	if _, _, err := AddEvidence(updated, []Evidence{first, second}, second, "principal:buyer-1", now.Add(4*time.Hour), submitted.Hash); !errors.Is(err, ErrConflict) {
		t.Fatalf("post-submit evidence error = %v", err)
	}
}

func TestSubmitRequiresAllEvidenceAndHonorsDeadline(t *testing.T) {
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	policy, _, _ := validPolicy().Canonical()
	current, created, err := NewCase(tenantID, caseID, supplierID, "principal:buyer-1", policy, now)
	if err != nil {
		t.Fatal(err)
	}
	item := Evidence{EvidenceID: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", Slot: "tax", Kind: "tax", UploadID: uploadID, Version: 1, MediaType: "application/pdf", Bytes: 17, SHA256: strings.Repeat("a", 64)}
	current, evidenceEvent, err := AddEvidence(current, nil, item, "principal:buyer-1", now.Add(time.Hour), created.Hash)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Submit(current, []Evidence{item}, policy, "principal:risk-1", now.Add(2*time.Hour), evidenceEvent.Hash); !errors.Is(err, ErrEvidence) {
		t.Fatalf("missing evidence error = %v", err)
	}
	if _, _, err := Submit(current, []Evidence{item}, policy, "principal:risk-1", current.DeadlineAt, evidenceEvent.Hash); !errors.Is(err, ErrConflict) {
		t.Fatalf("deadline error = %v", err)
	}
	wrong := policy
	wrong.Deadline -= time.Hour
	wrong, _, err = wrong.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Submit(current, []Evidence{item}, wrong, "principal:risk-1", now.Add(2*time.Hour), evidenceEvent.Hash); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("policy drift error = %v", err)
	}
}

func TestDecisionsEnforceSeparationDependenciesAndFrozenBoundary(t *testing.T) {
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	policy, _, err := validPolicy().Canonical()
	if err != nil {
		t.Fatal(err)
	}
	current := Case{TenantID: tenantID, CaseID: caseID, PolicyID: policyID, PolicyVersion: 1, PolicyDigest: policy.Digest,
		EvidenceDigest: strings.Repeat("a", 64), Status: Submitted, Version: 3, DeadlineAt: now.Add(time.Hour), LastEventHash: strings.Repeat("b", 64)}
	first := StepDecision{DecisionID: "11111111-1111-4111-8111-111111111111", StepKey: "risk", Actor: "principal:approver-1", Outcome: "approve", Role: "risk:reviewer"}
	creatorDecision := first
	creatorDecision.Actor = "principal:buyer-1"
	if _, _, err := Decide(current, policy, nil, creatorDecision, "principal:requester-1", "principal:buyer-1", now, current.LastEventHash); !errors.Is(err, ErrConflict) {
		t.Fatalf("creator was allowed to approve: %v", err)
	}
	submitterDecision := first
	submitterDecision.Actor = "principal:requester-1"
	if _, _, err := Decide(current, policy, nil, submitterDecision, "principal:requester-1", "principal:creator-1", now, current.LastEventHash); !errors.Is(err, ErrConflict) {
		t.Fatalf("submitter was allowed to approve: %v", err)
	}
	updated, event, err := Decide(current, policy, nil, first, "principal:requester-1", "principal:creator-1", now, current.LastEventHash)
	if err != nil || updated.Status != Submitted || event.Type != "supplier.case.approval-decided" {
		t.Fatalf("first approval result: %+v event=%+v err=%v", updated, event, err)
	}
	if eligible := EligibleSteps(policy, []StepDecision{first}); len(eligible) != 1 || eligible[0].Key != "procurement" {
		t.Fatalf("dependency did not unlock next step: %+v", eligible)
	}
	partialExpired, _, err := Expire(updated, current.DeadlineAt, updated.LastEventHash)
	if err != nil || partialExpired.Status != Expired {
		t.Fatalf("partial approval plan defeated expiry: %+v err=%v", partialExpired, err)
	}
	second := StepDecision{DecisionID: "22222222-2222-4222-8222-222222222222", StepKey: "procurement", Actor: "principal:approver-2", Outcome: "approve", Role: "procurement:reviewer"}
	final, _, err := Decide(updated, policy, []StepDecision{first}, second, "principal:requester-1", "principal:creator-1", now.Add(time.Minute), updated.LastEventHash)
	if err != nil || final.Status != Approved {
		t.Fatalf("complete plan did not approve: %+v err=%v", final, err)
	}
	if _, _, err := Decide(partialExpired, policy, []StepDecision{first}, second, "principal:requester-1", "principal:creator-1", current.DeadlineAt.Add(time.Minute), partialExpired.LastEventHash); !errors.Is(err, ErrConflict) {
		t.Fatalf("decision was accepted after expiry won: %v", err)
	}
	if _, _, err := Decide(current, policy, nil, first, "principal:requester-1", "principal:creator-1", current.DeadlineAt, current.LastEventHash); !errors.Is(err, ErrConflict) {
		t.Fatalf("decision at deadline accepted: %v", err)
	}
	collecting := current
	collecting.Status = Collecting
	if _, _, err := Expire(collecting, now, collecting.LastEventHash); !errors.Is(err, ErrConflict) {
		t.Fatalf("collecting case expired before its deadline: %v", err)
	}
	expiredCollecting, _, err := Expire(collecting, current.DeadlineAt, collecting.LastEventHash)
	if err != nil || expiredCollecting.Status != Expired {
		t.Fatalf("unsubmitted case did not expire at its deadline: %+v err=%v", expiredCollecting, err)
	}
	if _, _, err := Expire(current, current.DeadlineAt, strings.Repeat("a", 64)); err == nil {
		t.Fatal("expiry accepted a different event hash")
	}
	expired, expiryEvent, err := Expire(current, current.DeadlineAt, current.LastEventHash)
	if err != nil || expired.Status != Expired || expiryEvent.Actor != "service-principal:keel-supplier-case-expirer" {
		t.Fatalf("deadline expiry failed: %+v event=%+v err=%v", expired, expiryEvent, err)
	}
	if _, _, err := Decide(expired, policy, nil, first, "principal:requester-1", "principal:creator-1", current.DeadlineAt.Add(time.Minute), expired.LastEventHash); !errors.Is(err, ErrConflict) {
		t.Fatalf("decision was accepted after expiry won: %v", err)
	}
}

func TestAddEvidenceRejectsGapAndHistoryTampering(t *testing.T) {
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	policy, _, _ := validPolicy().Canonical()
	current, created, err := NewCase(tenantID, caseID, supplierID, "principal:buyer-1", policy, now)
	if err != nil {
		t.Fatal(err)
	}
	item := Evidence{EvidenceID: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", Slot: "tax", Kind: "tax", UploadID: uploadID, Version: 2, MediaType: "application/pdf", Bytes: 17, SHA256: strings.Repeat("a", 64)}
	if _, _, err := AddEvidence(current, nil, item, "principal:buyer-1", now.Add(time.Hour), created.Hash); !errors.Is(err, ErrEvidence) {
		t.Fatalf("version gap error = %v", err)
	}
	changed := created
	changed.Actor = "principal:attacker"
	if changed.Verify() {
		t.Fatal("tampered event passed hash verification")
	}
}

func TestEvidenceHistoryHasAggregateCountAndByteBudgets(t *testing.T) {
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	policy, _, _ := validPolicy().Canonical()
	current, created, err := NewCase(tenantID, caseID, supplierID, "principal:buyer-1", policy, now)
	if err != nil {
		t.Fatal(err)
	}
	item := Evidence{EvidenceID: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", Slot: "new-slot", Kind: "tax", UploadID: uploadID, Version: 1, MediaType: "text/plain", Bytes: 1, SHA256: strings.Repeat("a", 64)}
	tooMany := make([]Evidence, MaxEvidence)
	for i := range tooMany {
		tooMany[i] = Evidence{Slot: "slot"}
	}
	if _, _, err := AddEvidence(current, tooMany, item, "principal:buyer-1", now.Add(time.Hour), created.Hash); !errors.Is(err, ErrEvidence) {
		t.Fatalf("evidence-count budget error=%v", err)
	}
	tooLarge := []Evidence{{Bytes: MaxEvidenceBytes}}
	if _, _, err := AddEvidence(current, tooLarge, item, "principal:buyer-1", now.Add(time.Hour), created.Hash); !errors.Is(err, ErrEvidence) {
		t.Fatalf("evidence-byte budget error=%v", err)
	}
}
