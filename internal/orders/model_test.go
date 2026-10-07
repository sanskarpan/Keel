package orders

import (
	"errors"
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"
)

func testUUID(n int) string { return fmt.Sprintf("00000000-0000-4000-8000-%012x", n) }

func testMetadata(n int, actor string) EventMetadata {
	return EventMetadata{
		EventID: testUUID(n), TenantID: testUUID(100), OrderID: testUUID(200),
		OccurredAt: time.Date(2026, 10, 4, 12, 0, n%60, 0, time.FixedZone("test", 3600)),
		ActorRef:   actor, CausationID: testUUID(300 + n), CorrelationID: testUUID(400),
	}
}

func sampleOrder() CreateOrder {
	return CreateOrder{
		ExternalReference: "ERP-PO-18", SupplierID: testUUID(500), Currency: "INR", AmountMinor: 250000,
		LineItems: []LineItem{{Description: "Office equipment", Quantity: "2"}, {Description: "Adapters", Quantity: "0.250001"}},
	}
}

func sampleEvidence() []EvidenceRef {
	return []EvidenceRef{{DocumentID: testUUID(700), Version: 3}, {DocumentID: testUUID(600), Version: 2}}
}

func TestOrderLifecycleReplaysToTheCommandSnapshot(t *testing.T) {
	input := sampleOrder()
	input.LineItems[0].Quantity = "2.000000"
	snapshot, created, err := Create(testMetadata(1, "principal:requester"), input)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Status != Draft || snapshot.Version != 1 {
		t.Fatalf("created snapshot = %s/%d", snapshot.Status, snapshot.Version)
	}
	if snapshot.LineItems[0].Quantity != "2" {
		t.Fatalf("quantity was not normalized exactly: %q", snapshot.LineItems[0].Quantity)
	}
	input.LineItems[0].Description = "mutated caller buffer"
	if snapshot.LineItems[0].Description != "Office equipment" {
		t.Fatal("snapshot aliases command line items")
	}

	var events = []Event{created}
	snapshot, submitted, err := Submit(snapshot, 1, SubmitOrder{Evidence: sampleEvidence()}, testMetadata(2, "principal:requester"))
	if err != nil {
		t.Fatal(err)
	}
	events = append(events, submitted)
	if snapshot.Status != Submitted || snapshot.Version != 2 || snapshot.EvidenceDigest == "" {
		t.Fatalf("submitted snapshot = %#v", snapshot)
	}

	snapshot, started, err := StartVerification(snapshot, 2, testMetadata(3, "service-principal:order-verifier"))
	if err != nil {
		t.Fatal(err)
	}
	events = append(events, started)
	decision := Decision{Outcome: DecisionApprove, DecisionID: testUUID(800), EvidenceDigest: snapshot.EvidenceDigest, PolicyVersion: 4}
	snapshot, approved, err := Decide(snapshot, 3, decision, testMetadata(4, "principal:finance-approver"))
	if err != nil {
		t.Fatal(err)
	}
	events = append(events, approved)
	if snapshot.Status != Approved || snapshot.Version != 4 {
		t.Fatalf("approved snapshot = %s/%d", snapshot.Status, snapshot.Version)
	}

	replayed, err := Replay(events)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(replayed, snapshot) {
		t.Fatalf("replay differs from command snapshot:\n got %#v\nwant %#v", replayed, snapshot)
	}
	if err := VerifySnapshot(snapshot, events); err != nil {
		t.Fatalf("valid snapshot rejected: %v", err)
	}
	snapshot.AmountMinor++
	if !errors.Is(VerifySnapshot(snapshot, events), ErrSnapshotMismatch) {
		t.Fatal("tampered command snapshot passed replay verification")
	}
}

func TestEventMetadataUsesStrictTraceparentValidation(t *testing.T) {
	valid := "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
	metadata := testMetadata(1, "principal:requester")
	metadata.Traceparent = valid
	if normalized, err := validateMetadata(metadata); err != nil || normalized.Traceparent != valid {
		t.Fatalf("valid traceparent metadata=%+v err=%v", normalized, err)
	}
	for _, invalid := range []string{
		"ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
		"00-00000000000000000000000000000000-00f067aa0ba902b7-01",
		"00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01",
		"00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01",
		"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-0g",
	} {
		metadata.Traceparent = invalid
		if _, err := validateMetadata(metadata); !errors.Is(err, ErrInvalidCommand) {
			t.Errorf("invalid traceparent %q was accepted: err=%v", invalid, err)
		}
	}
}

func TestOrderCancellationAndRejectedDecision(t *testing.T) {
	for _, cancelAt := range []Status{Draft, Submitted, Verifying} {
		t.Run(string(cancelAt), func(t *testing.T) {
			snapshot, created, err := Create(testMetadata(1, "principal:requester"), sampleOrder())
			if err != nil {
				t.Fatal(err)
			}
			events := []Event{created}
			if cancelAt != Draft {
				var event Event
				snapshot, event, err = Submit(snapshot, snapshot.Version, SubmitOrder{Evidence: sampleEvidence()}, testMetadata(2, "principal:requester"))
				if err != nil {
					t.Fatal(err)
				}
				events = append(events, event)
			}
			if cancelAt == Verifying {
				var event Event
				snapshot, event, err = StartVerification(snapshot, snapshot.Version, testMetadata(3, "service-principal:order-verifier"))
				if err != nil {
					t.Fatal(err)
				}
				events = append(events, event)
			}
			snapshot, event, err := Cancel(snapshot, snapshot.Version, "requester_withdrew", testMetadata(5, "principal:requester"))
			if err != nil {
				t.Fatal(err)
			}
			if err := validateSnapshotShape(snapshot); err != nil {
				t.Fatalf("valid canceled snapshot rejected: %v", err)
			}
			events = append(events, event)
			if snapshot.Status != Canceled || snapshot.TerminalReason != "requester_withdrew" {
				t.Fatalf("canceled snapshot = %#v", snapshot)
			}
			if _, err := Replay(events); err != nil {
				t.Fatalf("cancel history failed replay: %v", err)
			}
		})
	}

	snapshot, created, err := Create(testMetadata(11, "principal:requester"), sampleOrder())
	if err != nil {
		t.Fatal(err)
	}
	snapshot, submitted, err := Submit(snapshot, 1, SubmitOrder{Evidence: sampleEvidence()}, testMetadata(12, "principal:requester"))
	if err != nil {
		t.Fatal(err)
	}
	snapshot, started, err := StartVerification(snapshot, 2, testMetadata(13, "service-principal:order-verifier"))
	if err != nil {
		t.Fatal(err)
	}
	decision := Decision{Outcome: DecisionReject, DecisionID: testUUID(900), EvidenceDigest: snapshot.EvidenceDigest, PolicyVersion: 2, ReasonCode: "supplier_ineligible"}
	snapshot, rejected, err := Decide(snapshot, 3, decision, testMetadata(14, "principal:reviewer"))
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Status != Rejected || snapshot.Decision == nil || snapshot.Decision.ReasonCode != "supplier_ineligible" {
		t.Fatalf("rejected snapshot = %#v", snapshot)
	}
	if _, err := Replay([]Event{created, submitted, started, rejected}); err != nil {
		t.Fatalf("rejection history failed replay: %v", err)
	}
}

func TestOrderCommandVersionScopeAndSeparationOfDuties(t *testing.T) {
	snapshot, _, err := Create(testMetadata(1, "principal:requester"), sampleOrder())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Submit(snapshot, 0, SubmitOrder{Evidence: sampleEvidence()}, testMetadata(2, "principal:requester")); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("zero expected version error = %v", err)
	}
	if _, _, err := Submit(snapshot, 2, SubmitOrder{Evidence: sampleEvidence()}, testMetadata(2, "principal:requester")); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("stale expected version error = %v", err)
	}
	badScope := testMetadata(2, "principal:requester")
	badScope.TenantID = testUUID(101)
	if _, _, err := Submit(snapshot, 1, SubmitOrder{Evidence: sampleEvidence()}, badScope); !errors.Is(err, ErrInvalidCommand) {
		t.Fatalf("cross-tenant command error = %v", err)
	}

	snapshot, _, err = Submit(snapshot, 1, SubmitOrder{Evidence: sampleEvidence()}, testMetadata(3, "principal:requester"))
	if err != nil {
		t.Fatal(err)
	}
	snapshot, _, err = StartVerification(snapshot, 2, testMetadata(4, "service-principal:order-verifier"))
	if err != nil {
		t.Fatal(err)
	}
	decision := Decision{Outcome: DecisionApprove, DecisionID: testUUID(901), EvidenceDigest: snapshot.EvidenceDigest, PolicyVersion: 1}
	if _, _, err := Decide(snapshot, 3, decision, testMetadata(5, "principal:requester")); !errors.Is(err, ErrIllegalTransition) {
		t.Fatalf("self-approval error = %v", err)
	}
	decision.EvidenceDigest = "sha256:" + fmt.Sprintf("%064x", 1)
	if _, _, err := Decide(snapshot, 3, decision, testMetadata(6, "principal:other")); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("evidence mismatch error = %v", err)
	}
}

func TestIndependentReferenceTransitionTable(t *testing.T) {
	base, created, err := Create(testMetadata(1, "principal:requester"), sampleOrder())
	if err != nil {
		t.Fatal(err)
	}
	submitted, submitEvent, err := Submit(base, 1, SubmitOrder{Evidence: sampleEvidence()}, testMetadata(2, "principal:requester"))
	if err != nil {
		t.Fatal(err)
	}
	verifying, verifyEvent, err := StartVerification(submitted, 2, testMetadata(3, "service-principal:verifier"))
	if err != nil {
		t.Fatal(err)
	}
	approved, approveEvent, err := Decide(verifying, 3, Decision{Outcome: DecisionApprove, DecisionID: testUUID(910), EvidenceDigest: verifying.EvidenceDigest, PolicyVersion: 1}, testMetadata(4, "principal:approver"))
	if err != nil {
		t.Fatal(err)
	}
	rejected, rejectEvent, err := Decide(verifying, 3, Decision{Outcome: DecisionReject, DecisionID: testUUID(911), EvidenceDigest: verifying.EvidenceDigest, PolicyVersion: 1, ReasonCode: "policy_denied"}, testMetadata(5, "principal:approver"))
	if err != nil {
		t.Fatal(err)
	}
	canceled, cancelEvent, err := Cancel(base, 1, "requester_withdrew", testMetadata(6, "principal:requester"))
	if err != nil {
		t.Fatal(err)
	}

	snapshots := map[Status]Snapshot{Draft: base, Submitted: submitted, Verifying: verifying, Approved: approved, Rejected: rejected, Canceled: canceled}
	events := []Event{created, submitEvent, verifyEvent, approveEvent, rejectEvent, cancelEvent}
	allowed := map[Status]map[EventType]Status{
		Draft:     {OrderSubmitted: Submitted, OrderCanceled: Canceled},
		Submitted: {OrderVerificationStarted: Verifying, OrderCanceled: Canceled},
		Verifying: {OrderApproved: Approved, OrderRejected: Rejected, OrderCanceled: Canceled},
	}
	for state, current := range snapshots {
		for _, candidate := range events[1:] {
			candidate = cloneEvent(candidate)
			candidate.Metadata.TenantID, candidate.Metadata.OrderID = current.TenantID, current.OrderID
			candidate.Version = current.Version + 1
			want, ok := allowed[state][candidate.Type]
			got, err := ApplyEvent(current, candidate)
			if ok {
				if err != nil || got.Status != want {
					t.Errorf("%s + %s: status=%s err=%v, want %s", state, candidate.Type, got.Status, err, want)
				}
			} else if !errors.Is(err, ErrIllegalTransition) && !errors.Is(err, ErrInvalidEvent) {
				t.Errorf("%s + %s: err=%v, want illegal transition", state, candidate.Type, err)
			}
		}
	}
}

func TestReplayRejectsGapsDuplicatesCrossAggregateAndMalformedPayload(t *testing.T) {
	_, created, err := Create(testMetadata(1, "principal:requester"), sampleOrder())
	if err != nil {
		t.Fatal(err)
	}
	snapshot, submitted, err := Submit(mustCreate(t), 1, SubmitOrder{Evidence: sampleEvidence()}, testMetadata(2, "principal:requester"))
	if err != nil {
		t.Fatal(err)
	}
	_ = snapshot

	gap := cloneEvent(submitted)
	gap.Version = 3
	if _, err := Replay([]Event{created, gap}); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("version gap error = %v", err)
	}
	if _, err := Replay([]Event{created, created}); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("duplicate event error = %v", err)
	}
	cross := cloneEvent(submitted)
	cross.Metadata.OrderID = testUUID(201)
	if _, err := Replay([]Event{created, cross}); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("cross-aggregate event error = %v", err)
	}
	wrongSupplier := cloneEvent(submitted)
	wrongSupplier.Submitted.SupplierID = testUUID(999)
	if _, err := Replay([]Event{created, wrongSupplier}); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("changed supplier event error = %v", err)
	}
	badPayload := Event{Metadata: testMetadata(9, "principal:requester"), Version: 1, Type: OrderCreated, Created: &CreateOrder{Currency: "INR"}, ReasonCode: "unexpected"}
	if _, err := Replay([]Event{badPayload}); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("unexpected event payload error = %v", err)
	}
}

func TestCreateValidatesCanonicalFinancialAndQuantityInputs(t *testing.T) {
	cases := map[string]func(*CreateOrder){
		"zero amount":                func(c *CreateOrder) { c.AmountMinor = 0 },
		"unsafe amount":              func(c *CreateOrder) { c.AmountMinor = MaxAmountMinor + 1 },
		"unsupported currency shape": func(c *CreateOrder) { c.Currency = "usd" },
		"zero quantity":              func(c *CreateOrder) { c.LineItems[0].Quantity = "0" },
		"float quantity":             func(c *CreateOrder) { c.LineItems[0].Quantity = "1e2" },
		"excess precision":           func(c *CreateOrder) { c.LineItems[0].Quantity = "1.0000001" },
		"quantity overflow":          func(c *CreateOrder) { c.LineItems[0].Quantity = "9223372036855" },
		"oversized quantity":         func(c *CreateOrder) { c.LineItems[0].Quantity = strings.Repeat("9", 33) },
		"empty line":                 func(c *CreateOrder) { c.LineItems[0].Description = " \t" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			input := sampleOrder()
			mutate(&input)
			if _, _, err := Create(testMetadata(1, "principal:requester"), input); !errors.Is(err, ErrInvalidCommand) {
				t.Fatalf("error=%v, want invalid command", err)
			}
		})
	}
	for input, want := range map[string]int64{"1": 1_000_000, "0.000001": 1, "12.34": 12_340_000} {
		if got, err := quantityMicros(input); err != nil || got != want {
			t.Errorf("quantityMicros(%q)=(%d,%v), want %d", input, got, err, want)
		}
	}
	if got, err := quantityMicros("9223372036854.775807"); err != nil || got != math.MaxInt64 {
		t.Errorf("max quantity=(%d,%v), want %d", got, err, int64(math.MaxInt64))
	}
}

func TestSubmissionEvidenceDigestIsOrderIndependentAndRejectsDuplicateVersion(t *testing.T) {
	first := sampleEvidence()
	second := []EvidenceRef{first[1], first[0]}
	_, digest1, err := validateEvidence(first)
	if err != nil {
		t.Fatal(err)
	}
	_, digest2, err := validateEvidence(second)
	if err != nil {
		t.Fatal(err)
	}
	if digest1 != digest2 {
		t.Fatal("evidence digest depends on request array order")
	}
	if _, _, err := validateEvidence([]EvidenceRef{{DocumentID: testUUID(600), Version: 2}, {DocumentID: testUUID(600), Version: 2}}); !errors.Is(err, ErrInvalidCommand) {
		t.Fatalf("duplicate evidence error = %v", err)
	}
}

func TestReferenceReducerMatchesIndependentStateModel(t *testing.T) {
	created, e1, err := Create(testMetadata(1, "principal:requester"), sampleOrder())
	if err != nil {
		t.Fatal(err)
	}
	_, e2, err := Submit(created, 1, SubmitOrder{Evidence: sampleEvidence()}, testMetadata(2, "principal:requester"))
	if err != nil {
		t.Fatal(err)
	}
	_, e3, err := StartVerification(Snapshot{TenantID: created.TenantID, OrderID: created.OrderID, SupplierID: created.SupplierID, ExternalReference: created.ExternalReference, Currency: created.Currency, AmountMinor: created.AmountMinor, LineItems: created.LineItems, Status: Submitted, Version: 2, RequestedByRef: created.RequestedByRef, EvidenceDigest: func() string { _, d, _ := validateEvidence(sampleEvidence()); return d }()}, 2, testMetadata(3, "service-principal:verifier"))
	if err != nil {
		t.Fatal(err)
	}
	decision := Decision{Outcome: DecisionReject, DecisionID: testUUID(920), EvidenceDigest: e2.Submitted.EvidenceDigest, PolicyVersion: 2, ReasonCode: "denied"}
	e4 := Event{Metadata: testMetadata(4, "principal:approver"), Version: 4, Type: OrderRejected, Decision: &decision}
	events := []Event{e1, e2, e3, e4}
	got, err := Replay(events)
	if err != nil {
		t.Fatal(err)
	}
	want, err := independentReference(events)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != want.Status || got.Version != want.Version {
		t.Fatalf("implementation=%s/%d reference=%s/%d", got.Status, got.Version, want.Status, want.Version)
	}
}

func independentReference(events []Event) (Snapshot, error) {
	// Deliberately small, test-only transition model; it does not call ApplyEvent or Replay.
	var state Status
	var version uint64
	for i, event := range events {
		if event.Version != uint64(i+1) {
			return Snapshot{}, ErrInvalidEvent
		}
		switch event.Type {
		case OrderCreated:
			if i != 0 {
				return Snapshot{}, ErrIllegalTransition
			}
			state = Draft
		case OrderSubmitted:
			if state != Draft {
				return Snapshot{}, ErrIllegalTransition
			}
			state = Submitted
		case OrderVerificationStarted:
			if state != Submitted {
				return Snapshot{}, ErrIllegalTransition
			}
			state = Verifying
		case OrderApproved:
			if state != Verifying {
				return Snapshot{}, ErrIllegalTransition
			}
			state = Approved
		case OrderRejected:
			if state != Verifying {
				return Snapshot{}, ErrIllegalTransition
			}
			state = Rejected
		case OrderCanceled:
			if state != Draft && state != Submitted && state != Verifying {
				return Snapshot{}, ErrIllegalTransition
			}
			state = Canceled
		default:
			return Snapshot{}, ErrInvalidEvent
		}
		version = event.Version
	}
	return Snapshot{Status: state, Version: version}, nil
}

func mustCreate(t *testing.T) Snapshot {
	t.Helper()
	snapshot, _, err := Create(testMetadata(21, "principal:requester"), sampleOrder())
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func cloneEvent(event Event) Event {
	if event.Created != nil {
		payload := *event.Created
		payload.LineItems = append([]LineItem(nil), payload.LineItems...)
		event.Created = &payload
	}
	if event.Submitted != nil {
		payload := *event.Submitted
		event.Submitted = &payload
	}
	if event.Decision != nil {
		payload := *event.Decision
		event.Decision = &payload
	}
	return event
}
