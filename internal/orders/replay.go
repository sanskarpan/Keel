package orders

import (
	"fmt"
	"math"
	"reflect"
)

type Submission struct {
	SupplierID     string `json:"supplier_id"`
	EvidenceDigest string `json:"evidence_digest"`
}

// Command functions validate optimistic versions and return the immutable event plus the
// authoritative snapshot produced by the same pure replay reducer used for recovery checks.
func Create(meta EventMetadata, command CreateOrder) (Snapshot, Event, error) {
	metadata, err := validateMetadata(meta)
	if err != nil {
		return Snapshot{}, Event{}, err
	}
	validated, err := validateCreateOrder(command)
	if err != nil {
		return Snapshot{}, Event{}, err
	}
	event := Event{Metadata: metadata, Version: 1, Type: OrderCreated, Created: &validated}
	next, err := ApplyEvent(Snapshot{}, event)
	if err != nil {
		return Snapshot{}, Event{}, err
	}
	return next, event, nil
}

func Submit(snapshot Snapshot, expectedVersion uint64, command SubmitOrder, meta EventMetadata) (Snapshot, Event, error) {
	if err := checkCommandBase(snapshot, expectedVersion, meta, Draft); err != nil {
		return Snapshot{}, Event{}, err
	}
	_, digest, err := CanonicalizeSubmitOrder(command)
	if err != nil {
		return Snapshot{}, Event{}, err
	}
	// Keep evidence references out of the shared event envelope; its digest binds the immutable
	// versions while access-controlled evidence records remain behind the document boundary.
	return emit(snapshot, Event{Type: OrderSubmitted, Submitted: &Submission{SupplierID: snapshot.SupplierID, EvidenceDigest: digest}}, meta)
}

func StartVerification(snapshot Snapshot, expectedVersion uint64, meta EventMetadata) (Snapshot, Event, error) {
	if err := checkCommandBase(snapshot, expectedVersion, meta, Submitted); err != nil {
		return Snapshot{}, Event{}, err
	}
	return emit(snapshot, Event{Type: OrderVerificationStarted}, meta)
}

func Decide(snapshot Snapshot, expectedVersion uint64, decision Decision, meta EventMetadata) (Snapshot, Event, error) {
	if err := checkCommandBase(snapshot, expectedVersion, meta, Verifying); err != nil {
		return Snapshot{}, Event{}, err
	}
	validated, err := validateDecision(decision)
	if err != nil {
		return Snapshot{}, Event{}, err
	}
	typeOfEvent := OrderRejected
	if validated.Outcome == DecisionApprove {
		typeOfEvent = OrderApproved
	}
	return emit(snapshot, Event{Type: typeOfEvent, Decision: &validated}, meta)
}

func Cancel(snapshot Snapshot, expectedVersion uint64, reasonCode string, meta EventMetadata) (Snapshot, Event, error) {
	if err := checkVersionAndIdentity(snapshot, expectedVersion, meta); err != nil {
		return Snapshot{}, Event{}, err
	}
	if snapshot.Status != Draft && snapshot.Status != Submitted && snapshot.Status != Verifying {
		return Snapshot{}, Event{}, transitionError(snapshot.Status, Canceled)
	}
	if !reasonCodePattern.MatchString(reasonCode) {
		return Snapshot{}, Event{}, fmt.Errorf("%w: cancellation requires a stable reason code", ErrInvalidCommand)
	}
	return emit(snapshot, Event{Type: OrderCanceled, ReasonCode: reasonCode}, meta)
}

func emit(snapshot Snapshot, event Event, meta EventMetadata) (Snapshot, Event, error) {
	metadata, err := validateMetadata(meta)
	if err != nil {
		return Snapshot{}, Event{}, err
	}
	event.Metadata = metadata
	if snapshot.Version == math.MaxUint64 {
		return Snapshot{}, Event{}, fmt.Errorf("%w: aggregate version exhausted", ErrInvalidCommand)
	}
	event.Version = snapshot.Version + 1
	next, err := ApplyEvent(snapshot, event)
	if err != nil {
		return Snapshot{}, Event{}, err
	}
	return next, event, nil
}

func checkCommandBase(snapshot Snapshot, expectedVersion uint64, meta EventMetadata, required Status) error {
	if err := checkVersionAndIdentity(snapshot, expectedVersion, meta); err != nil {
		return err
	}
	if snapshot.Status != required {
		return transitionError(snapshot.Status, required)
	}
	return nil
}

func checkVersionAndIdentity(snapshot Snapshot, expectedVersion uint64, meta EventMetadata) error {
	if err := validateSnapshotShape(snapshot); err != nil {
		return err
	}
	if expectedVersion == 0 || snapshot.Version != expectedVersion {
		return fmt.Errorf("%w: expected %d, current %d", ErrVersionConflict, expectedVersion, snapshot.Version)
	}
	metadata, err := validateMetadata(meta)
	if err != nil {
		return err
	}
	if metadata.TenantID != snapshot.TenantID || metadata.OrderID != snapshot.OrderID {
		return fmt.Errorf("%w: command scope does not match order", ErrInvalidCommand)
	}
	return nil
}

// ApplyEvent is the deterministic state reducer. It does not read the clock, database,
// provider, or process state; identical event histories always produce identical snapshots.
func ApplyEvent(current Snapshot, event Event) (Snapshot, error) {
	if err := validateEventShape(event); err != nil {
		return Snapshot{}, err
	}
	if current.Version == 0 {
		if event.Type != OrderCreated || event.Version != 1 {
			return Snapshot{}, fmt.Errorf("%w: first event must create version 1", ErrInvalidEvent)
		}
		return applyCreated(event)
	}
	if event.Type == OrderCreated {
		return Snapshot{}, fmt.Errorf("%w: order creation may appear only once", ErrInvalidEvent)
	}
	if err := validateSnapshotShape(current); err != nil {
		return Snapshot{}, fmt.Errorf("%w: current snapshot is invalid", ErrInvalidEvent)
	}
	if event.Metadata.TenantID != current.TenantID || event.Metadata.OrderID != current.OrderID {
		return Snapshot{}, fmt.Errorf("%w: event aggregate identity changed", ErrInvalidEvent)
	}
	if current.Version == math.MaxUint64 || event.Version != current.Version+1 {
		return Snapshot{}, fmt.Errorf("%w: expected aggregate version %d, received %d", ErrInvalidEvent, current.Version+1, event.Version)
	}

	next := cloneSnapshot(current)
	switch event.Type {
	case OrderSubmitted:
		if current.Status != Draft {
			return Snapshot{}, transitionError(current.Status, Submitted)
		}
		supplierID, err := canonicalUUID(event.Submitted.SupplierID)
		if err != nil || supplierID != current.SupplierID {
			return Snapshot{}, fmt.Errorf("%w: submitted supplier differs from the draft", ErrInvalidEvent)
		}
		if !digestPattern.MatchString(event.Submitted.EvidenceDigest) {
			return Snapshot{}, fmt.Errorf("%w: submitted evidence digest is invalid", ErrInvalidEvent)
		}
		next.Status = Submitted
		next.EvidenceDigest = event.Submitted.EvidenceDigest
	case OrderVerificationStarted:
		if current.Status != Submitted {
			return Snapshot{}, transitionError(current.Status, Verifying)
		}
		next.Status = Verifying
	case OrderApproved, OrderRejected:
		if current.Status != Verifying {
			return Snapshot{}, transitionError(current.Status, eventTarget(event.Type))
		}
		decision := *event.Decision
		validated, err := validateDecision(decision)
		if err != nil {
			return Snapshot{}, fmt.Errorf("%w: invalid decision payload", ErrInvalidEvent)
		}
		if validated.Outcome == DecisionApprove && event.Type != OrderApproved || validated.Outcome == DecisionReject && event.Type != OrderRejected {
			return Snapshot{}, fmt.Errorf("%w: decision outcome does not match event type", ErrInvalidEvent)
		}
		if event.Metadata.ActorRef == current.RequestedByRef {
			return Snapshot{}, fmt.Errorf("%w: requester cannot decide their own order", ErrIllegalTransition)
		}
		if validated.EvidenceDigest != current.EvidenceDigest {
			return Snapshot{}, fmt.Errorf("%w: decision evidence differs from submitted evidence", ErrInvalidEvent)
		}
		next.Decision = &validated
		if event.Type == OrderApproved {
			next.Status = Approved
		} else {
			next.Status = Rejected
		}
	case OrderCanceled:
		if current.Status != Draft && current.Status != Submitted && current.Status != Verifying {
			return Snapshot{}, transitionError(current.Status, Canceled)
		}
		if !reasonCodePattern.MatchString(event.ReasonCode) {
			return Snapshot{}, fmt.Errorf("%w: cancellation reason code is invalid", ErrInvalidEvent)
		}
		next.Status = Canceled
		next.TerminalReason = event.ReasonCode
	default:
		return Snapshot{}, fmt.Errorf("%w: unsupported event type", ErrInvalidEvent)
	}
	next.Version = event.Version
	return next, nil
}

// Replay rebuilds the command snapshot from one complete, ordered event stream and rejects
// duplicate event IDs, gaps, cross-tenant/order events, and illegal state transitions.
func Replay(events []Event) (Snapshot, error) {
	if len(events) == 0 {
		return Snapshot{}, fmt.Errorf("%w: event history is empty", ErrInvalidEvent)
	}
	seen := make(map[string]struct{}, len(events))
	var snapshot Snapshot
	for i, event := range events {
		id := event.Metadata.EventID
		if _, exists := seen[id]; exists {
			return Snapshot{}, fmt.Errorf("%w: duplicate event ID at position %d", ErrInvalidEvent, i)
		}
		seen[id] = struct{}{}
		next, err := ApplyEvent(snapshot, event)
		if err != nil {
			return Snapshot{}, fmt.Errorf("replay event %d: %w", i, err)
		}
		snapshot = next
	}
	return snapshot, nil
}

func VerifySnapshot(stored Snapshot, events []Event) error {
	replayed, err := Replay(events)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(replayed, stored) {
		return ErrSnapshotMismatch
	}
	return nil
}

func applyCreated(event Event) (Snapshot, error) {
	command, err := validateCreateOrder(*event.Created)
	if err != nil {
		return Snapshot{}, fmt.Errorf("%w: invalid creation payload", ErrInvalidEvent)
	}
	return Snapshot{
		TenantID: event.Metadata.TenantID, OrderID: event.Metadata.OrderID,
		SupplierID: command.SupplierID, ExternalReference: command.ExternalReference,
		Currency: command.Currency, AmountMinor: command.AmountMinor,
		LineItems: append([]LineItem(nil), command.LineItems...), Status: Draft,
		Version: event.Version, RequestedByRef: event.Metadata.ActorRef,
	}, nil
}

func validateEventShape(event Event) error {
	meta, err := validateMetadata(event.Metadata)
	if err != nil {
		return fmt.Errorf("%w: invalid metadata", ErrInvalidEvent)
	}
	if meta.EventID != event.Metadata.EventID || meta.TenantID != event.Metadata.TenantID || meta.OrderID != event.Metadata.OrderID || meta.CausationID != event.Metadata.CausationID || meta.CorrelationID != event.Metadata.CorrelationID {
		return fmt.Errorf("%w: event identifiers are not canonical", ErrInvalidEvent)
	}
	if event.Version == 0 {
		return fmt.Errorf("%w: version must be positive", ErrInvalidEvent)
	}
	payloads := 0
	if event.Created != nil {
		payloads++
	}
	if event.Submitted != nil {
		payloads++
	}
	if event.Decision != nil {
		payloads++
	}
	if event.ReasonCode != "" {
		payloads++
	}
	want := 0
	switch event.Type {
	case OrderCreated:
		want = 1
		if event.Created == nil {
			return fmt.Errorf("%w: create payload is required", ErrInvalidEvent)
		}
	case OrderSubmitted:
		want = 1
		if event.Submitted == nil {
			return fmt.Errorf("%w: submit payload is required", ErrInvalidEvent)
		}
	case OrderVerificationStarted:
		want = 0
	case OrderApproved, OrderRejected:
		want = 1
		if event.Decision == nil {
			return fmt.Errorf("%w: decision payload is required", ErrInvalidEvent)
		}
	case OrderCanceled:
		want = 1
		if event.ReasonCode == "" {
			return fmt.Errorf("%w: cancellation reason is required", ErrInvalidEvent)
		}
	default:
		return fmt.Errorf("%w: unknown event type", ErrInvalidEvent)
	}
	if payloads != want {
		return fmt.Errorf("%w: event has unexpected payload fields", ErrInvalidEvent)
	}
	return nil
}

func validateSnapshotShape(s Snapshot) error {
	if value, err := canonicalUUID(s.TenantID); err != nil || value != s.TenantID {
		return ErrInvalidEvent
	}
	if value, err := canonicalUUID(s.OrderID); err != nil || value != s.OrderID {
		return ErrInvalidEvent
	}
	if value, err := canonicalUUID(s.SupplierID); err != nil || value != s.SupplierID {
		return ErrInvalidEvent
	}
	if !actorPattern.MatchString(s.RequestedByRef) || s.Version == 0 {
		return ErrInvalidEvent
	}
	command := CreateOrder{ExternalReference: s.ExternalReference, SupplierID: s.SupplierID, Currency: s.Currency, AmountMinor: s.AmountMinor, LineItems: s.LineItems}
	if _, err := validateCreateOrder(command); err != nil {
		return ErrInvalidEvent
	}
	if s.Status != Draft && s.Status != Submitted && s.Status != Verifying && s.Status != Approved && s.Status != Rejected && s.Status != Canceled {
		return ErrInvalidEvent
	}
	switch s.Status {
	case Draft:
		if s.EvidenceDigest != "" {
			return ErrInvalidEvent
		}
	case Canceled:
		if s.EvidenceDigest != "" && !digestPattern.MatchString(s.EvidenceDigest) {
			return ErrInvalidEvent
		}
	default:
		if !digestPattern.MatchString(s.EvidenceDigest) {
			return ErrInvalidEvent
		}
	}
	if (s.Status == Approved || s.Status == Rejected) != (s.Decision != nil) {
		return ErrInvalidEvent
	}
	if s.Decision != nil {
		decision, err := validateDecision(*s.Decision)
		if err != nil || decision != *s.Decision || decision.EvidenceDigest != s.EvidenceDigest ||
			(s.Status == Approved) != (decision.Outcome == DecisionApprove) {
			return ErrInvalidEvent
		}
	}
	if s.Status == Canceled && !reasonCodePattern.MatchString(s.TerminalReason) || s.Status != Canceled && s.TerminalReason != "" {
		return ErrInvalidEvent
	}
	return nil
}

func cloneSnapshot(s Snapshot) Snapshot {
	s.LineItems = append([]LineItem(nil), s.LineItems...)
	if s.Decision != nil {
		decision := *s.Decision
		s.Decision = &decision
	}
	return s
}

func eventTarget(eventType EventType) Status {
	switch eventType {
	case OrderApproved:
		return Approved
	case OrderRejected:
		return Rejected
	case OrderVerificationStarted:
		return Verifying
	case OrderCanceled:
		return Canceled
	default:
		return Submitted
	}
}

func transitionError(from, to Status) error {
	return fmt.Errorf("%w: %s -> %s", ErrIllegalTransition, from, to)
}
