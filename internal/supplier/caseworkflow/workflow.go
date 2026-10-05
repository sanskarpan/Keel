// Package caseworkflow defines the deterministic projection of durable supplier-case events.
// It receives identifiers and integrity metadata only; evidence and supplier data stay in Postgres.
package caseworkflow

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/sanskarpan/keel/internal/platform/tenancy"
	"go.temporal.io/sdk/workflow"
)

const (
	WorkflowName = "SupplierCaseWorkflowV1"
	TaskQueue    = "keel-supplier-case-v1"
	SignalName   = "supplier-case-event-v1"
	StateQuery   = "supplier-case-state-v1"
	MaxEvents    = 135 // bounded K2.4 envelope: create + 100 evidence + submit + 32 decisions + expiry
)

var (
	ErrInvalidSignal = errors.New("invalid supplier case workflow signal")
	ErrCaseMismatch  = errors.New("supplier case workflow identity mismatch")
	ErrVersionGap    = errors.New("supplier case workflow event version gap")
	ErrConflict      = errors.New("conflicting supplier case workflow event")
	caseUUID         = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	sha256Hex        = regexp.MustCompile(`^[0-9a-f]{64}$`)
	intentUUID       = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
)

// EventSignal is the complete Temporal payload. It intentionally excludes event data,
// supplier identifiers, evidence metadata, actor references, and request credentials.
type EventSignal struct {
	CaseID    string `json:"case_id"`
	IntentID  string `json:"intent_id"`
	Version   uint64 `json:"version"`
	EventType string `json:"event_type"`
	EventHash string `json:"event_hash"`
}

type WorkflowInput struct {
	CaseID string `json:"case_id"`
}

type EventIdentity struct {
	IntentID  string `json:"intent_id"`
	EventType string `json:"event_type"`
	EventHash string `json:"event_hash"`
}

type State struct {
	CaseID      string                   `json:"case_id"`
	LastVersion uint64                   `json:"last_version"`
	Events      map[uint64]EventIdentity `json:"events"`
}

func WorkflowID(tenant tenancy.TenantID, caseID string) (string, error) {
	if _, err := tenancy.ParseTenantID(string(tenant)); err != nil || !caseUUID.MatchString(caseID) {
		return "", ErrInvalidSignal
	}
	identity := sha256.Sum256([]byte(strings.ToLower(string(tenant)) + "\x00" + caseID))
	return "keel.supplier-case.v1." + hex.EncodeToString(identity[:]), nil
}

func (s EventSignal) Validate() error {
	if !caseUUID.MatchString(s.CaseID) || !intentUUID.MatchString(s.IntentID) || s.Version == 0 || s.Version > MaxEvents ||
		!sha256Hex.MatchString(s.EventHash) || !allowedType(s.EventType) {
		return ErrInvalidSignal
	}
	return nil
}

func allowedType(value string) bool {
	switch value {
	case "supplier.case.created", "supplier.case.evidence-added", "supplier.case.submitted", "supplier.case.approval-decided", "supplier.case.expired":
		return true
	default:
		return false
	}
}

// Apply is a pure, deterministic transition used by the workflow and unit tests.
func Apply(state State, signal EventSignal) (State, error) {
	if err := signal.Validate(); err != nil {
		return state, err
	}
	if state.CaseID != signal.CaseID {
		return state, ErrCaseMismatch
	}
	if state.Events == nil {
		state.Events = make(map[uint64]EventIdentity, MaxEvents)
	}
	identity := EventIdentity{IntentID: signal.IntentID, EventType: signal.EventType, EventHash: signal.EventHash}
	if previous, ok := state.Events[signal.Version]; ok {
		if previous == identity {
			return state, nil
		}
		return state, ErrConflict
	}
	for _, previous := range state.Events {
		if previous.IntentID == signal.IntentID {
			return state, ErrConflict
		}
	}
	if signal.Version != state.LastVersion+1 {
		return state, fmt.Errorf("%w: got %d after %d", ErrVersionGap, signal.Version, state.LastVersion)
	}
	if len(state.Events) >= MaxEvents {
		return state, ErrInvalidSignal
	}
	if (signal.Version == 1) != (signal.EventType == "supplier.case.created") {
		return state, ErrInvalidSignal
	}
	state.Events[signal.Version] = identity
	state.LastVersion = signal.Version
	return state, nil
}

// SupplierCaseWorkflow validates and durably remembers every accepted event identity.
// Returning an error on corruption is fail-closed; Temporal retains the full history for repair.
func SupplierCaseWorkflow(ctx workflow.Context, input WorkflowInput) error {
	if !caseUUID.MatchString(input.CaseID) {
		return ErrInvalidSignal
	}
	state := State{CaseID: input.CaseID, Events: make(map[uint64]EventIdentity, MaxEvents)}
	if err := workflow.SetQueryHandler(ctx, StateQuery, func() (State, error) {
		copy := State{CaseID: state.CaseID, LastVersion: state.LastVersion, Events: make(map[uint64]EventIdentity, len(state.Events))}
		for version, identity := range state.Events {
			copy.Events[version] = identity
		}
		return copy, nil
	}); err != nil {
		return err
	}
	channel := workflow.GetSignalChannel(ctx, SignalName)
	for {
		var signal EventSignal
		channel.Receive(ctx, &signal)
		next, err := Apply(state, signal)
		if err != nil {
			return err
		}
		state = next
	}
}
