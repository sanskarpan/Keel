// Package orders contains Keel's pure order state machine and deterministic event model.
// It intentionally has no database, network, clock, or identity-provider dependencies.
package orders

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/sanskarpan/keel/internal/platform/tracecontext"
)

var (
	ErrInvalidCommand    = errors.New("invalid order command")
	ErrInvalidEvent      = errors.New("invalid order event")
	ErrIllegalTransition = errors.New("illegal order state transition")
	ErrVersionConflict   = errors.New("order version conflict")
	ErrSnapshotMismatch  = errors.New("order snapshot does not match event history")
)

const (
	MaxAmountMinor = int64(9007199254740991) // Keep JSON clients' integer representation exact.
	MaxLineItems   = 100
	MaxEvidence    = 100
)

type Status string

const (
	Draft     Status = "draft"
	Submitted Status = "submitted"
	Verifying Status = "verifying"
	Approved  Status = "approved"
	Rejected  Status = "rejected"
	Canceled  Status = "canceled"
)

type EventType string

const (
	OrderCreated             EventType = "order.created"
	OrderSubmitted           EventType = "order.submitted"
	OrderVerificationStarted EventType = "order.verification_started"
	OrderApproved            EventType = "order.approved"
	OrderRejected            EventType = "order.rejected"
	OrderCanceled            EventType = "order.canceled"
)

type LineItem struct {
	Description string `json:"description"`
	// Quantity is a canonical decimal string (up to six fractional digits), never a float.
	Quantity string `json:"quantity"`
}

type EvidenceRef struct {
	DocumentID string `json:"document_id"`
	Version    uint64 `json:"version"`
}

type CreateOrder struct {
	ExternalReference string     `json:"external_reference"`
	SupplierID        string     `json:"supplier_id"`
	Currency          string     `json:"currency"`
	AmountMinor       int64      `json:"amount_minor"`
	LineItems         []LineItem `json:"line_items"`
}

type SubmitOrder struct {
	Evidence []EvidenceRef `json:"evidence"`
}

// CanonicalizeCreateOrder validates and normalizes an order command for stable hashing and storage.
func CanonicalizeCreateOrder(command CreateOrder) (CreateOrder, error) {
	return validateCreateOrder(command)
}

// CanonicalizeSubmitOrder validates evidence references and returns their deterministic digest.
func CanonicalizeSubmitOrder(command SubmitOrder) (SubmitOrder, string, error) {
	refs, digest, err := validateEvidence(command.Evidence)
	if err != nil {
		return SubmitOrder{}, "", err
	}
	return SubmitOrder{Evidence: refs}, digest, nil
}

type DecisionOutcome string

const (
	DecisionApprove DecisionOutcome = "approve"
	DecisionReject  DecisionOutcome = "reject"
)

type Decision struct {
	Outcome        DecisionOutcome `json:"outcome"`
	DecisionID     string          `json:"decision_id"`
	EvidenceDigest string          `json:"evidence_digest"`
	PolicyVersion  uint64          `json:"policy_version"`
	ReasonCode     string          `json:"reason_code,omitempty"`
}

type EventMetadata struct {
	EventID       string    `json:"event_id"`
	TenantID      string    `json:"tenant_id"`
	OrderID       string    `json:"aggregate_id"`
	OccurredAt    time.Time `json:"occurred_at"`
	ActorRef      string    `json:"actor_ref"`
	CausationID   string    `json:"causation_id"`
	CorrelationID string    `json:"correlation_id"`
	Traceparent   string    `json:"traceparent,omitempty"`
}

// Event is the private aggregate-history representation used by the pure reducer. Created
// events contain order descriptions and external references; persistence must protect them
// under order-table controls, and outbox serializers must emit only allowlisted safe facts.
type Event struct {
	Metadata EventMetadata `json:"metadata"`
	Version  uint64        `json:"aggregate_version"`
	Type     EventType     `json:"event_type"`

	Created    *CreateOrder `json:"created,omitempty"`
	Submitted  *Submission  `json:"submitted,omitempty"`
	Decision   *Decision    `json:"decision,omitempty"`
	ReasonCode string       `json:"reason_code,omitempty"`
}

type Snapshot struct {
	TenantID          string     `json:"tenant_id"`
	OrderID           string     `json:"order_id"`
	SupplierID        string     `json:"supplier_id"`
	ExternalReference string     `json:"external_reference"`
	Currency          string     `json:"currency"`
	AmountMinor       int64      `json:"amount_minor"`
	LineItems         []LineItem `json:"line_items"`
	Status            Status     `json:"status"`
	Version           uint64     `json:"version"`
	RequestedByRef    string     `json:"requested_by_ref"`
	EvidenceDigest    string     `json:"evidence_digest,omitempty"`
	Decision          *Decision  `json:"decision,omitempty"`
	TerminalReason    string     `json:"terminal_reason,omitempty"`
}

var (
	uuidPattern        = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	actorPattern       = regexp.MustCompile(`^(principal|service-principal):[A-Za-z0-9._~-]{1,120}$`)
	reasonCodePattern  = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	digestPattern      = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

func canonicalUUID(value string) (string, error) {
	if !uuidPattern.MatchString(value) {
		return "", fmt.Errorf("%w: identifier must be a UUID", ErrInvalidCommand)
	}
	return strings.ToLower(value), nil
}

func validateMetadata(meta EventMetadata) (EventMetadata, error) {
	var err error
	if meta.EventID, err = canonicalUUID(meta.EventID); err != nil {
		return EventMetadata{}, err
	}
	if meta.TenantID, err = canonicalUUID(meta.TenantID); err != nil {
		return EventMetadata{}, err
	}
	if meta.OrderID, err = canonicalUUID(meta.OrderID); err != nil {
		return EventMetadata{}, err
	}
	if meta.CausationID, err = canonicalUUID(meta.CausationID); err != nil {
		return EventMetadata{}, err
	}
	if meta.CorrelationID, err = canonicalUUID(meta.CorrelationID); err != nil {
		return EventMetadata{}, err
	}
	if !actorPattern.MatchString(meta.ActorRef) {
		return EventMetadata{}, fmt.Errorf("%w: actor reference is invalid", ErrInvalidCommand)
	}
	if meta.OccurredAt.IsZero() {
		return EventMetadata{}, fmt.Errorf("%w: event time is required", ErrInvalidCommand)
	}
	meta.OccurredAt = meta.OccurredAt.UTC()
	if meta.Traceparent != "" {
		if _, ok := tracecontext.Parse(meta.Traceparent); !ok {
			return EventMetadata{}, fmt.Errorf("%w: traceparent is invalid", ErrInvalidCommand)
		}
	}
	return meta, nil
}

func validateCreateOrder(in CreateOrder) (CreateOrder, error) {
	var err error
	if in.SupplierID, err = canonicalUUID(in.SupplierID); err != nil {
		return CreateOrder{}, err
	}
	if strings.TrimSpace(in.ExternalReference) == "" || !utf8.ValidString(in.ExternalReference) || utf8.RuneCountInString(in.ExternalReference) > 128 || hasControl(in.ExternalReference) {
		return CreateOrder{}, fmt.Errorf("%w: external reference must contain 1-128 printable characters", ErrInvalidCommand)
	}
	if len(in.Currency) != 3 || in.Currency[0] < 'A' || in.Currency[0] > 'Z' || in.Currency[1] < 'A' || in.Currency[1] > 'Z' || in.Currency[2] < 'A' || in.Currency[2] > 'Z' {
		return CreateOrder{}, fmt.Errorf("%w: currency must be three uppercase ASCII letters", ErrInvalidCommand)
	}
	if in.AmountMinor < 1 || in.AmountMinor > MaxAmountMinor {
		return CreateOrder{}, fmt.Errorf("%w: amount is outside the supported positive integer range", ErrInvalidCommand)
	}
	if len(in.LineItems) == 0 || len(in.LineItems) > MaxLineItems {
		return CreateOrder{}, fmt.Errorf("%w: line item count must be between 1 and %d", ErrInvalidCommand, MaxLineItems)
	}
	items := append([]LineItem(nil), in.LineItems...)
	for i := range items {
		if !utf8.ValidString(items[i].Description) || strings.TrimSpace(items[i].Description) == "" || utf8.RuneCountInString(items[i].Description) > 500 || hasControl(items[i].Description) {
			return CreateOrder{}, fmt.Errorf("%w: line item %d description must contain 1-500 printable characters", ErrInvalidCommand, i)
		}
		canonical, _, err := canonicalQuantity(items[i].Quantity)
		if err != nil {
			return CreateOrder{}, fmt.Errorf("%w: line item %d quantity is invalid", ErrInvalidCommand, i)
		}
		items[i].Quantity = canonical
	}
	in.LineItems = items
	return in, nil
}

func quantityMicros(value string) (int64, error) {
	if value == "" {
		return 0, errors.New("empty")
	}
	if len(value) > 32 {
		return 0, errors.New("quantity length exceeds limit")
	}
	parts := strings.Split(value, ".")
	if len(parts) > 2 {
		return 0, errors.New("invalid decimal")
	}
	whole := parts[0]
	if whole == "" || (len(whole) > 1 && whole[0] == '0') {
		return 0, errors.New("noncanonical integer")
	}
	for i := range whole {
		if whole[i] < '0' || whole[i] > '9' {
			return 0, errors.New("invalid integer")
		}
	}
	integer, err := strconv.ParseInt(whole, 10, 64)
	if err != nil || integer > math.MaxInt64/1_000_000 {
		return 0, errors.New("quantity overflow")
	}
	fraction := ""
	if len(parts) == 2 {
		fraction = parts[1]
		if len(fraction) == 0 || len(fraction) > 6 {
			return 0, errors.New("invalid fractional precision")
		}
		for i := range fraction {
			if fraction[i] < '0' || fraction[i] > '9' {
				return 0, errors.New("invalid fraction")
			}
		}
	}
	fraction += strings.Repeat("0", 6-len(fraction))
	var fractional int64
	if fraction != "" {
		fractional, err = strconv.ParseInt(fraction, 10, 64)
		if err != nil {
			return 0, errors.New("invalid fraction")
		}
	}
	micros := integer*1_000_000 + fractional
	if micros <= 0 {
		return 0, errors.New("quantity must be positive")
	}
	return micros, nil
}

func canonicalQuantity(value string) (string, int64, error) {
	micros, err := quantityMicros(value)
	if err != nil {
		return "", 0, err
	}
	parts := strings.Split(value, ".")
	if len(parts) == 1 {
		return value, micros, nil
	}
	fraction := strings.TrimRight(parts[1], "0")
	if fraction == "" {
		return parts[0], micros, nil
	}
	return parts[0] + "." + fraction, micros, nil
}

func validateEvidence(in []EvidenceRef) ([]EvidenceRef, string, error) {
	if len(in) == 0 || len(in) > MaxEvidence {
		return nil, "", fmt.Errorf("%w: evidence count must be between 1 and %d", ErrInvalidCommand, MaxEvidence)
	}
	refs := append([]EvidenceRef(nil), in...)
	for i := range refs {
		id, err := canonicalUUID(refs[i].DocumentID)
		if err != nil {
			return nil, "", err
		}
		refs[i].DocumentID = id
		if refs[i].Version == 0 {
			return nil, "", fmt.Errorf("%w: evidence version must be positive", ErrInvalidCommand)
		}
	}
	sort.Slice(refs, func(i, j int) bool {
		if refs[i].DocumentID != refs[j].DocumentID {
			return refs[i].DocumentID < refs[j].DocumentID
		}
		return refs[i].Version < refs[j].Version
	})
	for i := 1; i < len(refs); i++ {
		if refs[i] == refs[i-1] {
			return nil, "", fmt.Errorf("%w: duplicate evidence reference", ErrInvalidCommand)
		}
	}
	canonical, err := json.Marshal(refs)
	if err != nil {
		return nil, "", fmt.Errorf("%w: encode evidence reference", ErrInvalidCommand)
	}
	digest := sha256.Sum256(canonical)
	return refs, "sha256:" + hex.EncodeToString(digest[:]), nil
}

func validateDecision(in Decision) (Decision, error) {
	var err error
	if in.DecisionID, err = canonicalUUID(in.DecisionID); err != nil {
		return Decision{}, err
	}
	if in.Outcome != DecisionApprove && in.Outcome != DecisionReject {
		return Decision{}, fmt.Errorf("%w: outcome must be approve or reject", ErrInvalidCommand)
	}
	if in.PolicyVersion == 0 {
		return Decision{}, fmt.Errorf("%w: policy version must be positive", ErrInvalidCommand)
	}
	if !digestPattern.MatchString(in.EvidenceDigest) {
		return Decision{}, fmt.Errorf("%w: decision evidence digest is invalid", ErrInvalidCommand)
	}
	if in.Outcome == DecisionApprove && in.ReasonCode != "" {
		return Decision{}, fmt.Errorf("%w: approval must not include a rejection reason", ErrInvalidCommand)
	}
	if in.Outcome == DecisionReject && !reasonCodePattern.MatchString(in.ReasonCode) {
		return Decision{}, fmt.Errorf("%w: rejection requires a stable reason code", ErrInvalidCommand)
	}
	return in, nil
}

func hasControl(value string) bool {
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}
