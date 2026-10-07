// Package projector validates transport events and coordinates durable, contiguous projections.
package projector

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"time"

	"github.com/sanskarpan/keel/internal/orders"
	"github.com/sanskarpan/keel/internal/platform/observability"
	"github.com/sanskarpan/keel/internal/platform/tracecontext"
)

const (
	DefaultConsumerID = "order-projection-v1"
	MaxEnvelopeBytes  = 8 * 1024
)

var (
	ErrInvalidRecord     = errors.New("invalid order event record")
	ErrUnsupportedSchema = errors.New("unsupported order event schema")
	uuidPattern          = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	topicPattern         = regexp.MustCompile(`^keel\.[a-z0-9-]+\.orders\.v1$`)
)

type Record struct {
	Topic     string
	Partition int
	Offset    int64
	Key       []byte
	Value     []byte
	Headers   []Header
}

// Header is a single Kafka header occurrence. A slice preserves duplicate keys so identity
// headers can be rejected instead of silently collapsed by a map conversion.
type Header struct {
	Key   string
	Value []byte
}

type Envelope struct {
	SchemaVersion    int              `json:"schema_version"`
	EventID          string           `json:"event_id"`
	TenantID         string           `json:"tenant_id"`
	AggregateID      string           `json:"aggregate_id"`
	AggregateVersion int64            `json:"aggregate_version"`
	EventType        orders.EventType `json:"event_type"`
	OccurredAt       time.Time        `json:"occurred_at"`
	Traceparent      string           `json:"traceparent,omitempty"`
}

type Disposition string

const (
	Applied     Disposition = "applied"
	Duplicate   Disposition = "duplicate"
	Deferred    Disposition = "deferred"
	Quarantined Disposition = "quarantined"
)

type Result struct {
	Disposition Disposition
	ReasonCode  string
	Applied     int
}

type Store interface {
	Apply(context.Context, string, Envelope, [32]byte) (Result, error)
	ReplayGaps(context.Context, string, string, int) (int, error)
	QuarantineTransport(context.Context, string, int, int64, [32]byte, string) error
}

type Processor struct {
	store      Store
	consumerID string
}

func New(store Store, consumerID string) (*Processor, error) {
	if store == nil {
		return nil, errors.New("projector store is required")
	}
	if consumerID == "" {
		consumerID = DefaultConsumerID
	}
	if consumerID != DefaultConsumerID {
		return nil, fmt.Errorf("this projection requires the single active consumer ID %q", DefaultConsumerID)
	}
	return &Processor{store: store, consumerID: consumerID}, nil
}

// Process validates broker identity and commits inbox/projection/quarantine state atomically.
// The Kafka caller must commit its offset only when this method returns nil error.
func (p *Processor) Process(ctx context.Context, tenantID string, record Record) (Result, error) {
	envelope, digest, err := Decode(tenantID, record)
	if err != nil {
		if !topicPattern.MatchString(record.Topic) || record.Partition < 0 || record.Offset < 0 {
			return Result{}, err
		}
		reason := "invalid_record"
		if errors.Is(err, ErrUnsupportedSchema) {
			reason = "unsupported_schema"
		}
		payloadHash := sha256.Sum256(record.Value)
		if quarantineErr := p.store.QuarantineTransport(ctx, record.Topic, record.Partition, record.Offset, payloadHash, reason); quarantineErr != nil {
			return Result{}, fmt.Errorf("persist malformed-record quarantine: %w", quarantineErr)
		}
		return Result{Disposition: Quarantined, ReasonCode: reason}, nil
	}
	if envelope.Traceparent != "" {
		if childContext, ok := observability.WithRemoteTraceparent(ctx, envelope.Traceparent); ok {
			ctx = childContext
		}
	}
	result, err := p.store.Apply(ctx, p.consumerID, envelope, digest)
	if err != nil {
		return Result{}, err
	}
	if result.Disposition == Quarantined && result.ReasonCode == "source_not_found" {
		payloadHash := sha256.Sum256(record.Value)
		if err := p.store.QuarantineTransport(ctx, record.Topic, record.Partition, record.Offset, payloadHash, "source_mismatch"); err != nil {
			return Result{}, fmt.Errorf("persist untrusted-tenant source-mismatch quarantine: %w", err)
		}
		result.ReasonCode = "source_mismatch"
	}
	return result, nil
}

// ProcessRecord derives only an untrusted tenant claim from the record so RLS can search that
// tenant's canonical outbox. Only an exact canonical outbox match can affect a projection.
// Records without a parseable tenant are digest-quarantined without creating a tenant claim.
func (p *Processor) ProcessRecord(ctx context.Context, record Record) (Result, error) {
	var claim struct {
		TenantID string `json:"tenant_id"`
	}
	if len(record.Value) > MaxEnvelopeBytes {
		return p.quarantineInvalidTransport(ctx, record)
	}
	if err := json.Unmarshal(record.Value, &claim); err != nil || !uuidPattern.MatchString(claim.TenantID) {
		return p.quarantineInvalidTransport(ctx, record)
	}
	return p.Process(ctx, claim.TenantID, record)
}

func (p *Processor) quarantineInvalidTransport(ctx context.Context, record Record) (Result, error) {
	if !topicPattern.MatchString(record.Topic) || record.Partition < 0 || record.Offset < 0 {
		return Result{}, fmt.Errorf("%w: invalid broker coordinates", ErrInvalidRecord)
	}
	payloadHash := sha256.Sum256(record.Value)
	if err := p.store.QuarantineTransport(ctx, record.Topic, record.Partition, record.Offset, payloadHash, "invalid_record"); err != nil {
		return Result{}, fmt.Errorf("persist malformed-record quarantine: %w", err)
	}
	return Result{Disposition: Quarantined, ReasonCode: "invalid_record"}, nil
}

// ReplayGaps applies missing canonical outbox envelopes for one tenant. It is bounded so a
// single tenant or corrupt stream cannot monopolize a projector worker.
func (p *Processor) ReplayGaps(ctx context.Context, tenantID string, limit int) (int, error) {
	if !uuidPattern.MatchString(tenantID) {
		return 0, fmt.Errorf("%w: invalid tenant identity", ErrInvalidRecord)
	}
	if limit < 1 || limit > 500 {
		return 0, errors.New("gap replay limit must be between 1 and 500")
	}
	return p.store.ReplayGaps(ctx, tenantID, p.consumerID, limit)
}

func Decode(tenantID string, record Record) (Envelope, [32]byte, error) {
	if !uuidPattern.MatchString(tenantID) || !topicPattern.MatchString(record.Topic) || record.Partition < 0 || record.Offset < 0 || len(record.Value) == 0 || len(record.Value) > MaxEnvelopeBytes {
		return Envelope{}, [32]byte{}, fmt.Errorf("%w: invalid tenant or envelope size", ErrInvalidRecord)
	}
	if err := rejectDuplicateJSONKeys(record.Value); err != nil {
		return Envelope{}, [32]byte{}, fmt.Errorf("%w: duplicate or malformed JSON keys", ErrInvalidRecord)
	}
	var envelope Envelope
	decoder := json.NewDecoder(bytes.NewReader(record.Value))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return Envelope{}, [32]byte{}, fmt.Errorf("%w: decode envelope", ErrInvalidRecord)
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return Envelope{}, [32]byte{}, fmt.Errorf("%w: trailing envelope data", ErrInvalidRecord)
	}
	if envelope.SchemaVersion < 1 {
		return Envelope{}, [32]byte{}, fmt.Errorf("%w: schema version is missing or invalid", ErrInvalidRecord)
	}
	if envelope.SchemaVersion > 2 {
		return Envelope{}, [32]byte{}, fmt.Errorf("%w: schema version %d", ErrUnsupportedSchema, envelope.SchemaVersion)
	}
	if (envelope.SchemaVersion == 1 && envelope.Traceparent != "") ||
		(envelope.SchemaVersion == 2 && (envelope.Traceparent == "" || !validTraceparent(envelope.Traceparent))) {
		return Envelope{}, [32]byte{}, fmt.Errorf("%w: trace context does not match envelope schema", ErrInvalidRecord)
	}
	if envelope.TenantID != tenantID ||
		!uuidPattern.MatchString(envelope.EventID) || !uuidPattern.MatchString(envelope.AggregateID) ||
		envelope.AggregateVersion < 1 || envelope.OccurredAt.IsZero() || !supportedEventType(envelope.EventType) {
		return Envelope{}, [32]byte{}, fmt.Errorf("%w: envelope identity or schema is invalid", ErrInvalidRecord)
	}
	if string(record.Key) != envelope.TenantID+"/"+envelope.AggregateID {
		return Envelope{}, [32]byte{}, fmt.Errorf("%w: partition key does not match aggregate", ErrInvalidRecord)
	}
	headers := make(map[string]string, 4)
	for _, header := range record.Headers {
		switch header.Key {
		case "event_id", "schema_version", "aggregate_version", "traceparent":
		default:
			return Envelope{}, [32]byte{}, fmt.Errorf("%w: unknown Kafka identity header", ErrInvalidRecord)
		}
		if _, exists := headers[header.Key]; exists {
			return Envelope{}, [32]byte{}, fmt.Errorf("%w: duplicate Kafka identity header", ErrInvalidRecord)
		}
		headers[header.Key] = string(header.Value)
	}
	if headers["event_id"] != envelope.EventID ||
		headers["schema_version"] != strconv.Itoa(envelope.SchemaVersion) ||
		headers["aggregate_version"] != strconv.FormatInt(envelope.AggregateVersion, 10) {
		return Envelope{}, [32]byte{}, fmt.Errorf("%w: Kafka identity headers do not match envelope", ErrInvalidRecord)
	}
	if (envelope.Traceparent == "" && headers["traceparent"] != "") ||
		(envelope.Traceparent != "" && (headers["traceparent"] != envelope.Traceparent || !validTraceparent(headers["traceparent"]))) {
		return Envelope{}, [32]byte{}, fmt.Errorf("%w: Kafka trace context does not match envelope", ErrInvalidRecord)
	}
	envelope.OccurredAt = envelope.OccurredAt.UTC()
	canonical, err := json.Marshal(envelope)
	if err != nil {
		return Envelope{}, [32]byte{}, fmt.Errorf("%w: canonicalize envelope", ErrInvalidRecord)
	}
	return envelope, sha256.Sum256(canonical), nil
}

func validTraceparent(value string) bool {
	_, ok := tracecontext.Parse(value)
	return ok
}

func rejectDuplicateJSONKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := consumeJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("JSON contains trailing data")
	}
	return nil
}

func consumeJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}
	switch delimiter {
	case '{':
		keys := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("JSON object key is not a string")
			}
			if _, exists := keys[key]; exists {
				return fmt.Errorf("duplicate JSON key %q", key)
			}
			keys[key] = struct{}{}
			if err := consumeJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errors.New("JSON object is not closed")
		}
	case '[':
		for decoder.More() {
			if err := consumeJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errors.New("JSON array is not closed")
		}
	default:
		return errors.New("invalid JSON delimiter")
	}
	return nil
}

func supportedEventType(eventType orders.EventType) bool {
	switch eventType {
	case orders.OrderCreated, orders.OrderSubmitted, orders.OrderVerificationStarted,
		orders.OrderApproved, orders.OrderRejected, orders.OrderCanceled:
		return true
	default:
		return false
	}
}

// NextStatus checks the legal order-status transition represented by one canonical event.
func NextStatus(previous *orders.Status, eventType orders.EventType) (orders.Status, error) {
	if previous == nil {
		if eventType == orders.OrderCreated {
			return orders.Draft, nil
		}
		return "", errors.New("first projected event must create the order")
	}
	switch eventType {
	case orders.OrderSubmitted:
		if *previous == orders.Draft {
			return orders.Submitted, nil
		}
	case orders.OrderVerificationStarted:
		if *previous == orders.Submitted {
			return orders.Verifying, nil
		}
	case orders.OrderApproved:
		if *previous == orders.Verifying {
			return orders.Approved, nil
		}
	case orders.OrderRejected:
		if *previous == orders.Verifying {
			return orders.Rejected, nil
		}
	case orders.OrderCanceled:
		if *previous == orders.Draft || *previous == orders.Submitted || *previous == orders.Verifying {
			return orders.Canceled, nil
		}
	}
	return "", fmt.Errorf("event %q is invalid after status %q", eventType, *previous)
}
