// Package outbox coordinates at-least-once delivery of immutable order event envelopes.
package outbox

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/sanskarpan/keel/internal/platform/observability"
	"github.com/sanskarpan/keel/internal/platform/tracecontext"
)

var (
	ErrBrokerUnavailable = errors.New("broker unavailable")
	ErrBrokerRejected    = errors.New("broker rejected event")
	ErrLeaseLost         = errors.New("outbox publish lease lost")
	ErrPoisonEnvelope    = errors.New("outbox envelope is corrupt")
)

const (
	DefaultLeaseDuration  = 30 * time.Second
	DefaultPublishTimeout = 10 * time.Second
	maximumLeaseDuration  = 2 * time.Minute
	maximumRetryDelay     = 5 * time.Minute
)

// Claim is one fenced publish-head attempt. Epoch increases whenever an expired head is reclaimed.
type Claim struct {
	TenantID     string
	AggregateID  string
	EventID      string
	EventType    string
	Version      int64
	Owner        string
	Epoch        int64
	LeaseExpires time.Time
	AttemptCount int
}

// Message contains the public allowlisted envelope already stored in the transactional outbox.
type Message struct {
	SchemaVersion    int
	TenantID         string
	AggregateID      string
	AggregateVersion int64
	EventID          string
	EventType        string
	Traceparent      string
	Payload          []byte
}

// ValidTraceparent reports whether the value is a supported W3C traceparent.
func ValidTraceparent(value string) bool {
	_, ok := tracecontext.Parse(value)
	return ok
}

// Key pins all versions of one tenant aggregate to one broker partition.
func (m Message) Key() []byte { return []byte(m.TenantID + "/" + m.AggregateID) }

type Store interface {
	ClaimNext(context.Context, string, string, time.Duration) (Claim, bool, error)
	LoadClaimed(context.Context, Claim) (Message, error)
	Acknowledge(context.Context, Claim) error
	RecordFailure(context.Context, Claim, string, time.Duration) error
	BlockPoison(context.Context, Claim) error
}

type Broker interface {
	Publish(context.Context, Message) error
}

type Config struct {
	LeaseDuration  time.Duration
	PublishTimeout time.Duration
	Observer       observability.Observer
}

type Publisher struct {
	store          Store
	broker         Broker
	leaseDuration  time.Duration
	publishTimeout time.Duration
	observer       observability.Observer
}

func NewPublisher(store Store, broker Broker, config Config) (*Publisher, error) {
	if store == nil || broker == nil {
		return nil, errors.New("outbox store and broker are required")
	}
	if config.LeaseDuration == 0 {
		config.LeaseDuration = DefaultLeaseDuration
	}
	if config.PublishTimeout == 0 {
		config.PublishTimeout = DefaultPublishTimeout
	}
	if config.LeaseDuration <= 0 || config.LeaseDuration > maximumLeaseDuration {
		return nil, fmt.Errorf("publish lease must be in (0,%s]", maximumLeaseDuration)
	}
	if config.PublishTimeout <= 0 || config.PublishTimeout >= config.LeaseDuration {
		return nil, errors.New("publish timeout must be positive and shorter than the lease")
	}
	return &Publisher{store: store, broker: broker, leaseDuration: config.LeaseDuration, publishTimeout: config.PublishTimeout, observer: config.Observer}, nil
}

type Result struct {
	Claimed        bool
	Published      bool
	RetryScheduled bool
	Blocked        bool
	EventID        string
	ErrorCode      string
}

// RunOnce sends at most one event. Broker I/O happens outside a database transaction; the
// publish-head epoch fences final state changes if this worker pauses past its lease.
func (p *Publisher) RunOnce(ctx context.Context, tenantID, workerID string) (result Result, returnedErr error) {
	started := time.Now()
	var schemaVersion, retryCount int
	var traceID string
	defer func() {
		outcome := "error"
		if result.Blocked {
			outcome = "blocked"
		} else if returnedErr == nil {
			switch {
			case !result.Claimed:
				outcome = "no_work"
			case result.Published:
				outcome = "published"
			case result.RetryScheduled:
				outcome = "retry_scheduled"
			case result.Blocked:
				outcome = "blocked"
			}
		}
		observability.ObserveSafely(p.observer, observability.Event{
			Operation: "outbox.publish", Outcome: outcome, Duration: time.Since(started),
			SchemaVersion: schemaVersion, RetryCount: retryCount, TraceID: traceID,
		})
	}()
	claim, ok, err := p.store.ClaimNext(ctx, tenantID, workerID, p.leaseDuration)
	if err != nil || !ok {
		return Result{}, err
	}
	result = Result{Claimed: true, EventID: claim.EventID}
	retryCount = claim.AttemptCount
	message, err := p.store.LoadClaimed(ctx, claim)
	if err != nil {
		if errors.Is(err, ErrPoisonEnvelope) {
			if blockErr := p.store.BlockPoison(ctx, claim); blockErr != nil {
				return result, fmt.Errorf("persist blocked outbox envelope: %w", blockErr)
			}
			result.Blocked = true
			result.ErrorCode = "outbox_corrupt"
		}
		return result, err
	}
	schemaVersion = message.SchemaVersion
	if message.SchemaVersion == 2 {
		parsed, ok := tracecontext.Parse(message.Traceparent)
		if ok {
			traceID = parsed.TraceID
		}
	}
	publishCtx, cancel := context.WithTimeout(ctx, p.publishTimeout)
	err = p.broker.Publish(publishCtx, message)
	cancel()
	if err != nil {
		result.RetryScheduled = true
		result.ErrorCode = ClassifyBrokerError(err)
		delay := RetryDelay(claim.EventID, claim.AttemptCount+1)
		if recordErr := p.store.RecordFailure(ctx, claim, result.ErrorCode, delay); recordErr != nil {
			return result, fmt.Errorf("record outbox retry: %w", recordErr)
		}
		return result, nil
	}
	if err := p.store.Acknowledge(ctx, claim); err != nil {
		return result, err
	}
	result.Published = true
	return result, nil
}

func ClassifyBrokerError(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "broker_timeout"
	case errors.Is(err, ErrBrokerUnavailable), errors.Is(err, context.Canceled):
		return "broker_unavailable"
	case errors.Is(err, ErrBrokerRejected):
		return "broker_rejected"
	default:
		return "broker_error"
	}
}

// RetryDelay is deterministic full jitter over an exponential window. The event ID spreads
// retries across streams without persisting raw broker errors or requiring synchronized clocks.
func RetryDelay(eventID string, attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	window := time.Second
	for i := 1; i < attempt && window < maximumRetryDelay; i++ {
		window *= 2
	}
	if window > maximumRetryDelay {
		window = maximumRetryDelay
	}
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s:%d", eventID, attempt)))
	spread := uint64(window)
	jitter := time.Duration(binary.BigEndian.Uint64(sum[:8]) % spread)
	return jitter
}
