package kafkarelay

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sync"
	"time"

	"github.com/sanskarpan/keel/internal/orders/projector"
	kafka "github.com/segmentio/kafka-go"
)

var (
	groupIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)
)

// GroupReader is the manual-commit subset of kafka.Reader. Keeping it narrow makes the
// process-before-commit rule explicit and permits deterministic offset-loss tests.
type GroupReader interface {
	FetchMessage(context.Context) (kafka.Message, error)
	CommitMessages(context.Context, ...kafka.Message) error
	Close() error
}

// RecordProcessor durably applies, defers, deduplicates, or quarantines each record.
type RecordProcessor interface {
	ProcessRecord(context.Context, projector.Record) (projector.Result, error)
}

type Consumer struct {
	mu        sync.Mutex
	reader    GroupReader
	processor RecordProcessor
	brokers   []string
	topic     string
	groupID   string
	closed    bool
	secure    bool
	security  *SecurityConfig
}

func validateConsumerConfig(topic, groupID string, processor RecordProcessor) error {
	if !validOrderTopic(topic) {
		return errors.New("Kafka order topic name is invalid")
	}
	if !groupIDPattern.MatchString(groupID) {
		return errors.New("Kafka consumer group ID is invalid")
	}
	if processor == nil {
		return errors.New("Kafka record processor is required")
	}
	return nil
}

func newReader(addresses []string, topic, groupID string, security *SecurityConfig) (*kafka.Reader, error) {
	config := kafka.ReaderConfig{
		Brokers: addresses, Topic: topic, GroupID: groupID,
		MinBytes: 1, MaxBytes: 10 << 20, MaxWait: time.Second,
		CommitInterval: 0, StartOffset: kafka.FirstOffset,
	}
	if security != nil {
		dialer, err := secureKafkaDialer(*security)
		if err != nil {
			return nil, err
		}
		config.Dialer = dialer
	}
	return kafka.NewReader(config), nil
}

func newConsumer(brokers []string, topic, groupID string, processor RecordProcessor, security *SecurityConfig, local bool) (*Consumer, error) {
	if err := validateConsumerConfig(topic, groupID, processor); err != nil {
		return nil, err
	}
	var addresses []string
	var err error
	if local {
		addresses, err = validateLocalBrokers(brokers)
	} else {
		addresses, err = normalizeBrokers(brokers)
	}
	if err != nil {
		return nil, err
	}
	reader, err := newReader(addresses, topic, groupID, security)
	if err != nil {
		return nil, err
	}
	return &Consumer{reader: reader, processor: processor, brokers: addresses, topic: topic, groupID: groupID, secure: security != nil, security: cloneOptionalSecurity(security)}, nil
}

func cloneOptionalSecurity(security *SecurityConfig) *SecurityConfig {
	if security == nil {
		return nil
	}
	return cloneSecurityConfig(*security)
}

// NewLocalSynthetic is restricted to loopback and the local Compose Kafka alias.
func NewLocalSyntheticConsumer(brokers []string, topic, groupID string, processor RecordProcessor) (*Consumer, error) {
	return newConsumer(brokers, topic, groupID, processor, nil, true)
}

// NewSecureConsumer always configures verified TLS and SASL/SCRAM-SHA-512.
func NewSecureConsumer(brokers []string, topic, groupID string, processor RecordProcessor, security SecurityConfig) (*Consumer, error) {
	return newConsumer(brokers, topic, groupID, processor, &security, false)
}

// RotateSecurity replaces the reader and reconnects with fresh trust roots and
// credentials. RunOnce is serialized against the swap; pending offsets are safe
// to replay because projector inbox processing is idempotent.
func (c *Consumer) RotateSecurity(security SecurityConfig) error {
	if c == nil {
		return errors.New("Kafka consumer is not configured")
	}
	if !c.secure {
		return errors.New("security rotation is available only for authenticated Kafka consumers")
	}
	reader, err := newReader(c.brokers, c.topic, c.groupID, &security)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		_ = reader.Close()
		return errors.New("Kafka consumer is closed")
	}
	old := c.reader
	oldSecurity := c.security
	c.reader = reader
	c.security = cloneSecurityConfig(security)
	if err := old.Close(); err != nil {
		return redactKafkaError(fmt.Errorf("close previous Kafka reader generation: %w", err), oldSecurity)
	}
	return nil
}

// NewConsumerWithReader installs a reader, primarily for testing failure boundaries.
func NewConsumerWithReader(reader GroupReader, processor RecordProcessor) (*Consumer, error) {
	if reader == nil || processor == nil {
		return nil, errors.New("Kafka reader and record processor are required")
	}
	return &Consumer{reader: reader, processor: processor}, nil
}

// RunOnce fetches one record, commits all durable processor outcomes, and never commits
// if processing or the durable offset commit fails. A retry after a lost commit is safe
// because the projector inbox deduplicates the database effect.
func (c *Consumer) RunOnce(ctx context.Context) (projector.Result, error) {
	if c == nil || c.reader == nil || c.processor == nil {
		return projector.Result{}, errors.New("Kafka consumer is not configured")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	message, err := c.reader.FetchMessage(ctx)
	if err != nil {
		return projector.Result{}, redactKafkaError(err, c.security)
	}
	record := projector.Record{
		Topic: message.Topic, Partition: message.Partition, Offset: message.Offset,
		Key: append([]byte(nil), message.Key...), Value: append([]byte(nil), message.Value...),
		Headers: make([]projector.Header, 0, len(message.Headers)),
	}
	for _, header := range message.Headers {
		record.Headers = append(record.Headers, projector.Header{Key: header.Key, Value: append([]byte(nil), header.Value...)})
	}
	result, err := c.processor.ProcessRecord(ctx, record)
	if err != nil {
		return projector.Result{}, redactKafkaError(err, c.security)
	}
	switch result.Disposition {
	case projector.Applied, projector.Duplicate, projector.Deferred, projector.Quarantined:
	default:
		return projector.Result{}, fmt.Errorf("processor returned non-durable disposition %q", result.Disposition)
	}
	if err := c.reader.CommitMessages(ctx, message); err != nil {
		return projector.Result{}, redactKafkaError(fmt.Errorf("commit Kafka offset after durable processing: %w", err), c.security)
	}
	return result, nil
}

func (c *Consumer) Close() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.reader == nil {
		return nil
	}
	c.closed = true
	return redactKafkaError(c.reader.Close(), c.security)
}
