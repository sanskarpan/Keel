package kafkarelay

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
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
}

// NewConsumer creates a consumer-group reader with synchronous explicit offset commits.
// The first group run starts at the earliest retained record; inbox uniqueness makes replay safe.
func NewConsumer(brokers []string, topic, groupID string, processor RecordProcessor) (*Consumer, error) {
	if len(brokers) == 0 {
		return nil, errors.New("at least one Kafka broker address is required")
	}
	if !validOrderTopic(topic) {
		return nil, errors.New("Kafka order topic name is invalid")
	}
	if !groupIDPattern.MatchString(groupID) {
		return nil, errors.New("Kafka consumer group ID is invalid")
	}
	if processor == nil {
		return nil, errors.New("Kafka record processor is required")
	}
	addresses := make([]string, 0, len(brokers))
	seen := make(map[string]struct{}, len(brokers))
	for _, address := range brokers {
		address = strings.TrimSpace(address)
		host, port, err := net.SplitHostPort(address)
		if err != nil || host == "" || port == "" {
			return nil, fmt.Errorf("invalid Kafka broker address %q", address)
		}
		if _, exists := seen[address]; exists {
			continue
		}
		seen[address] = struct{}{}
		addresses = append(addresses, address)
	}
	reader := kafka.NewReader(kafka.ReaderConfig{
		Brokers: addresses, Topic: topic, GroupID: groupID,
		MinBytes: 1, MaxBytes: 10 << 20, MaxWait: time.Second,
		CommitInterval: 0, StartOffset: kafka.FirstOffset,
	})
	return NewConsumerWithReader(reader, processor)
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
		return projector.Result{}, err
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
		return projector.Result{}, err
	}
	switch result.Disposition {
	case projector.Applied, projector.Duplicate, projector.Deferred, projector.Quarantined:
	default:
		return projector.Result{}, fmt.Errorf("processor returned non-durable disposition %q", result.Disposition)
	}
	if err := c.reader.CommitMessages(ctx, message); err != nil {
		return projector.Result{}, fmt.Errorf("commit Kafka offset after durable processing: %w", err)
	}
	return result, nil
}

func (c *Consumer) Close() error {
	if c == nil || c.reader == nil {
		return nil
	}
	return c.reader.Close()
}
