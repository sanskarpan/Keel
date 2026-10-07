// Package kafkarelay adapts the order outbox contract to Kafka's synchronous produce API.
package kafkarelay

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sync"
	"time"

	"github.com/sanskarpan/keel/internal/orders/outbox"
	kafka "github.com/segmentio/kafka-go"
)

var orderTopicPattern = regexp.MustCompile(`^keel\.[a-z0-9-]+\.orders\.v1$`)

func validOrderTopic(topic string) bool {
	return len(topic) <= 249 && orderTopicPattern.MatchString(topic)
}

type Broker struct {
	mu       sync.Mutex
	closed   bool
	brokers  []string
	topic    string
	security *SecurityConfig
	writer   *kafka.Writer
}

func validateTopic(topic string) error {
	if !validOrderTopic(topic) {
		return errors.New("Kafka order topic name is invalid")
	}
	return nil
}

func newWriter(addresses []string, topic string, security *SecurityConfig) (*kafka.Writer, error) {
	writer := &kafka.Writer{
		Addr: kafka.TCP(addresses...), Topic: topic, Balancer: &kafka.Hash{},
		MaxAttempts: 1, WriteBackoffMin: 50 * time.Millisecond, WriteBackoffMax: 50 * time.Millisecond,
		ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second,
		RequiredAcks: kafka.RequireAll, Async: false, AllowAutoTopicCreation: false,
	}
	if security != nil {
		transport, err := secureKafkaTransport(*security)
		if err != nil {
			return nil, err
		}
		writer.Transport = transport
	}
	return writer, nil
}

// NewLocalSynthetic is the only plaintext constructor. It accepts only loopback
// brokers or the fixed Kafka alias used by the local Compose profile.
func NewLocalSyntheticBroker(brokers []string, topic string) (*Broker, error) {
	addresses, err := validateLocalBrokers(brokers)
	if err != nil {
		return nil, err
	}
	if err := validateTopic(topic); err != nil {
		return nil, err
	}
	writer, err := newWriter(addresses, topic, nil)
	if err != nil {
		return nil, err
	}
	return &Broker{brokers: addresses, topic: topic, writer: writer}, nil
}

// NewSecure requires verified TLS and SASL/SCRAM-SHA-512 for every broker,
// including loopback endpoints.
func NewSecure(brokers []string, topic string, security SecurityConfig) (*Broker, error) {
	addresses, err := normalizeBrokers(brokers)
	if err != nil {
		return nil, err
	}
	if err := validateTopic(topic); err != nil {
		return nil, err
	}
	writer, err := newWriter(addresses, topic, &security)
	if err != nil {
		return nil, err
	}
	return &Broker{brokers: addresses, topic: topic, security: cloneSecurityConfig(security), writer: writer}, nil
}

func (b *Broker) replaceSecurity(security SecurityConfig) error {
	if b == nil {
		return errors.New("Kafka writer is not configured")
	}
	writer, err := newWriter(b.brokers, b.topic, &security)
	if err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		_ = writer.Close()
		return errors.New("Kafka writer is closed")
	}
	old := b.writer
	oldSecurity := b.security
	b.writer = writer
	b.security = cloneSecurityConfig(security)
	if err := old.Close(); err != nil {
		return redactKafkaError(fmt.Errorf("close previous Kafka connection generation: %w", err), oldSecurity)
	}
	return nil
}

// RotateSecurity validates the replacement credentials/trust before pausing
// writes, then swaps generations under the write lock. Existing in-flight writes
// finish before the previous transport is closed.
func (b *Broker) RotateSecurity(security SecurityConfig) error {
	return b.replaceSecurity(security)
}

func (b *Broker) Publish(ctx context.Context, message outbox.Message) error {
	if b == nil {
		return errors.New("Kafka writer is not configured")
	}
	if message.SchemaVersion < 1 || message.SchemaVersion > 2 || message.TenantID == "" || message.AggregateID == "" || message.EventID == "" || message.AggregateVersion < 1 || len(message.Payload) == 0 ||
		(message.SchemaVersion == 1 && message.Traceparent != "") ||
		(message.SchemaVersion == 2 && (message.Traceparent == "" || !outbox.ValidTraceparent(message.Traceparent))) {
		return errors.New("outbox message is incomplete")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed || b.writer == nil {
		return errors.New("Kafka writer is closed")
	}
	err := b.writer.WriteMessages(ctx, kafka.Message{
		Key:   message.Key(),
		Value: message.Payload,
		Headers: append([]kafka.Header{
			{Key: "event_id", Value: []byte(message.EventID)},
			{Key: "schema_version", Value: []byte(fmt.Sprintf("%d", message.SchemaVersion))},
			{Key: "aggregate_version", Value: []byte(fmt.Sprintf("%d", message.AggregateVersion))},
		}, func() []kafka.Header {
			if message.Traceparent == "" {
				return nil
			}
			return []kafka.Header{{Key: "traceparent", Value: []byte(message.Traceparent)}}
		}()...),
	})
	return redactKafkaError(err, b.security)
}

func (b *Broker) Close() error {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil
	}
	b.closed = true
	return redactKafkaError(b.writer.Close(), b.security)
}
