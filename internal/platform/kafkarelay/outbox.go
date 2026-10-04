// Package kafkarelay adapts the order outbox contract to Kafka's synchronous produce API.
package kafkarelay

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/sanskarpan/keel/internal/orders/outbox"
	kafka "github.com/segmentio/kafka-go"
)

var topicPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,249}$`)

type Broker struct {
	writer *kafka.Writer
}

func New(brokers []string, topic string) (*Broker, error) {
	if len(brokers) == 0 {
		return nil, errors.New("at least one Kafka broker address is required")
	}
	if !topicPattern.MatchString(topic) || topic == "." || topic == ".." {
		return nil, errors.New("Kafka topic name is invalid")
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
	writer := &kafka.Writer{
		Addr:                   kafka.TCP(addresses...),
		Topic:                  topic,
		Balancer:               &kafka.Hash{},
		MaxAttempts:            1,
		WriteBackoffMin:        50 * time.Millisecond,
		WriteBackoffMax:        50 * time.Millisecond,
		ReadTimeout:            10 * time.Second,
		WriteTimeout:           10 * time.Second,
		RequiredAcks:           kafka.RequireAll,
		Async:                  false,
		AllowAutoTopicCreation: false,
	}
	return &Broker{writer: writer}, nil
}

func (b *Broker) Publish(ctx context.Context, message outbox.Message) error {
	if b == nil || b.writer == nil {
		return errors.New("Kafka writer is not configured")
	}
	if message.SchemaVersion < 1 || message.TenantID == "" || message.AggregateID == "" || message.EventID == "" || message.AggregateVersion < 1 || len(message.Payload) == 0 {
		return errors.New("outbox message is incomplete")
	}
	return b.writer.WriteMessages(ctx, kafka.Message{
		Key:   message.Key(),
		Value: message.Payload,
		Headers: []kafka.Header{
			{Key: "event_id", Value: []byte(message.EventID)},
			{Key: "schema_version", Value: []byte(fmt.Sprintf("%d", message.SchemaVersion))},
			{Key: "aggregate_version", Value: []byte(fmt.Sprintf("%d", message.AggregateVersion))},
		},
	})
}

func (b *Broker) Close() error {
	if b == nil || b.writer == nil {
		return nil
	}
	return b.writer.Close()
}
