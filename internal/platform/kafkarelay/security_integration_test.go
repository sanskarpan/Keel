package kafkarelay

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/sanskarpan/keel/internal/orders/outbox"
	"github.com/sanskarpan/keel/internal/orders/projector"
)

func TestAuthenticatedKafkaBrokerIntegration(t *testing.T) {
	brokers := os.Getenv("KEEL_TEST_KAFKA_TLS_BROKERS")
	if brokers == "" {
		t.Skip("secure Kafka integration broker is not configured")
	}
	topic := os.Getenv("KEEL_TEST_KAFKA_TLS_TOPIC")
	caPath := os.Getenv("KEEL_TEST_KAFKA_TLS_CA")
	username := os.Getenv("KEEL_TEST_KAFKA_TLS_USERNAME")
	password := os.Getenv("KEEL_TEST_KAFKA_TLS_PASSWORD")
	rotatedUsername := os.Getenv("KEEL_TEST_KAFKA_TLS_ROTATED_USERNAME")
	rotatedPassword := os.Getenv("KEEL_TEST_KAFKA_TLS_ROTATED_PASSWORD")
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		t.Fatal("read secure Kafka CA bundle")
	}
	roots, err := RootCAsFromPEM(caPEM)
	if err != nil {
		t.Fatal(err)
	}
	makeConfig := func(user, secret, serverName string, pool *x509.CertPool) SecurityConfig {
		return SecurityConfig{TLS: &tls.Config{RootCAs: pool, ServerName: serverName}, Username: user, Password: secret}
	}
	valid := makeConfig(username, password, "localhost", roots)
	wrongCAPEM, err := os.ReadFile(os.Getenv("KEEL_TEST_KAFKA_TLS_WRONG_CA"))
	if err != nil {
		t.Fatal("read wrong Kafka CA fixture")
	}
	invalidRoots, err := RootCAsFromPEM(wrongCAPEM)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		config SecurityConfig
	}{
		{"untrusted CA", makeConfig(username, password, "localhost", invalidRoots)},
		{"hostname mismatch", makeConfig(username, password, "wrong-host.invalid", roots)},
		{"rejected password", makeConfig(username, "deliberately-invalid-password", "localhost", roots)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			broker, err := NewSecure(strings.Split(brokers, ","), topic, tc.config)
			if err != nil {
				t.Fatal(err)
			}
			defer broker.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			if err := broker.Publish(ctx, testOutboxMessage("should-fail")); err == nil {
				t.Fatal("Kafka broker accepted an invalid TLS/authentication configuration")
			} else if strings.Contains(err.Error(), tc.config.Username) || strings.Contains(err.Error(), tc.config.Password) {
				t.Fatalf("Kafka transport error exposed configured credentials: %v", err)
			}
		})
	}

	producer, err := NewSecure(strings.Split(brokers, ","), topic, valid)
	if err != nil {
		t.Fatal(err)
	}
	defer producer.Close()
	for _, event := range []string{"secure-before-rotation", "secure-after-rotation"} {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err = producer.Publish(ctx, testOutboxMessage(event))
		cancel()
		if err != nil {
			t.Fatalf("publish authenticated TLS event: %v", err)
		}
		if event == "secure-before-rotation" {
			if err := producer.RotateSecurity(makeConfig(rotatedUsername, rotatedPassword, "localhost", roots)); err != nil {
				t.Fatal(err)
			}
		}
	}
	processor := &fakeRecordProcessor{results: []projector.Result{{Disposition: projector.Applied}}}
	consumer, err := NewSecureConsumer(strings.Split(brokers, ","), topic, "secure-rotation-"+fmt.Sprint(time.Now().UnixNano()), processor, valid)
	if err != nil {
		t.Fatal(err)
	}
	defer consumer.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for i := 0; i < 2; i++ {
		if _, err := consumer.RunOnce(ctx); err != nil {
			t.Fatalf("consume authenticated TLS event %d: %v", i, err)
		}
		if i == 0 {
			if err := consumer.RotateSecurity(makeConfig(rotatedUsername, rotatedPassword, "localhost", roots)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if processor.calls != 2 {
		t.Fatalf("consumed %d messages after connection rotation, want 2", processor.calls)
	}
}

func testOutboxMessage(eventID string) outbox.Message {
	return outbox.Message{SchemaVersion: 1, TenantID: "secure-test", AggregateID: eventID, EventID: eventID, AggregateVersion: 1, Payload: []byte(`{"event_id":"` + eventID + `"}`)}
}
