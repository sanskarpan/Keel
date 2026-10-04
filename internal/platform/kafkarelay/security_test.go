package kafkarelay

import (
	"crypto/tls"
	"crypto/x509"
	"strings"
	"testing"
)

func validSecurityConfig() SecurityConfig {
	roots := x509.NewCertPool()
	roots.AddCert(&x509.Certificate{RawSubject: []byte("test-root")})
	return SecurityConfig{
		TLS: &tls.Config{RootCAs: roots}, Username: "keel-test-user", Password: "keel-test-password",
	}
}

func TestSecureConfigRequiresVerifiedTLSAndSCRAMCredentials(t *testing.T) {
	tests := []struct {
		name string
		edit func(*SecurityConfig)
	}{
		{"missing TLS", func(c *SecurityConfig) { c.TLS = nil }},
		{"system roots only", func(c *SecurityConfig) { c.TLS.RootCAs = nil }},
		{"empty roots", func(c *SecurityConfig) { c.TLS.RootCAs = x509.NewCertPool() }},
		{"verification disabled", func(c *SecurityConfig) { c.TLS.InsecureSkipVerify = true }},
		{"custom verifier", func(c *SecurityConfig) { c.TLS.VerifyConnection = func(tls.ConnectionState) error { return nil } }},
		{"TLS key logging", func(c *SecurityConfig) { c.TLS.KeyLogWriter = &strings.Builder{} }},
		{"old TLS", func(c *SecurityConfig) { c.TLS.MinVersion = tls.VersionTLS10 }},
		{"missing credentials", func(c *SecurityConfig) { c.Password = "" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := validSecurityConfig()
			tt.edit(&config)
			if _, err := validateSecurityConfig(config); err == nil {
				t.Fatal("invalid Kafka security config was accepted")
			}
		})
	}
	config := validSecurityConfig()
	tlsConfig, err := validateSecurityConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	if tlsConfig.MinVersion != tls.VersionTLS12 || tlsConfig.InsecureSkipVerify || tlsConfig.RootCAs == config.TLS.RootCAs {
		t.Fatal("validated transport did not enforce TLS 1.2 and clone verified trust roots")
	}
	if tlsConfig.ClientSessionCache != nil {
		t.Fatal("validated transport retained a TLS session cache across security generations")
	}
}

func TestPlaintextConstructorIsExplicitlyLocalOnly(t *testing.T) {
	for _, broker := range []string{"broker.example:9092", "192.0.2.10:9092"} {
		if _, err := NewLocalSyntheticBroker([]string{broker}, "keel.test.orders.v1"); err == nil {
			t.Fatalf("accepted remote plaintext broker %q", broker)
		}
	}
	for _, broker := range []string{"localhost:9092", "127.0.0.1:9092", "kafka:9092"} {
		brokerClient, err := NewLocalSyntheticBroker([]string{broker}, "keel.test.orders.v1")
		if err != nil {
			t.Fatalf("rejected local broker %q: %v", broker, err)
		}
		if err := brokerClient.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestBrokerAddressRejectsEmbeddedCredentialsAndInvalidPorts(t *testing.T) {
	for _, address := range []string{"user:secret@broker.example:9092", "broker.example:secret"} {
		if _, err := normalizeBrokers([]string{address}); err == nil || strings.Contains(err.Error(), "secret") {
			t.Fatalf("broker address %q was accepted or echoed in its error: %v", address, err)
		}
	}
}

func TestSecureConstructorsNeverFallBackToPlaintext(t *testing.T) {
	if _, err := NewSecure([]string{"localhost:9092"}, "keel.test.orders.v1", SecurityConfig{}); err == nil {
		t.Fatal("secure producer accepted missing security configuration")
	}
	if _, err := NewSecureConsumer([]string{"localhost:9092"}, "keel.test.orders.v1", "projector", &fakeRecordProcessor{}, SecurityConfig{}); err == nil {
		t.Fatal("secure consumer accepted missing security configuration")
	}
}

func TestKafkaErrorsRedactCredentials(t *testing.T) {
	config := validSecurityConfig()
	err := redactKafkaError(errString("user=keel-test-user password=keel-test-password"), &config)
	if strings.Contains(err.Error(), config.Username) || strings.Contains(err.Error(), config.Password) {
		t.Fatalf("Kafka error leaked credentials: %s", err)
	}
}

type stringError string

func (e stringError) Error() string { return string(e) }

func errString(s string) error { return stringError(s) }
