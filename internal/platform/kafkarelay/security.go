package kafkarelay

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	kafka "github.com/segmentio/kafka-go"
	"github.com/segmentio/kafka-go/sasl/scram"
)

// SecurityConfig describes one authenticated Kafka connection generation. TLS must
// contain an explicitly configured CA pool; credentials are never included in errors.
// Callers should source each value from their secret/configuration provider.
type SecurityConfig struct {
	TLS      *tls.Config
	Username string
	Password string
}

func normalizeBrokers(brokers []string) ([]string, error) {
	if len(brokers) == 0 {
		return nil, errors.New("at least one Kafka broker address is required")
	}
	addresses := make([]string, 0, len(brokers))
	seen := make(map[string]struct{}, len(brokers))
	for _, address := range brokers {
		address = strings.TrimSpace(address)
		host, port, err := net.SplitHostPort(address)
		portNumber, portErr := strconv.Atoi(port)
		if err != nil || host == "" || strings.ContainsAny(host, "@ /\\\t\r\n") || portErr != nil || portNumber < 1 || portNumber > 65535 {
			return nil, errors.New("invalid Kafka broker address")
		}
		if _, exists := seen[address]; exists {
			continue
		}
		seen[address] = struct{}{}
		addresses = append(addresses, address)
	}
	return addresses, nil
}

func validateLocalBrokers(brokers []string) ([]string, error) {
	addresses, err := normalizeBrokers(brokers)
	if err != nil {
		return nil, err
	}
	for _, address := range addresses {
		host, _, _ := net.SplitHostPort(address)
		ip := net.ParseIP(host)
		if !strings.EqualFold(host, "localhost") && !strings.EqualFold(host, "kafka") && (ip == nil || !ip.IsLoopback()) {
			return nil, errors.New("plaintext Kafka is restricted to loopback or the local Compose broker alias")
		}
	}
	return addresses, nil
}

func validateSecurityConfig(config SecurityConfig) (*tls.Config, error) {
	if config.TLS == nil {
		return nil, errors.New("Kafka TLS configuration is required")
	}
	if config.TLS.InsecureSkipVerify || config.TLS.VerifyPeerCertificate != nil || config.TLS.VerifyConnection != nil {
		return nil, errors.New("Kafka TLS certificate verification cannot be overridden")
	}
	if config.TLS.KeyLogWriter != nil {
		return nil, errors.New("Kafka TLS key logging is not supported")
	}
	if config.TLS.RootCAs == nil || len(config.TLS.RootCAs.Subjects()) == 0 {
		return nil, errors.New("Kafka TLS root CA pool must be explicitly configured and non-empty")
	}
	if config.TLS.MinVersion != 0 && config.TLS.MinVersion < tls.VersionTLS12 {
		return nil, errors.New("Kafka TLS minimum version must be TLS 1.2 or newer")
	}
	if len(config.TLS.Certificates) != 0 || config.TLS.GetClientCertificate != nil {
		return nil, errors.New("Kafka broker authentication uses SASL/SCRAM; client certificates are unsupported")
	}
	if strings.TrimSpace(config.Username) == "" || config.Password == "" {
		return nil, errors.New("Kafka SASL/SCRAM credentials are required")
	}
	if len(config.Username) > 256 || len(config.Password) > 1024 {
		return nil, errors.New("Kafka SASL/SCRAM credentials exceed configured bounds")
	}
	tlsConfig := config.TLS.Clone()
	tlsConfig.RootCAs = config.TLS.RootCAs.Clone()
	if tlsConfig.MinVersion == 0 {
		tlsConfig.MinVersion = tls.VersionTLS12
	}
	// Session caches can resume a prior peer session after a root-certificate
	// rotation. Each security generation must perform a full verified handshake.
	tlsConfig.ClientSessionCache = nil
	if tlsConfig.ServerName != "" && (len(tlsConfig.ServerName) > 253 || strings.ContainsAny(tlsConfig.ServerName, " /\\")) {
		return nil, errors.New("Kafka TLS server name is invalid")
	}
	return tlsConfig, nil
}

func cloneSecurityConfig(config SecurityConfig) *SecurityConfig {
	copy := config
	if config.TLS != nil {
		copy.TLS = config.TLS.Clone()
		if config.TLS.RootCAs != nil {
			copy.TLS.RootCAs = config.TLS.RootCAs.Clone()
		}
	}
	return &copy
}

func secureKafkaTransport(config SecurityConfig) (*kafka.Transport, error) {
	tlsConfig, err := validateSecurityConfig(config)
	if err != nil {
		return nil, err
	}
	mechanism, err := scram.Mechanism(scram.SHA512, config.Username, config.Password)
	if err != nil {
		return nil, fmt.Errorf("configure Kafka SASL/SCRAM mechanism: %w", err)
	}
	return &kafka.Transport{TLS: tlsConfig, SASL: mechanism}, nil
}

func secureKafkaDialer(config SecurityConfig) (*kafka.Dialer, error) {
	tlsConfig, err := validateSecurityConfig(config)
	if err != nil {
		return nil, err
	}
	mechanism, err := scram.Mechanism(scram.SHA512, config.Username, config.Password)
	if err != nil {
		return nil, fmt.Errorf("configure Kafka SASL/SCRAM mechanism: %w", err)
	}
	return &kafka.Dialer{TLS: tlsConfig, SASLMechanism: mechanism}, nil
}

func redactKafkaError(err error, config *SecurityConfig) error {
	if err == nil || config == nil {
		return err
	}
	message := err.Error()
	for _, secret := range []string{config.Username, config.Password} {
		if secret != "" {
			message = strings.ReplaceAll(message, secret, "[REDACTED]")
		}
	}
	return errors.New(message)
}

// RootCAsFromPEM creates an isolated trust pool from an explicit CA bundle. It does
// not append system roots, so trust changes are deliberate and can be rotated.
func RootCAsFromPEM(pem []byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if len(pem) == 0 || !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("Kafka TLS CA bundle is invalid")
	}
	return pool, nil
}
