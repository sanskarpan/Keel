// Package config loads and validates non-secret process configuration.
package config

import (
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"
)

type Role string

type Environment string

const (
	RoleAPI                Role = "api"
	RoleRelay              Role = "relay"
	RoleProjector          Role = "projector"
	RoleAIExecutor         Role = "ai-executor"
	RoleTemporalWorker     Role = "temporal-worker"
	RoleWebhookWorker      Role = "webhook-worker"
	RoleBillingWorker      Role = "billing-worker"
	RoleNotificationWorker Role = "notification-worker"
)

const (
	EnvironmentDevelopment Environment = "development"
	EnvironmentTest        Environment = "test"
	EnvironmentStaging     Environment = "staging"
	EnvironmentProduction  Environment = "production"
)

type Config struct {
	Role            Role
	Environment     Environment
	ListenAddress   string
	LogLevel        slog.Level
	ShutdownTimeout time.Duration
}

// Load reads the KEEL_* environment variables and applies safe development defaults.
func Load() (Config, error) {
	return LoadFrom(func(key string) string { return lookupEnvironment(key) })
}

// LoadFrom permits deterministic configuration tests without mutating process state.
func LoadFrom(lookup func(string) string) (Config, error) {
	if lookup == nil {
		return Config{}, fmt.Errorf("configuration lookup function is required")
	}

	cfg := Config{
		Role:            Role(valueOrDefault(lookup("KEEL_ROLE"), string(RoleAPI))),
		Environment:     Environment(valueOrDefault(lookup("KEEL_ENVIRONMENT"), string(EnvironmentDevelopment))),
		ListenAddress:   valueOrDefault(lookup("KEEL_LISTEN_ADDRESS"), "127.0.0.1:8080"),
		ShutdownTimeout: 15 * time.Second,
	}

	if !supportedRole(cfg.Role) {
		return Config{}, fmt.Errorf("KEEL_ROLE must name a supported runtime role")
	}
	if !supportedEnvironment(cfg.Environment) {
		return Config{}, fmt.Errorf("KEEL_ENVIRONMENT must be development, test, staging, or production")
	}
	if err := validateListenAddress(cfg.ListenAddress); err != nil {
		return Config{}, err
	}

	level, err := parseLogLevel(valueOrDefault(lookup("KEEL_LOG_LEVEL"), "info"))
	if err != nil {
		return Config{}, err
	}
	cfg.LogLevel = level

	if raw := lookup("KEEL_SHUTDOWN_TIMEOUT"); raw != "" {
		timeout, err := time.ParseDuration(raw)
		if err != nil || timeout < time.Second || timeout > 2*time.Minute {
			return Config{}, fmt.Errorf("KEEL_SHUTDOWN_TIMEOUT must be between 1s and 2m")
		}
		cfg.ShutdownTimeout = timeout
	}

	return cfg, nil
}

func valueOrDefault(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return strings.TrimSpace(value)
}

func supportedRole(role Role) bool {
	switch role {
	case RoleAPI, RoleRelay, RoleProjector, RoleAIExecutor, RoleTemporalWorker, RoleWebhookWorker, RoleBillingWorker, RoleNotificationWorker:
		return true
	default:
		return false
	}
}

func supportedEnvironment(environment Environment) bool {
	switch environment {
	case EnvironmentDevelopment, EnvironmentTest, EnvironmentStaging, EnvironmentProduction:
		return true
	default:
		return false
	}
}

func parseLogLevel(raw string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("KEEL_LOG_LEVEL must be debug, info, warn, or error")
	}
}

func validateListenAddress(address string) error {
	host, rawPort, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("KEEL_LISTEN_ADDRESS must be a host:port address")
	}
	if !validHost(host) {
		return fmt.Errorf("KEEL_LISTEN_ADDRESS must contain a valid IP address or DNS hostname")
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("KEEL_LISTEN_ADDRESS must contain a port from 1 through 65535")
	}
	return nil
}

func validHost(host string) bool {
	if host == "" || net.ParseIP(host) != nil {
		return true
	}
	if len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || !isASCIIAlphaNumeric(label[0]) || !isASCIIAlphaNumeric(label[len(label)-1]) {
			return false
		}
		for i := 1; i < len(label)-1; i++ {
			if !isASCIIAlphaNumeric(label[i]) && label[i] != '-' {
				return false
			}
		}
	}
	return true
}

func isASCIIAlphaNumeric(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9'
}
