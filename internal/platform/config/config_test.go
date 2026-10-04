package config

import (
	"log/slog"
	"testing"
	"time"
)

func TestLoadFromDefaults(t *testing.T) {
	cfg, err := LoadFrom(func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Role != RoleAPI || cfg.Environment != EnvironmentDevelopment || cfg.ListenAddress != "127.0.0.1:8080" || cfg.LogLevel != slog.LevelInfo || cfg.ShutdownTimeout != 15*time.Second {
		t.Fatalf("unexpected defaults: %#v", cfg)
	}
}

func TestLoadFromValidConfiguration(t *testing.T) {
	values := map[string]string{
		"KEEL_ROLE":             "webhook-worker",
		"KEEL_ENVIRONMENT":      "staging",
		"KEEL_LISTEN_ADDRESS":   "[::1]:9090",
		"KEEL_LOG_LEVEL":        "WARN",
		"KEEL_SHUTDOWN_TIMEOUT": "45s",
	}
	cfg, err := LoadFrom(func(key string) string { return values[key] })
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Role != RoleWebhookWorker || cfg.Environment != EnvironmentStaging || cfg.ListenAddress != "[::1]:9090" || cfg.LogLevel != slog.LevelWarn || cfg.ShutdownTimeout != 45*time.Second {
		t.Fatalf("unexpected configuration: %#v", cfg)
	}
}

func TestLoadFromRejectsInvalidValuesWithoutEchoingThem(t *testing.T) {
	cases := []struct {
		name   string
		key    string
		value  string
		secret string
	}{
		{name: "role", key: "KEEL_ROLE", value: "bad-role-with-secret", secret: "bad-role-with-secret"},
		{name: "environment", key: "KEEL_ENVIRONMENT", value: "production-ish-secret", secret: "production-ish-secret"},
		{name: "log level", key: "KEEL_LOG_LEVEL", value: "secret-debug-secret", secret: "secret-debug-secret"},
		{name: "address", key: "KEEL_LISTEN_ADDRESS", value: "bad-secret-address", secret: "bad-secret-address"},
		{name: "invalid host", key: "KEEL_LISTEN_ADDRESS", value: "bad/host:8080", secret: "bad/host:8080"},
		{name: "whitespace host", key: "KEEL_LISTEN_ADDRESS", value: "bad host:8080", secret: "bad host:8080"},
		{name: "timeout", key: "KEEL_SHUTDOWN_TIMEOUT", value: "900s-secret", secret: "900s-secret"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadFrom(func(key string) string {
				if key == tc.key {
					return tc.value
				}
				return ""
			})
			if err == nil {
				t.Fatal("expected invalid configuration error")
			}
			if got := err.Error(); got == "" || contains(got, tc.secret) {
				t.Fatalf("error is empty or leaked the invalid value: %q", got)
			}
		})
	}
}

func TestLoadFromRequiresLookup(t *testing.T) {
	if _, err := LoadFrom(nil); err == nil {
		t.Fatal("expected nil lookup to fail")
	}
}

func contains(value, part string) bool {
	for i := 0; i+len(part) <= len(value); i++ {
		if value[i:i+len(part)] == part {
			return true
		}
	}
	return false
}
