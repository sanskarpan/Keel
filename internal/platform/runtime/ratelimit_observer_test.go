package runtime

import (
	"strings"
	"testing"
	"time"

	"github.com/sanskarpan/keel/internal/platform/config"
)

func TestLoadRateLimitObserverSettings(t *testing.T) {
	values := map[string]string{
		rateLimitObserverDBEnv:       "postgres://observer:secret@db.internal:5432/keel?sslmode=verify-full",
		rateLimitObserverRegionEnv:   "us-east-1",
		rateLimitObserverIntervalEnv: "7s",
		rateLimitObserverTimeoutEnv:  "2s",
	}
	settings, err := loadRateLimitObserverSettings(config.EnvironmentProduction, func(key string) string { return values[key] })
	if err != nil {
		t.Fatal(err)
	}
	if settings.databaseURL != values[rateLimitObserverDBEnv] || settings.region != "us-east-1" || settings.interval != 7*time.Second || settings.queryTimeout != 2*time.Second {
		t.Fatalf("unexpected observer settings: %#v", settings)
	}
}

func TestLoadRateLimitObserverSettingsDefaultsAndTLS(t *testing.T) {
	values := map[string]string{
		rateLimitObserverDBEnv:     "postgres://observer:secret@localhost:5432/keel?sslmode=disable",
		rateLimitObserverRegionEnv: "local-dev",
	}
	settings, err := loadRateLimitObserverSettings(config.EnvironmentDevelopment, func(key string) string { return values[key] })
	if err != nil {
		t.Fatal(err)
	}
	if settings.interval != 5*time.Second || settings.queryTimeout != time.Second {
		t.Fatalf("unexpected default refresh timing: %#v", settings)
	}
	if _, err := loadRateLimitObserverSettings(config.EnvironmentProduction, func(key string) string { return values[key] }); err == nil {
		t.Fatal("production observer accepted sslmode=disable")
	}
}

func TestLoadRateLimitObserverSettingsRejectsInvalidOrAmbiguousValues(t *testing.T) {
	base := map[string]string{
		rateLimitObserverDBEnv:     "postgres://observer:top-secret@db.internal:5432/keel?sslmode=verify-full",
		rateLimitObserverRegionEnv: "us-east-1",
	}
	cases := []struct {
		name   string
		key    string
		value  string
		delete bool
	}{
		{name: "missing database URL", key: rateLimitObserverDBEnv, delete: true},
		{name: "invalid region", key: rateLimitObserverRegionEnv, value: "US-EAST-1"},
		{name: "invalid URL", key: rateLimitObserverDBEnv, value: "postgres://top-secret"},
		{name: "duplicate TLS mode", key: rateLimitObserverDBEnv, value: "postgres://observer:top-secret@db.internal:5432/keel?sslmode=verify-full&sslmode=disable"},
		{name: "unbounded interval", key: rateLimitObserverIntervalEnv, value: "61s"},
		{name: "timeout exceeds interval", key: rateLimitObserverTimeoutEnv, value: "6s"},
		{name: "invalid duration", key: rateLimitObserverIntervalEnv, value: "fast"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			values := make(map[string]string, len(base)+1)
			for key, value := range base {
				values[key] = value
			}
			if tc.delete {
				delete(values, tc.key)
			} else {
				values[tc.key] = tc.value
			}
			_, err := loadRateLimitObserverSettings(config.EnvironmentProduction, func(key string) string { return values[key] })
			if err == nil {
				t.Fatal("invalid observer configuration was accepted")
			}
			if got := err.Error(); got == "" || strings.Contains(got, "top-secret") || strings.Contains(got, "observer:secret") {
				t.Fatalf("configuration error leaked credentials: %q", got)
			}
		})
	}
}

func TestRegistryForRegistersRateLimitObserver(t *testing.T) {
	cfg := config.Config{Role: config.RoleRateLimitObserver, Environment: config.EnvironmentDevelopment}
	registry := RegistryFor(cfg)
	if registry[config.RoleRateLimitObserver] == nil {
		t.Fatal("rate-limit observer role has no runtime implementation")
	}
	if err := registry[config.RoleRateLimitObserver](nil); err == nil {
		t.Fatal("observer runner accepted a nil context")
	}
	if registry[config.RoleAPI] != nil {
		t.Fatal("unimplemented API role was unexpectedly registered")
	}
}
