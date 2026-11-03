package runtime

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sanskarpan/keel/internal/platform/config"
)

const identityTestDSN = "postgres://keel_identity:top-secret@db.internal:5432/keel?sslmode=disable"

func identityLookup(values map[string]string) func(string) string {
	return func(key string) string { return values[key] }
}

func validIdentityValues(t *testing.T) map[string]string {
	t.Helper()
	pepperPath := filepath.Join(t.TempDir(), "pepper")
	if err := os.WriteFile(pepperPath, []byte(strings.Repeat("p", 32)), 0600); err != nil {
		t.Fatal(err)
	}
	return map[string]string{
		identityAPIDatabaseEnv:   identityTestDSN,
		identityAPIPepperFileEnv: pepperPath,
	}
}

func TestLoadIdentityAPISettingsDefaults(t *testing.T) {
	settings, err := loadIdentityAPISettings(config.EnvironmentDevelopment, identityLookup(validIdentityValues(t)))
	if err != nil {
		t.Fatal(err)
	}
	if len(settings.pepper) < 32 || settings.rpID != "" || settings.allowNonLoopback {
		t.Fatalf("unexpected defaults: rp=%q origins=%v nonloop=%v", settings.rpID, settings.rpOrigins, settings.allowNonLoopback)
	}
}

func TestLoadIdentityAPISettingsRejectsInvalidConfiguration(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(map[string]string)
		env    config.Environment
	}{
		{"missing database", func(v map[string]string) { delete(v, identityAPIDatabaseEnv) }, config.EnvironmentDevelopment},
		{"bad database", func(v map[string]string) { v[identityAPIDatabaseEnv] = "http://user:pass@db/keel" }, config.EnvironmentDevelopment},
		{"missing pepper file", func(v map[string]string) { delete(v, identityAPIPepperFileEnv) }, config.EnvironmentDevelopment},
		{"bad pepper file", func(v map[string]string) { v[identityAPIPepperFileEnv] = "/nonexistent/pepper" }, config.EnvironmentDevelopment},
		{"partial RP", func(v map[string]string) { v[identityAPIRPIDEnv] = "example.test" }, config.EnvironmentDevelopment},
		{"bad flag", func(v map[string]string) { v[identityAPIAllowNonLoopback] = "maybe" }, config.EnvironmentDevelopment},
		{"production TLS", func(v map[string]string) {
			v[identityAPIDatabaseEnv] = "postgres://user:pass@db.internal:5432/keel?sslmode=require"
		}, config.EnvironmentProduction},
	} {
		t.Run(test.name, func(t *testing.T) {
			values := validIdentityValues(t)
			test.mutate(values)
			if _, err := loadIdentityAPISettings(test.env, identityLookup(values)); err == nil {
				t.Fatalf("%s accepted", test.name)
			}
		})
	}
}

func TestLoadIdentityAPISettingsAcceptsRelyingParty(t *testing.T) {
	values := validIdentityValues(t)
	values[identityAPIRPNameEnv] = "Keel"
	values[identityAPIRPIDEnv] = "example.test"
	values[identityAPIRPOriginsEnv] = "https://example.test, https://app.example.test"
	settings, err := loadIdentityAPISettings(config.EnvironmentDevelopment, identityLookup(values))
	if err != nil {
		t.Fatal(err)
	}
	if settings.rpID != "example.test" || len(settings.rpOrigins) != 2 {
		t.Fatalf("rp: %+v", settings)
	}
}

func TestValidateIdentityListenAddressRequiresLoopback(t *testing.T) {
	if err := validateIdentityListenAddress("127.0.0.1:8080", false); err != nil {
		t.Fatalf("loopback: %v", err)
	}
	if err := validateIdentityListenAddress("0.0.0.0:8080", false); err == nil {
		t.Fatal("wildcard accepted")
	}
	if err := validateIdentityListenAddress("0.0.0.0:8080", true); err != nil {
		t.Fatalf("override: %v", err)
	}
}

func TestRegistryForWiresIdentityAPI(t *testing.T) {
	registry := RegistryFor(config.Config{Role: config.RoleIdentityAPI})
	if registry[config.RoleIdentityAPI] == nil {
		t.Fatal("identity-api role is not wired")
	}
	if err := Dispatch(context.Background(), config.RoleIdentityAPI, Registry{}); err == nil {
		t.Fatal("unwired role accepted")
	}
}
