package runtime

import (
	"strings"
	"testing"

	"github.com/sanskarpan/keel/internal/platform/config"
)

const operatorTestDSN = "postgres://keel_operator:top-secret@db.internal:5432/keel?sslmode=disable"

func operatorLookup(values map[string]string) func(string) string {
	return func(key string) string { return values[key] }
}

func validOperatorValues() map[string]string {
	return map[string]string{
		operatorAPIDatabaseEnv: operatorTestDSN,
		operatorAPITokensEnv: "11111111-1111-4111-8111-111111111111:ops-one:" +
			strings.Repeat("k", 32),
	}
}

func TestLoadOperatorAPISettingsDefaults(t *testing.T) {
	settings, err := loadOperatorAPISettings(config.EnvironmentDevelopment, operatorLookup(validOperatorValues()))
	if err != nil {
		t.Fatal(err)
	}
	if len(settings.grants) != 1 || settings.keyring != nil || settings.allowNonLoopback {
		t.Fatalf("unexpected defaults: %+v", settings)
	}
}

func TestLoadOperatorAPISettingsRejectsInvalidConfiguration(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(map[string]string)
		env    config.Environment
	}{
		{"missing database", func(v map[string]string) { delete(v, operatorAPIDatabaseEnv) }, config.EnvironmentDevelopment},
		{"bad database", func(v map[string]string) { v[operatorAPIDatabaseEnv] = "http://user:pass@db/keel" }, config.EnvironmentDevelopment},
		{"missing tokens", func(v map[string]string) { delete(v, operatorAPITokensEnv) }, config.EnvironmentDevelopment},
		{"bad tokens", func(v map[string]string) { v[operatorAPITokensEnv] = "not-a-grant" }, config.EnvironmentDevelopment},
		{"missing key file", func(v map[string]string) { v[operatorAPIKeyFileEnv] = "/nonexistent/keys.json" }, config.EnvironmentDevelopment},
		{"bad flag", func(v map[string]string) { v[operatorAPIAllowNonLoopback] = "maybe" }, config.EnvironmentDevelopment},
		{"production TLS", func(v map[string]string) {
			v[operatorAPIDatabaseEnv] = "postgres://user:pass@db.internal:5432/keel?sslmode=require"
		}, config.EnvironmentProduction},
	} {
		t.Run(test.name, func(t *testing.T) {
			values := validOperatorValues()
			test.mutate(values)
			_, err := loadOperatorAPISettings(test.env, operatorLookup(values))
			if err == nil {
				t.Fatal("invalid configuration was accepted")
			}
			if strings.Contains(err.Error(), "top-secret") {
				t.Fatalf("configuration error leaked a credential: %q", err)
			}
		})
	}
}

func TestValidateOperatorListenAddressRequiresLoopback(t *testing.T) {
	for _, address := range []string{"127.0.0.1:18083", "[::1]:18083"} {
		if err := validateOperatorListenAddress(address, false); err != nil {
			t.Fatalf("%s rejected: %v", address, err)
		}
	}
	for _, address := range []string{"0.0.0.0:18083", "10.0.0.5:18083", "example.com:443", "not-an-address"} {
		if err := validateOperatorListenAddress(address, false); err == nil {
			t.Fatalf("%s was accepted without override", address)
		}
	}
	if err := validateOperatorListenAddress("10.0.0.5:18083", true); err != nil {
		t.Fatalf("explicit override rejected: %v", err)
	}
}

func TestRegistryForWiresOperatorAPI(t *testing.T) {
	registry := RegistryFor(config.Config{Role: config.RoleOperatorAPI})
	if registry[config.RoleOperatorAPI] == nil {
		t.Fatal("operator-api was not registered")
	}
}
