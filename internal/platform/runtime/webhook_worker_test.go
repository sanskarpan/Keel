package runtime

import (
	"bytes"
	"encoding/base64"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/sanskarpan/keel/internal/delivery/webhook/scheduler"
	"github.com/sanskarpan/keel/internal/platform/config"
)

const webhookTestDSN = "postgres://keel_webhook:top-secret@db.internal:5432/keel?sslmode=disable"

func webhookLookup(values map[string]string) func(string) string {
	return func(key string) string { return values[key] }
}

func webhookTestSecret() string {
	return base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 32)))
}

func validWebhookWorkerValues() map[string]string {
	return map[string]string{
		webhookDatabaseEnv:        webhookTestDSN,
		webhookActiveKeyIDEnv:     "key_2026",
		webhookActiveKeySecretEnv: webhookTestSecret(),
	}
}

func TestLoadWebhookWorkerSettingsDefaults(t *testing.T) {
	settings, err := loadWebhookWorkerSettings(config.EnvironmentDevelopment, webhookLookup(validWebhookWorkerValues()))
	if err != nil {
		t.Fatal(err)
	}
	if settings.interval != time.Second || settings.tenantLimit != 100 || settings.batch != 5 || settings.lease != 120*time.Second {
		t.Fatalf("unexpected defaults: %+v", settings)
	}
	if settings.keyring.ActiveKeyID() != "key_2026" {
		t.Fatalf("active key = %q", settings.keyring.ActiveKeyID())
	}
}

func TestLoadWebhookWorkerSettingsCustom(t *testing.T) {
	values := validWebhookWorkerValues()
	values[webhookPreviousKeyIDEnv] = "key_2025"
	values[webhookPreviousSecretEnv] = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("p", 32)))
	values[webhookPollIntervalEnv] = "250ms"
	values[webhookTenantLimitEnv] = "1000"
	values[webhookBatchEnv] = "100"
	values[webhookLeaseDurationEnv] = "5s"
	settings, err := loadWebhookWorkerSettings(config.EnvironmentDevelopment, webhookLookup(values))
	if err != nil {
		t.Fatal(err)
	}
	if settings.interval != 250*time.Millisecond || settings.tenantLimit != 1000 ||
		settings.batch != 100 || settings.lease != 5*time.Second {
		t.Fatalf("unexpected custom settings: %+v", settings)
	}
}

func TestLoadWebhookWorkerSettingsRejectsInvalidConfiguration(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(map[string]string)
		env    config.Environment
	}{
		{"missing database", func(v map[string]string) { delete(v, webhookDatabaseEnv) }, config.EnvironmentDevelopment},
		{"invalid database scheme", func(v map[string]string) { v[webhookDatabaseEnv] = "http://user:pass@db/keel" }, config.EnvironmentDevelopment},
		{"missing database user", func(v map[string]string) { v[webhookDatabaseEnv] = "postgres://db.internal/keel" }, config.EnvironmentDevelopment},
		{"missing database name", func(v map[string]string) { v[webhookDatabaseEnv] = "postgres://user:pass@db.internal:5432/" }, config.EnvironmentDevelopment},
		{"duplicate sslmode", func(v map[string]string) {
			v[webhookDatabaseEnv] = "postgres://user:pass@db.internal:5432/keel?sslmode=disable&sslmode=verify-full"
		}, config.EnvironmentDevelopment},
		{"production TLS", func(v map[string]string) {
			v[webhookDatabaseEnv] = "postgres://user:pass@db.internal:5432/keel?sslmode=require"
		}, config.EnvironmentProduction},
		{"missing active key id", func(v map[string]string) { delete(v, webhookActiveKeyIDEnv) }, config.EnvironmentDevelopment},
		{"missing active secret", func(v map[string]string) { delete(v, webhookActiveKeySecretEnv) }, config.EnvironmentDevelopment},
		{"invalid base64", func(v map[string]string) { v[webhookActiveKeySecretEnv] = "not base64!" }, config.EnvironmentDevelopment},
		{"short secret", func(v map[string]string) {
			v[webhookActiveKeySecretEnv] = base64.StdEncoding.EncodeToString([]byte("short"))
		}, config.EnvironmentDevelopment},
		{"previous id only", func(v map[string]string) { v[webhookPreviousKeyIDEnv] = "key_2025" }, config.EnvironmentDevelopment},
		{"previous secret only", func(v map[string]string) { v[webhookPreviousSecretEnv] = webhookTestSecret() }, config.EnvironmentDevelopment},
		{"duplicate key id", func(v map[string]string) {
			v[webhookPreviousKeyIDEnv] = v[webhookActiveKeyIDEnv]
			v[webhookPreviousSecretEnv] = webhookTestSecret()
		}, config.EnvironmentDevelopment},
		{"short interval", func(v map[string]string) { v[webhookPollIntervalEnv] = "50ms" }, config.EnvironmentDevelopment},
		{"long interval", func(v map[string]string) { v[webhookPollIntervalEnv] = "2m" }, config.EnvironmentDevelopment},
		{"bad interval", func(v map[string]string) { v[webhookPollIntervalEnv] = "soon" }, config.EnvironmentDevelopment},
		{"zero tenant limit", func(v map[string]string) { v[webhookTenantLimitEnv] = "0" }, config.EnvironmentDevelopment},
		{"large tenant limit", func(v map[string]string) { v[webhookTenantLimitEnv] = "1001" }, config.EnvironmentDevelopment},
		{"bad tenant limit", func(v map[string]string) { v[webhookTenantLimitEnv] = "many" }, config.EnvironmentDevelopment},
		{"zero batch", func(v map[string]string) { v[webhookBatchEnv] = "0" }, config.EnvironmentDevelopment},
		{"large batch", func(v map[string]string) { v[webhookBatchEnv] = "101" }, config.EnvironmentDevelopment},
		{"short lease", func(v map[string]string) { v[webhookLeaseDurationEnv] = "4s" }, config.EnvironmentDevelopment},
		{"long lease", func(v map[string]string) { v[webhookLeaseDurationEnv] = "301s" }, config.EnvironmentDevelopment},
		{"fractional lease", func(v map[string]string) { v[webhookLeaseDurationEnv] = "5.5s" }, config.EnvironmentDevelopment},
		{"bad lease", func(v map[string]string) { v[webhookLeaseDurationEnv] = "later" }, config.EnvironmentDevelopment},
	} {
		t.Run(test.name, func(t *testing.T) {
			values := validWebhookWorkerValues()
			test.mutate(values)
			_, err := loadWebhookWorkerSettings(test.env, webhookLookup(values))
			if err == nil {
				t.Fatal("invalid configuration was accepted")
			}
			if strings.Contains(err.Error(), "top-secret") || strings.Contains(err.Error(), "keel_webhook") {
				t.Fatalf("configuration error leaked a credential: %q", err)
			}
		})
	}
}

func TestRegistryForWiresWebhookWorker(t *testing.T) {
	registry := RegistryFor(config.Config{Role: config.RoleWebhookWorker})
	if registry[config.RoleWebhookWorker] == nil {
		t.Fatal("webhook-worker was not registered")
	}
	if registry[config.RoleAPI] != nil {
		t.Fatal("unexpected API runner registration")
	}
}

func TestWebhookWorkerPassLoggingIsContentFree(t *testing.T) {
	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, nil))
	logWebhookWorkerPass(logger, scheduler.Report{
		Tenants: 2, Leased: 3, Delivered: 1, RetryScheduled: 1, Exhausted: 1, Failures: 1,
	}, true)
	line := output.String()
	for _, expected := range []string{
		"webhook worker pass completed", "tenants", "leased", "delivered",
		"retry_scheduled", "exhausted", "tenant_batch_failures", "pass_failed",
	} {
		if !strings.Contains(line, expected) {
			t.Fatalf("log missing %q: %s", expected, line)
		}
	}
	for _, forbidden := range []string{"tenant_id", "endpoint", "delivery_id", "url", "error"} {
		if strings.Contains(strings.ToLower(line), forbidden) {
			t.Fatalf("log contains %q: %s", forbidden, line)
		}
	}
	output.Reset()
	logWebhookWorkerPass(logger, scheduler.Report{}, false)
	if output.Len() != 0 {
		t.Fatalf("idle pass logged: %s", output.String())
	}
}
