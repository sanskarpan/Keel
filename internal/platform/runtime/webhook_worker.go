package runtime

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/sanskarpan/keel/internal/delivery/webhook"
	webhookmetrics "github.com/sanskarpan/keel/internal/delivery/webhook/metrics"
	webhookpostgres "github.com/sanskarpan/keel/internal/delivery/webhook/postgres"
	"github.com/sanskarpan/keel/internal/delivery/webhook/scheduler"
	"github.com/sanskarpan/keel/internal/delivery/webhook/worker"
	"github.com/sanskarpan/keel/internal/platform/buildinfo"
	"github.com/sanskarpan/keel/internal/platform/config"
	"github.com/sanskarpan/keel/internal/platform/health"
	"github.com/sanskarpan/keel/internal/platform/logging"
)

const (
	webhookDatabaseEnv        = "KEEL_WEBHOOK_DATABASE_URL"
	webhookActiveKeyIDEnv     = "KEEL_WEBHOOK_ACTIVE_KEY_ID"
	webhookActiveKeySecretEnv = "KEEL_WEBHOOK_ACTIVE_KEY_SECRET_B64"
	webhookPreviousKeyIDEnv   = "KEEL_WEBHOOK_PREVIOUS_KEY_ID"
	webhookPreviousSecretEnv  = "KEEL_WEBHOOK_PREVIOUS_KEY_SECRET_B64"
	webhookPollIntervalEnv    = "KEEL_WEBHOOK_POLL_INTERVAL"
	webhookTenantLimitEnv     = "KEEL_WEBHOOK_TENANT_LIMIT"
	webhookBatchEnv           = "KEEL_WEBHOOK_BATCH"
	webhookLeaseDurationEnv   = "KEEL_WEBHOOK_LEASE_DURATION"
)

type webhookWorkerSettings struct {
	databaseURL string
	keyring     *webhook.Keyring
	interval    time.Duration
	tenantLimit int
	batch       int
	lease       time.Duration
}

func loadWebhookWorkerSettings(environment config.Environment, lookup func(string) string) (webhookWorkerSettings, error) {
	if lookup == nil {
		return webhookWorkerSettings{}, errors.New("webhook worker configuration source is required")
	}
	settings := webhookWorkerSettings{
		databaseURL: strings.TrimSpace(lookup(webhookDatabaseEnv)),
		interval:    scheduler.DefaultInterval,
		tenantLimit: scheduler.DefaultTenantLimit,
		batch:       5,
		lease:       120 * time.Second,
	}
	if settings.databaseURL == "" {
		return webhookWorkerSettings{}, errors.New("webhook worker database configuration is required")
	}
	if err := validateWebhookDatabaseURL(settings.databaseURL, environment); err != nil {
		return webhookWorkerSettings{}, err
	}

	activeID := strings.TrimSpace(lookup(webhookActiveKeyIDEnv))
	activeSecret := strings.TrimSpace(lookup(webhookActiveKeySecretEnv))
	if activeID == "" || activeSecret == "" {
		return webhookWorkerSettings{}, errors.New("webhook worker active signing key is required")
	}
	active, err := webhookKey(activeID, activeSecret)
	if err != nil {
		return webhookWorkerSettings{}, err
	}
	previousID := strings.TrimSpace(lookup(webhookPreviousKeyIDEnv))
	previousSecret := strings.TrimSpace(lookup(webhookPreviousSecretEnv))
	if (previousID == "") != (previousSecret == "") {
		return webhookWorkerSettings{}, errors.New("webhook worker previous signing key is incomplete")
	}
	var previous *webhook.Key
	if previousID != "" {
		key, err := webhookKey(previousID, previousSecret)
		if err != nil {
			return webhookWorkerSettings{}, err
		}
		previous = &key
	}
	keyring, err := webhook.NewKeyring(active, previous)
	if err != nil {
		return webhookWorkerSettings{}, errors.New("webhook worker signing keyring is invalid")
	}
	settings.keyring = keyring

	if raw := strings.TrimSpace(lookup(webhookPollIntervalEnv)); raw != "" {
		value, err := time.ParseDuration(raw)
		if err != nil || value < 100*time.Millisecond || value > time.Minute {
			return webhookWorkerSettings{}, errors.New("webhook worker poll interval is invalid")
		}
		settings.interval = value
	}
	if settings.tenantLimit, err = boundedWebhookInt(lookup, webhookTenantLimitEnv, settings.tenantLimit, 1, scheduler.MaxTenantLimit); err != nil {
		return webhookWorkerSettings{}, err
	}
	if settings.batch, err = boundedWebhookInt(lookup, webhookBatchEnv, settings.batch, 1, worker.MaxBatch); err != nil {
		return webhookWorkerSettings{}, err
	}
	if raw := strings.TrimSpace(lookup(webhookLeaseDurationEnv)); raw != "" {
		value, err := time.ParseDuration(raw)
		if err != nil || value < 5*time.Second || value > 300*time.Second || value != time.Duration(int(value/time.Second))*time.Second {
			return webhookWorkerSettings{}, errors.New("webhook worker lease duration is invalid")
		}
		settings.lease = value
	}
	return settings, nil
}

func webhookKey(id, encoded string) (webhook.Key, error) {
	secret, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(secret) == 0 {
		return webhook.Key{}, errors.New("webhook worker signing key secret is invalid")
	}
	return webhook.Key{ID: id, Secret: secret}, nil
}

func boundedWebhookInt(lookup func(string) string, key string, fallback, minimum, maximum int) (int, error) {
	raw := strings.TrimSpace(lookup(key))
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < minimum || value > maximum {
		return 0, fmt.Errorf("%s is outside its supported bounds", key)
	}
	return value, nil
}

func validateWebhookDatabaseURL(raw string, environment config.Environment) error {
	parsed, err := url.Parse(raw)
	if err != nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") ||
		parsed.Hostname() == "" || parsed.Path == "" || parsed.Path == "/" || parsed.User == nil {
		return errors.New("webhook worker database URL is invalid")
	}
	sslModes := parsed.Query()["sslmode"]
	if len(sslModes) > 1 {
		return errors.New("webhook worker database TLS mode is ambiguous")
	}
	if environment == config.EnvironmentProduction || environment == config.EnvironmentStaging {
		if len(sslModes) != 1 || sslModes[0] != "verify-full" {
			return errors.New("webhook worker requires sslmode=verify-full in staging and production")
		}
	}
	return nil
}

func runWebhookWorker(ctx context.Context, cfg config.Config, lookup func(string) string) error {
	if ctx == nil {
		return errors.New("webhook worker context is required")
	}
	settings, err := loadWebhookWorkerSettings(cfg.Environment, lookup)
	if err != nil {
		return err
	}
	logger := logging.NewJSON(os.Stderr, cfg.LogLevel)
	db, err := sql.Open("pgx", settings.databaseURL)
	if err != nil {
		return errors.New("open webhook worker database")
	}
	defer db.Close()
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(2)
	db.SetConnMaxIdleTime(time.Minute)
	db.SetConnMaxLifetime(5 * time.Minute)
	pingCtx, cancelPing := context.WithTimeout(ctx, 5*time.Second)
	defer cancelPing()
	if err := db.PingContext(pingCtx); err != nil {
		return errors.New("webhook worker database is unavailable")
	}

	store, err := webhookpostgres.New(db)
	if err != nil {
		return err
	}
	tenants, err := webhookpostgres.NewTenantSource(db)
	if err != nil {
		return err
	}
	egress, err := webhook.NewEgress(webhook.EgressPolicy{}, nil)
	if err != nil {
		return err
	}
	executor, err := webhook.NewExecutor(egress, settings.keyring)
	if err != nil {
		return err
	}
	retry, err := webhook.NewScheduler(webhook.DefaultRetryPolicy())
	if err != nil {
		return err
	}
	runner, err := worker.New(store, store, executor, retry, webhook.DefaultBreakerPolicy(),
		worker.WithLeaseDuration(settings.lease))
	if err != nil {
		return err
	}
	recorder := webhookmetrics.New()
	sched, err := scheduler.New(tenants, runner,
		scheduler.WithTenantLimit(settings.tenantLimit),
		scheduler.WithBatch(settings.batch),
		scheduler.WithInterval(settings.interval),
		scheduler.WithReporter(func(report scheduler.Report, failed bool) {
			logWebhookWorkerPass(logger, report, failed)
		}),
		scheduler.WithObserver(recorder))
	if err != nil {
		return err
	}

	serviceCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	runDone := make(chan error, 1)
	serveDone := make(chan error, 1)
	go func() { runDone <- sched.Run(serviceCtx) }()
	go func() {
		serveDone <- health.RunWithMetrics(serviceCtx, cfg.ListenAddress, buildinfo.Current(), recorder, func(probeCtx context.Context) error {
			if err := db.PingContext(probeCtx); err != nil {
				return err
			}
			last := sched.LastPoll()
			if last.IsZero() || time.Since(last) > 3*settings.interval {
				return errors.New("webhook tenant discovery is stale")
			}
			return nil
		})
	}()

	select {
	case err := <-runDone:
		cancel()
		serveErr := <-serveDone
		if serveErr != nil {
			return fmt.Errorf("serve webhook worker management endpoints: %w", serveErr)
		}
		if ctx.Err() != nil {
			return nil
		}
		if err != nil {
			return fmt.Errorf("run webhook worker: %w", err)
		}
		return errors.New("webhook worker stopped unexpectedly")
	case err := <-serveDone:
		cancel()
		runErr := <-runDone
		if err != nil {
			return fmt.Errorf("serve webhook worker management endpoints: %w", err)
		}
		if ctx.Err() != nil {
			return nil
		}
		return runErr
	case <-ctx.Done():
		cancel()
		runErr := <-runDone
		serveErr := <-serveDone
		if serveErr != nil {
			return fmt.Errorf("serve webhook worker management endpoints: %w", serveErr)
		}
		return runErr
	}
}

func logWebhookWorkerPass(logger *slog.Logger, report scheduler.Report, failed bool) {
	if logger == nil {
		return
	}
	if !failed && report.Tenants == 0 && report.Leased == 0 && report.Delivered == 0 &&
		report.RetryScheduled == 0 && report.Exhausted == 0 && report.Failed == 0 &&
		report.Deferred == 0 && report.Skipped == 0 && report.Failures == 0 {
		return
	}
	logger.Info("webhook worker pass completed",
		"tenants", report.Tenants,
		"leased", report.Leased,
		"delivered", report.Delivered,
		"retry_scheduled", report.RetryScheduled,
		"exhausted", report.Exhausted,
		"failed", report.Failed,
		"deferred", report.Deferred,
		"skipped", report.Skipped,
		"tenant_batch_failures", report.Failures,
		"pass_failed", failed)
}
