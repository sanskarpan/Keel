package runtime

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/sanskarpan/keel/internal/platform/buildinfo"
	"github.com/sanskarpan/keel/internal/platform/config"
	"github.com/sanskarpan/keel/internal/platform/health"
	"github.com/sanskarpan/keel/internal/platform/ratelimit"
)

const (
	rateLimitObserverDBEnv       = "KEEL_RATE_STATUS_DATABASE_URL"
	rateLimitObserverRegionEnv   = "KEEL_RATE_LIMIT_HOME_REGION"
	rateLimitObserverIntervalEnv = "KEEL_RATE_LIMIT_STATUS_REFRESH_INTERVAL"
	rateLimitObserverTimeoutEnv  = "KEEL_RATE_LIMIT_STATUS_QUERY_TIMEOUT"
)

type rateLimitObserverSettings struct {
	databaseURL  string
	region       string
	interval     time.Duration
	queryTimeout time.Duration
}

func loadRateLimitObserverSettings(environment config.Environment, lookup func(string) string) (rateLimitObserverSettings, error) {
	if lookup == nil {
		return rateLimitObserverSettings{}, errors.New("observer configuration source is required")
	}
	settings := rateLimitObserverSettings{
		databaseURL:  strings.TrimSpace(lookup(rateLimitObserverDBEnv)),
		region:       strings.TrimSpace(lookup(rateLimitObserverRegionEnv)),
		interval:     5 * time.Second,
		queryTimeout: time.Second,
	}
	if settings.databaseURL == "" || !validHomeRegion(settings.region) {
		return rateLimitObserverSettings{}, errors.New("rate-limit observer database and home-region configuration are required")
	}
	if raw := strings.TrimSpace(lookup(rateLimitObserverIntervalEnv)); raw != "" {
		value, err := time.ParseDuration(raw)
		if err != nil {
			return rateLimitObserverSettings{}, errors.New("rate-limit observer refresh interval is invalid")
		}
		settings.interval = value
	}
	if raw := strings.TrimSpace(lookup(rateLimitObserverTimeoutEnv)); raw != "" {
		value, err := time.ParseDuration(raw)
		if err != nil {
			return rateLimitObserverSettings{}, errors.New("rate-limit observer query timeout is invalid")
		}
		settings.queryTimeout = value
	}
	if settings.interval < time.Second || settings.interval > time.Minute || settings.queryTimeout < 100*time.Millisecond || settings.queryTimeout > settings.interval {
		return rateLimitObserverSettings{}, errors.New("rate-limit observer timing configuration is outside its supported bounds")
	}
	if err := validateObserverDatabaseURL(settings.databaseURL, environment); err != nil {
		return rateLimitObserverSettings{}, err
	}
	return settings, nil
}

func validateObserverDatabaseURL(raw string, environment config.Environment) error {
	parsed, err := url.Parse(raw)
	if err != nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") || parsed.Hostname() == "" || parsed.Path == "" || parsed.Path == "/" || parsed.User == nil {
		return errors.New("rate-limit observer database URL is invalid")
	}
	query := parsed.Query()
	sslModes := query["sslmode"]
	if len(sslModes) > 1 {
		return errors.New("rate-limit observer database TLS mode is ambiguous")
	}
	if environment == config.EnvironmentProduction || environment == config.EnvironmentStaging {
		if len(sslModes) != 1 || sslModes[0] != "verify-full" {
			return errors.New("rate-limit observer requires sslmode=verify-full in staging and production")
		}
	}
	return nil
}

func validHomeRegion(region string) bool {
	if len(region) == 0 || len(region) > 64 || region[0] < 'a' || region[0] > 'z' {
		return false
	}
	for i := 1; i < len(region); i++ {
		ch := region[i]
		if (ch < 'a' || ch > 'z') && (ch < '0' || ch > '9') && ch != '.' && ch != '_' && ch != '-' {
			return false
		}
	}
	return true
}

func runRateLimitObserver(ctx context.Context, cfg config.Config, lookup func(string) string) error {
	if ctx == nil {
		return errors.New("rate-limit observer context is required")
	}
	settings, err := loadRateLimitObserverSettings(cfg.Environment, lookup)
	if err != nil {
		return err
	}
	db, err := sql.Open("pgx", settings.databaseURL)
	if err != nil {
		return errors.New("open rate-limit observer database")
	}
	defer db.Close()
	db.SetMaxOpenConns(2)
	db.SetMaxIdleConns(1)
	db.SetConnMaxIdleTime(time.Minute)
	db.SetConnMaxLifetime(5 * time.Minute)

	metrics := ratelimit.NewDegradedMetrics()
	serviceCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	refreshDone := make(chan error, 1)
	serveDone := make(chan error, 1)
	go func() {
		refreshDone <- ratelimit.RunDegradedWindowStatusRefresh(serviceCtx, db, settings.region, metrics, settings.interval, settings.queryTimeout)
	}()
	go func() {
		ready := func(probeCtx context.Context) error {
			if err := db.PingContext(probeCtx); err != nil {
				return err
			}
			if !metrics.WindowStatusObserved() {
				return errors.New("degraded window status has not been observed")
			}
			return nil
		}
		serveDone <- health.RunWithMetrics(serviceCtx, cfg.ListenAddress, buildinfo.Current(), metrics, ready)
	}()

	select {
	case serveErr := <-serveDone:
		cancel()
		refreshErr := <-refreshDone
		if serveErr != nil {
			return fmt.Errorf("serve rate-limit observer management endpoints: %w", serveErr)
		}
		return refreshErr
	case refreshErr := <-refreshDone:
		cancel()
		serveErr := <-serveDone
		if ctx.Err() != nil {
			if serveErr != nil {
				return fmt.Errorf("serve rate-limit observer management endpoints: %w", serveErr)
			}
			return nil
		}
		if refreshErr != nil {
			return fmt.Errorf("run rate-limit observer refresh: %w", refreshErr)
		}
		return errors.New("rate-limit observer refresh stopped unexpectedly")
	case <-ctx.Done():
		cancel()
		serveErr := <-serveDone
		refreshErr := <-refreshDone
		if serveErr != nil {
			return fmt.Errorf("serve rate-limit observer management endpoints: %w", serveErr)
		}
		if refreshErr != nil {
			return fmt.Errorf("run rate-limit observer refresh: %w", refreshErr)
		}
		return nil
	}
}
