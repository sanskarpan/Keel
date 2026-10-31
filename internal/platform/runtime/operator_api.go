package runtime

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/sanskarpan/keel/internal/delivery/webhook"
	"github.com/sanskarpan/keel/internal/delivery/webhook/httpapi"
	webhookpostgres "github.com/sanskarpan/keel/internal/delivery/webhook/postgres"
	"github.com/sanskarpan/keel/internal/platform/buildinfo"
	"github.com/sanskarpan/keel/internal/platform/config"
	"github.com/sanskarpan/keel/internal/platform/health"
	"github.com/sanskarpan/keel/internal/platform/logging"
)

const (
	operatorAPIDatabaseEnv      = "KEEL_OPERATOR_DATABASE_URL"
	operatorAPITokensEnv        = "KEEL_OPERATOR_API_TOKENS"
	operatorAPIKeyFileEnv       = "KEEL_OPERATOR_API_KEY_FILE"
	operatorAPIAllowNonLoopback = "KEEL_OPERATOR_API_ALLOW_NON_LOOPBACK"
)

type operatorAPISettings struct {
	databaseURL      string
	grants           []httpapi.TokenGrant
	keyring          *webhook.Keyring
	allowNonLoopback bool
}

func loadOperatorAPISettings(environment config.Environment, lookup func(string) string) (operatorAPISettings, error) {
	if lookup == nil {
		return operatorAPISettings{}, errors.New("operator API configuration source is required")
	}
	settings := operatorAPISettings{
		databaseURL: strings.TrimSpace(lookup(operatorAPIDatabaseEnv)),
	}
	if settings.databaseURL == "" {
		return operatorAPISettings{}, errors.New("operator API database configuration is required")
	}
	if err := validateOperatorDatabaseURL(settings.databaseURL, environment); err != nil {
		return operatorAPISettings{}, err
	}
	var err error
	if settings.grants, err = httpapi.ParseTokenGrants(strings.TrimSpace(lookup(operatorAPITokensEnv))); err != nil {
		return operatorAPISettings{}, errors.New("operator API bearer tokens are invalid")
	}
	if raw := strings.TrimSpace(lookup(operatorAPIKeyFileEnv)); raw != "" {
		keyring, err := webhook.LoadKeyringFromFile(raw)
		if err != nil {
			return operatorAPISettings{}, errors.New("operator API signing key file is invalid")
		}
		settings.keyring = keyring
	}
	if raw := strings.TrimSpace(lookup(operatorAPIAllowNonLoopback)); raw != "" {
		switch strings.ToLower(raw) {
		case "true":
			settings.allowNonLoopback = true
		case "false":
		default:
			return operatorAPISettings{}, errors.New("operator API non-loopback flag is invalid")
		}
	}
	return settings, nil
}

func validateOperatorDatabaseURL(raw string, environment config.Environment) error {
	parsed, err := url.Parse(raw)
	if err != nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") ||
		parsed.Hostname() == "" || parsed.Path == "" || parsed.Path == "/" || parsed.User == nil {
		return errors.New("operator API database URL is invalid")
	}
	sslModes := parsed.Query()["sslmode"]
	if len(sslModes) > 1 {
		return errors.New("operator API database TLS mode is ambiguous")
	}
	if environment == config.EnvironmentProduction || environment == config.EnvironmentStaging {
		if len(sslModes) != 1 || sslModes[0] != "verify-full" {
			return errors.New("operator API requires sslmode=verify-full in staging and production")
		}
	}
	return nil
}

// validateOperatorListenAddress requires a loopback listener unless the deployment explicitly
// opts out. Bearer tokens authenticate every operator route, but unauthenticated health and
// version endpoints share the listener, so loopback remains the safe default.
func validateOperatorListenAddress(address string, allowNonLoopback bool) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return errors.New("operator API listen address is invalid")
	}
	if allowNonLoopback {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("operator API must listen on loopback without an explicit override")
	}
	return nil
}

func runOperatorAPI(ctx context.Context, cfg config.Config, lookup func(string) string) error {
	if ctx == nil {
		return errors.New("operator API context is required")
	}
	settings, err := loadOperatorAPISettings(cfg.Environment, lookup)
	if err != nil {
		return err
	}
	if err := validateOperatorListenAddress(cfg.ListenAddress, settings.allowNonLoopback); err != nil {
		return err
	}
	logger := logging.NewJSON(os.Stderr, cfg.LogLevel)
	db, err := sql.Open("pgx", settings.databaseURL)
	if err != nil {
		return errors.New("open operator API database")
	}
	defer db.Close()
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(2)
	db.SetConnMaxIdleTime(time.Minute)
	db.SetConnMaxLifetime(5 * time.Minute)
	pingCtx, cancelPing := context.WithTimeout(ctx, 5*time.Second)
	defer cancelPing()
	if err := db.PingContext(pingCtx); err != nil {
		return errors.New("operator API database is unavailable")
	}

	store, err := webhookpostgres.New(db)
	if err != nil {
		return err
	}
	auth, err := httpapi.NewBearerAuth(settings.grants)
	if err != nil {
		return err
	}
	keyring := settings.keyring
	handler, err := httpapi.New(store, auth, auth, func(keyID string) bool {
		return keyring != nil && keyring.HasKey(keyID)
	})
	if err != nil {
		return err
	}

	probe := func(probeCtx context.Context) error {
		return db.PingContext(probeCtx)
	}
	mux := http.NewServeMux()
	mux.Handle("/v1/webhooks/", handler)
	healthHandler := health.NewHandler(buildinfo.Current(), probe)
	healthHandler.MarkStartupComplete()
	mux.Handle("/", healthHandler)

	listener, err := net.Listen("tcp", cfg.ListenAddress)
	if err != nil {
		return fmt.Errorf("listen for operator API endpoints: %w", err)
	}
	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	logger.Info("operator API serving", "grants", len(settings.grants))
	serveResult := make(chan error, 1)
	go func() { serveResult <- server.Serve(listener) }()
	select {
	case err := <-serveResult:
		return fmt.Errorf("serve operator API endpoints: %w", err)
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shut down operator API endpoints: %w", err)
		}
		return nil
	}
}
