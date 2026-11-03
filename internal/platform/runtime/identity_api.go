package runtime

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/sanskarpan/keel/internal/auth"
	authhttpapi "github.com/sanskarpan/keel/internal/auth/httpapi"
	authpostgres "github.com/sanskarpan/keel/internal/auth/postgres"
	"github.com/sanskarpan/keel/internal/platform/buildinfo"
	"github.com/sanskarpan/keel/internal/platform/config"
	"github.com/sanskarpan/keel/internal/platform/health"
	"github.com/sanskarpan/keel/internal/platform/logging"
)

const (
	identityAPIDatabaseEnv    = "KEEL_IDENTITY_DATABASE_URL"
	identityAPIPepperFileEnv  = "KEEL_IDENTITY_PEPPER_FILE"
	identityAPIRPNameEnv      = "KEEL_IDENTITY_RP_DISPLAY_NAME"
	identityAPIRPIDEnv        = "KEEL_IDENTITY_RP_ID"
	identityAPIRPOriginsEnv   = "KEEL_IDENTITY_RP_ORIGINS"
	identityAPIAllowNonLoopback = "KEEL_IDENTITY_API_ALLOW_NON_LOOPBACK"
)

type identityAPISettings struct {
	databaseURL    string
	pepper         []byte
	rpDisplayName  string
	rpID           string
	rpOrigins      []string
	allowNonLoopback bool
}

func loadIdentityAPISettings(environment config.Environment, lookup func(string) string) (identityAPISettings, error) {
	if lookup == nil {
		return identityAPISettings{}, errors.New("identity API configuration source is required")
	}
	settings := identityAPISettings{
		databaseURL: strings.TrimSpace(lookup(identityAPIDatabaseEnv)),
	}
	if settings.databaseURL == "" {
		return identityAPISettings{}, errors.New("identity API database configuration is required")
	}
	if err := validateIdentityDatabaseURL(settings.databaseURL, environment); err != nil {
		return identityAPISettings{}, err
	}
	pepperFile := strings.TrimSpace(lookup(identityAPIPepperFileEnv))
	if pepperFile == "" {
		return identityAPISettings{}, errors.New("identity API pepper file configuration is required")
	}
	pepper, err := auth.ReadPepperFile(pepperFile)
	if err != nil {
		return identityAPISettings{}, fmt.Errorf("identity API pepper file is invalid: %w", err)
	}
	settings.pepper = pepper
	settings.rpDisplayName = strings.TrimSpace(lookup(identityAPIRPNameEnv))
	settings.rpID = strings.TrimSpace(lookup(identityAPIRPIDEnv))
	for _, origin := range strings.Split(lookup(identityAPIRPOriginsEnv), ",") {
		if trimmed := strings.TrimSpace(origin); trimmed != "" {
			settings.rpOrigins = append(settings.rpOrigins, trimmed)
		}
	}
	if (settings.rpDisplayName != "" || settings.rpID != "" || len(settings.rpOrigins) != 0) &&
		(settings.rpDisplayName == "" || settings.rpID == "" || len(settings.rpOrigins) == 0) {
		return identityAPISettings{}, errors.New("identity API relying party configuration is incomplete")
	}
	if raw := strings.TrimSpace(lookup(identityAPIAllowNonLoopback)); raw != "" {
		switch strings.ToLower(raw) {
		case "true":
			settings.allowNonLoopback = true
		case "false":
		default:
			return identityAPISettings{}, errors.New("identity API non-loopback flag is invalid")
		}
	}
	return settings, nil
}

func validateIdentityDatabaseURL(raw string, environment config.Environment) error {
	parsed, err := url.Parse(raw)
	if err != nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") ||
		parsed.Hostname() == "" || parsed.Path == "" || parsed.Path == "/" || parsed.User == nil {
		return errors.New("identity API database URL is invalid")
	}
	sslModes := parsed.Query()["sslmode"]
	if len(sslModes) > 1 {
		return errors.New("identity API database TLS mode is ambiguous")
	}
	if environment == config.EnvironmentProduction || environment == config.EnvironmentStaging {
		if len(sslModes) != 1 || sslModes[0] != "verify-full" {
			return errors.New("identity API requires sslmode=verify-full in staging and production")
		}
	}
	return nil
}

// logSender delivers no mail: it records content-free send events for the
// local synthetic profile. Real email transport is a K8.10 qualification;
// production must inject a real sender here.
type logSender struct{ logger *slog.Logger }

func (s logSender) SendVerification(_ string, _ string) error {
	s.logger.Info("identity verification sender invoked", "channel", "verification")
	return nil
}

func (s logSender) SendReset(_ string, _ string) error {
	s.logger.Info("identity reset sender invoked", "channel", "reset")
	return nil
}

func runIdentityAPI(ctx context.Context, cfg config.Config, lookup func(string) string) error {
	if ctx == nil {
		return errors.New("identity API context is required")
	}
	settings, err := loadIdentityAPISettings(cfg.Environment, lookup)
	if err != nil {
		return err
	}
	if err := validateIdentityListenAddress(cfg.ListenAddress, settings.allowNonLoopback); err != nil {
		return err
	}
	logger := logging.NewJSON(os.Stderr, cfg.LogLevel)
	db, err := sql.Open("pgx", settings.databaseURL)
	if err != nil {
		return errors.New("open identity API database")
	}
	defer db.Close()
	db.SetMaxOpenConns(8)
	db.SetMaxIdleConns(2)
	db.SetConnMaxIdleTime(time.Minute)
	db.SetConnMaxLifetime(5 * time.Minute)
	pingCtx, cancelPing := context.WithTimeout(ctx, 5*time.Second)
	defer cancelPing()
	if err := db.PingContext(pingCtx); err != nil {
		return errors.New("identity API database is unavailable")
	}

	store, err := authpostgres.New(db)
	if err != nil {
		return err
	}
	sender := logSender{logger: logging.NewJSON(os.Stderr, cfg.LogLevel)}
	handler, err := authhttpapi.New(store, settings.pepper, auth.DefaultArgonParams(), sender, sender)
	if err != nil {
		return err
	}
	if settings.rpID != "" {
		if err := handler.EnableWebAuthn(authhttpapi.WebAuthnConfig{
			RPDisplayName: settings.rpDisplayName,
			RPID:          settings.rpID,
			RPOrigins:     settings.rpOrigins,
		}); err != nil {
			return err
		}
	}

	probe := func(probeCtx context.Context) error {
		return db.PingContext(probeCtx)
	}
	mux := http.NewServeMux()
	mux.Handle("/v1/auth/", handler)
	healthHandler := health.NewHandler(buildinfo.Current(), probe)
	healthHandler.MarkStartupComplete()
	mux.Handle("/", healthHandler)

	listener, err := net.Listen("tcp", cfg.ListenAddress)
	if err != nil {
		return fmt.Errorf("listen for identity API endpoints: %w", err)
	}
	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	logger.Info("identity API serving")
	serveResult := make(chan error, 1)
	go func() { serveResult <- server.Serve(listener) }()
	select {
	case err := <-serveResult:
		return fmt.Errorf("serve identity API endpoints: %w", err)
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shut down identity API endpoints: %w", err)
		}
		return nil
	}
}

func validateIdentityListenAddress(address string, allowNonLoopback bool) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return errors.New("identity API listen address is invalid")
	}
	if allowNonLoopback {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("identity API must listen on loopback without an explicit override")
	}
	return nil
}
