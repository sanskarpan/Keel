package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/sanskarpan/keel/internal/platform/config"
	"github.com/sanskarpan/keel/internal/platform/logging"
	"github.com/sanskarpan/keel/internal/platform/runtime"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "migrate" {
		if err := runMigrations(); err != nil {
			logging.NewJSON(os.Stderr, slog.LevelError).Error("Keel migrations failed", "error", err)
			os.Exit(1)
		}
		return
	}
	if err := run(); err != nil {
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		logging.NewJSON(os.Stderr, slog.LevelInfo).Error("Keel configuration rejected", "error", err)
		return err
	}

	logger := logging.NewJSON(os.Stderr, cfg.LogLevel)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	logger.Info("Keel runtime role requested",
		"role", cfg.Role,
		"environment", cfg.Environment,
		"listen_address", cfg.ListenAddress,
	)
	if err := runtime.Dispatch(ctx, cfg.Role, runtime.Registry{}); err != nil {
		logger.Error("Keel runtime role is not available yet", "role", cfg.Role, "error_code", "role_not_registered")
		return err
	}
	return nil
}
