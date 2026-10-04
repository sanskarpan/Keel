package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/sanskarpan/keel/internal/platform/logging"
	"github.com/sanskarpan/keel/internal/platform/migrations"
)

const migrationLockID int64 = 704198227

func runMigrations() error {
	dsn := os.Getenv("KEEL_MIGRATION_DATABASE_URL")
	if dsn == "" {
		return errors.New("KEEL_MIGRATION_DATABASE_URL is required for the migrate command")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return fmt.Errorf("open migration database: %w", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	connectCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := db.PingContext(connectCtx); err != nil {
		return fmt.Errorf("connect to migration database: %w", err)
	}
	applyCtx, applyCancel := context.WithTimeout(ctx, 30*time.Minute)
	defer applyCancel()
	if err := migrations.Apply(applyCtx, db, migrations.Embedded(), migrations.Options{LockID: migrationLockID}); err != nil {
		return fmt.Errorf("apply Keel migrations: %w", err)
	}
	logging.NewJSON(os.Stdout, slog.LevelInfo).Info("Keel migrations completed")
	return nil
}
