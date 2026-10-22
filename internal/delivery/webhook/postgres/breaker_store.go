package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/sanskarpan/keel/internal/delivery/webhook"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

// BreakerSnapshot is one endpoint's persisted breaker state. Version zero means no row exists and
// the state is the zero, closed value.
type BreakerSnapshot struct {
	State   webhook.BreakerState
	Version int64
}

// Breaker loads the shared circuit-breaker state for an endpoint. A missing row is a closed breaker
// with version zero, so a new endpoint needs no initialization. A resolved endpoint can be looked up
// before its first attempt.
func (s *Store) Breaker(ctx context.Context, tenant tenancy.TenantID, endpointID string) (BreakerSnapshot, error) {
	if s == nil || s.db == nil {
		return BreakerSnapshot{}, errors.New("webhook delivery store database is required")
	}
	if ctx == nil {
		return BreakerSnapshot{}, errors.New("webhook breaker context is required")
	}
	if err := validateEndpointTenant(tenant); err != nil {
		return BreakerSnapshot{}, err
	}
	if err := webhook.ValidateEndpointID(endpointID); err != nil {
		return BreakerSnapshot{}, err
	}

	var snapshot BreakerSnapshot
	err := inTenantTx(ctx, s.db, tenant, func(ctx context.Context, tx *sql.Tx) error {
		var status string
		var failures, probes, version int64
		var openedAt sql.NullTime
		var openFor sql.NullInt64
		err := tx.QueryRowContext(ctx,
			`SELECT r_status,r_failures,r_opened_at,r_open_for_seconds,r_probes,r_version
			   FROM keel_meta.load_webhook_breaker($1)`, endpointID).
			Scan(&status, &failures, &openedAt, &openFor, &probes, &version)
		if errors.Is(err, sql.ErrNoRows) {
			snapshot = BreakerSnapshot{State: webhook.BreakerState{Status: webhook.BreakerClosed}}
			return nil
		}
		if err != nil {
			return fmt.Errorf("load webhook breaker: %w", err)
		}
		state, err := breakerState(status, failures, openedAt, openFor, probes)
		if err != nil {
			return err
		}
		snapshot = BreakerSnapshot{State: state, Version: version}
		return nil
	})
	if err != nil {
		return BreakerSnapshot{}, err
	}
	return snapshot, nil
}

// SaveBreaker persists the policy result for one endpoint. ExpectedVersion zero inserts the first
// row; a positive value updates only when the stored version matches, so two workers observing the
// same state produce one winner and one version conflict. The caller reloads and recomputes after a
// conflict.
func (s *Store) SaveBreaker(ctx context.Context, tenant tenancy.TenantID, endpointID string, expectedVersion int64, state webhook.BreakerState) (BreakerSnapshot, error) {
	if s == nil || s.db == nil {
		return BreakerSnapshot{}, errors.New("webhook delivery store database is required")
	}
	if ctx == nil {
		return BreakerSnapshot{}, errors.New("webhook breaker context is required")
	}
	if err := validateEndpointTenant(tenant); err != nil {
		return BreakerSnapshot{}, err
	}
	if err := webhook.ValidateEndpointID(endpointID); err != nil {
		return BreakerSnapshot{}, err
	}
	if expectedVersion < 0 || expectedVersion > maxEndpointVersion {
		return BreakerSnapshot{}, webhook.ErrInvalidBreakerState
	}
	state, err := normalizedBreakerState(state)
	if err != nil {
		return BreakerSnapshot{}, err
	}

	var openedAt, openFor any
	if state.Status != webhook.BreakerClosed {
		openedAt = state.OpenedAt
		openFor = int64(state.OpenFor / time.Second)
	}

	var snapshot BreakerSnapshot
	err = inTenantTx(ctx, s.db, tenant, func(ctx context.Context, tx *sql.Tx) error {
		var status string
		var failures, probes, version int64
		var recordedOpenedAt sql.NullTime
		var recordedOpenFor sql.NullInt64
		if err := tx.QueryRowContext(ctx,
			`SELECT r_status,r_failures,r_opened_at,r_open_for_seconds,r_probes,r_version
			   FROM keel_meta.save_webhook_breaker($1,$2,$3,$4,$5,$6,$7)`,
			endpointID, expectedVersion, string(state.Status), int64(state.Failures),
			openedAt, openFor, int64(state.Probes)).
			Scan(&status, &failures, &recordedOpenedAt, &recordedOpenFor, &probes, &version); err != nil {
			return fmt.Errorf("save webhook breaker: %w", err)
		}
		stored, err := breakerState(status, failures, recordedOpenedAt, recordedOpenFor, probes)
		if err != nil {
			return err
		}
		snapshot = BreakerSnapshot{State: stored, Version: version}
		return nil
	})
	if err != nil {
		return BreakerSnapshot{}, err
	}
	return snapshot, nil
}

func breakerState(status string, failures int64, openedAt sql.NullTime, openFor sql.NullInt64, probes int64) (webhook.BreakerState, error) {
	state := webhook.BreakerState{
		Status:   webhook.BreakerStatus(status),
		Failures: int(failures),
		Probes:   int(probes),
	}
	if openedAt.Valid {
		state.OpenedAt = openedAt.Time.UTC()
	}
	if openFor.Valid {
		state.OpenFor = time.Duration(openFor.Int64) * time.Second
	}
	if _, err := normalizedBreakerState(state); err != nil {
		return webhook.BreakerState{}, fmt.Errorf("webhook breaker returned an invalid state: %w", err)
	}
	return state, nil
}

func normalizedBreakerState(state webhook.BreakerState) (webhook.BreakerState, error) {
	if state.Status == "" {
		state.Status = webhook.BreakerClosed
	}
	if err := state.Validate(); err != nil {
		return webhook.BreakerState{}, err
	}
	if state.Failures < 0 || state.Failures > 1_000_000 || state.Probes < 0 || state.Probes > 10 {
		return webhook.BreakerState{}, webhook.ErrInvalidBreakerState
	}
	if state.Status != webhook.BreakerClosed &&
		(state.OpenFor < time.Second || state.OpenFor > 24*time.Hour) {
		return webhook.BreakerState{}, webhook.ErrInvalidBreakerState
	}
	return state, nil
}

func inTenantTx(ctx context.Context, db *sql.DB, tenant tenancy.TenantID, fn func(context.Context, *sql.Tx) error) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin webhook tenant transaction: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	if _, err := tx.ExecContext(ctx, "SELECT set_config('keel.tenant_id', $1, true)", string(tenant)); err != nil {
		return fmt.Errorf("set webhook tenant context: %w", err)
	}
	if err := fn(ctx, tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit webhook tenant transaction: %w", err)
	}
	committed = true
	return nil
}
