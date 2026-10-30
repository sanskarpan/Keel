// Package postgres enforces the webhook logical delivery identity in PostgreSQL.
//
// The store mints one delivery ID per (tenant, event, endpoint, subscription revision) and returns
// that same delivery on every later claim, so a retried or concurrent scheduler cannot give a
// receiver two distinct deliveries of one logical effect.
package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/sanskarpan/keel/internal/delivery/webhook"
)

// ReconciliationObserver receives content-free reconciliation outcomes. Implementations must not
// retain tenant, event, endpoint or error strings; the metrics recorder implements it. Failure
// observations fire only for operational failures after request validation, never for invalid
// requests or missing dependencies.
type ReconciliationObserver interface {
	ObserveReconciliationPlan(webhook.ReconciliationPage)
	ObserveReconciliationRepair(webhook.RepairResult)
	ObservePlanFailure()
	ObserveRepairFailure()
}

// Store claims durable webhook deliveries over the webhook capability's database connection.
type Store struct {
	mu            sync.Mutex
	db            *sql.DB
	reconObserver ReconciliationObserver
}

// SetReconciliationObserver registers an optional content-free reconciliation observer, fired by
// the plan and repair paths after a successful call. A nil observer disables observation.
func (s *Store) SetReconciliationObserver(observer ReconciliationObserver) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reconObserver = observer
}

func (s *Store) reconciliationObserver() ReconciliationObserver {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reconObserver
}

// Claim is the durable outcome of one claim. Created reports whether this call inserted the
// delivery; a duplicate claim returns the recorded delivery with Created false.
type Claim struct {
	Delivery  webhook.Delivery
	Created   bool
	CreatedAt time.Time
}

// New creates a store over the webhook capability's connection. The database is required: a store
// that cannot enforce uniqueness must not mint delivery IDs.
func New(db *sql.DB) (*Store, error) {
	if db == nil {
		return nil, errors.New("webhook delivery store database is required")
	}
	return &Store{db: db}, nil
}

// Ensure validates the logical identity and claims its delivery in one tenant transaction. A
// duplicate claim returns the recorded delivery ID and creation time without rewriting the row.
func (s *Store) Ensure(ctx context.Context, identity webhook.Identity) (Claim, error) {
	if s == nil || s.db == nil {
		return Claim{}, errors.New("webhook delivery store database is required")
	}
	if ctx == nil {
		return Claim{}, errors.New("webhook delivery context is required")
	}
	if err := identity.Validate(); err != nil {
		return Claim{}, err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Claim{}, fmt.Errorf("begin webhook delivery transaction: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	if _, err := tx.ExecContext(ctx, "SELECT set_config('keel.tenant_id', $1, true)", string(identity.Tenant)); err != nil {
		return Claim{}, fmt.Errorf("set webhook delivery tenant context: %w", err)
	}

	var deliveryID string
	var created bool
	var createdAt time.Time
	err = tx.QueryRowContext(ctx,
		`SELECT delivery_id,created,created_at FROM keel_meta.claim_webhook_delivery($1,$2,$3,$4)`,
		identity.EventID, identity.EndpointID, int64(identity.SubscriptionVersion), uuid.NewString()).
		Scan(&deliveryID, &created, &createdAt)
	if err != nil {
		return Claim{}, fmt.Errorf("claim webhook delivery: %w", err)
	}

	delivery := webhook.Delivery{ID: deliveryID, Identity: identity}
	if err := delivery.Validate(); err != nil {
		return Claim{}, fmt.Errorf("webhook claim returned an invalid delivery: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return Claim{}, fmt.Errorf("commit webhook delivery transaction: %w", err)
	}
	committed = true
	return Claim{Delivery: delivery, Created: created, CreatedAt: createdAt.UTC()}, nil
}
