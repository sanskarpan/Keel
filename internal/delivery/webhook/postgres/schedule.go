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

const (
	minLeaseSeconds = 5
	maxLeaseSeconds = 300
	maxLeaseBatch   = 100
	maxAttempts     = 100
	maxLatency      = 10 * time.Minute
	zeroTenant      = "00000000-0000-0000-0000-000000000000"
)

// Lease is one fenced attempt grant. AttemptNumber is the attempt the worker must record, and
// LeaseEpoch fences the grant so a worker whose lease expired cannot record its result.
type Lease struct {
	Delivery       webhook.Delivery
	AttemptNumber  int
	AttemptID      string
	LeaseEpoch     int64
	LeaseExpiresAt time.Time
}

// Validate checks that the lease can be sent and recorded.
func (l Lease) Validate() error {
	if err := l.Delivery.Validate(); err != nil {
		return err
	}
	if l.AttemptNumber < 1 || l.AttemptNumber > maxAttempts {
		return webhook.ErrInvalidAttempt
	}
	if err := webhook.ValidateAttemptID(l.AttemptID); err != nil {
		return err
	}
	if l.LeaseEpoch < 1 {
		return webhook.ErrInvalidAttempt
	}
	if l.LeaseExpiresAt.IsZero() {
		return webhook.ErrInvalidAttempt
	}
	return nil
}

// AttemptResult is the classified outcome of one attempt. NextAttemptAt is set only for a
// retryable outcome that still has budget; nil there means the retry policy exhausted the
// delivery. A delivered or permanent result must not carry a next attempt time.
type AttemptResult struct {
	Outcome       webhook.Outcome
	HTTPStatus    int
	Latency       time.Duration
	NextAttemptAt *time.Time
}

// DeliveryState is the durable state after recording an attempt.
type DeliveryState struct {
	State         webhook.DeliveryState
	Attempts      int
	NextAttemptAt *time.Time
	FinishedAt    *time.Time
}

// Lease grants up to limit due deliveries to the caller under one tenant, each for leaseFor. An
// expired in-flight lease is re-leased with a higher epoch, so the previous holder can no longer
// record an attempt. The caller must derive the tenant from a trusted scheduling source, never from
// an endpoint or receiver payload.
func (s *Store) Lease(ctx context.Context, tenant tenancy.TenantID, limit int, leaseFor time.Duration) ([]Lease, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("webhook delivery store database is required")
	}
	if ctx == nil {
		return nil, errors.New("webhook delivery context is required")
	}
	if string(tenant) == "" || string(tenant) == zeroTenant {
		return nil, webhook.ErrInvalidDelivery
	}
	if _, err := tenancy.ParseTenantID(string(tenant)); err != nil {
		return nil, webhook.ErrInvalidDelivery
	}
	if limit < 1 || limit > maxLeaseBatch {
		return nil, webhook.ErrInvalidAttempt
	}
	seconds := int(leaseFor / time.Second)
	if seconds < minLeaseSeconds || seconds > maxLeaseSeconds || leaseFor != time.Duration(seconds)*time.Second {
		return nil, webhook.ErrInvalidAttempt
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin webhook delivery lease transaction: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	if _, err := tx.ExecContext(ctx, "SELECT set_config('keel.tenant_id', $1, true)", string(tenant)); err != nil {
		return nil, fmt.Errorf("set webhook delivery tenant context: %w", err)
	}

	rows, err := tx.QueryContext(ctx,
		`SELECT event_id,endpoint_id,subscription_version,delivery_id,attempt_number,
		        attempt_id,lease_epoch,lease_expires_at
		   FROM keel_meta.lease_webhook_deliveries($1,$2)`, limit, seconds)
	if err != nil {
		return nil, fmt.Errorf("lease webhook deliveries: %w", err)
	}
	leases := make([]Lease, 0, limit)
	for rows.Next() {
		var eventID, endpointID, deliveryID, attemptID string
		var version, attemptNumber int64
		var epoch int64
		var expiresAt time.Time
		if err := rows.Scan(&eventID, &endpointID, &version, &deliveryID, &attemptNumber,
			&attemptID, &epoch, &expiresAt); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan webhook delivery lease: %w", err)
		}
		if version < 1 || version > webhook.MaxSubscriptionVersion {
			rows.Close()
			return nil, fmt.Errorf("webhook lease returned an invalid subscription version")
		}
		lease := Lease{
			Delivery: webhook.Delivery{
				ID: deliveryID,
				Identity: webhook.Identity{
					Tenant:              tenant,
					EventID:             eventID,
					EndpointID:          endpointID,
					SubscriptionVersion: uint32(version),
				},
			},
			AttemptNumber:  int(attemptNumber),
			AttemptID:      attemptID,
			LeaseEpoch:     epoch,
			LeaseExpiresAt: expiresAt.UTC(),
		}
		if err := lease.Validate(); err != nil {
			rows.Close()
			return nil, fmt.Errorf("webhook lease is invalid: %w", err)
		}
		leases = append(leases, lease)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, fmt.Errorf("iterate webhook delivery leases: %w", err)
	}
	rows.Close()
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit webhook delivery lease transaction: %w", err)
	}
	committed = true
	return leases, nil
}

// RecordAttempt records one classified attempt under the lease's tenant and fence. A stale epoch,
// attempt number or a non-in-flight delivery is rejected and nothing is written.
func (s *Store) RecordAttempt(ctx context.Context, lease Lease, result AttemptResult) (DeliveryState, error) {
	if s == nil || s.db == nil {
		return DeliveryState{}, errors.New("webhook delivery store database is required")
	}
	if ctx == nil {
		return DeliveryState{}, errors.New("webhook delivery context is required")
	}
	if err := lease.Validate(); err != nil {
		return DeliveryState{}, err
	}
	if !result.Outcome.Valid() {
		return DeliveryState{}, webhook.ErrInvalidAttempt
	}
	if result.HTTPStatus < 0 || result.HTTPStatus > webhook.MaxResponseStatus {
		return DeliveryState{}, webhook.ErrInvalidAttempt
	}
	if result.Outcome == webhook.OutcomeDelivered &&
		(result.HTTPStatus < 200 || result.HTTPStatus > 299) {
		return DeliveryState{}, webhook.ErrInvalidAttempt
	}
	if result.Latency < 0 || result.Latency > maxLatency {
		return DeliveryState{}, webhook.ErrInvalidAttempt
	}
	if result.Outcome != webhook.OutcomeRetryable && result.NextAttemptAt != nil {
		return DeliveryState{}, webhook.ErrInvalidAttempt
	}
	var nextAttempt any
	if result.NextAttemptAt != nil {
		nextAttempt = result.NextAttemptAt.UTC()
	}
	latencyMS := int(result.Latency / time.Millisecond)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return DeliveryState{}, fmt.Errorf("begin webhook attempt transaction: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	tenant := lease.Delivery.Identity.Tenant
	if _, err := tx.ExecContext(ctx, "SELECT set_config('keel.tenant_id', $1, true)", string(tenant)); err != nil {
		return DeliveryState{}, fmt.Errorf("set webhook delivery tenant context: %w", err)
	}

	var state string
	var attempts int
	var next, finished sql.NullTime
	err = tx.QueryRowContext(ctx,
		`SELECT state,attempts,next_attempt_at,finished_at
		   FROM keel_meta.record_webhook_attempt($1,$2,$3,$4,$5,$6,$7,$8)`,
		lease.Delivery.ID, lease.AttemptNumber, lease.AttemptID, lease.LeaseEpoch,
		string(result.Outcome), result.HTTPStatus, latencyMS, nextAttempt).
		Scan(&state, &attempts, &next, &finished)
	if err != nil {
		return DeliveryState{}, fmt.Errorf("record webhook attempt: %w", err)
	}
	deliveryState := DeliveryState{
		State:    webhook.DeliveryState(state),
		Attempts: attempts,
	}
	if next.Valid {
		value := next.Time.UTC()
		deliveryState.NextAttemptAt = &value
	}
	if finished.Valid {
		value := finished.Time.UTC()
		deliveryState.FinishedAt = &value
	}
	if !deliveryState.State.Valid() {
		return DeliveryState{}, fmt.Errorf("webhook attempt returned an invalid state %q", state)
	}
	if err := tx.Commit(); err != nil {
		return DeliveryState{}, fmt.Errorf("commit webhook attempt transaction: %w", err)
	}
	committed = true
	return deliveryState, nil
}
