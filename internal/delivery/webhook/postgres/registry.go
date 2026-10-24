package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/sanskarpan/keel/internal/delivery/webhook"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

const maxEndpointVersion = 1 << 53

// Registry manages endpoint registrations over the application capability's connection. Endpoint
// URLs are caller-supplied and sensitive; they are returned to the caller that supplied or resolved
// them and must never be logged.
type Registry struct {
	db *sql.DB
}

// NewRegistry creates a registry over the application capability's connection. The database is
// required: endpoint state must be durable and versioned.
func NewRegistry(db *sql.DB) (*Registry, error) {
	if db == nil {
		return nil, errors.New("webhook endpoint registry database is required")
	}
	return &Registry{db: db}, nil
}

// Register creates an endpoint when expectedVersion is zero, or replaces its URL, key reference and
// subscription revision when expectedVersion equals the stored version. Creation is exclusive: a
// duplicate endpoint ID returns an error instead of overwriting the existing registration.
func (r *Registry) Register(ctx context.Context, tenant tenancy.TenantID, registration webhook.EndpointRegistration, expectedVersion int64) (webhook.Endpoint, error) {
	if r == nil || r.db == nil {
		return webhook.Endpoint{}, errors.New("webhook endpoint registry database is required")
	}
	if ctx == nil {
		return webhook.Endpoint{}, errors.New("webhook endpoint context is required")
	}
	if err := validateEndpointTenant(tenant); err != nil {
		return webhook.Endpoint{}, err
	}
	if err := registration.Validate(); err != nil {
		return webhook.Endpoint{}, err
	}
	if expectedVersion < 0 || expectedVersion > maxEndpointVersion {
		return webhook.Endpoint{}, webhook.ErrInvalidEndpoint
	}

	var endpoint webhook.Endpoint
	err := r.inTenantTx(ctx, tenant, func(ctx context.Context, tx *sql.Tx) error {
		var endpointID, status, rawURL, keyID string
		var version, subscription int64
		var createdAt, updatedAt time.Time
		var created bool
		if err := tx.QueryRowContext(ctx,
			`SELECT r_endpoint_id,r_endpoint_version,r_status,r_url,r_key_id,r_subscription_version,
			        r_created_at,r_updated_at,r_created
			   FROM keel_meta.register_webhook_endpoint($1,$2,$3,$4,$5)`,
			registration.ID, registration.URL, registration.KeyID,
			int64(registration.SubscriptionVersion), expectedVersion).
			Scan(&endpointID, &version, &status, &rawURL, &keyID, &subscription,
				&createdAt, &updatedAt, &created); err != nil {
			return fmt.Errorf("register webhook endpoint: %w", err)
		}
		if created != (expectedVersion == 0) {
			return fmt.Errorf("webhook endpoint registration returned an inconsistent creation flag")
		}
		stored, err := storedEndpoint(tenant, endpointID, version, status, rawURL, keyID, subscription, createdAt, updatedAt)
		if err != nil {
			return err
		}
		endpoint = stored
		return nil
	})
	if err != nil {
		return webhook.Endpoint{}, mapEndpointRegistryError(err)
	}
	return endpoint, nil
}

// SetStatus activates or deactivates one endpoint revision under the same optimistic concurrency
// check. Deactivated endpoints are never resolved for delivery and rows are never deleted.
func (r *Registry) SetStatus(ctx context.Context, tenant tenancy.TenantID, endpointID string, status webhook.EndpointStatus, expectedVersion int64) (webhook.Endpoint, error) {
	if r == nil || r.db == nil {
		return webhook.Endpoint{}, errors.New("webhook endpoint registry database is required")
	}
	if ctx == nil {
		return webhook.Endpoint{}, errors.New("webhook endpoint context is required")
	}
	if err := validateEndpointTenant(tenant); err != nil {
		return webhook.Endpoint{}, err
	}
	if err := webhook.ValidateEndpointID(endpointID); err != nil {
		return webhook.Endpoint{}, err
	}
	if status != webhook.EndpointActive && status != webhook.EndpointInactive {
		return webhook.Endpoint{}, webhook.ErrInvalidEndpoint
	}
	if expectedVersion < 1 || expectedVersion > maxEndpointVersion {
		return webhook.Endpoint{}, webhook.ErrInvalidEndpoint
	}

	var endpoint webhook.Endpoint
	err := r.inTenantTx(ctx, tenant, func(ctx context.Context, tx *sql.Tx) error {
		var recordedID, recordedStatus, rawURL, keyID string
		var version, subscription int64
		var createdAt, updatedAt time.Time
		var created bool
		if err := tx.QueryRowContext(ctx,
			`SELECT r_endpoint_id,r_endpoint_version,r_status,r_url,r_key_id,r_subscription_version,
			        r_created_at,r_updated_at,r_created
			   FROM keel_meta.set_webhook_endpoint_status($1,$2,$3)`,
			endpointID, string(status), expectedVersion).
			Scan(&recordedID, &version, &recordedStatus, &rawURL, &keyID, &subscription,
				&createdAt, &updatedAt, &created); err != nil {
			return fmt.Errorf("set webhook endpoint status: %w", err)
		}
		if created {
			return fmt.Errorf("webhook endpoint status change reported a creation")
		}
		stored, err := storedEndpoint(tenant, recordedID, version, recordedStatus, rawURL, keyID, subscription, createdAt, updatedAt)
		if err != nil {
			return err
		}
		endpoint = stored
		return nil
	})
	if err != nil {
		return webhook.Endpoint{}, mapEndpointRegistryError(err)
	}
	return endpoint, nil
}

// Endpoint resolves the active URL and signing key for one delivery's endpoint and subscription
// revision. It requires the webhook delivery capability; an inactive, missing or stale revision
// returns webhook.ErrEndpointUnavailable.
func (s *Store) Endpoint(ctx context.Context, tenant tenancy.TenantID, endpointID string, subscriptionVersion uint32) (webhook.Endpoint, error) {
	if s == nil || s.db == nil {
		return webhook.Endpoint{}, errors.New("webhook delivery store database is required")
	}
	if ctx == nil {
		return webhook.Endpoint{}, errors.New("webhook endpoint context is required")
	}
	if err := validateEndpointTenant(tenant); err != nil {
		return webhook.Endpoint{}, err
	}
	if err := webhook.ValidateEndpointID(endpointID); err != nil {
		return webhook.Endpoint{}, err
	}
	if subscriptionVersion < 1 || subscriptionVersion > webhook.MaxSubscriptionVersion {
		return webhook.Endpoint{}, webhook.ErrInvalidEndpoint
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return webhook.Endpoint{}, fmt.Errorf("begin webhook endpoint transaction: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	if _, err := tx.ExecContext(ctx, "SELECT set_config('keel.tenant_id', $1, true)", string(tenant)); err != nil {
		return webhook.Endpoint{}, fmt.Errorf("set webhook endpoint tenant context: %w", err)
	}

	var recordedID, rawURL, keyID string
	var recordedSubscription int64
	err = tx.QueryRowContext(ctx,
		`SELECT r_endpoint_id,r_url,r_key_id,r_subscription_version
		   FROM keel_meta.resolve_webhook_endpoint($1,$2)`,
		endpointID, int64(subscriptionVersion)).
		Scan(&recordedID, &rawURL, &keyID, &recordedSubscription)
	if errors.Is(err, sql.ErrNoRows) {
		return webhook.Endpoint{}, webhook.ErrEndpointUnavailable
	}
	if err != nil {
		return webhook.Endpoint{}, fmt.Errorf("resolve webhook endpoint: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return webhook.Endpoint{}, fmt.Errorf("commit webhook endpoint transaction: %w", err)
	}
	committed = true

	endpoint := webhook.Endpoint{
		Tenant:              tenant,
		ID:                  recordedID,
		URL:                 rawURL,
		KeyID:               keyID,
		SubscriptionVersion: uint32(recordedSubscription),
		Status:              webhook.EndpointActive,
	}
	if err := endpoint.Registration().Validate(); err != nil {
		return webhook.Endpoint{}, fmt.Errorf("webhook endpoint lookup returned an invalid endpoint: %w", err)
	}
	return endpoint, nil
}

func (r *Registry) inTenantTx(ctx context.Context, tenant tenancy.TenantID, fn func(context.Context, *sql.Tx) error) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin webhook endpoint transaction: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	if _, err := tx.ExecContext(ctx, "SELECT set_config('keel.tenant_id', $1, true)", string(tenant)); err != nil {
		return fmt.Errorf("set webhook endpoint tenant context: %w", err)
	}
	if err := fn(ctx, tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit webhook endpoint transaction: %w", err)
	}
	committed = true
	return nil
}

func storedEndpoint(tenant tenancy.TenantID, endpointID string, version int64, status, rawURL, keyID string, subscription int64, createdAt, updatedAt time.Time) (webhook.Endpoint, error) {
	endpoint := webhook.Endpoint{
		Tenant:              tenant,
		ID:                  endpointID,
		URL:                 rawURL,
		KeyID:               keyID,
		SubscriptionVersion: uint32(subscription),
		Status:              webhook.EndpointStatus(status),
		Version:             version,
		CreatedAt:           createdAt.UTC(),
		UpdatedAt:           updatedAt.UTC(),
	}
	if version < 1 || subscription < 1 || subscription > int64(webhook.MaxSubscriptionVersion) {
		return webhook.Endpoint{}, fmt.Errorf("webhook endpoint returned invalid version bounds")
	}
	if endpoint.Status != webhook.EndpointActive && endpoint.Status != webhook.EndpointInactive {
		return webhook.Endpoint{}, fmt.Errorf("webhook endpoint returned an invalid status")
	}
	if err := endpoint.Registration().Validate(); err != nil {
		return webhook.Endpoint{}, fmt.Errorf("webhook endpoint returned an invalid registration: %w", err)
	}
	return endpoint, nil
}

func validateEndpointTenant(tenant tenancy.TenantID) error {
	if string(tenant) == "" || string(tenant) == zeroTenant {
		return webhook.ErrInvalidEndpoint
	}
	if _, err := tenancy.ParseTenantID(string(tenant)); err != nil {
		return webhook.ErrInvalidEndpoint
	}
	return nil
}

func mapEndpointRegistryError(err error) error {
	if err != nil && strings.Contains(err.Error(), "active endpoint quota exceeded") {
		return webhook.ErrEndpointQuota
	}
	return err
}
