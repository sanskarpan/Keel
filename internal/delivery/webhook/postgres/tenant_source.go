package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

const (
	maxTenantBatch = 1000
	zeroTenantID   = "00000000-0000-0000-0000-000000000000"
)

// TenantSource discovers tenants with due or expired deliveries over the webhook capability's
// connection. It returns tenant IDs only; delivery, endpoint and payload data stay behind the
// existing tenant-scoped functions.
type TenantSource struct {
	db *sql.DB
}

// NewTenantSource creates a tenant source over the webhook capability's connection.
func NewTenantSource(db *sql.DB) (*TenantSource, error) {
	if db == nil {
		return nil, errors.New("webhook tenant source database is required")
	}
	return &TenantSource{db: db}, nil
}

// DueTenants returns up to limit tenant IDs ordered by their earliest due or expired delivery.
func (s *TenantSource) DueTenants(ctx context.Context, limit int) ([]tenancy.TenantID, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("webhook tenant source database is required")
	}
	if ctx == nil {
		return nil, errors.New("webhook tenant source context is required")
	}
	if limit < 1 || limit > maxTenantBatch {
		return nil, errors.New("webhook tenant limit is invalid")
	}

	rows, err := s.db.QueryContext(ctx,
		`SELECT r_tenant_id FROM keel_meta.list_webhook_delivery_tenants($1)`, limit)
	if err != nil {
		return nil, fmt.Errorf("list webhook delivery tenants: %w", err)
	}
	defer rows.Close()

	tenants := make([]tenancy.TenantID, 0, limit)
	seen := make(map[string]struct{}, limit)
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, fmt.Errorf("scan webhook delivery tenant: %w", err)
		}
		if raw == zeroTenantID {
			return nil, errors.New("webhook tenant source returned a zero tenant")
		}
		tenant, err := tenancy.ParseTenantID(raw)
		if err != nil {
			return nil, errors.New("webhook tenant source returned an invalid tenant")
		}
		if _, duplicate := seen[raw]; duplicate {
			continue
		}
		seen[raw] = struct{}{}
		tenants = append(tenants, tenant)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate webhook delivery tenants: %w", err)
	}
	return tenants, nil
}
