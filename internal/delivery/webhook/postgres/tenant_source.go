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
	maxTenantBatch = 1000
	zeroTenantID   = "00000000-0000-0000-0000-000000000000"
)

// TenantSource discovers tenants with due or expired deliveries over the webhook capability's
// connection. It returns tenant IDs, due times and due counts only; delivery, endpoint and payload
// data stay behind the existing tenant-scoped functions.
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

// DueTenants returns up to limit tenants ordered by their earliest due or expired delivery.
func (s *TenantSource) DueTenants(ctx context.Context, limit int) ([]webhook.DueTenant, error) {
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
		`SELECT r_tenant_id,r_due_at,r_due_count FROM keel_meta.list_webhook_delivery_tenants($1)`, limit)
	if err != nil {
		return nil, fmt.Errorf("list webhook delivery tenants: %w", err)
	}
	defer rows.Close()

	tenants := make([]webhook.DueTenant, 0, limit)
	seen := make(map[string]int, limit)
	for rows.Next() {
		var raw string
		var dueAt time.Time
		var dueCount int64
		if err := rows.Scan(&raw, &dueAt, &dueCount); err != nil {
			return nil, fmt.Errorf("scan webhook delivery tenant: %w", err)
		}
		if raw == zeroTenantID {
			return nil, errors.New("webhook tenant source returned a zero tenant")
		}
		tenant, err := tenancy.ParseTenantID(raw)
		if err != nil {
			return nil, errors.New("webhook tenant source returned an invalid tenant")
		}
		if dueAt.IsZero() || dueCount < 1 {
			return nil, errors.New("webhook tenant source returned an invalid schedule")
		}
		if index, duplicate := seen[raw]; duplicate {
			if dueAt.Before(tenants[index].DueAt) {
				tenants[index].DueAt = dueAt
			}
			tenants[index].DueCount += dueCount
			continue
		}
		seen[raw] = len(tenants)
		tenants = append(tenants, webhook.DueTenant{Tenant: tenant, DueAt: dueAt, DueCount: dueCount})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate webhook delivery tenants: %w", err)
	}
	return tenants, nil
}
