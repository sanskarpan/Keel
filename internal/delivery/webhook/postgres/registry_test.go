package postgres

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/sanskarpan/keel/internal/delivery/webhook"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

func unreachableRegistry(t *testing.T) *Registry {
	t.Helper()
	db, err := sql.Open("pgx", "postgres://127.0.0.1:1/keel?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return &Registry{db: db}
}

func validRegistryRegistration() webhook.EndpointRegistration {
	return webhook.EndpointRegistration{
		ID:                  uuid.NewString(),
		URL:                 "https://example.com/webhooks/orders",
		KeyID:               "key_2026",
		SubscriptionVersion: 1,
	}
}

func TestNewRegistryRequiresDatabase(t *testing.T) {
	if _, err := NewRegistry(nil); err == nil {
		t.Fatal("NewRegistry(nil) error = nil")
	}
}

func TestRegistryRegisterRejectsInvalidInput(t *testing.T) {
	registry := unreachableRegistry(t)
	ctx := context.Background()
	tenant := randomTenant(t)
	registration := validRegistryRegistration()
	cases := map[string]struct {
		ctx      context.Context
		tenant   tenancy.TenantID
		change   func(*webhook.EndpointRegistration)
		expected int64
	}{
		"nil context":        {ctx: nil, tenant: tenant},
		"empty tenant":       {ctx: ctx, tenant: "", expected: 0},
		"invalid tenant":     {ctx: ctx, tenant: "not-a-tenant", expected: 0},
		"invalid id":         {ctx: ctx, tenant: tenant, change: func(r *webhook.EndpointRegistration) { r.ID = "short" }},
		"invalid url":        {ctx: ctx, tenant: tenant, change: func(r *webhook.EndpointRegistration) { r.URL = "http://example.com/hook" }},
		"invalid key":        {ctx: ctx, tenant: tenant, change: func(r *webhook.EndpointRegistration) { r.KeyID = "abc" }},
		"invalid version":    {ctx: ctx, tenant: tenant, change: func(r *webhook.EndpointRegistration) { r.SubscriptionVersion = 0 }},
		"negative expected":  {ctx: ctx, tenant: tenant, expected: -1},
		"expected above cap": {ctx: ctx, tenant: tenant, expected: maxEndpointVersion + 1},
	}
	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			candidate := registration
			if testCase.change != nil {
				testCase.change(&candidate)
			}
			_, err := registry.Register(testCase.ctx, testCase.tenant, candidate, testCase.expected)
			if testCase.ctx == nil {
				if err == nil {
					t.Fatal("Register(nil) error = nil")
				}
				return
			}
			if !errors.Is(err, webhook.ErrInvalidEndpoint) {
				t.Fatalf("Register() error = %v, want ErrInvalidEndpoint", err)
			}
		})
	}
}

func TestRegistrySetStatusRejectsInvalidInput(t *testing.T) {
	registry := unreachableRegistry(t)
	ctx := context.Background()
	tenant := randomTenant(t)
	endpointID := uuid.NewString()
	cases := map[string]struct {
		ctx      context.Context
		tenant   tenancy.TenantID
		id       string
		status   webhook.EndpointStatus
		expected int64
	}{
		"nil context":        {ctx: nil, tenant: tenant, id: endpointID, status: webhook.EndpointActive, expected: 1},
		"empty tenant":       {ctx: ctx, tenant: "", id: endpointID, status: webhook.EndpointActive, expected: 1},
		"invalid id":         {ctx: ctx, tenant: tenant, id: "short", status: webhook.EndpointActive, expected: 1},
		"unknown status":     {ctx: ctx, tenant: tenant, id: endpointID, status: webhook.EndpointUnknown, expected: 1},
		"empty status":       {ctx: ctx, tenant: tenant, id: endpointID, status: "", expected: 1},
		"zero expected":      {ctx: ctx, tenant: tenant, id: endpointID, status: webhook.EndpointActive, expected: 0},
		"expected above cap": {ctx: ctx, tenant: tenant, id: endpointID, status: webhook.EndpointActive, expected: maxEndpointVersion + 1},
	}
	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := registry.SetStatus(testCase.ctx, testCase.tenant, testCase.id, testCase.status, testCase.expected)
			if testCase.ctx == nil {
				if err == nil {
					t.Fatal("SetStatus(nil) error = nil")
				}
				return
			}
			if !errors.Is(err, webhook.ErrInvalidEndpoint) {
				t.Fatalf("SetStatus() error = %v, want ErrInvalidEndpoint", err)
			}
		})
	}
}

func TestStoreEndpointRejectsInvalidInput(t *testing.T) {
	store := newStore(t, unreachableRegistry(t).db)
	ctx := context.Background()
	tenant := randomTenant(t)
	cases := map[string]struct {
		ctx          context.Context
		tenant       tenancy.TenantID
		id           string
		subscription uint32
	}{
		"nil context":       {ctx: nil, tenant: tenant, id: uuid.NewString(), subscription: 1},
		"empty tenant":      {ctx: ctx, tenant: "", id: uuid.NewString(), subscription: 1},
		"invalid id":        {ctx: ctx, tenant: tenant, id: "short", subscription: 1},
		"zero subscription": {ctx: ctx, tenant: tenant, id: uuid.NewString(), subscription: 0},
		"subscription cap":  {ctx: ctx, tenant: tenant, id: uuid.NewString(), subscription: webhook.MaxSubscriptionVersion + 1},
	}
	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := store.Endpoint(testCase.ctx, testCase.tenant, testCase.id, testCase.subscription)
			if testCase.ctx == nil {
				if err == nil {
					t.Fatal("Endpoint(nil) error = nil")
				}
				return
			}
			if !errors.Is(err, webhook.ErrInvalidEndpoint) {
				t.Fatalf("Endpoint() error = %v, want ErrInvalidEndpoint", err)
			}
		})
	}
}
