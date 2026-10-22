package postgres

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/sanskarpan/keel/internal/delivery/webhook"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

const (
	storeTenantID   = "11111111-1111-4111-8111-111111111111"
	storeEventID    = "0b6f6b9e-2f3c-4f0e-9a3f-7b0f1f2c3d4e"
	storeEndpointID = "9a0e7f3c-1b2a-4c5d-8e9f-0a1b2c3d4e5f"
)

func validStoreIdentity(t *testing.T) webhook.Identity {
	t.Helper()
	tenant, err := tenancy.ParseTenantID(storeTenantID)
	if err != nil {
		t.Fatalf("ParseTenantID: %v", err)
	}
	return webhook.Identity{
		Tenant:              tenant,
		EventID:             storeEventID,
		EndpointID:          storeEndpointID,
		SubscriptionVersion: 2,
	}
}

func TestNewStoreRequiresDatabase(t *testing.T) {
	t.Parallel()

	if store, err := New(nil); err == nil || store != nil {
		t.Fatalf("expected an error for a nil database, got store=%v err=%v", store, err)
	}
}

func TestEnsureNilSafety(t *testing.T) {
	t.Parallel()

	var store *Store
	if _, err := store.Ensure(context.Background(), validStoreIdentity(t)); err == nil {
		t.Fatal("expected an error for a nil store")
	}
	empty := &Store{}
	if _, err := empty.Ensure(context.Background(), validStoreIdentity(t)); err == nil {
		t.Fatal("expected an error for a store without a database")
	}
}

func TestEnsureRequiresContext(t *testing.T) {
	t.Parallel()

	store, err := New(&sql.DB{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := store.Ensure(nil, validStoreIdentity(t)); err == nil {
		t.Fatal("expected an error for a nil context")
	}
}

func TestEnsureValidatesIdentity(t *testing.T) {
	t.Parallel()

	store, err := New(&sql.DB{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	valid := validStoreIdentity(t)
	cases := []struct {
		name   string
		mutate func(webhook.Identity) webhook.Identity
	}{
		{name: "zero tenant", mutate: func(i webhook.Identity) webhook.Identity { i.Tenant = ""; return i }},
		{name: "nil tenant", mutate: func(i webhook.Identity) webhook.Identity {
			i.Tenant = "00000000-0000-0000-0000-000000000000"
			return i
		}},
		{name: "malformed tenant", mutate: func(i webhook.Identity) webhook.Identity { i.Tenant = "tenant-one"; return i }},
		{name: "short event", mutate: func(i webhook.Identity) webhook.Identity { i.EventID = "short"; return i }},
		{name: "empty endpoint", mutate: func(i webhook.Identity) webhook.Identity { i.EndpointID = ""; return i }},
		{name: "zero version", mutate: func(i webhook.Identity) webhook.Identity { i.SubscriptionVersion = 0; return i }},
		{name: "version above cap", mutate: func(i webhook.Identity) webhook.Identity {
			i.SubscriptionVersion = webhook.MaxSubscriptionVersion + 1
			return i
		}},
	}

	for _, testCase := range cases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			if _, err := store.Ensure(context.Background(), testCase.mutate(valid)); !errors.Is(err, webhook.ErrInvalidDelivery) {
				t.Fatalf("expected ErrInvalidDelivery, got %v", err)
			}
		})
	}
}
