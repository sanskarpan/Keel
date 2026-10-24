package webhook

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

func testEndpointLimitChange(t *testing.T) EndpointLimitChange {
	t.Helper()
	tenant, err := tenancy.ParseTenantID("11111111-1111-4111-8111-111111111111")
	if err != nil {
		t.Fatal(err)
	}
	return EndpointLimitChange{
		Tenant: tenant, ChangeID: "pol_0123456789abcdef", RequestedBy: "operator@example.com",
		Limit: 100, Reason: "raise the tenant endpoint limit", ExpectedVersion: 0,
	}
}

func TestEndpointLimitChangeValidate(t *testing.T) {
	if err := testEndpointLimitChange(t).Validate(); err != nil {
		t.Fatalf("valid change rejected: %v", err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*EndpointLimitChange)
	}{
		{"zero tenant", func(c *EndpointLimitChange) { c.Tenant = "" }},
		{"bad change", func(c *EndpointLimitChange) { c.ChangeID = "short" }},
		{"bad actor", func(c *EndpointLimitChange) { c.RequestedBy = " operator" }},
		{"zero limit", func(c *EndpointLimitChange) { c.Limit = 0 }},
		{"large limit", func(c *EndpointLimitChange) { c.Limit = MaxEndpointLimit + 1 }},
		{"empty reason", func(c *EndpointLimitChange) { c.Reason = "" }},
		{"control reason", func(c *EndpointLimitChange) { c.Reason = "bad\nreason" }},
		{"long reason", func(c *EndpointLimitChange) { c.Reason = strings.Repeat("r", MaxReplayReasonBytes+1) }},
		{"negative version", func(c *EndpointLimitChange) { c.ExpectedVersion = -1 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			change := testEndpointLimitChange(t)
			test.mutate(&change)
			if err := change.Validate(); !errors.Is(err, ErrInvalidEndpoint) {
				t.Fatalf("error = %v, want invalid endpoint", err)
			}
		})
	}
}

func TestEndpointLimitPolicyUpdatedAt(t *testing.T) {
	now := time.Now().UTC()
	policy := EndpointLimitPolicy{ChangeID: "pol_0123456789abcdef", Version: 1, ActiveEndpointLimit: 100, UpdatedAt: now}
	if policy.Version != 1 || policy.ActiveEndpointLimit != 100 || !policy.UpdatedAt.Equal(now) {
		t.Fatalf("policy = %+v", policy)
	}
}
