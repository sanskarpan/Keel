package webhook

import (
	"errors"
	"testing"
	"time"

	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

func testStatusAtQuery(t *testing.T) EndpointStatusAtQuery {
	t.Helper()
	tenant, err := tenancy.ParseTenantID("11111111-1111-4111-8111-111111111111")
	if err != nil {
		t.Fatal(err)
	}
	return EndpointStatusAtQuery{
		Tenant: tenant, ID: "endpoint_0123456789abcdef", At: time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC),
	}
}

func TestEndpointStatusAtQueryValidate(t *testing.T) {
	if err := testStatusAtQuery(t).Validate(); err != nil {
		t.Fatalf("valid query rejected: %v", err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*EndpointStatusAtQuery)
	}{
		{"zero tenant", func(q *EndpointStatusAtQuery) { q.Tenant = "" }},
		{"bad endpoint", func(q *EndpointStatusAtQuery) { q.ID = "short" }},
		{"zero time", func(q *EndpointStatusAtQuery) { q.At = time.Time{} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			query := testStatusAtQuery(t)
			test.mutate(&query)
			if err := query.Validate(); !errors.Is(err, ErrInvalidEndpoint) {
				t.Fatalf("error = %v, want invalid endpoint", err)
			}
		})
	}
}
