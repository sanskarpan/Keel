package webhook

import (
	"errors"
	"testing"
	"time"

	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

func testReconciliationRequest(t *testing.T) ReconciliationRequest {
	t.Helper()
	tenant, err := tenancy.ParseTenantID("11111111-1111-4111-8111-111111111111")
	if err != nil {
		t.Fatal(err)
	}
	from := time.Now().Add(-time.Minute)
	return ReconciliationRequest{
		Tenant:      tenant,
		RunID:       "rec_0123456789abcdef",
		RequestedBy: "operator@example.com",
		From:        &from,
		PageSize:    DefaultReconciliationPage,
	}
}

func TestReconciliationRequestValidate(t *testing.T) {
	request := testReconciliationRequest(t)
	if err := request.Validate(); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}
	request.From = nil
	if err := request.Validate(); err != nil {
		t.Fatalf("request without from rejected: %v", err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*ReconciliationRequest)
	}{
		{"zero tenant", func(r *ReconciliationRequest) { r.Tenant = "" }},
		{"bad tenant", func(r *ReconciliationRequest) { r.Tenant = "tenant" }},
		{"short run", func(r *ReconciliationRequest) { r.RunID = "short" }},
		{"bad run", func(r *ReconciliationRequest) { r.RunID = "not a run id" }},
		{"empty actor", func(r *ReconciliationRequest) { r.RequestedBy = "" }},
		{"bad actor", func(r *ReconciliationRequest) { r.RequestedBy = " operator" }},
		{"zero from", func(r *ReconciliationRequest) {
			zero := time.Time{}
			r.From = &zero
		}},
		{"zero page", func(r *ReconciliationRequest) { r.PageSize = 0 }},
		{"large page", func(r *ReconciliationRequest) { r.PageSize = MaxReconciliationPage + 1 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := testReconciliationRequest(t)
			test.mutate(&request)
			if err := request.Validate(); !errors.Is(err, ErrInvalidReconciliation) {
				t.Fatalf("error = %v, want invalid reconciliation", err)
			}
		})
	}
}

func TestReconciliationPageAccounting(t *testing.T) {
	page := ReconciliationPage{
		Events: []ReconciliationEvent{
			{EventID: "event-1", Missing: 0},
			{EventID: "event-2", Missing: 3},
		},
		Scanned:   2,
		GapEvents: 1,
		Missing:   3,
	}
	if page.Scanned != len(page.Events) || page.GapEvents != 1 || page.Missing != 3 {
		t.Fatalf("unexpected page accounting: %+v", page)
	}
}
