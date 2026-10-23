package webhook

import (
	"errors"
	"strings"
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

func testRepairRequest(t *testing.T) RepairRequest {
	t.Helper()
	request := testReconciliationRequest(t)
	return RepairRequest{
		Tenant:      request.Tenant,
		RepairID:    "rep_0123456789abcdef",
		RunID:       request.RunID,
		RequestedBy: "operator@example.com",
		EventLimit:  100,
	}
}

func TestRepairRequestValidate(t *testing.T) {
	if err := testRepairRequest(t).Validate(); err != nil {
		t.Fatalf("valid repair rejected: %v", err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*RepairRequest)
	}{
		{"zero tenant", func(r *RepairRequest) { r.Tenant = "" }},
		{"bad repair", func(r *RepairRequest) { r.RepairID = "not a repair" }},
		{"bad run", func(r *RepairRequest) { r.RunID = "short" }},
		{"bad actor", func(r *RepairRequest) { r.RequestedBy = " operator" }},
		{"zero limit", func(r *RepairRequest) { r.EventLimit = 0 }},
		{"large limit", func(r *RepairRequest) { r.EventLimit = MaxReconciliationPage + 1 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := testRepairRequest(t)
			test.mutate(&request)
			if err := request.Validate(); !errors.Is(err, ErrInvalidReconciliation) {
				t.Fatalf("error = %v, want invalid reconciliation", err)
			}
		})
	}
}

func testCursorResetRequest(t *testing.T) CursorResetRequest {
	t.Helper()
	return CursorResetRequest{
		Tenant:      testReconciliationRequest(t).Tenant,
		ResetID:     "rst_0123456789abcdef",
		RequestedBy: "operator@example.com",
		To:          time.Now().Add(-2 * time.Minute),
		Reason:      "rescan the known gap window",
	}
}

func TestCursorResetRequestValidate(t *testing.T) {
	if err := testCursorResetRequest(t).Validate(); err != nil {
		t.Fatalf("valid reset rejected: %v", err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*CursorResetRequest)
	}{
		{"zero tenant", func(r *CursorResetRequest) { r.Tenant = "" }},
		{"bad reset", func(r *CursorResetRequest) { r.ResetID = "not a reset" }},
		{"bad actor", func(r *CursorResetRequest) { r.RequestedBy = " operator" }},
		{"zero time", func(r *CursorResetRequest) { r.To = time.Time{} }},
		{"empty reason", func(r *CursorResetRequest) { r.Reason = "" }},
		{"control reason", func(r *CursorResetRequest) { r.Reason = "bad\nreason" }},
		{"long reason", func(r *CursorResetRequest) { r.Reason = strings.Repeat("r", MaxReplayReasonBytes+1) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := testCursorResetRequest(t)
			test.mutate(&request)
			if err := request.Validate(); !errors.Is(err, ErrInvalidReconciliation) {
				t.Fatalf("error = %v, want invalid reconciliation", err)
			}
		})
	}
}
