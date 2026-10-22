package webhook

import (
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

func replayTenant(t *testing.T) tenancy.TenantID {
	t.Helper()
	tenant, err := tenancy.ParseTenantID(uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	return tenant
}

func replayCandidate(t *testing.T, tenant tenancy.TenantID) ReplayCandidate {
	t.Helper()
	return ReplayCandidate{
		Delivery: Delivery{
			ID: uuid.NewString(),
			Identity: Identity{
				Tenant:              tenant,
				EventID:             "evt_" + uuid.NewString(),
				EndpointID:          uuid.NewString(),
				SubscriptionVersion: 2,
			},
		},
		State:    StateExhausted,
		Attempts: 12,
		Endpoint: EndpointEligibility{
			Status:              EndpointActive,
			SubscriptionVersion: 2,
			SignatureKeyReady:   true,
		},
	}
}

func TestSelectReplaySelectsTerminalFailures(t *testing.T) {
	tenant := replayTenant(t)
	exhausted := replayCandidate(t, tenant)
	failed := replayCandidate(t, tenant)
	failed.State = StateFailed
	failed.Attempts = 3

	selection, err := SelectReplay([]ReplayCandidate{exhausted, failed}, 10)
	if err != nil {
		t.Fatalf("SelectReplay: %v", err)
	}
	if len(selection.Deliveries) != 2 || len(selection.Skipped) != 0 {
		t.Fatalf("unexpected selection: %+v", selection)
	}
	if selection.Deliveries[0].ID != exhausted.Delivery.ID ||
		selection.Deliveries[1].ID != failed.Delivery.ID {
		t.Fatalf("selection order changed: %+v", selection.Deliveries)
	}
}

func TestSelectReplaySkipsByReason(t *testing.T) {
	tenant := replayTenant(t)
	cases := []struct {
		name   string
		mutate func(*ReplayCandidate)
		want   ReplaySkipReason
	}{
		{"delivered", func(c *ReplayCandidate) { c.State = StateDelivered; c.Attempts = 1 }, ReplaySkipDelivered},
		{"pending", func(c *ReplayCandidate) { c.State = StatePending }, ReplaySkipNotReplayable},
		{"in flight", func(c *ReplayCandidate) { c.State = StateInFlight }, ReplaySkipNotReplayable},
		{"unknown state", func(c *ReplayCandidate) { c.State = "queued" }, ReplaySkipNotReplayable},
		{"no attempts", func(c *ReplayCandidate) { c.Attempts = 0 }, ReplaySkipNoAttempts},
		{"already replayed", func(c *ReplayCandidate) { c.Replayed = true }, ReplaySkipAlreadyReplayed},
		{"inactive endpoint", func(c *ReplayCandidate) { c.Endpoint.Status = EndpointInactive }, ReplaySkipEndpointInactive},
		{"unknown endpoint", func(c *ReplayCandidate) { c.Endpoint.Status = EndpointUnknown }, ReplaySkipEndpointUnknown},
		{"empty endpoint", func(c *ReplayCandidate) { c.Endpoint.Status = "" }, ReplaySkipEndpointUnknown},
		{"stale subscription", func(c *ReplayCandidate) { c.Endpoint.SubscriptionVersion = 1 }, ReplaySkipSubscriptionMismatch},
		{"missing key", func(c *ReplayCandidate) { c.Endpoint.SignatureKeyReady = false }, ReplaySkipSignatureUnavailable},
		{"invalid delivery", func(c *ReplayCandidate) { c.Delivery.ID = "x" }, ReplaySkipInvalidDelivery},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			candidate := replayCandidate(t, tenant)
			tc.mutate(&candidate)
			selection, err := SelectReplay([]ReplayCandidate{candidate}, 10)
			if err != nil {
				t.Fatalf("SelectReplay: %v", err)
			}
			if len(selection.Deliveries) != 0 {
				t.Fatalf("expected nothing selected, got %+v", selection.Deliveries)
			}
			if len(selection.Skipped) != 1 || selection.Skipped[0].Reason != tc.want {
				t.Fatalf("skips = %+v, want %q", selection.Skipped, tc.want)
			}
			if !selection.Skipped[0].Reason.Valid() {
				t.Fatalf("reason %q is not valid", selection.Skipped[0].Reason)
			}
		})
	}
}

func TestSelectReplayDeduplicates(t *testing.T) {
	tenant := replayTenant(t)
	candidate := replayCandidate(t, tenant)
	selection, err := SelectReplay([]ReplayCandidate{candidate, candidate}, 10)
	if err != nil {
		t.Fatalf("SelectReplay: %v", err)
	}
	if len(selection.Deliveries) != 1 {
		t.Fatalf("expected one selected delivery, got %d", len(selection.Deliveries))
	}
	if len(selection.Skipped) != 1 || selection.Skipped[0].Reason != ReplaySkipDuplicate {
		t.Fatalf("unexpected skips: %+v", selection.Skipped)
	}

	ineligible := candidate
	ineligible.State = StateDelivered
	eligible := candidate
	selection, err = SelectReplay([]ReplayCandidate{ineligible, eligible}, 10)
	if err != nil {
		t.Fatalf("SelectReplay: %v", err)
	}
	if len(selection.Deliveries) != 0 || len(selection.Skipped) != 2 {
		t.Fatalf("a duplicate bypassed the first decision: %+v", selection)
	}
	if selection.Skipped[1].Reason != ReplaySkipDuplicate {
		t.Fatalf("second skip = %q, want duplicate", selection.Skipped[1].Reason)
	}
}

func TestSelectReplayEnforcesCap(t *testing.T) {
	tenant := replayTenant(t)
	candidates := make([]ReplayCandidate, 0, 3)
	for index := 0; index < 3; index++ {
		candidates = append(candidates, replayCandidate(t, tenant))
	}
	if _, err := SelectReplay(candidates, 2); !errors.Is(err, ErrReplayTooLarge) {
		t.Fatalf("error = %v, want ErrReplayTooLarge", err)
	}
	selection, err := SelectReplay(candidates, 3)
	if err != nil {
		t.Fatalf("SelectReplay at the cap: %v", err)
	}
	if len(selection.Deliveries) != 3 {
		t.Fatalf("expected three deliveries at the cap, got %d", len(selection.Deliveries))
	}

	for _, limit := range []int{0, -1, MaxReplayBatch + 1} {
		if _, err := SelectReplay(candidates, limit); !errors.Is(err, ErrInvalidReplay) {
			t.Fatalf("limit %d: error = %v, want ErrInvalidReplay", limit, err)
		}
	}
	if _, err := SelectReplay(make([]ReplayCandidate, MaxReplayCandidates+1), 10); !errors.Is(err, ErrInvalidReplay) {
		t.Fatalf("oversized candidate set: error = %v, want ErrInvalidReplay", err)
	}
}

func TestSelectReplayEmptyInput(t *testing.T) {
	selection, err := SelectReplay(nil, 10)
	if err != nil {
		t.Fatalf("SelectReplay(nil): %v", err)
	}
	if len(selection.Deliveries) != 0 || len(selection.Skipped) != 0 {
		t.Fatalf("unexpected empty selection: %+v", selection)
	}
}

func TestReplaySkipReasonValid(t *testing.T) {
	for _, reason := range []ReplaySkipReason{
		ReplaySkipDelivered, ReplaySkipNotReplayable, ReplaySkipAlreadyReplayed,
		ReplaySkipEndpointInactive, ReplaySkipEndpointUnknown, ReplaySkipSubscriptionMismatch,
		ReplaySkipSignatureUnavailable, ReplaySkipNoAttempts, ReplaySkipInvalidDelivery,
		ReplaySkipDuplicate,
	} {
		if !reason.Valid() {
			t.Fatalf("reason %q reported invalid", reason)
		}
	}
	for _, reason := range []ReplaySkipReason{"", "unknown"} {
		if reason.Valid() {
			t.Fatalf("reason %q reported valid", reason)
		}
	}
}
