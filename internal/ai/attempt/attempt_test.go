package attempt

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func capability(provider string, max int64, idempotency bool) Capability {
	return Capability{ProviderID: provider, ProviderVersion: "v1", ModelID: "model-v1",
		ArtifactDigest: strings.Repeat("a", 64), SupportsIdempotency: idempotency,
		MaximumAttemptLiabilityUSD: max}
}

func plan() Plan {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	fallback := capability("offline-fallback", 40, true)
	return Plan{TenantID: "00000000-0000-4000-8000-000000000001",
		InferenceID: "00000000-0000-4000-8000-000000000002", PolicyDigest: strings.Repeat("b", 64),
		PrimaryAttemptID: "00000000-0000-4000-8000-000000000003", FallbackAttemptID: "00000000-0000-4000-8000-000000000004",
		Primary: capability("offline-primary", 60, true), Fallback: &fallback,
		FallbackAllowanceMicroUSD: 40, ReservedLiabilityMicroUSD: 100, Deadline: now.Add(time.Minute)}
}

func TestNextCreatesStableDistinctIdempotencyIdentityPerAttempt(t *testing.T) {
	p := plan()
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	secret := []byte(strings.Repeat("s", 32))
	primary, err := Next(p, nil, p.PolicyDigest, "idempotency.v1", secret, now)
	if err != nil {
		t.Fatal(err)
	}
	if primary.Ordinal != 1 || primary.ProviderID != p.Primary.ProviderID || primary.IdempotencyKey == "" {
		t.Fatalf("invalid primary attempt record: %+v", primary)
	}
	primaryReplay, err := Next(p, nil, p.PolicyDigest, "idempotency.v1", secret, now)
	if err != nil || primary != primaryReplay {
		t.Fatalf("primary identity was not replay-stable: %+v %v", primaryReplay, err)
	}
	outcome := Outcome{AttemptID: p.PrimaryAttemptID, Acceptance: AcceptanceRejected, Charge: ChargeNone,
		Failure: FailureRateLimited, FinishedAt: now.Add(time.Second)}
	fallback, err := Next(p, []Outcome{outcome}, p.PolicyDigest, "idempotency.v1", secret, now.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if fallback.Ordinal != 2 || fallback.AttemptID == primary.AttemptID || fallback.IdempotencyKey == primary.IdempotencyKey ||
		fallback.ProviderID != p.Fallback.ProviderID || fallback.MaximumLiability != p.Fallback.MaximumAttemptLiabilityUSD {
		t.Fatalf("fallback did not create a distinct bounded attempt: %+v", fallback)
	}
	if _, err := Next(p, nil, strings.Repeat("c", 64), "idempotency.v1", secret, now); !errors.Is(err, ErrInvalidPlan) {
		t.Fatalf("stale policy digest permitted dispatch: %v", err)
	}
	withoutIdempotency := p
	withoutIdempotency.Primary.SupportsIdempotency = false
	plain, err := Next(withoutIdempotency, nil, p.PolicyDigest, "idempotency.v1", secret, now)
	if err != nil || plain.IdempotencyKey != "" {
		t.Fatalf("route without idempotency support received a fabricated key: %+v err=%v", plain, err)
	}
}

func TestFallbackRequiresDefiniteNonBillablePreTokenFailure(t *testing.T) {
	p := plan()
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	base := Outcome{AttemptID: p.PrimaryAttemptID, Acceptance: AcceptanceRejected, Charge: ChargeNone,
		Failure: FailureUnavailable, FinishedAt: now.Add(time.Second)}
	unsafe := map[string]func(*Outcome){
		"accepted":           func(o *Outcome) { o.Acceptance = AcceptanceAccepted },
		"unknown-acceptance": func(o *Outcome) { o.Acceptance = AcceptanceUnknown },
		"unknown-charge":     func(o *Outcome) { o.Charge = ChargeUnknown },
		"charged":            func(o *Outcome) { o.Charge = ChargeConfirmed; o.UsageMicroUSD = 3 },
		"provider-output":    func(o *Outcome) { o.ProviderOutputSeen = true },
		"client-token":       func(o *Outcome) { o.ClientTokenBytes = 1 },
		"ambiguous-timeout":  func(o *Outcome) { o.Failure = FailureTimeout },
		"wrong-attempt":      func(o *Outcome) { o.AttemptID = p.FallbackAttemptID },
	}
	for name, mutate := range unsafe {
		t.Run(name, func(t *testing.T) {
			o := base
			mutate(&o)
			if _, err := Next(p, []Outcome{o}, p.PolicyDigest, "idempotency.v1", []byte(strings.Repeat("s", 32)), now.Add(2*time.Second)); !errors.Is(err, ErrNoFallback) {
				t.Fatalf("unsafe outcome allowed a fallback: %v", err)
			}
		})
	}
	if _, err := Next(p, []Outcome{base, base}, p.PolicyDigest, "idempotency.v1", []byte(strings.Repeat("s", 32)), now.Add(2*time.Second)); !errors.Is(err, ErrNoFallback) {
		t.Fatalf("second fallback was not refused: %v", err)
	}
	if _, err := Next(p, []Outcome{base}, p.PolicyDigest, "idempotency.v1", []byte(strings.Repeat("s", 32)), p.Deadline); !errors.Is(err, ErrNoFallback) {
		t.Fatalf("expired plan allowed a fallback: %v", err)
	}
}

func TestFallbackNeedsPinnedCapabilityAndPreReservedAllowance(t *testing.T) {
	p := plan()
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	short := p
	short.FallbackAllowanceMicroUSD = 39
	if short.Validate() == nil {
		t.Fatal("underfunded fallback capability accepted")
	}
	short = p
	short.ReservedLiabilityMicroUSD = 99
	if short.Validate() == nil {
		t.Fatal("fallback allowance was not present in reserved liability")
	}
	noKey := p
	noKey.FallbackAttemptID = noKey.PrimaryAttemptID
	if noKey.Validate() == nil {
		t.Fatal("same attempt identity reused for fallback")
	}
	primaryOnly := p
	primaryOnly.Fallback = nil
	primaryOnly.FallbackAttemptID = ""
	primaryOnly.FallbackAllowanceMicroUSD = 0
	if _, err := Next(primaryOnly, []Outcome{{AttemptID: p.PrimaryAttemptID, Acceptance: AcceptanceRejected, Charge: ChargeNone,
		Failure: FailureConnectBeforeSend, FinishedAt: time.Now().Add(-time.Second)}}, p.PolicyDigest, "idempotency.v1", []byte(strings.Repeat("s", 32)), time.Now()); !errors.Is(err, ErrNoFallback) {
		t.Fatalf("unconfigured fallback was accepted: %v", err)
	}
}

func TestOutcomeReplayIsExactAndContentFree(t *testing.T) {
	o := Outcome{AttemptID: "00000000-0000-4000-8000-000000000003", Acceptance: AcceptanceAccepted,
		Charge: ChargeConfirmed, Failure: FailureNone, UsageMicroUSD: 17, FinishedAt: time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)}
	if err := CheckOutcomeReplay(o, o); err != nil {
		t.Fatalf("exact replay rejected: %v", err)
	}
	conflict := o
	conflict.UsageMicroUSD++
	if !errors.Is(CheckOutcomeReplay(o, conflict), ErrOutcomeConflict) {
		t.Fatal("conflicting usage replay accepted")
	}
	first, err := OutcomeDigest(o)
	if err != nil {
		t.Fatal(err)
	}
	second, err := OutcomeDigest(conflict)
	if err != nil {
		t.Fatal(err)
	}
	if first == second || strings.Contains(first, "provider response") {
		t.Fatal("outcome digest did not remain content-free")
	}
}
