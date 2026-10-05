package queue

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sanskarpan/keel/internal/ai/budget"
	"github.com/sanskarpan/keel/internal/ai/policy"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

func TestQueueInputValidation(t *testing.T) {
	tenant := tenancy.TenantID(uuid.NewString())
	now := time.Now().UTC()
	bundle := policy.Bundle{ID: "test", Version: "v1", Prompt: policy.PromptTemplate{ID: "summary", Version: "v1", Text: "{{document}}", Variables: []string{"document"}},
		Provider: policy.ProviderPolicy{ID: "offline-fake", Version: "v1", ModelID: "model-offline-v1"}, Generation: policy.GenerationLimits{MaxInputBytes: 1024, MaxOutputTokens: 128},
		Tools: policy.ToolPolicy{Version: "tools.none.v1"}, Scrubber: policy.ScrubberPolicy{Version: policy.ScrubberHighConfidenceV1}}
	registry, err := policy.NewRegistry([]policy.Bundle{bundle})
	if err != nil {
		t.Fatal(err)
	}
	call, err := registry.Prepare(policy.Request{BundleID: "test", BundleVersion: "v1", Variables: map[string]policy.InputSegment{"document": {Source: policy.SourceUser, Classification: policy.ClassificationGeneral, Text: "synthetic"}}})
	if err != nil {
		t.Fatal(err)
	}
	book, err := budget.NewRateBook([]budget.RateCard{{ID: "offline", Version: "v1", ProviderID: "offline-fake", ProviderVersion: "v1", ModelID: "model-offline-v1", Currency: "USD", InputMicroUSDPerMillionTokens: 1000, OutputMicroUSDPerMillionTokens: 1000, SafetyMarginBasisPoints: 1000, EffectiveFrom: now.Add(-time.Hour), EffectiveUntil: now.Add(time.Hour)}})
	if err != nil {
		t.Fatal(err)
	}
	quote, err := book.QuoteWorstCase(call.Policy(), now)
	if err != nil {
		t.Fatal(err)
	}
	spec := JobSpec{Admission: budget.Admission{Tenant: tenant, InferenceID: uuid.NewString(), AttemptID: uuid.NewString(), PeriodID: uuid.NewString(), ReservationID: uuid.NewString(), PeriodStart: now, PeriodEnd: now.Add(time.Hour), PrincipalBinding: "principal:member-123", RequestDigest: strings.Repeat("a", 64), Quote: quote}, ProviderID: "offline-fake", ModelID: "model-offline-v1", MaxOutputTokens: 128}
	if !validSpec(spec) {
		t.Fatal("well-formed content-free job specification rejected")
	}
	for name, mutate := range map[string]func(*JobSpec){
		"tenant":      func(s *JobSpec) { s.Admission.Tenant = "untrusted-tenant" },
		"inference":   func(s *JobSpec) { s.Admission.InferenceID = "not-a-uuid" },
		"attempt":     func(s *JobSpec) { s.Admission.AttemptID = "not-a-uuid" },
		"period":      func(s *JobSpec) { s.Admission.PeriodID = "not-a-uuid" },
		"provider":    func(s *JobSpec) { s.ProviderID = "../provider" },
		"model":       func(s *JobSpec) { s.ModelID = "" },
		"principal":   func(s *JobSpec) { s.Admission.PrincipalBinding = strings.Repeat("x", 257) },
		"token bound": func(s *JobSpec) { s.MaxOutputTokens = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := spec
			mutate(&candidate)
			if validSpec(candidate) {
				t.Fatal("invalid job specification accepted")
			}
		})
	}
}

func TestLeaseInputValidationAndHardMaximum(t *testing.T) {
	lease := Lease{
		Tenant: tenancy.TenantID(uuid.NewString()), InferenceID: uuid.NewString(), AttemptID: uuid.NewString(),
		ProviderID: "offline-fake", ModelID: "model-offline-v1", WorkerID: "worker-1", Epoch: 1,
		LeaseUntil: time.Now().Add(time.Second), AttemptDeadline: time.Now().Add(time.Minute),
	}
	if !validLease(lease) || MaxLease != 30*time.Second {
		t.Fatal("valid lease or hard lease maximum is incorrect")
	}
	lease.Epoch = 0
	if validLease(lease) {
		t.Fatal("zero epoch accepted")
	}
}
