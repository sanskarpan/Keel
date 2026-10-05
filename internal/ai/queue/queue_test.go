package queue

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

func TestQueueInputValidation(t *testing.T) {
	tenant := tenancy.TenantID(uuid.NewString())
	spec := JobSpec{
		Tenant: tenant, InferenceID: uuid.NewString(), AttemptID: uuid.NewString(), PeriodID: uuid.NewString(),
		ProviderID: "offline-test", ModelID: "model-v1", PolicySHA256: strings.Repeat("a", 64),
		Principal: "principal:member-123", MaxOutputTokens: 128,
	}
	if !validSpec(spec) {
		t.Fatal("well-formed content-free job specification rejected")
	}
	for name, mutate := range map[string]func(*JobSpec){
		"tenant":        func(s *JobSpec) { s.Tenant = "untrusted-tenant" },
		"inference":     func(s *JobSpec) { s.InferenceID = "not-a-uuid" },
		"attempt":       func(s *JobSpec) { s.AttemptID = "not-a-uuid" },
		"period":        func(s *JobSpec) { s.PeriodID = "not-a-uuid" },
		"provider":      func(s *JobSpec) { s.ProviderID = "../provider" },
		"model":         func(s *JobSpec) { s.ModelID = "" },
		"policy digest": func(s *JobSpec) { s.PolicySHA256 = "xyz" },
		"principal":     func(s *JobSpec) { s.Principal = strings.Repeat("x", 257) },
		"token bound":   func(s *JobSpec) { s.MaxOutputTokens = 0 },
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
		ProviderID: "offline-test", ModelID: "model-v1", WorkerID: "worker-1", Epoch: 1,
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
