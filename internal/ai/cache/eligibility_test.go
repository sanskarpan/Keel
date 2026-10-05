package cache

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func testScope() Scope {
	d := strings.Repeat("a", 64)
	return Scope{TenantID: "00000000-0000-4000-8000-000000000001", AccessDigest: d,
		PolicyDigest: d, PromptDigest: d, ProviderID: "offline-fake", ProviderVersion: "v1",
		ModelID: "model-offline-v1", ToolPolicyDigest: d, ContextDigest: d, SourceSetDigest: d,
		Locale: "en-US", Classification: "general", CachePolicy: "cache.v1"}
}

func testFacts() RiskFacts {
	d := strings.Repeat("b", 64)
	return RiskFacts{EntityDigest: d, NumericDigest: d, DateDigest: d, PolarityDigest: d}
}

func TestKeyDerivationIsOpaqueAndScopeBound(t *testing.T) {
	secret := []byte(strings.Repeat("s", 32))
	deriver, err := NewKeyDeriver("hmac-v1", secret)
	if err != nil {
		t.Fatal(err)
	}
	prompt := []byte("sensitive prompt material")
	key, err := deriver.Key(testScope(), prompt)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(key, string(prompt)) || len(key) != len("hmac-v1.")+64 {
		t.Fatalf("unexpected key shape/content: %q", key)
	}
	changed := testScope()
	changed.AccessDigest = strings.Repeat("c", 64)
	otherScopeKey, err := deriver.Key(changed, prompt)
	if err != nil {
		t.Fatal(err)
	}
	otherPromptKey, err := deriver.Key(testScope(), []byte("different prompt"))
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := NewKeyDeriver("hmac-v2", []byte(strings.Repeat("r", 32)))
	if err != nil {
		t.Fatal(err)
	}
	rotatedKey, err := rotated.Key(testScope(), prompt)
	if err != nil {
		t.Fatal(err)
	}
	if key == otherScopeKey || key == otherPromptKey || key == rotatedKey {
		t.Fatal("key failed to bind scope, prompt, or key rotation")
	}
}

func TestEligibilityRequiresCurrentExactScopeAndLifecycle(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	deriver, _ := NewKeyDeriver("hmac-v1", []byte(strings.Repeat("s", 32)))
	key, _ := deriver.Key(testScope(), []byte("canonical prompt"))
	scopeDigest, _ := testScope().Digest()
	request := EligibilityRequest{Scope: testScope(), Key: key, Now: now, MaximumAge: 2 * time.Hour, CacheEnabled: true}
	candidate := Candidate{Key: key, ScopeDigest: scopeDigest, Mode: MatchExact, CreatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)}
	if err := Eligible(candidate, request); err != nil {
		t.Fatalf("valid exact candidate rejected: %v", err)
	}
	changedScope := request
	changedScope.Scope.AccessDigest = strings.Repeat("c", 64)
	if !errors.Is(Eligible(candidate, changedScope), ErrIneligible) {
		t.Fatal("candidate crossed authorization change")
	}
	for name, mutate := range map[string]func(*Candidate, *EligibilityRequest){
		"revoked":          func(c *Candidate, _ *EligibilityRequest) { c.Revoked = true },
		"expired":          func(c *Candidate, _ *EligibilityRequest) { c.ExpiresAt = now },
		"over-age":         func(c *Candidate, _ *EligibilityRequest) { c.CreatedAt = now.Add(-3 * time.Hour) },
		"disabled":         func(_ *Candidate, r *EligibilityRequest) { r.CacheEnabled = false },
		"different-prompt": func(c *Candidate, _ *EligibilityRequest) { c.Key = strings.Repeat("a", len(c.Key)) },
	} {
		t.Run(name, func(t *testing.T) {
			c, r := candidate, request
			mutate(&c, &r)
			if !errors.Is(Eligible(c, r), ErrIneligible) {
				t.Fatal("unsafe candidate accepted")
			}
		})
	}
	sensitive := request
	sensitive.Scope.Classification = "sensitive"
	if !errors.Is(Eligible(candidate, sensitive), ErrIneligible) {
		t.Fatal("sensitive input was eligible")
	}
}

func TestSemanticEligibilityRequiresPinnedVerifierAndRiskFactEquality(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	deriver, _ := NewKeyDeriver("hmac-v1", []byte(strings.Repeat("s", 32)))
	requestKey, _ := deriver.Key(testScope(), []byte("current query"))
	candidateKey, _ := deriver.Key(testScope(), []byte("candidate query"))
	scopeDigest, _ := testScope().Digest()
	verifier := Verifier{ID: "strict-facts", Version: "v1", ArtifactDigest: strings.Repeat("d", 64), MinimumSimilarity: 0.98}
	facts := testFacts()
	request := EligibilityRequest{Scope: testScope(), Key: requestKey, Now: now, MaximumAge: time.Hour, CacheEnabled: true, Facts: facts, Verifier: verifier}
	candidate := Candidate{Key: candidateKey, ScopeDigest: scopeDigest, Mode: MatchSemantic,
		CreatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(30 * time.Minute), Facts: facts, Verifier: verifier, Similarity: 0.99}
	if err := Eligible(candidate, request); err != nil {
		t.Fatalf("verified semantic candidate rejected: %v", err)
	}
	for name, mutate := range map[string]func(*Candidate, *EligibilityRequest){
		"entity":     func(c *Candidate, _ *EligibilityRequest) { c.Facts.EntityDigest = strings.Repeat("e", 64) },
		"number":     func(c *Candidate, _ *EligibilityRequest) { c.Facts.NumericDigest = strings.Repeat("e", 64) },
		"date":       func(c *Candidate, _ *EligibilityRequest) { c.Facts.DateDigest = strings.Repeat("e", 64) },
		"polarity":   func(c *Candidate, _ *EligibilityRequest) { c.Facts.PolarityDigest = strings.Repeat("e", 64) },
		"verifier":   func(_ *Candidate, r *EligibilityRequest) { r.Verifier.Version = "v2" },
		"low-score":  func(c *Candidate, _ *EligibilityRequest) { c.Similarity = 0.97 },
		"same-query": func(c *Candidate, r *EligibilityRequest) { c.Key = r.Key },
	} {
		t.Run(name, func(t *testing.T) {
			c, r := candidate, request
			mutate(&c, &r)
			if !errors.Is(Eligible(c, r), ErrIneligible) {
				t.Fatal("semantic mismatch accepted")
			}
		})
	}
}
