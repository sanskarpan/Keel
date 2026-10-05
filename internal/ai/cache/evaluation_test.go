package cache

import (
	"errors"
	"fmt"
	"testing"
)

func evaluationPairs(count int) []LabelledPair {
	pairs := make([]LabelledPair, count)
	for i := range pairs {
		pairs[i] = LabelledPair{PairID: fmt.Sprintf("pair.%04d", i), IndependenceUnitID: fmt.Sprintf("unit.%04d", i),
			ServingPolicyID: "policy.v1", AdjudicationRef: fmt.Sprintf("review.%04d", i),
			Independent: true, Served: true, Equivalent: true}
	}
	return pairs
}

func TestAssessmentRequires600IndependentHitsAndExactBound(t *testing.T) {
	assessment, err := Assess("policy.v1", evaluationPairs(600))
	if err != nil {
		t.Fatal(err)
	}
	if !assessment.Qualified || assessment.IndependentServed != 600 || assessment.Precision != 1 ||
		assessment.LowerBound95 < 0.995 || assessment.LowerBound95 >= 1 {
		t.Fatalf("zero-error 600-pair result missed the gate: %+v", assessment)
	}
	assessment, err = Assess("policy.v1", evaluationPairs(599))
	if !errors.Is(err, ErrInsufficientPairs) || assessment.Qualified {
		t.Fatalf("599 pairs were not held below qualification: result=%+v err=%v", assessment, err)
	}
}

func TestAssessmentRejectsFalseHitsAndCriticalRiskMismatches(t *testing.T) {
	pairs := evaluationPairs(600)
	pairs[0].Equivalent = false
	assessment, err := Assess("policy.v1", pairs)
	if err != nil {
		t.Fatal(err)
	}
	if assessment.Qualified || assessment.FalseHits != 1 || assessment.LowerBound95 >= 0.995 {
		t.Fatalf("one false hit among 600 unexpectedly passed: %+v", assessment)
	}
	large := evaluationPairs(3000)
	large[0].NumericMismatch = true
	assessment, err = Assess("policy.v1", large)
	if err != nil {
		t.Fatal(err)
	}
	if assessment.LowerBound95 < 0.995 || assessment.CriticalFalseHits != 1 || assessment.Qualified {
		t.Fatalf("aggregate precision overrode a numeric risk failure: %+v", assessment)
	}
}

func TestAssessmentRequiresUniqueIndependentRowsForOnePolicy(t *testing.T) {
	cases := map[string]func([]LabelledPair){
		"duplicate-pair": func(p []LabelledPair) { p[1].PairID = p[0].PairID },
		"dependent-pair": func(p []LabelledPair) { p[1].IndependenceUnitID = p[0].IndependenceUnitID },
		"unadjudicated":  func(p []LabelledPair) { p[0].Independent = false },
		"mixed-policy":   func(p []LabelledPair) { p[0].ServingPolicyID = "policy.v2" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			pairs := evaluationPairs(600)
			mutate(pairs)
			if _, err := Assess("policy.v1", pairs); !errors.Is(err, ErrInvalidEvaluation) {
				t.Fatalf("invalid sample accepted: %v", err)
			}
		})
	}
}
