package cache

import "math"

const (
	minimumPrecision      = 0.995
	maximumEvaluationRows = 1_000_000
)

// LabelledPair is a content-free curator export row. An adjudication system
// must set Independent and issue unique IDs; this package cannot infer
// statistical independence or truth labels from user text.
type LabelledPair struct {
	PairID               string
	IndependenceUnitID   string
	ServingPolicyID      string
	AdjudicationRef      string
	Independent          bool
	Served               bool
	Equivalent           bool
	TenantPermissionLeak bool
	EntityMismatch       bool
	NumericMismatch      bool
	DateMismatch         bool
	PolarityMismatch     bool
}

type Assessment struct {
	ServingPolicyID     string
	LabelledPairs       int
	IndependentServed   int
	MissedOpportunities int
	FalseHits           int
	CriticalFalseHits   int
	Precision           float64
	LowerBound95        float64
	Qualified           bool
}

// Assess calculates an exact one-sided 95% Clopper-Pearson precision bound
// over independently adjudicated served pairs. Scope and risk-fact errors
// remain zero-tolerance even if aggregate precision is high.
func Assess(policyID string, pairs []LabelledPair) (Assessment, error) {
	result := Assessment{ServingPolicyID: policyID, LabelledPairs: len(pairs)}
	if !idPattern.MatchString(policyID) || len(pairs) == 0 || len(pairs) > maximumEvaluationRows {
		return result, ErrInvalidEvaluation
	}
	seenPairs := make(map[string]struct{}, len(pairs))
	seenUnits := make(map[string]struct{}, len(pairs))
	for _, pair := range pairs {
		if !idPattern.MatchString(pair.PairID) || !idPattern.MatchString(pair.IndependenceUnitID) ||
			!idPattern.MatchString(pair.AdjudicationRef) || pair.ServingPolicyID != policyID {
			return result, ErrInvalidEvaluation
		}
		if _, exists := seenPairs[pair.PairID]; exists {
			return result, ErrInvalidEvaluation
		}
		seenPairs[pair.PairID] = struct{}{}
		if !pair.Served {
			result.MissedOpportunities++
			continue
		}
		if !pair.Independent {
			return result, ErrInvalidEvaluation
		}
		if _, exists := seenUnits[pair.IndependenceUnitID]; exists {
			return result, ErrInvalidEvaluation
		}
		seenUnits[pair.IndependenceUnitID] = struct{}{}
		result.IndependentServed++
		critical := pair.TenantPermissionLeak || pair.EntityMismatch || pair.NumericMismatch || pair.DateMismatch || pair.PolarityMismatch
		if critical {
			result.CriticalFalseHits++
		}
		if !pair.Equivalent || critical {
			result.FalseHits++
		}
	}
	if result.IndependentServed == 0 {
		return result, ErrInvalidEvaluation
	}
	successes := result.IndependentServed - result.FalseHits
	result.Precision = float64(successes) / float64(result.IndependentServed)
	result.LowerBound95 = exactBinomialLower95(successes, result.IndependentServed)
	result.Qualified = result.IndependentServed >= minimumEligiblePairs &&
		result.LowerBound95 >= minimumPrecision && result.CriticalFalseHits == 0
	if result.IndependentServed < minimumEligiblePairs {
		return result, ErrInsufficientPairs
	}
	return result, nil
}

func exactBinomialLower95(successes, trials int) float64 {
	if trials <= 0 || successes <= 0 || successes > trials {
		return 0
	}
	if successes == trials {
		return math.Pow(confidenceAlpha, 1/float64(trials))
	}
	return inverseRegularizedBeta(confidenceAlpha, float64(successes), float64(trials-successes+1))
}

func inverseRegularizedBeta(p, a, b float64) float64 {
	lo, hi := 0.0, 1.0
	for i := 0; i < 100; i++ {
		mid := (lo + hi) / 2
		if regularizedBeta(mid, a, b) < p {
			lo = mid
		} else {
			hi = mid
		}
	}
	return (lo + hi) / 2
}

func regularizedBeta(x, a, b float64) float64 {
	if x <= 0 {
		return 0
	}
	if x >= 1 {
		return 1
	}
	lgAB, _ := math.Lgamma(a + b)
	lgA, _ := math.Lgamma(a)
	lgB, _ := math.Lgamma(b)
	front := math.Exp(lgAB - lgA - lgB + a*math.Log(x) + b*math.Log1p(-x))
	if x < (a+1)/(a+b+2) {
		return front * betaContinuedFraction(a, b, x) / a
	}
	return 1 - front*betaContinuedFraction(b, a, 1-x)/b
}

func betaContinuedFraction(a, b, x float64) float64 {
	const maxIterations = 300
	const epsilon = 3e-14
	const floor = 1e-300
	qab, qap, qam := a+b, a+1, a-1
	c := 1.0
	d := 1 - qab*x/qap
	if math.Abs(d) < floor {
		d = floor
	}
	d = 1 / d
	h := d
	for m := 1; m <= maxIterations; m++ {
		m2 := float64(2 * m)
		term := float64(m) * (b - float64(m)) * x / ((qam + m2) * (a + m2))
		d = 1 + term*d
		if math.Abs(d) < floor {
			d = floor
		}
		c = 1 + term/c
		if math.Abs(c) < floor {
			c = floor
		}
		d = 1 / d
		h *= d * c
		term = -(a + float64(m)) * (qab + float64(m)) * x / ((a + m2) * (qap + m2))
		d = 1 + term*d
		if math.Abs(d) < floor {
			d = floor
		}
		c = 1 + term/c
		if math.Abs(c) < floor {
			c = floor
		}
		d = 1 / d
		delta := d * c
		h *= delta
		if math.Abs(delta-1) < epsilon {
			break
		}
	}
	return h
}
