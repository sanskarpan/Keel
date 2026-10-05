package budget

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sanskarpan/keel/internal/ai/policy"
)

func testPolicySnapshot(t *testing.T) policy.PolicySnapshot {
	t.Helper()
	bundle := policy.Bundle{
		ID: "supplier-summary", Version: "v1",
		Prompt:     policy.PromptTemplate{ID: "summary", Version: "v1", Text: "Summarize {{document}}", Variables: []string{"document"}},
		Provider:   policy.ProviderPolicy{ID: "offline-fake", Version: "v1", ModelID: "model-offline-v1"},
		Generation: policy.GenerationLimits{MaxInputBytes: 8192, MaxOutputTokens: 512},
		Tools:      policy.ToolPolicy{Version: "tools.none.v1"},
		Scrubber:   policy.ScrubberPolicy{Version: policy.ScrubberHighConfidenceV1},
	}
	registry, err := policy.NewRegistry([]policy.Bundle{bundle})
	if err != nil {
		t.Fatal(err)
	}
	call, err := registry.Prepare(policy.Request{
		BundleID: "supplier-summary", BundleVersion: "v1",
		Variables: map[string]policy.InputSegment{"document": {Source: policy.SourceSupplierDocument, Classification: policy.ClassificationGeneral, Text: "synthetic"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return call.Policy()
}

func testRateCard() RateCard {
	return RateCard{
		ID: "offline-test", Version: "v1", ProviderID: "offline-fake", ProviderVersion: "v1", ModelID: "model-offline-v1", Currency: "USD",
		InputMicroUSDPerMillionTokens: 1000, OutputMicroUSDPerMillionTokens: 2000, SafetyMarginBasisPoints: 2500,
		EffectiveFrom: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), EffectiveUntil: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
	}
}

func TestQuoteWorstCaseUsesInstalledPolicyAndRoundsUp(t *testing.T) {
	rateBook, err := NewRateBook([]RateCard{testRateCard()})
	if err != nil {
		t.Fatal(err)
	}
	quote, err := rateBook.QuoteWorstCase(testPolicySnapshot(t), time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if quote.InputTokenCeiling() != 8192 || quote.OutputTokenCeiling() != 512 {
		t.Fatalf("quote ceilings did not come from installed policy: input=%d output=%d", quote.InputTokenCeiling(), quote.OutputTokenCeiling())
	}
	if quote.InputCostMicroUSD() != 9 || quote.OutputCostMicroUSD() != 2 || quote.SafetyMarginMicroUSD() != 3 || quote.MaximumLiabilityMicroUSD() != 14 {
		t.Fatalf("unexpected ceiling-rounded quote: input=%d output=%d margin=%d maximum=%d", quote.InputCostMicroUSD(), quote.OutputCostMicroUSD(), quote.SafetyMarginMicroUSD(), quote.MaximumLiabilityMicroUSD())
	}
	if quote.Digest() == "" || quote.RateCardDigest() == "" || quote.PolicyDigest() == "" {
		t.Fatal("quote omitted its immutable identities")
	}
	if strings.Contains(quote.String(), "synthetic") {
		t.Fatalf("quote debug output exposed input content: %s", quote)
	}
}

func TestRateBookRejectsExpiredAmbiguousAndUnregisteredQuotes(t *testing.T) {
	rateBook, err := NewRateBook([]RateCard{testRateCard()})
	if err != nil {
		t.Fatal(err)
	}
	snapshot := testPolicySnapshot(t)
	for _, at := range []time.Time{time.Date(2025, 12, 31, 23, 59, 59, 0, time.UTC), time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)} {
		if _, err := rateBook.QuoteWorstCase(snapshot, at); !errors.Is(err, ErrQuoteRejected) {
			t.Fatalf("quote outside effective interval was accepted: %v", err)
		}
	}
	other := testRateCard()
	other.ModelID = "unregistered-model"
	otherBook, err := NewRateBook([]RateCard{other})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := otherBook.QuoteWorstCase(snapshot, time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)); !errors.Is(err, ErrQuoteRejected) {
		t.Fatalf("missing provider/model rate card was accepted: %v", err)
	}
}

func TestRateBookRejectsOverlapAndCheckedArithmeticOverflow(t *testing.T) {
	first := testRateCard()
	second := first
	second.ID = "second"
	second.EffectiveFrom = first.EffectiveFrom.Add(24 * time.Hour)
	if _, err := NewRateBook([]RateCard{first, second}); !errors.Is(err, ErrInvalidRateBook) {
		t.Fatalf("overlapping effective rate cards were accepted: %v", err)
	}
	if _, ok := ceilProductRatio(^uint64(0), int64(^uint64(0)>>1), microUSDPerMillion); ok {
		t.Fatal("overflowing integer quote arithmetic was accepted")
	}
	badCurrency := testRateCard()
	badCurrency.Currency = "EUR"
	if _, err := NewRateBook([]RateCard{badCurrency}); !errors.Is(err, ErrInvalidRateBook) {
		t.Fatalf("unsupported currency was accepted: %v", err)
	}
}

func TestRateCardDigestNormalizesEquivalentInstantsToUTC(t *testing.T) {
	first := testRateCard()
	zone := time.FixedZone("synthetic-offset", 5*60*60+30*60)
	second := first
	second.EffectiveFrom = first.EffectiveFrom.In(zone)
	second.EffectiveUntil = first.EffectiveUntil.In(zone)
	a, err := NewRateBook([]RateCard{first})
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewRateBook([]RateCard{second})
	if err != nil {
		t.Fatal(err)
	}
	qa, err := a.QuoteWorstCase(testPolicySnapshot(t), time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	qb, err := b.QuoteWorstCase(testPolicySnapshot(t), time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if qa.RateCardDigest() != qb.RateCardDigest() || qa.Digest() != qb.Digest() {
		t.Fatal("equivalent UTC instants produced different rate card or quote digests")
	}
}

func TestQuoteIdentityIsStableAcrossFreshQuoteTimestamps(t *testing.T) {
	book, err := NewRateBook([]RateCard{testRateCard()})
	if err != nil {
		t.Fatal(err)
	}
	snapshot := testPolicySnapshot(t)
	at := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	first, err := book.QuoteWorstCase(snapshot, at)
	if err != nil {
		t.Fatal(err)
	}
	second, err := book.QuoteWorstCase(snapshot, at.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if first.QuotedAt() == second.QuotedAt() {
		t.Fatal("test quotes unexpectedly share observation timestamps")
	}
	if first.Digest() != second.Digest() {
		t.Fatal("refreshing an otherwise identical quote changed its idempotency identity")
	}
}
