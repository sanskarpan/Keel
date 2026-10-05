// Package budget quotes and accounts for inference spend. This first slice has
// no provider adapter; its price book contains synthetic qualification rates.
package budget

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"sort"
	"time"

	"github.com/sanskarpan/keel/internal/ai/policy"
)

const (
	microUSDPerMillion = int64(1_000_000)
	maxQuoteBytes      = 64 * 1024
	maxQuoteTokens     = 8192
	maxQuoteAge        = 30 * time.Second
	maxQuoteFutureSkew = 5 * time.Second
)

var (
	ErrInvalidRateBook = errors.New("AI rate book is invalid")
	ErrQuoteRejected   = errors.New("AI cost quote rejected")
	idPattern          = regexp.MustCompile(`^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$`)
)

type RateCard struct {
	ID                             string
	Version                        string
	ProviderID                     string
	ProviderVersion                string
	ModelID                        string
	Currency                       string
	InputMicroUSDPerMillionTokens  int64
	OutputMicroUSDPerMillionTokens int64
	SafetyMarginBasisPoints        uint32
	EffectiveFrom                  time.Time
	EffectiveUntil                 time.Time
}

type rateCard struct {
	value  RateCard
	digest string
}

type RateBook struct {
	cards map[string][]rateCard
}

// Quote fields are private so callers cannot alter the policy/rate identity or
// the maximum liability after deterministic calculation.
type Quote struct {
	rateCardID         string
	rateCardVersion    string
	rateCardDigest     string
	policyDigest       string
	providerID         string
	providerVersion    string
	modelID            string
	currency           string
	inputTokenCeil     uint64
	outputTokenCeil    uint64
	inputCost          int64
	outputCost         int64
	safetyMargin       int64
	maximumLiability   int64
	digest             string
	quotedAt           time.Time
	rateEffectiveFrom  time.Time
	rateEffectiveUntil time.Time
}

func (q Quote) RateCardID() string              { return q.rateCardID }
func (q Quote) RateCardVersion() string         { return q.rateCardVersion }
func (q Quote) RateCardDigest() string          { return q.rateCardDigest }
func (q Quote) PolicyDigest() string            { return q.policyDigest }
func (q Quote) ProviderID() string              { return q.providerID }
func (q Quote) ProviderVersion() string         { return q.providerVersion }
func (q Quote) ModelID() string                 { return q.modelID }
func (q Quote) Currency() string                { return q.currency }
func (q Quote) InputTokenCeiling() uint64       { return q.inputTokenCeil }
func (q Quote) OutputTokenCeiling() uint64      { return q.outputTokenCeil }
func (q Quote) InputCostMicroUSD() int64        { return q.inputCost }
func (q Quote) OutputCostMicroUSD() int64       { return q.outputCost }
func (q Quote) SafetyMarginMicroUSD() int64     { return q.safetyMargin }
func (q Quote) MaximumLiabilityMicroUSD() int64 { return q.maximumLiability }
func (q Quote) Digest() string                  { return q.digest }
func (q Quote) QuotedAt() time.Time             { return q.quotedAt }
func (q Quote) RateEffectiveFrom() time.Time    { return q.rateEffectiveFrom }
func (q Quote) RateEffectiveUntil() time.Time   { return q.rateEffectiveUntil }
func (q Quote) String() string {
	return fmt.Sprintf("[AI quote %s@%s %s %d micro-USD]", q.rateCardID, q.rateCardVersion, q.digest, q.maximumLiability)
}
func (q Quote) GoString() string { return q.String() }

// NewRateBook copies and freezes code-owned rate cards. Overlapping cards for
// the same provider/model are rejected so time selection is unambiguous.
func NewRateBook(cards []RateCard) (*RateBook, error) {
	if len(cards) == 0 {
		return nil, ErrInvalidRateBook
	}
	book := &RateBook{cards: make(map[string][]rateCard)}
	seen := make(map[string]struct{}, len(cards))
	for _, input := range cards {
		card := input
		// Strip caller location and monotonic clock data before validation and hashing.
		card.EffectiveFrom = card.EffectiveFrom.UTC().Round(0)
		card.EffectiveUntil = card.EffectiveUntil.UTC().Round(0)
		if !validRateCard(card) {
			return nil, ErrInvalidRateBook
		}
		key := providerModelKey(card.ProviderID, card.ProviderVersion, card.ModelID)
		identity := key + "\x00" + card.ID + "\x00" + card.Version
		if _, exists := seen[identity]; exists {
			return nil, ErrInvalidRateBook
		}
		seen[identity] = struct{}{}
		digest, err := rateCardDigest(card)
		if err != nil {
			return nil, ErrInvalidRateBook
		}
		book.cards[key] = append(book.cards[key], rateCard{value: card, digest: digest})
	}
	for key, versions := range book.cards {
		sort.Slice(versions, func(i, j int) bool { return versions[i].value.EffectiveFrom.Before(versions[j].value.EffectiveFrom) })
		for i := 1; i < len(versions); i++ {
			if versions[i].value.EffectiveFrom.Before(versions[i-1].value.EffectiveUntil) {
				return nil, ErrInvalidRateBook
			}
		}
		book.cards[key] = versions
	}
	return book, nil
}

// QuoteWorstCase uses the installed immutable policy snapshot. With no
// tokenizer integration, every allowed input byte is budgeted as a token;
// output is bounded by the policy's explicit token ceiling.
func (b *RateBook) QuoteWorstCase(snapshot policy.PolicySnapshot, at time.Time) (Quote, error) {
	if b == nil || at.IsZero() || snapshot.Digest() == "" || snapshot.MaxInputBytes() < 1 || snapshot.MaxInputBytes() > maxQuoteBytes || snapshot.MaxOutputTokens() < 1 || snapshot.MaxOutputTokens() > maxQuoteTokens {
		return Quote{}, ErrQuoteRejected
	}
	key := providerModelKey(snapshot.ProviderID(), snapshot.ProviderVersion(), snapshot.ModelID())
	versions := b.cards[key]
	var selected *rateCard
	for i := range versions {
		card := &versions[i]
		if !at.Before(card.value.EffectiveFrom) && at.Before(card.value.EffectiveUntil) {
			if selected != nil {
				return Quote{}, ErrQuoteRejected
			}
			selected = card
		}
	}
	if selected == nil {
		return Quote{}, ErrQuoteRejected
	}
	inputCeiling := uint64(snapshot.MaxInputBytes())
	outputCeiling := uint64(snapshot.MaxOutputTokens())
	inputCost, ok := ceilProductRatio(inputCeiling, selected.value.InputMicroUSDPerMillionTokens, microUSDPerMillion)
	if !ok {
		return Quote{}, ErrQuoteRejected
	}
	outputCost, ok := ceilProductRatio(outputCeiling, selected.value.OutputMicroUSDPerMillionTokens, microUSDPerMillion)
	if !ok {
		return Quote{}, ErrQuoteRejected
	}
	base, ok := checkedAdd(inputCost, outputCost)
	if !ok {
		return Quote{}, ErrQuoteRejected
	}
	margin, ok := ceilProductRatio(uint64(base), int64(selected.value.SafetyMarginBasisPoints), 10_000)
	if !ok {
		return Quote{}, ErrQuoteRejected
	}
	maximum, ok := checkedAdd(base, margin)
	if !ok || maximum <= 0 {
		return Quote{}, ErrQuoteRejected
	}
	q := Quote{
		rateCardID: selected.value.ID, rateCardVersion: selected.value.Version, rateCardDigest: selected.digest,
		policyDigest: snapshot.Digest(), providerID: selected.value.ProviderID, providerVersion: selected.value.ProviderVersion,
		modelID: selected.value.ModelID, currency: selected.value.Currency, inputTokenCeil: inputCeiling, outputTokenCeil: outputCeiling,
		inputCost: inputCost, outputCost: outputCost, safetyMargin: margin, maximumLiability: maximum,
		quotedAt: at.UTC().Round(0), rateEffectiveFrom: selected.value.EffectiveFrom, rateEffectiveUntil: selected.value.EffectiveUntil,
	}
	canonical := struct {
		RateCardDigest, PolicyDigest, ProviderID, ProviderVersion, ModelID, Currency string
		InputTokenCeiling, OutputTokenCeiling                                        uint64
		InputCost, OutputCost, SafetyMargin, MaximumLiability                        int64
		RateEffectiveFrom, RateEffectiveUntil                                        time.Time
	}{q.rateCardDigest, q.policyDigest, q.providerID, q.providerVersion, q.modelID, q.currency, q.inputTokenCeil, q.outputTokenCeil, q.inputCost, q.outputCost, q.safetyMargin, q.maximumLiability, q.rateEffectiveFrom, q.rateEffectiveUntil}
	payload, err := json.Marshal(canonical)
	if err != nil {
		return Quote{}, ErrQuoteRejected
	}
	sum := sha256.Sum256(payload)
	q.digest = hex.EncodeToString(sum[:])
	return q, nil
}

func validRateCard(card RateCard) bool {
	return idPattern.MatchString(card.ID) && idPattern.MatchString(card.Version) &&
		idPattern.MatchString(card.ProviderID) && idPattern.MatchString(card.ProviderVersion) && idPattern.MatchString(card.ModelID) &&
		card.Currency == "USD" && card.InputMicroUSDPerMillionTokens > 0 && card.OutputMicroUSDPerMillionTokens > 0 &&
		card.SafetyMarginBasisPoints <= 10_000 && !card.EffectiveFrom.IsZero() && !card.EffectiveUntil.IsZero() && card.EffectiveFrom.Before(card.EffectiveUntil)
}

func rateCardDigest(card RateCard) (string, error) {
	payload, err := json.Marshal(card)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:]), nil
}

func providerModelKey(provider, version, model string) string {
	return provider + "\x00" + version + "\x00" + model
}

func ceilProductRatio(a uint64, b int64, divisor int64) (int64, bool) {
	if b < 0 || divisor <= 0 {
		return 0, false
	}
	product := new(big.Int).Mul(new(big.Int).SetUint64(a), big.NewInt(b))
	product.Add(product, big.NewInt(divisor-1))
	product.Div(product, big.NewInt(divisor))
	if !product.IsInt64() {
		return 0, false
	}
	return product.Int64(), true
}

func checkedAdd(a, b int64) (int64, bool) {
	if a < 0 || b < 0 || a > int64(^uint64(0)>>1)-b {
		return 0, false
	}
	return a + b, true
}
