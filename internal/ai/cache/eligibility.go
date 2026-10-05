// Package cache contains content-free cache identity and fail-closed hit
// eligibility rules. It does not retrieve or persist prompts or responses.
package cache

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"regexp"
	"time"
)

var (
	ErrInvalidScope      = errors.New("AI cache scope is invalid")
	ErrInvalidKey        = errors.New("AI cache key material is invalid")
	ErrIneligible        = errors.New("AI cache candidate is ineligible")
	ErrInvalidEvaluation = errors.New("AI cache evaluation set is invalid")
	ErrInsufficientPairs = errors.New("AI cache evaluation has too few independent served pairs")
	idPattern            = regexp.MustCompile(`^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$`)
	uuidPattern          = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	digestPattern        = regexp.MustCompile(`^[0-9a-f]{64}$`)
	localePattern        = regexp.MustCompile(`^[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8})*$`)
)

const (
	minimumEligiblePairs = 600
	confidenceAlpha      = 0.05
)

// Scope binds an answer to every input whose change can make it wrong or
// visible to a different principal. Digests must come from trusted server
// code, never from client authorization claims.
type Scope struct {
	TenantID         string `json:"tenant_id"`
	AccessDigest     string `json:"access_digest"`
	PolicyDigest     string `json:"policy_digest"`
	PromptDigest     string `json:"prompt_digest"`
	ProviderID       string `json:"provider_id"`
	ProviderVersion  string `json:"provider_version"`
	ModelID          string `json:"model_id"`
	ToolPolicyDigest string `json:"tool_policy_digest"`
	ContextDigest    string `json:"context_digest"`
	SourceSetDigest  string `json:"source_set_digest"`
	Locale           string `json:"locale"`
	Classification   string `json:"classification"`
	CachePolicy      string `json:"cache_policy_version"`
}

func (s Scope) Validate() error {
	if !uuidPattern.MatchString(s.TenantID) ||
		!validDigest(s.AccessDigest) || !validDigest(s.PolicyDigest) || !validDigest(s.PromptDigest) ||
		!validDigest(s.ToolPolicyDigest) || !validDigest(s.ContextDigest) || !validDigest(s.SourceSetDigest) ||
		!idPattern.MatchString(s.ProviderID) || !idPattern.MatchString(s.ProviderVersion) ||
		!idPattern.MatchString(s.ModelID) || !idPattern.MatchString(s.CachePolicy) ||
		!localePattern.MatchString(s.Locale) || s.Classification != "general" {
		return ErrInvalidScope
	}
	return nil
}

func (s Scope) Digest() (string, error) {
	if err := s.Validate(); err != nil {
		return "", err
	}
	b, err := json.Marshal(s)
	if err != nil {
		return "", ErrInvalidScope
	}
	d := sha256.Sum256(append([]byte("keel.ai.cache-scope.v1\x00"), b...))
	return hex.EncodeToString(d[:]), nil
}

// KeyDeriver owns one active HMAC key. Rotating the key ID and secret causes
// existing entries to miss without exposing prompt content in lookup keys.
type KeyDeriver struct {
	ID     string
	secret []byte
}

func NewKeyDeriver(id string, secret []byte) (*KeyDeriver, error) {
	if !idPattern.MatchString(id) || len(secret) < 32 {
		return nil, ErrInvalidKey
	}
	return &KeyDeriver{ID: id, secret: append([]byte(nil), secret...)}, nil
}

func (d *KeyDeriver) Key(scope Scope, canonicalPrompt []byte) (string, error) {
	if d == nil || len(d.secret) < 32 || len(canonicalPrompt) == 0 || len(canonicalPrompt) > 64*1024 {
		return "", ErrInvalidKey
	}
	scopeDigest, err := scope.Digest()
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, d.secret)
	_, _ = mac.Write([]byte("keel.ai.cache-key.v1\x00"))
	_, _ = mac.Write([]byte(scopeDigest))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write(canonicalPrompt)
	return d.ID + "." + hex.EncodeToString(mac.Sum(nil)), nil
}

type MatchMode string

const (
	MatchExact    MatchMode = "exact"
	MatchSemantic MatchMode = "semantic"
)

type RiskFacts struct {
	EntityDigest   string `json:"entity_digest"`
	NumericDigest  string `json:"numeric_digest"`
	DateDigest     string `json:"date_digest"`
	PolarityDigest string `json:"polarity_digest"`
}

func (f RiskFacts) Validate() error {
	if !validDigest(f.EntityDigest) || !validDigest(f.NumericDigest) ||
		!validDigest(f.DateDigest) || !validDigest(f.PolarityDigest) {
		return ErrIneligible
	}
	return nil
}

type Verifier struct {
	ID                string  `json:"id"`
	Version           string  `json:"version"`
	ArtifactDigest    string  `json:"artifact_digest"`
	MinimumSimilarity float64 `json:"minimum_similarity"`
}

func (v Verifier) validate() bool {
	return idPattern.MatchString(v.ID) && idPattern.MatchString(v.Version) && validDigest(v.ArtifactDigest) &&
		!math.IsNaN(v.MinimumSimilarity) && !math.IsInf(v.MinimumSimilarity, 0) &&
		v.MinimumSimilarity > 0 && v.MinimumSimilarity <= 1
}

// Candidate contains metadata only. The response must be loaded from a
// separately authorized, encrypted store after Eligible returns nil.
type Candidate struct {
	Key         string
	ScopeDigest string
	Mode        MatchMode
	CreatedAt   time.Time
	ExpiresAt   time.Time
	Revoked     bool
	Facts       RiskFacts
	Verifier    Verifier
	Similarity  float64
}

type EligibilityRequest struct {
	Scope        Scope
	Key          string
	Now          time.Time
	MaximumAge   time.Duration
	CacheEnabled bool
	Facts        RiskFacts
	Verifier     Verifier
}

func Eligible(candidate Candidate, request EligibilityRequest) error {
	if !request.CacheEnabled || request.Now.IsZero() || request.MaximumAge <= 0 ||
		request.MaximumAge > 30*24*time.Hour || candidate.Revoked ||
		!validCacheKey(candidate.Key) || !validCacheKey(request.Key) ||
		candidate.CreatedAt.IsZero() || candidate.ExpiresAt.IsZero() ||
		candidate.CreatedAt.After(request.Now) || !candidate.ExpiresAt.After(request.Now) ||
		candidate.ExpiresAt.After(candidate.CreatedAt.Add(request.MaximumAge)) {
		return ErrIneligible
	}
	scopeDigest, err := request.Scope.Digest()
	if err != nil || !validDigest(candidate.ScopeDigest) || !hmac.Equal([]byte(scopeDigest), []byte(candidate.ScopeDigest)) {
		return ErrIneligible
	}
	switch candidate.Mode {
	case MatchExact:
		if candidate.Key != request.Key {
			return ErrIneligible
		}
	case MatchSemantic:
		if candidate.Key == request.Key || !request.Verifier.validate() || !candidate.Verifier.validate() ||
			candidate.Verifier != request.Verifier || math.IsNaN(candidate.Similarity) || math.IsInf(candidate.Similarity, 0) ||
			candidate.Similarity < request.Verifier.MinimumSimilarity || candidate.Similarity > 1 ||
			request.Facts.Validate() != nil || candidate.Facts.Validate() != nil || candidate.Facts != request.Facts {
			return ErrIneligible
		}
	default:
		return ErrIneligible
	}
	return nil
}

func validDigest(s string) bool { return digestPattern.MatchString(s) }

func validCacheKey(s string) bool {
	if len(s) <= 65 || s[len(s)-65] != '.' || !idPattern.MatchString(s[:len(s)-65]) {
		return false
	}
	return validDigest(s[len(s)-64:])
}
