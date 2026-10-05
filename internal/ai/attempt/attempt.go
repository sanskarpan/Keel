// Package attempt defines fail-closed provider attempt planning. It has no
// network client or persistent ledger adapter.
package attempt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"time"
)

var (
	ErrInvalidPlan     = errors.New("AI provider attempt plan is invalid")
	ErrNoFallback      = errors.New("AI provider fallback is not allowed")
	ErrOutcomeConflict = errors.New("AI provider attempt outcome conflicts with prior evidence")
	idPattern          = regexp.MustCompile(`^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$`)
	uuidPattern        = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	digestPattern      = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type Capability struct {
	ProviderID                 string `json:"provider_id"`
	ProviderVersion            string `json:"provider_version"`
	ModelID                    string `json:"model_id"`
	ArtifactDigest             string `json:"artifact_digest"`
	SupportsIdempotency        bool   `json:"supports_idempotency"`
	MaximumAttemptLiabilityUSD int64  `json:"maximum_attempt_liability_micro_usd"`
}

func (c Capability) Validate() error {
	if !idPattern.MatchString(c.ProviderID) || !idPattern.MatchString(c.ProviderVersion) ||
		!idPattern.MatchString(c.ModelID) || !digestPattern.MatchString(c.ArtifactDigest) ||
		c.MaximumAttemptLiabilityUSD <= 0 {
		return ErrInvalidPlan
	}
	return nil
}

func (c Capability) digest() (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	b, err := json.Marshal(c)
	if err != nil {
		return "", ErrInvalidPlan
	}
	d := sha256.Sum256(append([]byte("keel.ai.provider-capability.v1\x00"), b...))
	return hex.EncodeToString(d[:]), nil
}

type Plan struct {
	TenantID                  string
	InferenceID               string
	PolicyDigest              string
	PrimaryAttemptID          string
	FallbackAttemptID         string
	Primary                   Capability
	Fallback                  *Capability
	FallbackAllowanceMicroUSD int64
	ReservedLiabilityMicroUSD int64
	Deadline                  time.Time
}

func (p Plan) Validate() error {
	if !uuidPattern.MatchString(p.TenantID) || !uuidPattern.MatchString(p.InferenceID) ||
		!digestPattern.MatchString(p.PolicyDigest) || !uuidPattern.MatchString(p.PrimaryAttemptID) ||
		p.Deadline.IsZero() || p.ReservedLiabilityMicroUSD <= 0 || p.Primary.Validate() != nil ||
		p.ReservedLiabilityMicroUSD < p.Primary.MaximumAttemptLiabilityUSD {
		return ErrInvalidPlan
	}
	if p.Fallback == nil {
		if p.FallbackAttemptID != "" || p.FallbackAllowanceMicroUSD != 0 {
			return ErrInvalidPlan
		}
		return nil
	}
	if !uuidPattern.MatchString(p.FallbackAttemptID) || p.FallbackAttemptID == p.PrimaryAttemptID ||
		p.Fallback.Validate() != nil || p.FallbackAllowanceMicroUSD < p.Fallback.MaximumAttemptLiabilityUSD ||
		p.ReservedLiabilityMicroUSD-p.Primary.MaximumAttemptLiabilityUSD < p.FallbackAllowanceMicroUSD {
		return ErrInvalidPlan
	}
	return nil
}

type Acceptance string

const (
	AcceptanceRejected Acceptance = "rejected_before_acceptance"
	AcceptanceAccepted Acceptance = "accepted"
	AcceptanceUnknown  Acceptance = "unknown"
)

type ChargeState string

const (
	ChargeNone      ChargeState = "confirmed_no_charge"
	ChargeConfirmed ChargeState = "confirmed_charge"
	ChargeUnknown   ChargeState = "unknown"
)

type FailureClass string

const (
	FailureNone              FailureClass = "none"
	FailureConnectBeforeSend FailureClass = "connect_before_send"
	FailureRateLimited       FailureClass = "rate_limited_rejected"
	FailureUnavailable       FailureClass = "unavailable_rejected"
	FailureTimeout           FailureClass = "timeout"
	FailureProvider          FailureClass = "provider_error"
)

type Outcome struct {
	AttemptID          string
	Acceptance         Acceptance
	Charge             ChargeState
	Failure            FailureClass
	ProviderOutputSeen bool
	ClientTokenBytes   int64
	UsageMicroUSD      int64
	FinishedAt         time.Time
}

func (o Outcome) Validate() error {
	if !uuidPattern.MatchString(o.AttemptID) || o.FinishedAt.IsZero() || o.ClientTokenBytes < 0 || o.UsageMicroUSD < 0 {
		return ErrInvalidPlan
	}
	switch o.Acceptance {
	case AcceptanceRejected, AcceptanceAccepted, AcceptanceUnknown:
	default:
		return ErrInvalidPlan
	}
	switch o.Charge {
	case ChargeNone, ChargeConfirmed, ChargeUnknown:
	default:
		return ErrInvalidPlan
	}
	switch o.Failure {
	case FailureNone, FailureConnectBeforeSend, FailureRateLimited, FailureUnavailable, FailureTimeout, FailureProvider:
	default:
		return ErrInvalidPlan
	}
	if o.Charge == ChargeNone && o.UsageMicroUSD != 0 || o.Charge == ChargeUnknown && o.UsageMicroUSD != 0 {
		return ErrInvalidPlan
	}
	return nil
}

type AttemptRecord struct {
	TenantID         string
	InferenceID      string
	AttemptID        string
	Ordinal          int
	ProviderID       string
	ProviderVersion  string
	ModelID          string
	CapabilityDigest string
	PolicyDigest     string
	IdempotencyKey   string
	MaximumLiability int64
}

// Next returns the primary record when there is no outcome, or the one
// permitted fallback only after a proven pre-acceptance, no-charge failure.
func Next(p Plan, outcomes []Outcome, activePolicyDigest, keyID string, secret []byte, now time.Time) (AttemptRecord, error) {
	if p.Validate() != nil || !digestPattern.MatchString(activePolicyDigest) || activePolicyDigest != p.PolicyDigest ||
		now.IsZero() || !idPattern.MatchString(keyID) || len(secret) < 32 {
		return AttemptRecord{}, ErrInvalidPlan
	}
	if !now.Before(p.Deadline) {
		return AttemptRecord{}, ErrNoFallback
	}
	if len(outcomes) == 0 {
		return makeRecord(p, p.Primary, p.PrimaryAttemptID, 1, keyID, secret)
	}
	if len(outcomes) != 1 || p.Fallback == nil {
		return AttemptRecord{}, ErrNoFallback
	}
	primary := outcomes[0]
	if primary.Validate() != nil || primary.AttemptID != p.PrimaryAttemptID ||
		primary.Acceptance != AcceptanceRejected || primary.Charge != ChargeNone ||
		primary.ProviderOutputSeen || primary.ClientTokenBytes != 0 ||
		(primary.Failure != FailureConnectBeforeSend && primary.Failure != FailureRateLimited && primary.Failure != FailureUnavailable) ||
		!now.After(primary.FinishedAt) {
		return AttemptRecord{}, ErrNoFallback
	}
	return makeRecord(p, *p.Fallback, p.FallbackAttemptID, 2, keyID, secret)
}

func makeRecord(p Plan, c Capability, attemptID string, ordinal int, keyID string, secret []byte) (AttemptRecord, error) {
	capabilityDigest, err := c.digest()
	if err != nil {
		return AttemptRecord{}, err
	}
	record := AttemptRecord{TenantID: p.TenantID, InferenceID: p.InferenceID, AttemptID: attemptID,
		Ordinal: ordinal, ProviderID: c.ProviderID, ProviderVersion: c.ProviderVersion, ModelID: c.ModelID,
		CapabilityDigest: capabilityDigest, PolicyDigest: p.PolicyDigest, MaximumLiability: c.MaximumAttemptLiabilityUSD}
	if c.SupportsIdempotency {
		mac := hmac.New(sha256.New, secret)
		_, _ = mac.Write([]byte("keel.ai.provider-idempotency.v1\x00"))
		_, _ = mac.Write([]byte(record.TenantID))
		_, _ = mac.Write([]byte{0})
		_, _ = mac.Write([]byte(record.InferenceID))
		_, _ = mac.Write([]byte{0})
		_, _ = mac.Write([]byte(record.AttemptID))
		_, _ = mac.Write([]byte{0})
		_, _ = mac.Write([]byte(capabilityDigest))
		record.IdempotencyKey = keyID + "." + hex.EncodeToString(mac.Sum(nil))
	}
	return record, nil
}

// OutcomeDigest is a content-free fingerprint used by a future append-only
// ledger to accept exact delivery replay and reject conflicting reuse.
func OutcomeDigest(o Outcome) (string, error) {
	if err := o.Validate(); err != nil {
		return "", err
	}
	b, err := json.Marshal(o)
	if err != nil {
		return "", ErrInvalidPlan
	}
	d := sha256.Sum256(append([]byte("keel.ai.provider-outcome.v1\x00"), b...))
	return hex.EncodeToString(d[:]), nil
}

func CheckOutcomeReplay(existing, incoming Outcome) error {
	a, err := OutcomeDigest(existing)
	if err != nil {
		return err
	}
	b, err := OutcomeDigest(incoming)
	if err != nil {
		return err
	}
	if existing.AttemptID != incoming.AttemptID || !hmac.Equal([]byte(a), []byte(b)) {
		return ErrOutcomeConflict
	}
	return nil
}
