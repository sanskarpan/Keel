package callbackinbox

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"

	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

// DefaultSyntheticSkew bounds the distance between a synthetic callback timestamp and the
// verifier clock. It matches the webhook signature tolerance convention.
const DefaultSyntheticSkew = 5 * time.Minute

// MinSyntheticSecretBytes bounds a synthetic provider secret. Short secrets are rejected so a
// development placeholder cannot silently become a weak production credential.
const MinSyntheticSecretBytes = 32

// SyntheticVerifier is a code-owned HMAC verifier for local development and tests. It is not a
// production provider adapter: the tenant mapping is static and configured explicitly, and the
// wire scheme is fixed below. A production provider needs its own Verifier with provider-owned
// signature, rotation and tenant-resolution rules.
type SyntheticVerifier struct {
	provider  string
	tenant    tenancy.TenantID
	secret    []byte
	keyID     string
	tolerance time.Duration
}

// ProviderConfig binds one provider name to one tenant with an HMAC secret and key reference.
// A Registry entry carries the same trust shape as a SyntheticVerifier.
type ProviderConfig struct {
	Provider string
	Tenant   tenancy.TenantID
	Secret   []byte
	KeyID    string
}

// Registry dispatches verification across configured providers. Each provider name maps to
// exactly one tenant, secret and key reference; an unknown provider is rejected fail-closed
// without applying anything. It carries no production signature schemes: every entry uses the
// same code-owned HMAC wire contract.
type Registry struct {
	entries map[string]providerEntry
}

type providerEntry struct {
	tenant    tenancy.TenantID
	secret    []byte
	keyID     string
	tolerance time.Duration
}

// NewRegistry validates one entry per provider name. Duplicate names, weak identities and
// short secrets are rejected.
func NewRegistry(configs []ProviderConfig) (*Registry, error) {
	if len(configs) == 0 {
		return nil, ErrInvalidCallback
	}
	registry := &Registry{entries: make(map[string]providerEntry, len(configs))}
	for _, config := range configs {
		if !providerPattern.MatchString(config.Provider) {
			return nil, ErrInvalidCallback
		}
		if _, duplicate := registry.entries[config.Provider]; duplicate {
			return nil, ErrInvalidCallback
		}
		if string(config.Tenant) == "" || string(config.Tenant) == zeroTenant {
			return nil, ErrInvalidCallback
		}
		if _, err := tenancy.ParseTenantID(string(config.Tenant)); err != nil {
			return nil, ErrInvalidCallback
		}
		if len(config.Secret) < MinSyntheticSecretBytes {
			return nil, ErrUnauthenticated
		}
		if !keyIDPattern.MatchString(config.KeyID) {
			return nil, ErrInvalidCallback
		}
		registry.entries[config.Provider] = providerEntry{
			tenant: config.Tenant, secret: append([]byte(nil), config.Secret...),
			keyID: config.KeyID, tolerance: DefaultSyntheticSkew,
		}
	}
	return registry, nil
}

// Verify authenticates one callback against the named provider's secret. An unknown provider
// is an authentication failure: no credential verifies it, so nothing is applied.
func (r *Registry) Verify(ctx context.Context, request VerificationRequest) (VerifiedEvent, error) {
	var event VerifiedEvent
	if r == nil {
		return event, ErrUnauthenticated
	}
	entry, ok := r.entries[request.Provider]
	if !ok {
		return event, ErrUnauthenticated
	}
	return entry.verify(ctx, request)
}

// Verify authenticates one synthetic callback. The signature must be the lowercase hex
// HMAC-SHA256 of `timestamp + "\n" + exact payload bytes`; the timestamp must be RFC 3339
// within the skew window; the payload must carry an event type and occurrence time.
func (v *SyntheticVerifier) Verify(ctx context.Context, request VerificationRequest) (VerifiedEvent, error) {
	var event VerifiedEvent
	if v == nil {
		return event, ErrUnauthenticated
	}
	if request.Provider != v.provider {
		return event, ErrInvalidCallback
	}
	return providerEntry{
		tenant: v.tenant, secret: v.secret, keyID: v.keyID, tolerance: v.tolerance,
	}.verify(ctx, request)
}

// NewSyntheticVerifier binds one provider name to one tenant with an HMAC secret and key
// reference. The secret is cloned; nil and short secrets are rejected.
func NewSyntheticVerifier(provider string, tenant tenancy.TenantID, secret []byte, keyID string) (*SyntheticVerifier, error) {
	if !providerPattern.MatchString(provider) {
		return nil, ErrInvalidCallback
	}
	if string(tenant) == "" || string(tenant) == zeroTenant {
		return nil, ErrInvalidCallback
	}
	if _, err := tenancy.ParseTenantID(string(tenant)); err != nil {
		return nil, ErrInvalidCallback
	}
	if len(secret) < MinSyntheticSecretBytes {
		return nil, ErrUnauthenticated
	}
	if !keyIDPattern.MatchString(keyID) {
		return nil, ErrInvalidCallback
	}
	return &SyntheticVerifier{
		provider: provider, tenant: tenant, secret: append([]byte(nil), secret...),
		keyID: keyID, tolerance: DefaultSyntheticSkew,
	}, nil
}

// syntheticPayload is the fixed development wire body a synthetic callback carries.
type syntheticPayload struct {
	EventType  string `json:"event_type"`
	OccurredAt string `json:"occurred_at"`
}

func (e providerEntry) verify(ctx context.Context, request VerificationRequest) (VerifiedEvent, error) {
	var event VerifiedEvent
	if len(e.secret) == 0 {
		return event, ErrUnauthenticated
	}
	if ctx == nil {
		return event, ErrUnauthenticated
	}
	if request.ProviderEventID == "" ||
		!eventIDPattern.MatchString(request.ProviderEventID) {
		return event, ErrInvalidCallback
	}
	if len(request.Payload) == 0 || len(request.Payload) > MaxPayloadBytes {
		return event, ErrInvalidCallback
	}
	stamp, err := time.Parse(time.RFC3339, request.Timestamp)
	if err != nil {
		return event, ErrUnauthenticated
	}
	skew := time.Since(stamp.UTC())
	if skew < 0 {
		skew = -skew
	}
	if skew > e.tolerance {
		return event, ErrUnauthenticated
	}
	mac := hmac.New(sha256.New, e.secret)
	mac.Write([]byte(request.Timestamp))
	mac.Write([]byte("\n"))
	mac.Write(request.Payload)
	expected := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(strings.ToLower(string(request.Signature))), []byte(expected)) {
		return event, ErrUnauthenticated
	}
	var body syntheticPayload
	decoder := json.NewDecoder(bytes.NewReader(request.Payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil {
		return event, ErrInvalidCallback
	}
	if !eventTypePattern.MatchString(body.EventType) {
		return event, ErrInvalidCallback
	}
	occurred, err := time.Parse(time.RFC3339, body.OccurredAt)
	if err != nil || occurred.IsZero() {
		return event, ErrInvalidCallback
	}
	return VerifiedEvent{
		Tenant: e.tenant, Provider: request.Provider, ProviderEventID: request.ProviderEventID,
		PayloadDigest: DigestPayload(request.Payload), EventType: body.EventType,
		KeyID: e.keyID, OccurredAt: occurred.UTC(),
	}, nil
}

var (
	_ Verifier = (*SyntheticVerifier)(nil)
	_ Verifier = (*Registry)(nil)
)
