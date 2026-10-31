package callbackinbox

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

func testSyntheticVerifier(t *testing.T) *SyntheticVerifier {
	t.Helper()
	tenant, err := tenancy.ParseTenantID("11111111-1111-4111-8111-111111111111")
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewSyntheticVerifier("provider_one", tenant,
		[]byte("0123456789abcdef0123456789abcdef"), "key_2026_01")
	if err != nil {
		t.Fatal(err)
	}
	return verifier
}

func syntheticRequest(t *testing.T, verifier *SyntheticVerifier, payload string, stamp time.Time) VerificationRequest {
	t.Helper()
	mac := hmac.New(sha256.New, verifier.secret)
	mac.Write([]byte(stamp.UTC().Format(time.RFC3339)))
	mac.Write([]byte("\n"))
	mac.Write([]byte(payload))
	return VerificationRequest{
		Provider:        "provider_one",
		ProviderEventID: "evt_abc123",
		Payload:         []byte(payload),
		Signature:       []byte(hex.EncodeToString(mac.Sum(nil))),
		Timestamp:       stamp.UTC().Format(time.RFC3339),
	}
}

func validSyntheticPayload() string {
	return `{"event_type":"payment.settled","occurred_at":"2026-10-26T12:00:00Z"}`
}

func TestSyntheticVerifierAcceptsSignedCallback(t *testing.T) {
	verifier := testSyntheticVerifier(t)
	event, err := verifier.Verify(context.Background(),
		syntheticRequest(t, verifier, validSyntheticPayload(), time.Now()))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if event.Provider != "provider_one" || event.ProviderEventID != "evt_abc123" ||
		event.EventType != "payment.settled" || event.KeyID != "key_2026_01" {
		t.Fatalf("verified event = %+v", event)
	}
	if event.PayloadDigest != DigestPayload([]byte(validSyntheticPayload())) {
		t.Fatalf("payload digest = %q", event.PayloadDigest)
	}
	if string(event.Tenant) != "11111111-1111-4111-8111-111111111111" {
		t.Fatalf("tenant = %q", event.Tenant)
	}
}

func TestSyntheticVerifierRejectsUntrustedCallbacks(t *testing.T) {
	verifier := testSyntheticVerifier(t)
	now := time.Now()
	valid := syntheticRequest(t, verifier, validSyntheticPayload(), now)
	for _, test := range []struct {
		name   string
		mutate func(*VerificationRequest)
		want   error
	}{
		{"tampered payload", func(r *VerificationRequest) {
			r.Payload = []byte(`{"event_type":"payment.refunded","occurred_at":"2026-10-26T12:00:00Z"}`)
		}, ErrUnauthenticated},
		{"tampered signature", func(r *VerificationRequest) {
			r.Signature = []byte(strings.Repeat("0", 64))
		}, ErrUnauthenticated},
		{"missing signature", func(r *VerificationRequest) {
			r.Signature = nil
		}, ErrUnauthenticated},
		{"stale timestamp", func(r *VerificationRequest) {
			stale := now.Add(-DefaultSyntheticSkew - time.Minute).UTC().Format(time.RFC3339)
			r.Timestamp = stale
		}, ErrUnauthenticated},
		{"future timestamp", func(r *VerificationRequest) {
			future := now.Add(DefaultSyntheticSkew + time.Minute).UTC().Format(time.RFC3339)
			r.Timestamp = future
		}, ErrUnauthenticated},
		{"bad timestamp", func(r *VerificationRequest) { r.Timestamp = "yesterday" }, ErrUnauthenticated},
		{"wrong provider", func(r *VerificationRequest) { r.Provider = "provider_two" }, ErrInvalidCallback},
		{"bad event", func(r *VerificationRequest) { r.ProviderEventID = "not an event!" }, ErrInvalidCallback},
		{"bad payload", func(r *VerificationRequest) {
			r.Payload = []byte(`{"event_type":"payment.settled"}`)
			mac := hmac.New(sha256.New, verifier.secret)
			mac.Write([]byte(r.Timestamp))
			mac.Write([]byte("\n"))
			mac.Write(r.Payload)
			r.Signature = []byte(hex.EncodeToString(mac.Sum(nil)))
		}, ErrInvalidCallback},
		{"unknown field", func(r *VerificationRequest) {
			r.Payload = []byte(`{"event_type":"payment.settled","occurred_at":"2026-10-26T12:00:00Z","extra":1}`)
			mac := hmac.New(sha256.New, verifier.secret)
			mac.Write([]byte(r.Timestamp))
			mac.Write([]byte("\n"))
			mac.Write(r.Payload)
			r.Signature = []byte(hex.EncodeToString(mac.Sum(nil)))
		}, ErrInvalidCallback},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := valid
			test.mutate(&request)
			if _, err := verifier.Verify(context.Background(), request); !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
	if _, err := verifier.Verify(nil, valid); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("nil context error = %v", err)
	}
}

func TestNewSyntheticVerifierRejectsWeakIdentity(t *testing.T) {
	tenant, err := tenancy.ParseTenantID("11111111-1111-4111-8111-111111111111")
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte("0123456789abcdef0123456789abcdef")
	for _, test := range []struct {
		name     string
		provider string
		tenant   tenancy.TenantID
		secret   []byte
		keyID    string
	}{
		{"bad provider", "Provider One", tenant, secret, "key_2026_01"},
		{"zero tenant", "provider_one", "", secret, "key_2026_01"},
		{"short secret", "provider_one", tenant, []byte("short"), "key_2026_01"},
		{"nil secret", "provider_one", tenant, nil, "key_2026_01"},
		{"bad key", "provider_one", tenant, secret, "not a key!"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewSyntheticVerifier(test.provider, test.tenant, test.secret, test.keyID); err == nil {
				t.Fatal("weak synthetic identity was accepted")
			}
		})
	}
}

func TestValidateObservationRejectsBadShapes(t *testing.T) {
	none := sql.NullInt64{}
	some := sql.NullInt64{Int64: 1500, Valid: true}
	negative := sql.NullInt64{Int64: -1, Valid: true}
	if err := validateObservation(ObservationApplied, none); err != nil {
		t.Fatalf("valid applied observation rejected: %v", err)
	}
	if err := validateObservation(ObservationDuplicate, some); err != nil {
		t.Fatalf("valid duplicate observation rejected: %v", err)
	}
	for _, test := range []struct {
		name    string
		outcome ObservationOutcome
		delay   sql.NullInt64
	}{
		{"bad outcome", "replayed", none},
		{"delay on applied", ObservationApplied, some},
		{"delay on conflict", ObservationConflict, some},
		{"negative delay", ObservationDuplicate, negative},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := validateObservation(test.outcome, test.delay); !errors.Is(err, ErrInvalidCallback) {
				t.Fatalf("error = %v, want invalid callback", err)
			}
		})
	}
}

func testRegistry(t *testing.T) (*Registry, tenancy.TenantID, tenancy.TenantID) {
	t.Helper()
	first, err := tenancy.ParseTenantID("11111111-1111-4111-8111-111111111111")
	if err != nil {
		t.Fatal(err)
	}
	second, err := tenancy.ParseTenantID("22222222-2222-4222-8222-222222222222")
	if err != nil {
		t.Fatal(err)
	}
	registry, err := NewRegistry([]ProviderConfig{
		{Provider: "provider_one", Tenant: first,
			Secret: []byte("0123456789abcdef0123456789abcdef"), KeyID: "key_2026_01"},
		{Provider: "provider_two", Tenant: second,
			Secret: []byte("fedcba9876543210fedcba9876543210"), KeyID: "key_2026_02"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return registry, first, second
}

func registryRequest(t *testing.T, registry *Registry, provider, secretID string) VerificationRequest {
	t.Helper()
	var secret []byte
	switch secretID {
	case "one":
		secret = []byte("0123456789abcdef0123456789abcdef")
	case "two":
		secret = []byte("fedcba9876543210fedcba9876543210")
	default:
		t.Fatalf("unknown secret %q", secretID)
	}
	stamp := time.Now().UTC().Format(time.RFC3339)
	payload := `{"event_type":"payment.settled","occurred_at":"2026-10-26T12:00:00Z"}`
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(stamp))
	mac.Write([]byte("\n"))
	mac.Write([]byte(payload))
	return VerificationRequest{
		Provider:        provider,
		ProviderEventID: "evt_abc123",
		Payload:         []byte(payload),
		Signature:       []byte(hex.EncodeToString(mac.Sum(nil))),
		Timestamp:       stamp,
	}
}

func TestRegistryDispatchesPerProviderSecrets(t *testing.T) {
	registry, first, second := testRegistry(t)
	event, err := registry.Verify(context.Background(), registryRequest(t, registry, "provider_one", "one"))
	if err != nil {
		t.Fatalf("provider_one verify: %v", err)
	}
	if event.Tenant != first || event.KeyID != "key_2026_01" {
		t.Fatalf("provider_one event = %+v", event)
	}
	event, err = registry.Verify(context.Background(), registryRequest(t, registry, "provider_two", "two"))
	if err != nil {
		t.Fatalf("provider_two verify: %v", err)
	}
	if event.Tenant != second || event.KeyID != "key_2026_02" {
		t.Fatalf("provider_two event = %+v", event)
	}
	// Each provider's secret verifies only its own callbacks.
	request := registryRequest(t, registry, "provider_one", "two")
	if _, err := registry.Verify(context.Background(), request); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("cross-provider secret error = %v, want unauthenticated", err)
	}
}

func TestRegistryRejectsUnknownProvider(t *testing.T) {
	registry, _, _ := testRegistry(t)
	request := registryRequest(t, registry, "provider_one", "one")
	request.Provider = "provider_three"
	if _, err := registry.Verify(context.Background(), request); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("unknown provider error = %v, want unauthenticated", err)
	}
	var nilRegistry *Registry
	if _, err := nilRegistry.Verify(context.Background(), request); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("nil registry error = %v, want unauthenticated", err)
	}
}

func TestNewRegistryRejectsBadConfigs(t *testing.T) {
	tenant, err := tenancy.ParseTenantID("11111111-1111-4111-8111-111111111111")
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte("0123456789abcdef0123456789abcdef")
	good := ProviderConfig{Provider: "provider_one", Tenant: tenant, Secret: secret, KeyID: "key_2026_01"}
	other := ProviderConfig{Provider: "provider_two", Tenant: tenant, Secret: secret, KeyID: "key_2026_02"}
	for _, test := range []struct {
		name    string
		configs []ProviderConfig
	}{
		{"empty", nil},
		{"bad provider", []ProviderConfig{{Provider: "Provider One", Tenant: tenant, Secret: secret, KeyID: "key_2026_01"}}},
		{"duplicate provider", []ProviderConfig{good, good}},
		{"zero tenant", []ProviderConfig{{Provider: "provider_one", Secret: secret, KeyID: "key_2026_01"}}},
		{"short secret", []ProviderConfig{{Provider: "provider_one", Tenant: tenant, Secret: []byte("short"), KeyID: "key_2026_01"}}},
		{"bad key", []ProviderConfig{{Provider: "provider_one", Tenant: tenant, Secret: secret, KeyID: "k!"}}},
		{"second bad", []ProviderConfig{good, {Provider: "provider_two", Tenant: tenant, KeyID: "key_2026_02"}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewRegistry(test.configs); err == nil {
				t.Fatal("bad registry config was accepted")
			}
		})
	}
	if _, err := NewRegistry([]ProviderConfig{good, other}); err != nil {
		t.Fatalf("two-provider registry rejected: %v", err)
	}
}
