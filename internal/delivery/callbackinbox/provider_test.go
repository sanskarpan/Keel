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
