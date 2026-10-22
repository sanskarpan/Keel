package webhook

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

const (
	testTenantID   = "11111111-1111-4111-8111-111111111111"
	testEventID    = "0b6f6b9e-2f3c-4f0e-9a3f-7b0f1f2c3d4e"
	testEndpointID = "9a0e7f3c-1b2a-4c5d-8e9f-0a1b2c3d4e5f"
	testDeliveryID = "d1e2f3a4-b5c6-4d7e-8f90-a1b2c3d4e5f6"
)

func testIdentity(t *testing.T) Identity {
	t.Helper()
	tenant, err := tenancy.ParseTenantID(testTenantID)
	if err != nil {
		t.Fatalf("ParseTenantID: %v", err)
	}
	return Identity{Tenant: tenant, EventID: testEventID, EndpointID: testEndpointID, SubscriptionVersion: 3}
}

func TestIdentityValidate(t *testing.T) {
	t.Parallel()

	valid := testIdentity(t)
	cases := []struct {
		name     string
		mutate   func(Identity) Identity
		wantFail bool
	}{
		{name: "valid", mutate: func(i Identity) Identity { return i }},
		{name: "zero tenant", mutate: func(i Identity) Identity { i.Tenant = ""; return i }, wantFail: true},
		{name: "nil tenant", mutate: func(i Identity) Identity { i.Tenant = "00000000-0000-0000-0000-000000000000"; return i }, wantFail: true},
		{name: "malformed tenant", mutate: func(i Identity) Identity { i.Tenant = "tenant-one"; return i }, wantFail: true},
		{name: "short event", mutate: func(i Identity) Identity { i.EventID = "short"; return i }, wantFail: true},
		{name: "event with separator", mutate: func(i Identity) Identity { i.EventID = "event/with/slash"; return i }, wantFail: true},
		{name: "long event", mutate: func(i Identity) Identity { i.EventID = strings.Repeat("a", 129); return i }, wantFail: true},
		{name: "short endpoint", mutate: func(i Identity) Identity { i.EndpointID = "ep"; return i }, wantFail: true},
		{name: "endpoint with dot", mutate: func(i Identity) Identity { i.EndpointID = "endpoint.with.dots"; return i }, wantFail: true},
		{name: "zero version", mutate: func(i Identity) Identity { i.SubscriptionVersion = 0; return i }, wantFail: true},
		{name: "version above cap", mutate: func(i Identity) Identity { i.SubscriptionVersion = MaxSubscriptionVersion + 1; return i }, wantFail: true},
		{name: "max version", mutate: func(i Identity) Identity { i.SubscriptionVersion = MaxSubscriptionVersion; return i }},
	}

	for _, testCase := range cases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			err := testCase.mutate(valid).Validate()
			if testCase.wantFail {
				if !errors.Is(err, ErrInvalidDelivery) {
					t.Fatalf("expected ErrInvalidDelivery, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Validate: %v", err)
			}
		})
	}
}

func TestIdentityKeyIsStableAndLengthPrefixed(t *testing.T) {
	t.Parallel()

	identity := testIdentity(t)
	key := identity.Key()
	if key != identity.Key() {
		t.Fatal("identity key is not stable")
	}
	for _, fragment := range []string{
		DeliveryIdentityVersion,
		"36:" + testTenantID,
		"36:" + testEventID,
		"36:" + testEndpointID,
		"|3",
	} {
		if !strings.Contains(key, fragment) {
			t.Fatalf("key %q is missing %q", key, fragment)
		}
	}

	variants := []Identity{
		identity,
		func() Identity { i := identity; i.SubscriptionVersion = 4; return i }(),
		func() Identity { i := identity; i.EndpointID = "9a0e7f3c-1b2a-4c5d-8e9f-0a1b2c3d4e50"; return i }(),
		func() Identity { i := identity; i.EventID = "0b6f6b9e-2f3c-4f0e-9a3f-7b0f1f2c3d4f"; return i }(),
		func() Identity { i := identity; i.Tenant = "22222222-2222-4222-8222-222222222222"; return i }(),
	}
	seen := make(map[string]struct{}, len(variants))
	for _, variant := range variants {
		if _, duplicate := seen[variant.Key()]; duplicate {
			t.Fatalf("identity keys collide: %q", variant.Key())
		}
		seen[variant.Key()] = struct{}{}
	}
}

func TestDeliveryValidate(t *testing.T) {
	t.Parallel()

	identity := testIdentity(t)
	valid := Delivery{ID: testDeliveryID, Identity: identity}
	if err := valid.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if err := (Delivery{ID: "", Identity: identity}).Validate(); !errors.Is(err, ErrInvalidDelivery) {
		t.Fatalf("expected ErrInvalidDelivery for an empty delivery id, got %v", err)
	}
	if err := (Delivery{ID: "not a valid id", Identity: identity}).Validate(); !errors.Is(err, ErrInvalidDelivery) {
		t.Fatalf("expected ErrInvalidDelivery for a malformed delivery id, got %v", err)
	}
	if err := (Delivery{ID: testDeliveryID, Identity: Identity{}}).Validate(); !errors.Is(err, ErrInvalidDelivery) {
		t.Fatalf("expected ErrInvalidDelivery for an empty identity, got %v", err)
	}
}

func TestPrepareHeaders(t *testing.T) {
	t.Parallel()

	ring := newTestKeyring(t)
	delivery := Delivery{ID: testDeliveryID, Identity: testIdentity(t)}
	headers, err := ring.Prepare(delivery, "attempt-0001", testBody, testClock)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if headers.EventID != testEventID || headers.DeliveryID != testDeliveryID {
		t.Fatalf("unexpected stable headers: %+v", headers)
	}
	if headers.AttemptID != "attempt-0001" {
		t.Fatalf("unexpected attempt id %q", headers.AttemptID)
	}
	values := headers.Values()
	if values[HeaderEventID] != testEventID || values[HeaderDeliveryID] != testDeliveryID ||
		values[HeaderAttemptID] != "attempt-0001" || values[HeaderSignature] != headers.Signature.String() {
		t.Fatalf("unexpected header values: %v", values)
	}
	if err := ring.VerifyHeaders(headers, testBody, testClock); err != nil {
		t.Fatalf("VerifyHeaders: %v", err)
	}
	if err := ring.VerifyHeaders(headers, []byte(`{"event":"other"}`), testClock); !errors.Is(err, ErrSignatureMismatch) {
		t.Fatalf("expected ErrSignatureMismatch for a different body, got %v", err)
	}
	if err := ring.VerifyHeaders(Headers{}, testBody, testClock); !errors.Is(err, ErrInvalidDelivery) {
		t.Fatalf("expected ErrInvalidDelivery for empty headers, got %v", err)
	}
}

func TestPrepareRejectsUnboundedInput(t *testing.T) {
	t.Parallel()

	ring := newTestKeyring(t)
	delivery := Delivery{ID: testDeliveryID, Identity: testIdentity(t)}
	for _, attemptID := range []string{"", "short", "attempt with space", strings.Repeat("a", 65)} {
		if _, err := ring.Prepare(delivery, attemptID, testBody, testClock); !errors.Is(err, ErrInvalidDelivery) {
			t.Fatalf("attempt %q: expected ErrInvalidDelivery, got %v", attemptID, err)
		}
	}
	if _, err := ring.Prepare(Delivery{ID: testDeliveryID}, "attempt-0001", testBody, testClock); !errors.Is(err, ErrInvalidDelivery) {
		t.Fatalf("expected ErrInvalidDelivery for an invalid identity, got %v", err)
	}
	var nilRing *Keyring
	if _, err := nilRing.Prepare(delivery, "attempt-0001", testBody, testClock); !errors.Is(err, ErrInvalidKeyring) {
		t.Fatalf("expected ErrInvalidKeyring, got %v", err)
	}
}

func TestPrepareReplayKeepsIdentityAndRotatesAttempt(t *testing.T) {
	t.Parallel()

	ring := newTestKeyring(t)
	delivery := Delivery{ID: testDeliveryID, Identity: testIdentity(t)}
	first, err := ring.Prepare(delivery, "attempt-0001", testBody, testClock)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	second, err := ring.Prepare(delivery, "attempt-0002", testBody, testClock.Add(30*time.Second))
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if first.EventID != second.EventID || first.DeliveryID != second.DeliveryID {
		t.Fatalf("a replay must keep the event and delivery identity: %+v vs %+v", first, second)
	}
	if first.AttemptID == second.AttemptID {
		t.Fatal("a replay must use a fresh attempt id")
	}
	if first.Signature.Timestamp == second.Signature.Timestamp || first.Signature.MAC == second.Signature.MAC {
		t.Fatal("a replay must use a fresh timestamp and signature")
	}
	if err := ring.VerifyHeaders(first, testBody, testClock); err != nil {
		t.Fatalf("first attempt must remain verifiable: %v", err)
	}
	if err := ring.VerifyHeaders(second, testBody, testClock.Add(30*time.Second)); err != nil {
		t.Fatalf("second attempt must verify: %v", err)
	}
}
