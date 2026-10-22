package webhook

import (
	"errors"
	"testing"
	"time"
)

var (
	testKey = Key{
		ID:     "key_2026_01",
		Secret: []byte("0123456789abcdef0123456789abcdef"),
	}
	testNextKey = Key{
		ID:     "key_2026_02",
		Secret: []byte("fedcba9876543210fedcba9876543210"),
	}
	testBody  = []byte(`{"event":"order.submitted"}`)
	testClock = time.Unix(1735689600, 0).UTC()
)

func newTestKeyring(t *testing.T) *Keyring {
	t.Helper()
	ring, err := NewKeyring(testKey, nil)
	if err != nil {
		t.Fatalf("NewKeyring: %v", err)
	}
	return ring
}

func TestKeyringValidation(t *testing.T) {
	t.Parallel()

	valid := testKey
	cases := []struct {
		name      string
		active    Key
		previous  *Key
		tolerance time.Duration
	}{
		{name: "valid", active: valid, tolerance: DefaultTimestampTolerance},
		{name: "empty key id", active: Key{ID: "", Secret: valid.Secret}, tolerance: DefaultTimestampTolerance},
		{name: "short key id", active: Key{ID: "abc", Secret: valid.Secret}, tolerance: DefaultTimestampTolerance},
		{name: "key id with separator", active: Key{ID: "key/2026", Secret: valid.Secret}, tolerance: DefaultTimestampTolerance},
		{name: "nil secret", active: Key{ID: valid.ID}, tolerance: DefaultTimestampTolerance},
		{name: "short secret", active: Key{ID: valid.ID, Secret: []byte("short")}, tolerance: DefaultTimestampTolerance},
		{name: "zero tolerance", active: valid, tolerance: 0},
		{name: "negative tolerance", active: valid, tolerance: -time.Minute},
		{name: "previous duplicates active", active: valid, previous: &valid, tolerance: DefaultTimestampTolerance},
		{name: "previous too short", active: valid, previous: &Key{ID: "key_2025_12", Secret: []byte("short")}, tolerance: DefaultTimestampTolerance},
	}

	for _, testCase := range cases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			ring, err := NewKeyringWithTolerance(testCase.active, testCase.previous, testCase.tolerance)
			if testCase.name == "valid" {
				if err != nil || ring == nil {
					t.Fatalf("expected a valid keyring, got %v", err)
				}
				return
			}
			if !errors.Is(err, ErrInvalidKeyring) || ring != nil {
				t.Fatalf("expected ErrInvalidKeyring, got ring=%v err=%v", ring, err)
			}
		})
	}
}

func TestKeyringCopiesSecrets(t *testing.T) {
	t.Parallel()

	secret := []byte("0123456789abcdef0123456789abcdef")
	ring, err := NewKeyring(Key{ID: "key_copy_test", Secret: secret}, nil)
	if err != nil {
		t.Fatalf("NewKeyring: %v", err)
	}
	secret[0] = 'x'
	signature, err := ring.Sign(testClock, testBody)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if signature.KeyID != "key_copy_test" {
		t.Fatalf("unexpected key id %q", signature.KeyID)
	}
	if signature.MAC == "" {
		t.Fatal("signature MAC is empty")
	}
	want, err := NewKeyring(Key{ID: "key_copy_test", Secret: []byte("0123456789abcdef0123456789abcdef")}, nil)
	if err != nil {
		t.Fatalf("NewKeyring: %v", err)
	}
	expected, err := want.Sign(testClock, testBody)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if signature.MAC != expected.MAC {
		t.Fatalf("keyring retained a mutable secret reference")
	}
}

func TestSignatureKnownAnswerVector(t *testing.T) {
	t.Parallel()

	ring := newTestKeyring(t)
	signature, err := ring.Sign(testClock, testBody)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	const wantMAC = "d5cd4a4c95570419feaa5d6bb696ace7b589a5eb24387916b6296cc310f9c008"
	if signature.Timestamp != 1735689600 {
		t.Fatalf("unexpected timestamp %d", signature.Timestamp)
	}
	if signature.MAC != wantMAC {
		t.Fatalf("unexpected MAC %q", signature.MAC)
	}
	if err := ring.Verify(signature, testBody, testClock); err != nil {
		t.Fatalf("Verify known answer: %v", err)
	}
}

func TestSignatureCoversExactBody(t *testing.T) {
	t.Parallel()

	ring := newTestKeyring(t)
	signature, err := ring.Sign(testClock, testBody)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := ring.Verify(signature, []byte(`{"event":"order.canceled"}`), testClock); !errors.Is(err, ErrSignatureMismatch) {
		t.Fatalf("expected ErrSignatureMismatch for a different body, got %v", err)
	}
	if err := ring.Verify(signature, append(testBody, ' '), testClock); !errors.Is(err, ErrSignatureMismatch) {
		t.Fatalf("expected ErrSignatureMismatch for trailing whitespace, got %v", err)
	}
}

func TestSignatureTimestampTolerance(t *testing.T) {
	t.Parallel()

	ring := newTestKeyring(t)
	signature, err := ring.Sign(testClock, testBody)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	for _, offset := range []time.Duration{0, time.Minute, -time.Minute, 5 * time.Minute, -5 * time.Minute} {
		if err := ring.Verify(signature, testBody, testClock.Add(offset)); err != nil {
			t.Fatalf("offset %s: expected verification, got %v", offset, err)
		}
	}
	for _, offset := range []time.Duration{5*time.Minute + time.Second, -5*time.Minute - time.Second, time.Hour, -time.Hour} {
		if err := ring.Verify(signature, testBody, testClock.Add(offset)); !errors.Is(err, ErrTimestampSkew) {
			t.Fatalf("offset %s: expected ErrTimestampSkew, got %v", offset, err)
		}
	}
}

func TestVerifyRejectsTamperedSignature(t *testing.T) {
	t.Parallel()

	ring := newTestKeyring(t)
	signature, err := ring.Sign(testClock, testBody)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	tampered := signature
	tampered.MAC = "00" + signature.MAC[2:]
	if tampered.MAC == signature.MAC {
		tampered.MAC = "ff" + signature.MAC[2:]
	}
	if err := ring.Verify(tampered, testBody, testClock); !errors.Is(err, ErrSignatureMismatch) {
		t.Fatalf("expected ErrSignatureMismatch, got %v", err)
	}

	otherRing, err := NewKeyring(testNextKey, nil)
	if err != nil {
		t.Fatalf("NewKeyring: %v", err)
	}
	if err := otherRing.Verify(signature, testBody, testClock); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("expected ErrUnknownKey, got %v", err)
	}
}

func TestParseSignature(t *testing.T) {
	t.Parallel()

	const mac = "d5cd4a4c95570419feaa5d6bb696ace7b589a5eb24387916b6296cc310f9c008"
	cases := []struct {
		name    string
		value   string
		want    Signature
		wantErr error
	}{
		{
			name:  "header",
			value: "t=1735689600,kid=key_2026_01,v1=" + mac,
			want:  Signature{Timestamp: 1735689600, KeyID: "key_2026_01", MAC: mac},
		},
		{name: "empty", value: "", wantErr: ErrInvalidSignature},
		{name: "missing mac", value: "t=1735689600,kid=key_2026_01", wantErr: ErrInvalidSignature},
		{name: "extra field", value: "t=1735689600,kid=key_2026_01,v1=" + mac + ",v2=x", wantErr: ErrInvalidSignature},
		{name: "reordered", value: "kid=key_2026_01,t=1735689600,v1=" + mac, wantErr: ErrInvalidSignature},
		{name: "duplicate timestamp", value: "t=1,t=2,kid=key_2026_01", wantErr: ErrInvalidSignature},
		{name: "tampered prefix", value: "t=17a5689600,kid=key_2026_01,v1=" + mac, wantErr: ErrInvalidSignature},
		{name: "zero timestamp", value: "t=0,kid=key_2026_01,v1=" + mac, wantErr: ErrInvalidSignature},
		{name: "short mac", value: "t=1735689600,kid=key_2026_01,v1=abcd", wantErr: ErrInvalidSignature},
		{name: "uppercase mac", value: "t=1735689600,kid=key_2026_01,v1=" + "D5CD4A4C95570419FEAA5D6BB696ACE7B589A5EB24387916B6296CC310F9C008", wantErr: ErrInvalidSignature},
		{name: "invalid key id", value: "t=1735689600,kid=key.2026.01,v1=" + mac, wantErr: ErrInvalidSignature},
		{name: "whitespace", value: " t=1735689600,kid=key_2026_01,v1=" + mac, wantErr: ErrInvalidSignature},
	}

	for _, testCase := range cases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			got, err := ParseSignature(testCase.value)
			if testCase.wantErr != nil {
				if !errors.Is(err, testCase.wantErr) || got != (Signature{}) {
					t.Fatalf("expected %v and a zero signature, got %v and %v", testCase.wantErr, err, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseSignature: %v", err)
			}
			if got != testCase.want {
				t.Fatalf("expected %+v, got %+v", testCase.want, got)
			}
			if roundTrip, err := ParseSignature(got.String()); err != nil || roundTrip != got {
				t.Fatalf("String round trip failed: %+v %v", roundTrip, err)
			}
		})
	}
}

func TestSignatureRotationOverlap(t *testing.T) {
	t.Parallel()

	oldRing := newTestKeyring(t)
	oldSignature, err := oldRing.Sign(testClock, testBody)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	rotated, err := oldRing.Rotated(testNextKey)
	if err != nil {
		t.Fatalf("Rotated: %v", err)
	}
	if rotated.ActiveKeyID() != testNextKey.ID {
		t.Fatalf("expected active key %q, got %q", testNextKey.ID, rotated.ActiveKeyID())
	}
	if err := rotated.Verify(oldSignature, testBody, testClock); err != nil {
		t.Fatalf("previous key must keep verifying during the overlap: %v", err)
	}
	newSignature, err := rotated.Sign(testClock, testBody)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if newSignature.KeyID != testNextKey.ID {
		t.Fatalf("expected new signatures to use %q, got %q", testNextKey.ID, newSignature.KeyID)
	}

	retired, err := rotated.Rotated(Key{ID: "key_2026_03", Secret: []byte("aaaabbbbccccddddeeeeffff00001111")})
	if err != nil {
		t.Fatalf("Rotated: %v", err)
	}
	if err := retired.Verify(oldSignature, testBody, testClock); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("expected the first key to be retired, got %v", err)
	}
	if err := retired.Verify(newSignature, testBody, testClock); err != nil {
		t.Fatalf("expected the second key to verify during rotation: %v", err)
	}

	if _, err := rotated.Rotated(testNextKey); !errors.Is(err, ErrInvalidKeyring) {
		t.Fatalf("expected rotating to the active key to fail, got %v", err)
	}
}

func TestSignRejectsNonPositiveTimestamp(t *testing.T) {
	t.Parallel()

	ring := newTestKeyring(t)
	if _, err := ring.Sign(time.Unix(0, 0), testBody); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature, got %v", err)
	}
	if _, err := ring.Sign(time.Unix(-1, 0), testBody); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature, got %v", err)
	}
}

func TestKeyringNilSafety(t *testing.T) {
	t.Parallel()

	var ring *Keyring
	if _, err := ring.Sign(testClock, testBody); !errors.Is(err, ErrInvalidKeyring) {
		t.Fatalf("expected ErrInvalidKeyring, got %v", err)
	}
	if err := ring.Verify(Signature{}, testBody, testClock); !errors.Is(err, ErrInvalidKeyring) {
		t.Fatalf("expected ErrInvalidKeyring, got %v", err)
	}
	if ring.ActiveKeyID() != "" {
		t.Fatalf("expected an empty key id, got %q", ring.ActiveKeyID())
	}
	if _, err := ring.Rotated(testNextKey); !errors.Is(err, ErrInvalidKeyring) {
		t.Fatalf("expected ErrInvalidKeyring, got %v", err)
	}
}
