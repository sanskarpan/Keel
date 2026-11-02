package auth

import (
	"strings"
	"testing"
	"time"
)

func TestWebAuthnChallengeBounds(t *testing.T) {
	now := time.Date(2026, time.November, 2, 12, 0, 0, 0, time.UTC)
	if err := ValidateWebAuthnChallengeTTL(now, now.Add(5*time.Minute)); err != nil {
		t.Fatalf("valid window: %v", err)
	}
	if err := ValidateWebAuthnChallengeTTL(now, now.Add(30*time.Second)); err == nil {
		t.Fatal("under-min window accepted")
	}
	if err := ValidateWebAuthnChallengeTTL(now, now.Add(time.Hour)); err == nil {
		t.Fatal("over-max window accepted")
	}
	if err := ValidateChallengeBytes(make([]byte, WebAuthnChallengeBytes)); err != nil {
		t.Fatalf("valid nonce: %v", err)
	}
	if err := ValidateChallengeBytes(make([]byte, WebAuthnChallengeBytes-1)); err == nil {
		t.Fatal("short nonce accepted")
	}
}

func TestWebAuthnCredentialBounds(t *testing.T) {
	if err := ValidateCredentialID(make([]byte, 64)); err != nil {
		t.Fatalf("valid id: %v", err)
	}
	if err := ValidateCredentialID(nil); err == nil {
		t.Fatal("empty id accepted")
	}
	if err := ValidateCredentialID(make([]byte, MaxCredentialIDBytes+1)); err == nil {
		t.Fatal("oversized id accepted")
	}
	if err := ValidatePublicKey(make([]byte, 77)); err != nil {
		t.Fatalf("valid key: %v", err)
	}
	if err := ValidatePublicKey(make([]byte, MaxPublicKeyBytes+1)); err == nil {
		t.Fatal("oversized key accepted")
	}
	for _, ok := range []string{"", "usb", "usb,nfc", "internal,hybrid,ble,nfc,usb"} {
		if err := ValidateTransports(ok); err != nil {
			t.Fatalf("valid transports %q: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"bluetooth", "USB", "usb,,nfc", ",usb", "usb,", strings.Repeat("usb,", 6) + "usb",
	} {
		if err := ValidateTransports(bad); err == nil {
			t.Fatalf("invalid transports accepted: %q", bad)
		}
	}
}

func TestWebAuthnSignCount(t *testing.T) {
	if advanced, cloned := CheckSignCount(0, 0); advanced || cloned {
		t.Fatal("counterless pair misjudged")
	}
	if advanced, cloned := CheckSignCount(3, 4); !advanced || cloned {
		t.Fatal("advancing counter misjudged")
	}
	if advanced, cloned := CheckSignCount(4, 4); advanced || !cloned {
		t.Fatal("replayed counter not flagged")
	}
	if advanced, cloned := CheckSignCount(4, 0); advanced || !cloned {
		t.Fatal("regressed counter not flagged")
	}
	if advanced, cloned := CheckSignCount(0, 1); !advanced || cloned {
		t.Fatal("first counter misjudged")
	}
}
