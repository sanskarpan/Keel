package auth

import (
	"strings"
	"testing"
	"time"
)

func TestAPIKeyFormatRoundTrip(t *testing.T) {
	secret, prefix, err := NewAPIKeySecret()
	if err != nil {
		t.Fatal(err)
	}
	formatted, err := FormatAPIKey(secret)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(formatted, APIKeyPrefix) {
		t.Fatalf("prefix missing: %q", formatted)
	}
	gotPrefix, gotSecret, err := ParseAPIKey(formatted)
	if err != nil || gotPrefix != prefix || gotSecret != secret {
		t.Fatalf("round trip: %q %q %v", gotPrefix, gotSecret, err)
	}
	digest, err := APIKeyDigest(secret)
	if err != nil {
		t.Fatal(err)
	}
	again, err := APIKeyDigest(secret)
	if err != nil || again != digest {
		t.Fatalf("digest not deterministic: %v", err)
	}
	// A key digest is purpose-bound: the same secret differs per purpose.
	session, err := TokenDigest(secret, PurposeSession)
	if err != nil {
		t.Fatal(err)
	}
	var sessionBytes = session
	if sessionBytes == digest {
		t.Fatal("API key digest equals session digest")
	}
}

func TestAPIKeyRejectsBadInput(t *testing.T) {
	secret, _, err := NewAPIKeySecret()
	if err != nil {
		t.Fatal(err)
	}
	_ = secret
	if _, err := FormatAPIKey(secret); err != nil {
		t.Fatalf("generated secret rejected: %v", err)
	}
	for _, bad := range []string{
		"", "keel_", "keel_short", "other_" + secret,
		APIKeyPrefix + "bad!char-after-prefix",
	} {
		if _, _, err := ParseAPIKey(bad); err == nil {
			t.Fatalf("accepted: %q", bad)
		}
	}
	if _, err := FormatAPIKey("short"); err == nil {
		t.Fatal("short secret accepted")
	}
	// Secrets containing separators stay unambiguous: the whole tail is secret.
	withUnderscore := secret[:8] + "_" + secret[8:]
	joined, err := FormatAPIKey(withUnderscore)
	if err != nil {
		t.Fatalf("separator secret rejected: %v", err)
	}
	if gotPrefix, gotSecret, err := ParseAPIKey(joined); err != nil || gotSecret != withUnderscore || gotPrefix != withUnderscore[:APIKeyPrefixLen] {
		t.Fatalf("separator round trip: %q %q %v", gotPrefix, gotSecret, err)
	}
	if err := ValidateServiceName(""); err == nil {
		t.Fatal("empty name accepted")
	}
	if err := ValidateServiceName(strings.Repeat("n", MaxServiceNameLen+1)); err == nil {
		t.Fatal("oversized name accepted")
	}
	now := time.Date(2026, time.November, 2, 12, 0, 0, 0, time.UTC)
	if err := ValidateAPIKeyTTL(now, time.Time{}); err != nil {
		t.Fatalf("zero expiry rejected: %v", err)
	}
	if err := ValidateAPIKeyTTL(now, now.Add(30*time.Minute)); err == nil {
		t.Fatal("under-min TTL accepted")
	}
}
