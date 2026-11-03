package auth

import (
	"errors"
	"strings"
	"testing"
	"testing/iotest"
)

func TestTokenDigestRejectsUnknownPurpose(t *testing.T) {
	secret, err := NewSecret(nil)
	if err != nil {
		t.Fatalf("NewSecret: %v", err)
	}
	if _, err := TokenDigest(secret, "identity-password-reset-v1"); err == nil {
		t.Fatal("unknown purpose accepted")
	}
	if _, err := TokenDigest(secret, ""); err == nil {
		t.Fatal("empty purpose accepted")
	}
}

func TestTokenDigestIsPurposeSeparated(t *testing.T) {
	secret, err := NewSecret(nil)
	if err != nil {
		t.Fatalf("NewSecret: %v", err)
	}
	session, err := TokenDigest(secret, PurposeSession)
	if err != nil {
		t.Fatalf("session digest: %v", err)
	}
	verification, err := TokenDigest(secret, PurposeEmailVerification)
	if err != nil {
		t.Fatalf("verification digest: %v", err)
	}
	if session == verification {
		t.Fatal("one purpose digest must not equal another purpose digest")
	}
	if _, err := TokenDigest("!"+secret, PurposeSession); err == nil {
		t.Fatal("malformed secret accepted")
	}
	if _, err := TokenDigest(strings.Repeat("A", 100), PurposeSession); err == nil {
		t.Fatal("oversized secret accepted")
	}
}

func TestNewSecretFailsClosedOnReaderFailure(t *testing.T) {
	if _, err := NewSecret(iotest.ErrReader(testReaderFailure)); err == nil {
		t.Fatal("failed reader accepted")
	}
}

var testReaderFailure = errors.New("test reader failure")

func TestEmailCanonicalizationAndDigest(t *testing.T) {
	valid := "owner@example.com"
	canonical, err := CanonicalizeEmail(valid)
	if err != nil || canonical != valid {
		t.Fatalf("canonicalize: %v %q", err, canonical)
	}
	for _, bad := range []string{
		"", "nope", "a@@b.com", "a b@c.com", strings.Repeat("a", 250) + "@x.com",
		"@example.com", "user@", ".dot@x.com", "dots..d@x.com", "u@.x.com", "u@x..com",
	} {
		if _, err := CanonicalizeEmail(bad); err == nil {
			t.Fatalf("invalid email accepted: %q", bad)
		}
	}
	pepper := make([]byte, MinPepperBytes)
	for i := range pepper {
		pepper[i] = byte(i)
	}
	if _, err := EmailDigest("Owner@Example.com", pepper); err == nil {
		t.Fatal("non-canonical address accepted without error")
	}
	baseline, err := EmailDigest(valid, pepper)
	if err != nil {
		t.Fatalf("valid digest: %v", err)
	}
	same, err := EmailDigest(valid, pepper)
	if err != nil || same != baseline {
		t.Fatalf("digest not deterministic: %v", err)
	}
	if _, err := EmailDigest(valid, pepper[:MinPepperBytes-1]); err == nil {
		t.Fatal("short pepper accepted")
	}
	if _, err := EmailDigest(valid, nil); err == nil {
		t.Fatal("nil pepper accepted")
	}
}
