package auth

import (
	"strings"
	"testing"
	"time"
)

func fixedNow() time.Time {
	return time.Date(2026, time.November, 2, 12, 0, 0, 0, time.UTC)
}

func TestPasswordHashVerifyLifecycle(t *testing.T) {
	hash, err := HashPassword("correct-horse-battery", TestArgonParams())
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if len(hash) > MaxHashLen {
		t.Fatalf("encoded hash too long: %d", len(hash))
	}
	ok, err := VerifyPassword("correct-horse-battery", hash)
	if err != nil || !ok {
		t.Fatalf("correct password rejected: %v %v", ok, err)
	}
	ok, err = VerifyPassword("wrong-horse-battery!", hash)
	if err != nil || ok {
		t.Fatalf("wrong password accepted: %v %v", ok, err)
	}
	downgraded := strings.Replace(hash, "argon2id", "argon2i", 1)
	if _, err := VerifyPassword("correct-horse-battery", downgraded); err == nil {
		t.Fatal("algorithm downgrade accepted")
	}
	for _, broken := range []string{
		"",
		strings.Repeat("$", MaxHashLen+1),
		"plain",
		"$argon2id$v=999$m=8192,t=1,p=1$" + strings.TrimPrefix(hash, "$argon2id$v=19$m=8192,t=1,p=1$"),
	} {
		if _, err := VerifyPassword("correct-horse-battery", broken); err == nil {
			t.Fatalf("broken hash accepted: %q", broken)
		}
	}
	// A truncated-but-parseable tail is a mismatch, never an authentication.
	if ok, _ := VerifyPassword("correct-horse-battery", hash[:len(hash)-8]); ok {
		t.Fatal("truncated hash authenticated")
	}
	if _, err := HashPassword("short", TestArgonParams()); err == nil {
		t.Fatal("short password accepted")
	}
	if _, err := HashPassword(strings.Repeat("p", MaxPasswordBytes+1), TestArgonParams()); err == nil {
		t.Fatal("oversized password accepted")
	}
	if _, err := HashPassword("bounds-check-password", ArgonParams{MemoryKiB: 8, Time: 1, Threads: 1}); err == nil {
		t.Fatal("under-bounded params accepted")
	}
	if _, err := HashPassword("bounds-check-password", ArgonParams{MemoryKiB: MaxArgonMemoryKiB + 1, Time: 1, Threads: 1}); err == nil {
		t.Fatal("over-bounded params accepted")
	}
	// Test and default effort profiles each verify, proving stored params parse.
	defaultHash, err := HashPassword("default-profile-check", DefaultArgonParams())
	if err != nil {
		t.Fatalf("default hash: %v", err)
	}
	if ok, err := VerifyPassword("default-profile-check", defaultHash); err != nil || !ok {
		t.Fatalf("default profile verify: %v %v", ok, err)
	}
	if !CredentialMatches(hash, hash) || CredentialMatches(hash, defaultHash) {
		t.Fatal("credential byte compare misbehaves")
	}
}

func TestCredentialMatchesRejectsBadInput(t *testing.T) {
	if CredentialMatches("", "") {
		t.Fatal("empty hash matched")
	}
	if CredentialMatches(strings.Repeat("x", MaxHashLen+1), strings.Repeat("x", MaxHashLen+1)) {
		t.Fatal("oversized hash matched")
	}
}

func TestSessionValidityAndBounds(t *testing.T) {
	now := fixedNow()
	valid := Session{
		SessionID:      "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		PrincipalID:    "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
		CreatedAt:      now,
		ExpiresAt:      now.Add(time.Hour),
		PrincipalState: PrincipalActive,
	}
	if !valid.Valid(now) {
		t.Fatal("active unrevoked session judged invalid")
	}
	revoked := valid
	revoked.RevokedAt = now.Add(-time.Minute)
	if revoked.Valid(now) {
		t.Fatal("revoked session judged valid")
	}
	expired := valid
	expired.ExpiresAt = now.Add(-time.Second)
	if expired.Valid(now) {
		t.Fatal("expired session judged valid")
	}
	pending := valid
	pending.PrincipalState = PrincipalPending
	if pending.Valid(now) {
		t.Fatal("pending principal session judged valid")
	}
	disabled := valid
	disabled.PrincipalState = PrincipalDisabled
	if disabled.Valid(now) {
		t.Fatal("disabled principal session judged valid")
	}
	bare := Session{}
	if bare.Valid(now) {
		t.Fatal("empty session judged valid")
	}

	if err := ValidateSessionTTL(now, now.Add(MaxSessionTTL)); err != nil {
		t.Fatalf("exact max session TTL rejected: %v", err)
	}
	if err := ValidateSessionTTL(now, now.Add(MaxSessionTTL+time.Hour)); err == nil {
		t.Fatal("over-max session TTL accepted")
	}
	if err := ValidateSessionTTL(now, now.Add(-time.Minute)); err == nil {
		t.Fatal("past expiry accepted")
	}
	if err := ValidateVerificationTTL(now, now.Add(MaxVerificationTTL+time.Hour)); err == nil {
		t.Fatal("over-max verification TTL accepted")
	}
	if err := ValidateVerificationTTL(now, now.Add(time.Minute)); err == nil {
		t.Fatal("under-min verification TTL accepted")
	}
}
