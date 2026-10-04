package intake

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"
)

const (
	testTenantID = "11111111-1111-4111-8111-111111111111"
	testInviteID = "22222222-2222-4222-8222-222222222222"
	testUploadID = "33333333-3333-4333-8333-333333333333"
)

func TestOpaqueSupplierTokensAreHighEntropyAndPurposeSeparated(t *testing.T) {
	one, err := NewSecret(nil)
	if err != nil {
		t.Fatal(err)
	}
	two, err := NewSecret(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(one) != 43 || one == two {
		t.Fatalf("opaque token length/uniqueness invalid: length=%d equal=%v", len(one), one == two)
	}
	inviteDigest, err := TokenDigest(one, "supplier-invitation-v1")
	if err != nil {
		t.Fatal(err)
	}
	sessionDigest, err := TokenDigest(one, "supplier-upload-session-v1")
	if err != nil {
		t.Fatal(err)
	}
	if inviteDigest == sessionDigest || inviteDigest == sha256.Sum256([]byte(one)) {
		t.Fatal("purpose-specific token digests were not domain separated")
	}
	if _, err := TokenDigest("not-a-token", "supplier-invitation-v1"); err == nil {
		t.Fatal("malformed bearer token was accepted")
	}
}

func TestUploadCapabilityBindsTenantObjectChecksumAndExpiry(t *testing.T) {
	key := []byte(strings.Repeat("k", 32))
	data := []byte("safe evidence")
	digest := sha256.Sum256(data)
	metadata := UploadMetadata{Filename: "evidence.txt", ContentType: string(FormatText), Size: int64(len(data)), SHA256: hex.EncodeToString(digest[:])}
	now := time.Date(2026, 10, 4, 20, 0, 0, 0, time.UTC)
	claims := UploadCapability{TenantID: testTenantID, InviteID: testInviteID, UploadID: testUploadID, Size: metadata.Size, SHA256: metadata.SHA256, ExpiresAt: now.Add(10 * time.Minute), Purpose: "supplier-upload-v1"}
	token, err := SignUploadCapability(claims, key)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyUploadCapability(token, key, now, testTenantID, testUploadID, metadata)
	if err != nil || verified.InviteID != testInviteID {
		t.Fatalf("valid upload capability rejected: %+v %v", verified, err)
	}
	for name, verify := range map[string]func() error{
		"tenant substitution": func() error {
			_, err := VerifyUploadCapability(token, key, now, testInviteID, testUploadID, metadata)
			return err
		},
		"object substitution": func() error {
			_, err := VerifyUploadCapability(token, key, now, testTenantID, testInviteID, metadata)
			return err
		},
		"checksum substitution": func() error {
			altered := metadata
			altered.SHA256 = strings.Repeat("0", 64)
			_, err := VerifyUploadCapability(token, key, now, testTenantID, testUploadID, altered)
			return err
		},
		"expiry": func() error {
			_, err := VerifyUploadCapability(token, key, now.Add(11*time.Minute), testTenantID, testUploadID, metadata)
			return err
		},
		"forged signature": func() error {
			_, err := VerifyUploadCapability(token+"a", key, now, testTenantID, testUploadID, metadata)
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := verify(); !errors.Is(err, ErrInvalidCapability) {
				t.Fatalf("error=%v, want invalid capability", err)
			}
		})
	}
}

func TestUploadCapabilityRejectsLongTTLAndWeakSigningKey(t *testing.T) {
	now := time.Date(2026, 10, 4, 20, 0, 0, 0, time.UTC)
	key := []byte(strings.Repeat("x", 32))
	claims := UploadCapability{TenantID: testTenantID, InviteID: testInviteID, UploadID: testUploadID, Size: 1, SHA256: strings.Repeat("a", 64), ExpiresAt: now.Add(16 * time.Minute), Purpose: "supplier-upload-v1"}
	token, err := SignUploadCapability(claims, key)
	if err != nil {
		t.Fatal(err)
	}
	metadata := UploadMetadata{Filename: "x.txt", ContentType: string(FormatText), Size: 1, SHA256: strings.Repeat("a", 64)}
	if _, err := VerifyUploadCapability(token, key, now, testTenantID, testUploadID, metadata); !errors.Is(err, ErrInvalidCapability) {
		t.Fatalf("long-lived upload capability error=%v", err)
	}
	if _, err := VerifyUploadCapability("x.y", []byte("short"), time.Now(), testTenantID, testUploadID, metadata); !errors.Is(err, ErrInvalidCapability) {
		t.Fatalf("weak key error=%v", err)
	}
}
