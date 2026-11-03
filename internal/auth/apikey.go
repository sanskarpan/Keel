package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"time"
)

// API-key service principals. A service principal is a machine identity owned
// by one organization; each holds bearer keys shown exactly once. Keys carry
// a public prefix for log-safe identification and only a purpose-bound digest
// is stored. Rotation is issue-then-revoke (overlap supported); revocation is
// terminal. Expiry is optional per key and checked against the verifier's
// clock after the database read.
const (
	APIKeyPrefix      = "keel_"
	APIKeyPrefixLen   = 8
	APIKeySecretBytes = 32
	MinServiceNameLen = 1
	MaxServiceNameLen = 64
	// MinAPIKeySecretLen floors accepted secrets at 128 bits. Generated
	// secrets are 256-bit (43 chars); the floor keeps parsing strict.
	MinAPIKeySecretLen = 16
)

// MinAPIKeyTTL bounds caller-chosen expiries; zero expiry means no expiry.
const MinAPIKeyTTL = time.Hour

var (
	// ErrInvalidAPIKey reports malformed key material.
	ErrInvalidAPIKey = errors.New("identity API key is invalid")
	// ErrInvalidServicePrincipal reports a malformed service principal field.
	ErrInvalidServicePrincipal = errors.New("identity service principal is invalid")
)

// APIKeyPurpose binds digests so a key digest can never verify as any other
// identity token.
const PurposeAPIKey = "identity-api-key-v1"

// NewAPIKeySecret returns 256 bits of URL-safe bearer material for one key.
func NewAPIKeySecret() (secret string, prefix string, err error) {
	raw, err := NewSecret(nil)
	if err != nil {
		return "", "", err
	}
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil || len(decoded) != TokenBytes {
		return "", "", ErrInvalidAPIKey
	}
	return raw, raw[:APIKeyPrefixLen], nil
}

// FormatAPIKey renders the wire form: keel_ followed by the secret. The
// public prefix is the secret's leading APIKeyPrefixLen characters.
func FormatAPIKey(secret string) (string, error) {
	if len(secret) < MinAPIKeySecretLen || !isURLSafe(secret) {
		return "", ErrInvalidAPIKey
	}
	return APIKeyPrefix + secret, nil
}

// ParseAPIKey splits the wire form back into prefix and secret.
func ParseAPIKey(formatted string) (prefix, secret string, err error) {
	secret, ok := strings.CutPrefix(formatted, APIKeyPrefix)
	if !ok || len(secret) < MinAPIKeySecretLen || !isURLSafe(secret) {
		return "", "", ErrInvalidAPIKey
	}
	return secret[:APIKeyPrefixLen], secret, nil
}

// APIKeyDigest binds one secret to the API-key purpose.
func APIKeyDigest(secret string) ([sha256.Size]byte, error) {
	return TokenDigest(secret, PurposeAPIKey)
}

func isURLSafe(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' {
			continue
		}
		return false
	}
	return len(s) > 0
}

// ValidateServiceName bounds machine-identity display names.
func ValidateServiceName(name string) error {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" || len(trimmed) > MaxServiceNameLen || strings.ContainsAny(trimmed, "\r\n\x00") {
		return ErrInvalidServicePrincipal
	}
	return nil
}

// ValidateAPIKeyTTL accepts a caller-chosen expiry or the zero no-expiry.
func ValidateAPIKeyTTL(now, expires time.Time) error {
	if expires.IsZero() {
		return nil
	}
	if expires.Before(now.Add(MinAPIKeyTTL)) {
		return ErrInvalidRecord
	}
	return nil
}
