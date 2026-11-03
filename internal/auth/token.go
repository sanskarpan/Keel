// Package auth implements the K8.11 identity slices: first-party principals,
// verified email, session lifecycle, and password recovery with rotation. This
// file owns the purpose-separated opaque token scheme and peppered email
// digests. Callers persist only digests; the original secret is shown to its
// recipient exactly once.
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"io"
	"net/mail"
	"strings"
)

const (
	// TokenBytes is the entropy width of every identity secret, matching the
	// supplier capability precedent.
	TokenBytes = 32
	// MinPepperBytes matches the intake RecipientDigest precedent: a database
	// snapshot must not be dictionary-attackable without a separately held pepper.
	MinPepperBytes = 32
)

// Token purposes are an allowlist with a version suffix, separated from the secret
// by a zero byte so a digest for one purpose can never verify as another.
const (
	PurposeSession            = "identity-session-v1"
	PurposeEmailVerification  = "identity-email-verification-v1"
	PurposePasswordReset      = "identity-password-reset-v1"
	PurposeOrganizationInvite = "identity-organization-invite-v1"
)

var (
	// ErrInvalidToken reports malformed secret material for any purpose.
	ErrInvalidToken = errors.New("identity token is invalid")
	// ErrInvalidEmail reports an email address that fails canonical validation.
	ErrInvalidEmail = errors.New("email address is invalid")
	// ErrInvalidPepper reports a pepper shorter than MinPepperBytes or empty.
	ErrInvalidPepper = errors.New("identity pepper is invalid")
)

// NewSecret returns 256 bits of URL-safe opaque bearer material.
func NewSecret(source io.Reader) (string, error) {
	if source == nil {
		source = rand.Reader
	}
	secret := make([]byte, TokenBytes)
	if _, err := io.ReadFull(source, secret); err != nil {
		return "", errors.New("secure token generation failed")
	}
	return base64.RawURLEncoding.EncodeToString(secret), nil
}

// TokenDigest binds one allowed purpose to one well-formed secret.
func TokenDigest(secret, purpose string) ([sha256.Size]byte, error) {
	if purpose != PurposeSession && purpose != PurposeEmailVerification && purpose != PurposePasswordReset &&
		purpose != PurposeOrganizationInvite {
		return [sha256.Size]byte{}, ErrInvalidToken
	}
	decoded, err := base64.RawURLEncoding.DecodeString(secret)
	if err != nil || len(decoded) != TokenBytes {
		return [sha256.Size]byte{}, ErrInvalidToken
	}
	return sha256.Sum256([]byte(purpose + "\x00" + secret)), nil
}

// CanonicalizeEmail validates an address and returns the lowercased, trimmed
// form used for digesting, so case or spacing differences converge on one
// principal. Only pre-hash material changes; the raw address is never stored.
func CanonicalizeEmail(address string) (string, error) {
	trimmed := strings.TrimSpace(address)
	if trimmed == "" || len(trimmed) > 254 || strings.Count(trimmed, "@") != 1 {
		return "", ErrInvalidEmail
	}
	parsed, err := mail.ParseAddress(trimmed)
	if err != nil || parsed.Name != "" || strings.ContainsAny(parsed.Address, " \t\r\n") {
		return "", ErrInvalidEmail
	}
	canonical := strings.ToLower(parsed.Address)
	if canonical != trimmed {
		return "", ErrInvalidEmail
	}
	local, domain, ok := strings.Cut(canonical, "@")
	if !ok || local == "" || local == "." || strings.HasPrefix(local, ".") ||
		strings.HasSuffix(local, ".") || strings.Contains(local, "..") ||
		len(local) > 64 || domain == "" || domain == "." ||
		strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") ||
		strings.Contains(domain, "..") || len(domain) > 253 {
		return "", ErrInvalidEmail
	}
	return canonical, nil
}

// EmailDigest returns a peppered HMAC digest of the canonical address. The pepper
// must be at least MinPepperBytes; the raw address is never stored or returned.
func EmailDigest(address string, pepper []byte) ([sha256.Size]byte, error) {
	if len(pepper) < MinPepperBytes {
		return [sha256.Size]byte{}, ErrInvalidPepper
	}
	canonical, err := CanonicalizeEmail(address)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	mac := hmac.New(sha256.New, pepper)
	_, _ = mac.Write([]byte("identity-email-v1\x00" + canonical))
	var out [sha256.Size]byte
	copy(out[:], mac.Sum(nil))
	return out, nil
}

// DigestMatches compares two digests in constant time.
func DigestMatches(a, b []byte) bool {
	if len(a) != sha256.Size || len(b) != sha256.Size {
		return false
	}
	return subtle.ConstantTimeCompare(a, b) == 1
}
