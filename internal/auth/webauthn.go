package auth

import (
	"errors"
	"time"
)

// WebAuthn challenge purposes. Registration binds a new credential after a
// registration ceremony; authentication challenges gate assertions. A
// challenge for one purpose never satisfies the other.
const (
	PurposeWebAuthnRegistration   = "identity-webauthn-registration-v1"
	PurposeWebAuthnAuthentication = "identity-webauthn-authentication-v1"
)

// WebAuthn bounds. Challenges are interactive ceremony nonces with a short
// window; credential IDs follow the WebAuthn 1023-byte ceiling with one byte
// of headroom accounting, and public keys carry a COSE envelope cap.
const (
	WebAuthnChallengeBytes  = 32
	MinWebAuthnChallengeTTL = time.Minute
	MaxWebAuthnChallengeTTL = 10 * time.Minute
	MinCredentialIDBytes    = 1
	MaxCredentialIDBytes    = 1024
	MinPublicKeyBytes       = 1
	MaxPublicKeyBytes       = 2048
	MaxTransports           = 5
	MaxTransportLen         = 16
)

var (
	// ErrInvalidChallenge reports malformed challenge material.
	ErrInvalidChallenge = errors.New("identity challenge is invalid")
	// ErrInvalidCredential reports a malformed credential field.
	ErrInvalidCredential = errors.New("identity credential is invalid")
)

// webAuthnTransports is the allowlist of authenticator transport tokens.
var webAuthnTransports = map[string]bool{
	"usb": true, "nfc": true, "ble": true, "hybrid": true, "internal": true,
}

// ValidateWebAuthnChallenge accepts one bounded ceremony window.
func ValidateWebAuthnChallengeTTL(now, expires time.Time) error {
	if expires.IsZero() || expires.Before(now.Add(MinWebAuthnChallengeTTL)) || expires.After(now.Add(MaxWebAuthnChallengeTTL)) {
		return ErrInvalidRecord
	}
	return nil
}

// ValidateChallengeBytes accepts one well-formed ceremony nonce.
func ValidateChallengeBytes(challenge []byte) error {
	if len(challenge) != WebAuthnChallengeBytes {
		return ErrInvalidChallenge
	}
	return nil
}

// ValidateCredentialID bounds a WebAuthn credential identifier.
func ValidateCredentialID(credentialID []byte) error {
	if len(credentialID) < MinCredentialIDBytes || len(credentialID) > MaxCredentialIDBytes {
		return ErrInvalidCredential
	}
	return nil
}

// ValidatePublicKey bounds a COSE credential public key envelope.
func ValidatePublicKey(publicKey []byte) error {
	if len(publicKey) < MinPublicKeyBytes || len(publicKey) > MaxPublicKeyBytes {
		return ErrInvalidCredential
	}
	return nil
}

// ValidateTransports accepts a comma-separated transport list drawn only from
// the allowlist. Empty means the authenticator reported no transports.
func ValidateTransports(transports string) error {
	if transports == "" {
		return nil
	}
	if len(transports) > MaxTransports*(MaxTransportLen+1) {
		return ErrInvalidCredential
	}
	seen := 0
	start := 0
	for i := 0; i <= len(transports); i++ {
		if i == len(transports) || transports[i] == ',' {
			token := transports[start:i]
			if len(token) < 1 || len(token) > MaxTransportLen || !webAuthnTransports[token] {
				return ErrInvalidCredential
			}
			seen++
			if seen > MaxTransports {
				return ErrInvalidCredential
			}
			start = i + 1
		}
	}
	return nil
}

// CheckSignCount judges a presented authenticator counter against the stored
// value. Advanced reports a strictly increasing counter; cloned reports a
// counter that did not advance while one was expected, which signals a
// cloned authenticator and must fail the ceremony closed. Authenticators
// without a counter report zero on both sides and carry no signal.
func CheckSignCount(stored, presented uint32) (advanced, cloned bool) {
	if stored == 0 && presented == 0 {
		return false, false
	}
	if presented > stored {
		return true, false
	}
	return false, true
}
