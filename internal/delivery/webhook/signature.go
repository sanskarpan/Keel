// Package webhook prepares outbound webhook attempts: a stable logical delivery identity, the
// versioned signature and key rotation, and an SSRF-safe egress client.
//
// The package performs no delivery, retry or persistence. It fixes the wire contract so a later
// delivery worker cannot choose a weaker signature, a mutable delivery identity or an unchecked
// destination under pressure.
package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// DefaultTimestampTolerance is the accepted distance between a signature timestamp and the
// verifier clock. A receiver should configure the same value documented for its integration.
const DefaultTimestampTolerance = 5 * time.Minute

// MinSecretBytes is the shortest accepted HMAC secret.
const MinSecretBytes = 32

var (
	// ErrInvalidKeyring means the active or previous key is malformed.
	ErrInvalidKeyring = errors.New("webhook keyring is invalid")
	// ErrInvalidSignature means a signature header cannot be parsed.
	ErrInvalidSignature = errors.New("webhook signature header is invalid")
	// ErrUnknownKey means the signature names a key this keyring does not hold.
	ErrUnknownKey = errors.New("webhook signature key is unknown")
	// ErrSignatureMismatch means the HMAC does not cover the presented body.
	ErrSignatureMismatch = errors.New("webhook signature does not match the payload")
	// ErrTimestampSkew means the signature timestamp is outside the accepted window.
	ErrTimestampSkew = errors.New("webhook signature timestamp is outside the accepted window")
)

var (
	keyIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{4,64}$`)
	macPattern   = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Key is one HMAC-SHA256 signing secret identified by a stable key ID. The ID is published in the
// signature header so a receiver can select the matching secret during rotation.
type Key struct {
	ID     string
	Secret []byte
}

func (k Key) validate() error {
	if !keyIDPattern.MatchString(k.ID) {
		return ErrInvalidKeyring
	}
	if len(k.Secret) < MinSecretBytes {
		return ErrInvalidKeyring
	}
	return nil
}

// Keyring signs with one active key and verifies with the active key plus at most one previous
// key. The overlap lets a receiver rotate its secret without rejecting in-flight signatures.
type Keyring struct {
	active      Key
	previous    Key
	hasPrevious bool
	tolerance   time.Duration
}

// NewKeyring creates a keyring with one active key and the default timestamp tolerance.
// A nil previous key means no rotation overlap is configured.
func NewKeyring(active Key, previous *Key) (*Keyring, error) {
	return NewKeyringWithTolerance(active, previous, DefaultTimestampTolerance)
}

// NewKeyringWithTolerance is NewKeyring with an explicit timestamp tolerance. A non-positive
// tolerance is rejected so a verifier cannot accidentally accept every timestamp.
func NewKeyringWithTolerance(active Key, previous *Key, tolerance time.Duration) (*Keyring, error) {
	if err := active.validate(); err != nil {
		return nil, err
	}
	if active.Secret == nil {
		return nil, ErrInvalidKeyring
	}
	ring := &Keyring{active: Key{ID: active.ID, Secret: cloneSecret(active.Secret)}, tolerance: tolerance}
	if tolerance <= 0 {
		return nil, ErrInvalidKeyring
	}
	if previous != nil {
		if err := previous.validate(); err != nil || previous.ID == active.ID {
			return nil, ErrInvalidKeyring
		}
		ring.previous = Key{ID: previous.ID, Secret: cloneSecret(previous.Secret)}
		ring.hasPrevious = true
	}
	return ring, nil
}

// ActiveKeyID reports the key ID new signatures use.
func (k *Keyring) ActiveKeyID() string {
	if k == nil {
		return ""
	}
	return k.active.ID
}

// HasKey reports whether the keyring holds a key reference. The operator API uses it for
// replay-candidate readiness without signing anything.
func (k *Keyring) HasKey(keyID string) bool {
	if k == nil {
		return false
	}
	_, ok := k.keyFor(keyID)
	return ok
}

// Rotated returns a keyring whose active key is next and whose only previous key is the current
// active key. The receiver keeps verifying old signatures for one overlap window.
func (k *Keyring) Rotated(next Key) (*Keyring, error) {
	if k == nil {
		return nil, ErrInvalidKeyring
	}
	if err := next.validate(); err != nil {
		return nil, err
	}
	if next.ID == k.active.ID {
		return nil, ErrInvalidKeyring
	}
	return NewKeyringWithTolerance(next, &k.active, k.tolerance)
}

// Signature is the parsed wire signature header.
type Signature struct {
	Timestamp int64
	KeyID     string
	MAC       string
}

// String renders t=<unix>,kid=<id>,v1=<hex>.
func (s Signature) String() string {
	return "t=" + strconv.FormatInt(s.Timestamp, 10) + ",kid=" + s.KeyID + ",v1=" + s.MAC
}

// ParseSignature parses the signature header strictly. Unknown, reordered or duplicated parts are
// rejected so an intermediary cannot smuggle a second interpretation of the header.
func ParseSignature(value string) (Signature, error) {
	parts := strings.Split(value, ",")
	if len(parts) != 3 {
		return Signature{}, ErrInvalidSignature
	}
	if !strings.HasPrefix(parts[0], "t=") || !strings.HasPrefix(parts[1], "kid=") || !strings.HasPrefix(parts[2], "v1=") {
		return Signature{}, ErrInvalidSignature
	}
	rawTimestamp := strings.TrimPrefix(parts[0], "t=")
	for _, r := range rawTimestamp {
		if r < '0' || r > '9' {
			return Signature{}, ErrInvalidSignature
		}
	}
	timestamp, err := strconv.ParseInt(rawTimestamp, 10, 64)
	if err != nil || timestamp <= 0 {
		return Signature{}, ErrInvalidSignature
	}
	keyID := strings.TrimPrefix(parts[1], "kid=")
	if !keyIDPattern.MatchString(keyID) {
		return Signature{}, ErrInvalidSignature
	}
	mac := strings.TrimPrefix(parts[2], "v1=")
	if !macPattern.MatchString(mac) {
		return Signature{}, ErrInvalidSignature
	}
	return Signature{Timestamp: timestamp, KeyID: keyID, MAC: mac}, nil
}

// Sign computes the HMAC-SHA256 over the decimal timestamp, a dot, and the exact body bytes.
func (k *Keyring) Sign(timestamp time.Time, body []byte) (Signature, error) {
	if k == nil {
		return Signature{}, ErrInvalidKeyring
	}
	seconds := timestamp.UTC().Unix()
	if seconds <= 0 {
		return Signature{}, ErrInvalidSignature
	}
	return Signature{
		Timestamp: seconds,
		KeyID:     k.active.ID,
		MAC:       hex.EncodeToString(macFor(k.active.Secret, seconds, body)),
	}, nil
}

// Verify checks that the signature names a held key, covers the exact body, and is inside the
// timestamp tolerance. Signature comparison is constant time.
func (k *Keyring) Verify(signature Signature, body []byte, now time.Time) error {
	if k == nil {
		return ErrInvalidKeyring
	}
	key, ok := k.keyFor(signature.KeyID)
	if !ok {
		return ErrUnknownKey
	}
	if signature.Timestamp <= 0 {
		return ErrInvalidSignature
	}
	skew := now.UTC().Unix() - signature.Timestamp
	if skew < 0 {
		skew = -skew
	}
	if time.Duration(skew)*time.Second > k.tolerance {
		return ErrTimestampSkew
	}
	expected := macFor(key.Secret, signature.Timestamp, body)
	presented, err := hex.DecodeString(signature.MAC)
	if err != nil {
		return ErrInvalidSignature
	}
	if subtle.ConstantTimeCompare(expected, presented) != 1 {
		return ErrSignatureMismatch
	}
	return nil
}

func (k *Keyring) keyFor(keyID string) (Key, bool) {
	if keyID == k.active.ID {
		return k.active, true
	}
	if k.hasPrevious && keyID == k.previous.ID {
		return k.previous, true
	}
	return Key{}, false
}

func macFor(secret []byte, timestamp int64, body []byte) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(strconv.FormatInt(timestamp, 10)))
	mac.Write([]byte("."))
	mac.Write(body)
	return mac.Sum(nil)
}

func cloneSecret(secret []byte) []byte {
	cloned := make([]byte, len(secret))
	copy(cloned, secret)
	return cloned
}
