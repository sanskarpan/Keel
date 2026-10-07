// Package contextvault encrypts sensitive inference context before durable storage.
// It deliberately contains no storage, key-provider, replay, or telemetry adapter.
package contextvault

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

const Algorithm = "AES-256-GCM"

// MaxPlaintextBytes bounds one encrypted context record to 1 MiB.
const MaxPlaintextBytes = 1 << 20

const (
	maxWrappedKeyBytes = 8192
	maxKeyIDBytes      = 128
	dataKeyBytes       = 32
)

var (
	ErrInvalidInput   = errors.New("invalid context-vault input")
	ErrKeyUnavailable = errors.New("context-vault key unavailable")
	ErrAuthentication = errors.New("context-vault authentication failed")

	keyIDPattern        = regexp.MustCompile(`^[A-Za-z0-9._:/-]{1,128}$`)
	uuidPattern         = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	policyDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// KeyWrapper delegates data-key protection to a KMS or HSM implementation.
// Implementations must authenticate every KeyBinding attribute and must never log key material.
type KeyWrapper interface {
	WrapKey(context.Context, KeyBinding, []byte) ([]byte, error)
	UnwrapKey(context.Context, KeyBinding, []byte) ([]byte, error)
}

// KeyBinding is the canonical record context a KMS/HSM must authenticate when wrapping
// a data key. Its fields are private so adapters receive only validated scope values.
type KeyBinding struct {
	tenantID     string
	recordID     string
	version      uint64
	policyDigest string
	keyID        string
}

// TenantID returns the canonical tenant UUID for provider encryption context.
func (b KeyBinding) TenantID() string { return b.tenantID }

// RecordID returns the canonical record UUID for provider encryption context.
func (b KeyBinding) RecordID() string { return b.recordID }

// Version returns the immutable record version for provider encryption context.
func (b KeyBinding) Version() uint64 { return b.version }

// PolicyDigest returns the bound policy digest for provider encryption context.
func (b KeyBinding) PolicyDigest() string { return b.policyDigest }

// KeyID returns the configured KMS/HSM key identifier for provider encryption context.
func (b KeyBinding) KeyID() string { return b.keyID }

// EncryptionContext returns provider-safe string attributes for authenticated key wrapping.
func (b KeyBinding) EncryptionContext() map[string]string {
	return map[string]string{
		"keel:binding_version": "1",
		"keel:tenant_id":       b.tenantID,
		"keel:record_id":       b.recordID,
		"keel:version":         fmt.Sprintf("%d", b.version),
		"keel:policy_digest":   b.policyDigest,
		"keel:key_id":          b.keyID,
	}
}

// KeyBinding validates and canonicalizes the immutable scope for provider-side DEK binding.
func (scope Scope) KeyBinding(keyID string) (KeyBinding, error) {
	if _, err := validateScope(scope, keyID); err != nil {
		return KeyBinding{}, err
	}
	return KeyBinding{
		tenantID: strings.ToLower(scope.TenantID), recordID: strings.ToLower(scope.RecordID),
		version: scope.Version, policyDigest: scope.PolicyDigest, keyID: keyID,
	}, nil
}

// Scope is authenticated alongside the ciphertext and cannot be changed at read time.
type Scope struct {
	TenantID     string
	RecordID     string
	Version      uint64
	PolicyDigest string
}

// Envelope contains only ciphertext and a wrapped per-record data key.
type Envelope struct {
	Algorithm  string `json:"algorithm"`
	KeyID      string `json:"key_id"`
	WrappedDEK []byte `json:"wrapped_dek"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

// Encrypt creates a fresh data key for one record and authenticates its immutable scope.
func Encrypt(ctx context.Context, wrapper KeyWrapper, keyID string, scope Scope, plaintext []byte) (Envelope, error) {
	aad, err := validateScope(scope, keyID)
	if err != nil || wrapper == nil || ctx == nil || len(plaintext) > MaxPlaintextBytes {
		return Envelope{}, ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return Envelope{}, err
	}
	dek := make([]byte, dataKeyBytes)
	defer wipe(dek)
	if _, err := rand.Read(dek); err != nil {
		return Envelope{}, ErrKeyUnavailable
	}
	binding, err := scope.KeyBinding(keyID)
	if err != nil {
		return Envelope{}, ErrInvalidInput
	}
	wrapped, err := wrapper.WrapKey(ctx, binding, dek)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return Envelope{}, ctxErr
		}
		return Envelope{}, ErrKeyUnavailable
	}
	if len(wrapped) == 0 || len(wrapped) > maxWrappedKeyBytes || bytes.Equal(wrapped, dek) {
		return Envelope{}, ErrKeyUnavailable
	}
	block, err := aes.NewCipher(dek)
	if err != nil {
		return Envelope{}, ErrInvalidInput
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return Envelope{}, ErrInvalidInput
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return Envelope{}, ErrKeyUnavailable
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, aad)
	return Envelope{Algorithm: Algorithm, KeyID: keyID, WrappedDEK: wrapped, Nonce: nonce, Ciphertext: ciphertext}, nil
}

// Decrypt authenticates the caller's requested scope before returning plaintext.
func Decrypt(ctx context.Context, wrapper KeyWrapper, scope Scope, envelope Envelope) ([]byte, error) {
	aad, err := validateEnvelope(scope, envelope)
	if err != nil || wrapper == nil || ctx == nil {
		return nil, ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	binding, err := scope.KeyBinding(envelope.KeyID)
	if err != nil {
		return nil, ErrInvalidInput
	}
	dek, err := wrapper.UnwrapKey(ctx, binding, envelope.WrappedDEK)
	if err != nil {
		wipe(dek)
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, ErrKeyUnavailable
	}
	if len(dek) != dataKeyBytes {
		wipe(dek)
		return nil, ErrKeyUnavailable
	}
	defer wipe(dek)
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, ErrInvalidInput
	}
	aead, err := cipher.NewGCM(block)
	if err != nil || len(envelope.Nonce) != aead.NonceSize() {
		return nil, ErrInvalidInput
	}
	plaintext, err := aead.Open(nil, envelope.Nonce, envelope.Ciphertext, aad)
	if err != nil {
		return nil, ErrAuthentication
	}
	return plaintext, nil
}

// ValidateEnvelope checks the bounded ciphertext shape and scope binding without unwrapping
// the data key. Storage adapters use it before persisting an envelope.
func ValidateEnvelope(scope Scope, envelope Envelope) error {
	_, err := validateEnvelope(scope, envelope)
	return err
}

func validateEnvelope(scope Scope, envelope Envelope) ([]byte, error) {
	aad, err := validateScope(scope, envelope.KeyID)
	if err != nil || envelope.Algorithm != Algorithm || len(envelope.WrappedDEK) == 0 ||
		len(envelope.WrappedDEK) > maxWrappedKeyBytes || len(envelope.Nonce) != 12 ||
		len(envelope.Ciphertext) < 16 || len(envelope.Ciphertext) > MaxPlaintextBytes+16 {
		return nil, ErrInvalidInput
	}
	return aad, nil
}

func validateScope(scope Scope, keyID string) ([]byte, error) {
	if !uuidPattern.MatchString(scope.TenantID) || !uuidPattern.MatchString(scope.RecordID) ||
		isNilUUID(scope.TenantID) || isNilUUID(scope.RecordID) || scope.Version == 0 ||
		!policyDigestPattern.MatchString(scope.PolicyDigest) || !keyIDPattern.MatchString(keyID) ||
		len(keyID) > maxKeyIDBytes {
		return nil, ErrInvalidInput
	}
	scope.TenantID = strings.ToLower(scope.TenantID)
	scope.RecordID = strings.ToLower(scope.RecordID)
	return []byte(fmt.Sprintf("keel-context-v1\x00%s\x00%s\x00%d\x00%s\x00%s", scope.TenantID, scope.RecordID, scope.Version, scope.PolicyDigest, keyID)), nil
}

func isNilUUID(value string) bool {
	return strings.ReplaceAll(value, "-", "") == "00000000000000000000000000000000"
}

func wipe(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
