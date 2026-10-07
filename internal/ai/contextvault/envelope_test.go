package contextvault

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"strconv"
	"strings"
	"testing"
)

const testKeyID = "kms://keel-test/context-v1"

var testScope = Scope{
	TenantID:     "11111111-1111-4111-8111-111111111111",
	RecordID:     "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
	Version:      3,
	PolicyDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
}

type testKeyWrapper struct{ key []byte }

func (w testKeyWrapper) WrapKey(_ context.Context, binding KeyBinding, plaintext []byte) ([]byte, error) {
	if binding.KeyID() != testKeyID {
		return nil, errors.New("unexpected key ID")
	}
	block, err := aes.NewCipher(w.key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, plaintext, []byte(bindingContext(binding))), nil
}

func (w testKeyWrapper) UnwrapKey(_ context.Context, binding KeyBinding, wrapped []byte) ([]byte, error) {
	if binding.KeyID() != testKeyID || len(wrapped) < 12 {
		return nil, errors.New("unknown test key")
	}
	block, err := aes.NewCipher(w.key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, wrapped[:aead.NonceSize()], wrapped[aead.NonceSize():], []byte(bindingContext(binding)))
}

func bindingContext(binding KeyBinding) string {
	return strings.Join([]string{binding.TenantID(), binding.RecordID(),
		strconv.FormatUint(binding.Version(), 10), binding.PolicyDigest(), binding.KeyID()}, "\x00")
}

type cancelingKeyWrapper struct{ cancel context.CancelFunc }

func (w cancelingKeyWrapper) WrapKey(ctx context.Context, _ KeyBinding, _ []byte) ([]byte, error) {
	w.cancel()
	return nil, ctx.Err()
}

func (w cancelingKeyWrapper) UnwrapKey(ctx context.Context, _ KeyBinding, _ []byte) ([]byte, error) {
	w.cancel()
	return nil, ctx.Err()
}

func TestEnvelopeRoundTripUsesPerRecordCiphertext(t *testing.T) {
	wrapper := testKeyWrapper{key: []byte("0123456789abcdef0123456789abcdef")}
	plaintext := []byte("sensitive prompt and context")
	first, err := Encrypt(context.Background(), wrapper, testKeyID, testScope, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Encrypt(context.Background(), wrapper, testKeyID, testScope, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if string(first.Ciphertext) == string(plaintext) || string(first.Ciphertext) == string(second.Ciphertext) || string(first.WrappedDEK) == string(second.WrappedDEK) {
		t.Fatal("encryption reused plaintext or per-record key material")
	}
	decoded, err := Decrypt(context.Background(), wrapper, testScope, first)
	if err != nil || string(decoded) != string(plaintext) {
		t.Fatalf("decrypted=%q err=%v", decoded, err)
	}
}

func TestDecryptRejectsChangedAuthenticatedScopeAndCiphertext(t *testing.T) {
	wrapper := testKeyWrapper{key: []byte("0123456789abcdef0123456789abcdef")}
	envelope, err := Encrypt(context.Background(), wrapper, testKeyID, testScope, []byte("private"))
	if err != nil {
		t.Fatal(err)
	}
	for name, scope := range map[string]Scope{
		"tenant": func() Scope {
			changed := testScope
			changed.TenantID = "22222222-2222-4222-8222-222222222222"
			return changed
		}(),
		"record": func() Scope {
			changed := testScope
			changed.RecordID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
			return changed
		}(),
		"version": func() Scope { changed := testScope; changed.Version++; return changed }(),
		"policy": func() Scope {
			changed := testScope
			changed.PolicyDigest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
			return changed
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Decrypt(context.Background(), wrapper, scope, envelope); !errors.Is(err, ErrKeyUnavailable) {
				t.Fatalf("scope change error=%v, want provider binding failure", err)
			}
		})
	}
	changedKeyID := envelope
	changedKeyID.KeyID = "kms://keel-test/context-v2"
	if _, err := Decrypt(context.Background(), wrapper, testScope, changedKeyID); !errors.Is(err, ErrKeyUnavailable) {
		t.Fatalf("key ID change error=%v, want provider binding failure", err)
	}
	tampered := envelope
	tampered.Ciphertext = append([]byte(nil), envelope.Ciphertext...)
	tampered.Ciphertext[len(tampered.Ciphertext)-1] ^= 0xff
	if _, err := Decrypt(context.Background(), wrapper, testScope, tampered); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("ciphertext tamper error=%v, want authentication failure", err)
	}
}

func TestKeyBindingCanonicalizesAndRequiresCompleteScope(t *testing.T) {
	uppercase := testScope
	uppercase.TenantID = strings.ToUpper(uppercase.TenantID)
	uppercase.RecordID = strings.ToUpper(uppercase.RecordID)
	binding, err := uppercase.KeyBinding(testKeyID)
	if err != nil {
		t.Fatal(err)
	}
	if binding.TenantID() != strings.ToLower(testScope.TenantID) || binding.RecordID() != strings.ToLower(testScope.RecordID) {
		t.Fatalf("binding IDs are not canonical: tenant=%q record=%q", binding.TenantID(), binding.RecordID())
	}
	if got := binding.EncryptionContext(); got["keel:binding_version"] != "1" ||
		got["keel:tenant_id"] != strings.ToLower(testScope.TenantID) ||
		got["keel:record_id"] != strings.ToLower(testScope.RecordID) || got["keel:version"] != "3" ||
		got["keel:policy_digest"] != testScope.PolicyDigest || got["keel:key_id"] != testKeyID {
		t.Fatalf("provider encryption context is incomplete: %#v", got)
	}
	invalid := testScope
	invalid.PolicyDigest = ""
	if _, err := invalid.KeyBinding(testKeyID); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("invalid binding error=%v, want invalid input", err)
	}
}

func TestKeyWrapperCancellationPropagates(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	if _, err := Encrypt(ctx, cancelingKeyWrapper{cancel: cancel}, testKeyID, testScope, []byte("private")); !errors.Is(err, context.Canceled) {
		t.Fatalf("wrap cancellation error=%v, want context canceled", err)
	}

	wrapper := testKeyWrapper{key: []byte("0123456789abcdef0123456789abcdef")}
	envelope, err := Encrypt(context.Background(), wrapper, testKeyID, testScope, []byte("private"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	if _, err := Decrypt(ctx, cancelingKeyWrapper{cancel: cancel}, testScope, envelope); !errors.Is(err, context.Canceled) {
		t.Fatalf("unwrap cancellation error=%v, want context canceled", err)
	}
}

func TestEnvelopeValidationFailsBeforeKeyUse(t *testing.T) {
	wrapper := testKeyWrapper{key: []byte("0123456789abcdef0123456789abcdef")}
	if _, err := Encrypt(context.Background(), wrapper, testKeyID, testScope, make([]byte, MaxPlaintextBytes+1)); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("oversize plaintext error=%v", err)
	}
	if _, err := Encrypt(context.Background(), nil, testKeyID, testScope, []byte("private")); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("nil key wrapper error=%v", err)
	}
	for name, mutate := range map[string]func(*Envelope){
		"algorithm":   func(value *Envelope) { value.Algorithm = "AES-128-GCM" },
		"key id":      func(value *Envelope) { value.KeyID = "bad key id" },
		"wrapped key": func(value *Envelope) { value.WrappedDEK = nil },
		"nonce":       func(value *Envelope) { value.Nonce = value.Nonce[:len(value.Nonce)-1] },
		"ciphertext":  func(value *Envelope) { value.Ciphertext = value.Ciphertext[:4] },
	} {
		t.Run(name, func(t *testing.T) {
			envelope, err := Encrypt(context.Background(), wrapper, testKeyID, testScope, []byte("private"))
			if err != nil {
				t.Fatal(err)
			}
			mutate(&envelope)
			if _, err := Decrypt(context.Background(), wrapper, testScope, envelope); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("malformed envelope error=%v", err)
			}
		})
	}
}

func TestInvalidScopeIsRejected(t *testing.T) {
	wrapper := testKeyWrapper{key: []byte("0123456789abcdef0123456789abcdef")}
	invalid := testScope
	invalid.Version = 0
	if _, err := Encrypt(context.Background(), wrapper, testKeyID, invalid, []byte("private")); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("zero version error=%v", err)
	}
	if _, err := Encrypt(context.Background(), wrapper, "invalid key id", testScope, []byte("private")); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("invalid key ID error=%v", err)
	}
}
