package webhook

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
)

// MaxKeyFileBytes bounds the signing-key file one process may load. The file carries at most
// two secrets, so the bound exists only to keep startup work finite.
const MaxKeyFileBytes = 64 << 10

// keyFileEntry is one named secret in a signing-key file. The secret is base64-encoded so the
// file stays valid JSON/YAML-adjacent text.
type keyFileEntry struct {
	ID        string `json:"id"`
	SecretB64 string `json:"secret_b64"`
}

// keyFile is the signing-key file shape: one active key plus at most one previous key for
// rotation overlap. Unknown fields are rejected so a misspelled file cannot silently drop a
// key.
type keyFile struct {
	Active   keyFileEntry  `json:"active"`
	Previous *keyFileEntry `json:"previous"`
}

// LoadKeyringFromFile builds a signing keyring from a JSON key file instead of environment
// secrets. File delivery is how container platforms mount secrets; the signing semantics are
// identical to the environment path. An empty path is rejected so callers must choose one
// source explicitly.
func LoadKeyringFromFile(path string) (*Keyring, error) {
	if path == "" {
		return nil, ErrInvalidKeyring
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, ErrInvalidKeyring
	}
	if info.IsDir() || info.Size() <= 0 || info.Size() > MaxKeyFileBytes {
		return nil, ErrInvalidKeyring
	}
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) == 0 || int64(len(raw)) > MaxKeyFileBytes {
		return nil, ErrInvalidKeyring
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var file keyFile
	if err := decoder.Decode(&file); err != nil {
		return nil, ErrInvalidKeyring
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return nil, ErrInvalidKeyring
	}
	active, err := fileKey(file.Active)
	if err != nil {
		return nil, err
	}
	var previous *Key
	if file.Previous != nil {
		key, err := fileKey(*file.Previous)
		if err != nil {
			return nil, err
		}
		previous = &key
	}
	return NewKeyring(active, previous)
}

func fileKey(entry keyFileEntry) (Key, error) {
	if !keyIDPattern.MatchString(entry.ID) {
		return Key{}, ErrInvalidKeyring
	}
	secret, err := base64.StdEncoding.DecodeString(entry.SecretB64)
	if err != nil || len(secret) < MinSecretBytes {
		return Key{}, ErrInvalidKeyring
	}
	return Key{ID: entry.ID, Secret: secret}, nil
}
