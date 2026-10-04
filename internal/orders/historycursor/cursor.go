// Package historycursor issues opaque, authenticated continuation tokens for order history.
package historycursor

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

const (
	defaultLifetime = 7 * 24 * time.Hour
	maxTokenLength  = 2048
)

var keyIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,32}$`)

type payload struct {
	Version     int    `json:"v"`
	TenantID    string `json:"t"`
	OrderID     string `json:"o"`
	Before      uint64 `json:"b"`
	Limit       int    `json:"l"`
	ExpiresUnix int64  `json:"e"`
}

// Codec encrypts cursor claims so tenant and order identifiers are not exposed in URLs.
// Retain old key IDs for at least defaultLifetime during secret rotation.
type Codec struct {
	activeKeyID string
	keys        map[string][]byte
	newReader   io.Reader
	now         func() time.Time
}

func New(activeKeyID string, keys map[string][]byte) (*Codec, error) {
	if !keyIDPattern.MatchString(activeKeyID) {
		return nil, errors.New("active history cursor key ID is invalid")
	}
	cloned := make(map[string][]byte, len(keys))
	for id, key := range keys {
		if !keyIDPattern.MatchString(id) || len(key) != 32 {
			return nil, fmt.Errorf("history cursor key %q must have a valid ID and 32-byte AES-256 material", id)
		}
		cloned[id] = append([]byte(nil), key...)
	}
	if _, ok := cloned[activeKeyID]; !ok {
		return nil, errors.New("active history cursor key is missing")
	}
	return &Codec{activeKeyID: activeKeyID, keys: cloned, newReader: rand.Reader, now: time.Now}, nil
}

func (c *Codec) Encode(tenantID, orderID string, before uint64, limit int) (string, error) {
	if c == nil || before < 2 || limit < 1 || limit > 100 {
		return "", errors.New("history cursor claims are invalid")
	}
	tenant, err := tenancy.ParseTenantID(tenantID)
	if err != nil {
		return "", errors.New("history cursor tenant scope is invalid")
	}
	order, err := tenancy.ParseTenantID(orderID)
	if err != nil {
		return "", errors.New("history cursor order scope is invalid")
	}
	claims := payload{Version: 1, TenantID: strings.ToLower(string(tenant)), OrderID: strings.ToLower(string(order)), Before: before, Limit: limit, ExpiresUnix: c.now().Add(defaultLifetime).Unix()}
	plain, err := json.Marshal(claims)
	if err != nil {
		return "", errors.New("history cursor encoding failed")
	}
	block, err := aes.NewCipher(c.keys[c.activeKeyID])
	if err != nil {
		return "", errors.New("history cursor encryption is unavailable")
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", errors.New("history cursor encryption is unavailable")
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(c.newReader, nonce); err != nil {
		return "", errors.New("history cursor randomness is unavailable")
	}
	ciphertext := aead.Seal(nil, nonce, plain, []byte("keel-order-history-cursor:v1"))
	token := c.activeKeyID + "." + base64.RawURLEncoding.EncodeToString(nonce) + "." + base64.RawURLEncoding.EncodeToString(ciphertext)
	if len(token) > maxTokenLength {
		return "", errors.New("history cursor exceeded its size limit")
	}
	return token, nil
}

func (c *Codec) Decode(token, tenantID, orderID string, limit int) (uint64, error) {
	if c == nil || len(token) == 0 || len(token) > maxTokenLength || limit < 1 || limit > 100 {
		return 0, errors.New("history cursor is invalid")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || !keyIDPattern.MatchString(parts[0]) {
		return 0, errors.New("history cursor is invalid")
	}
	key, ok := c.keys[parts[0]]
	if !ok {
		return 0, errors.New("history cursor is invalid")
	}
	nonce, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return 0, errors.New("history cursor is invalid")
	}
	ciphertext, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return 0, errors.New("history cursor is invalid")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return 0, errors.New("history cursor is invalid")
	}
	aead, err := cipher.NewGCM(block)
	if err != nil || len(nonce) != aead.NonceSize() {
		return 0, errors.New("history cursor is invalid")
	}
	plain, err := aead.Open(nil, nonce, ciphertext, []byte("keel-order-history-cursor:v1"))
	if err != nil {
		return 0, errors.New("history cursor is invalid")
	}
	var claims payload
	decoder := json.NewDecoder(strings.NewReader(string(plain)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&claims); err != nil || claims.Version != 1 || claims.Before < 2 || claims.Limit != limit || claims.ExpiresUnix <= c.now().Unix() {
		return 0, errors.New("history cursor is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return 0, errors.New("history cursor is invalid")
	}
	tenant, err := tenancy.ParseTenantID(tenantID)
	if err != nil {
		return 0, errors.New("history cursor is invalid")
	}
	order, err := tenancy.ParseTenantID(orderID)
	if err != nil || claims.TenantID != strings.ToLower(string(tenant)) || claims.OrderID != strings.ToLower(string(order)) {
		return 0, errors.New("history cursor is invalid")
	}
	return claims.Before, nil
}
