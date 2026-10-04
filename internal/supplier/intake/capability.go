package intake

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

const (
	TokenBytes             = 32
	MaxUploadCapabilityTTL = 15 * time.Minute
)

var (
	idPattern            = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	ErrInvalidCapability = errors.New("upload capability is invalid or expired")
	ErrInvalidInvitation = errors.New("supplier invitation is invalid or expired")
)

// NewSecret returns 256 bits of URL-safe opaque bearer material. Callers persist only
// TokenDigest(secret, purpose), and must show the original value once to its recipient.
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

func TokenDigest(secret, purpose string) ([sha256.Size]byte, error) {
	if purpose != "supplier-invitation-v1" && purpose != "supplier-upload-session-v1" {
		return [sha256.Size]byte{}, errors.New("token purpose is invalid")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(secret)
	if err != nil || len(decoded) != TokenBytes {
		return [sha256.Size]byte{}, errors.New("token is invalid")
	}
	return sha256.Sum256([]byte(purpose + "\x00" + secret)), nil
}

type UploadCapability struct {
	TenantID  string    `json:"tenant_id"`
	InviteID  string    `json:"invite_id"`
	UploadID  string    `json:"upload_id"`
	Size      int64     `json:"size"`
	SHA256    string    `json:"sha256"`
	ExpiresAt time.Time `json:"expires_at"`
	Purpose   string    `json:"purpose"`
}

func SignUploadCapability(claims UploadCapability, key []byte) (string, error) {
	if len(key) < 32 || !idPattern.MatchString(claims.TenantID) || !idPattern.MatchString(claims.InviteID) || !idPattern.MatchString(claims.UploadID) || claims.Purpose != "supplier-upload-v1" || claims.Size < 1 || claims.Size > MaxUploadBytes || len(claims.SHA256) != 64 || strings.ToLower(claims.SHA256) != claims.SHA256 || !isHex(claims.SHA256) {
		return "", errors.New("upload capability claims are invalid")
	}
	if claims.ExpiresAt.IsZero() {
		return "", errors.New("upload capability expiry is required")
	}
	claims.ExpiresAt = claims.ExpiresAt.UTC().Truncate(time.Second)
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", errors.New("upload capability could not be encoded")
	}
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(encoded))
	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return encoded + "." + signature, nil
}

func VerifyUploadCapability(token string, key []byte, now time.Time, tenantID, uploadID string, metadata UploadMetadata) (UploadCapability, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 || len(key) < 32 || !idPattern.MatchString(tenantID) || !idPattern.MatchString(uploadID) || ValidateUploadMetadata(metadata) != nil {
		return UploadCapability{}, ErrInvalidCapability
	}
	provided, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return UploadCapability{}, ErrInvalidCapability
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(parts[0]))
	want := mac.Sum(nil)
	if len(provided) != len(want) || subtle.ConstantTimeCompare(provided, want) != 1 {
		return UploadCapability{}, ErrInvalidCapability
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || len(payload) > 2048 {
		return UploadCapability{}, ErrInvalidCapability
	}
	var claims UploadCapability
	if json.Unmarshal(payload, &claims) != nil || !idPattern.MatchString(claims.TenantID) || !idPattern.MatchString(claims.InviteID) || !idPattern.MatchString(claims.UploadID) || claims.Purpose != "supplier-upload-v1" || claims.Size != metadata.Size || subtle.ConstantTimeCompare([]byte(claims.SHA256), []byte(metadata.SHA256)) != 1 || claims.TenantID != tenantID || claims.UploadID != uploadID {
		return UploadCapability{}, ErrInvalidCapability
	}
	if _, err := tenancy.ParseTenantID(claims.TenantID); err != nil {
		return UploadCapability{}, ErrInvalidCapability
	}
	now = now.UTC()
	if claims.ExpiresAt.IsZero() || !now.Before(claims.ExpiresAt) || claims.ExpiresAt.After(now.Add(MaxUploadCapabilityTTL+time.Second)) {
		return UploadCapability{}, ErrInvalidCapability
	}
	return claims, nil
}

func isHex(value string) bool {
	for _, r := range value {
		if !(r >= '0' && r <= '9') && !(r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}
