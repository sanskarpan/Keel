package auth

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"io"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Principal lifecycle states persisted in keel_meta.identity_principals.
const (
	PrincipalPending  = "pending_verification"
	PrincipalActive   = "active"
	PrincipalDisabled = "disabled"
)

var (
	// ErrInvalidRecord reports an argument that fails bounded validation.
	ErrInvalidRecord = errors.New("identity record is invalid")
	// ErrInvalidPassword reports a password outside the accepted bounds.
	ErrInvalidPassword = errors.New("password is invalid")
	// ErrInvalidCredentialHash reports stored credential material that does not
	// parse as a supported Argon2id PHC string; verification fails closed.
	ErrInvalidCredentialHash = errors.New("stored credential hash is invalid")
)

// Credential params (PHC `$argon2id$` string). Verification accepts a bounded
// parameter range so stored hashes remain auditable and old hashes stay verifiable
// without re-implementing other algorithms.
const (
	MinArgonMemoryKiB = 8 * 1024
	MaxArgonMemoryKiB = 256 * 1024
	MinArgonTime      = 1
	MaxArgonTime      = 8
	MaxArgonThreads   = 4
	MinSaltBytes      = 16
	MinHashBytes      = 16
	MaxHashBytes      = 64
	MaxHashLen        = 256
	MinPasswordBytes  = 8
	MaxPasswordBytes  = 256
)

// ArgonParams is the effort profile used at hash time.
type ArgonParams struct {
	MemoryKiB uint32
	Time      uint32
	Threads   uint8
}

// DefaultArgonParams returns the production effort: 64 MiB, 3 passes, 1 thread.
func DefaultArgonParams() ArgonParams {
	return ArgonParams{MemoryKiB: 64 * 1024, Time: 3, Threads: 1}
}

// TestArgonParams is the reduced-effort profile for unit and integration tests.
func TestArgonParams() ArgonParams {
	return ArgonParams{MemoryKiB: 8 * 1024, Time: 1, Threads: 1}
}

// ValidatePassword bounds accepted secret lengths so unbounded input cannot reach
// Argon2 or storage. Content is otherwise unrestricted.
func ValidatePassword(password string) error {
	if len(password) < MinPasswordBytes || len(password) > MaxPasswordBytes {
		return ErrInvalidPassword
	}
	return nil
}

// HashPassword derives an Argon2id PHC string. The derivation parameters and salt
// are returned inside the encoded string.
func HashPassword(password string, params ArgonParams) (string, error) {
	if err := ValidatePassword(password); err != nil {
		return "", err
	}
	if err := validateParams(params); err != nil {
		return "", err
	}
	salt, err := NewSalt()
	if err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, params.Time, params.MemoryKiB, params.Threads, MaxHashBytes)
	var out strings.Builder
	out.WriteString("$argon2id$v=")
	out.WriteString(strconv.Itoa(argon2.Version))
	out.WriteString("$m=")
	out.WriteString(strconv.FormatUint(uint64(params.MemoryKiB), 10))
	out.WriteString(",t=")
	out.WriteString(strconv.FormatUint(uint64(params.Time), 10))
	out.WriteString(",p=")
	out.WriteString(strconv.FormatUint(uint64(params.Threads), 10))
	out.WriteString("$")
	out.WriteString(base64.RawStdEncoding.EncodeToString(salt))
	out.WriteString("$")
	out.WriteString(base64.RawStdEncoding.EncodeToString(key))
	return out.String(), nil
}

func validateParams(params ArgonParams) error {
	if params.MemoryKiB < MinArgonMemoryKiB || params.MemoryKiB > MaxArgonMemoryKiB ||
		params.Time < MinArgonTime || params.Time > MaxArgonTime ||
		params.Threads < 1 || params.Threads > MaxArgonThreads {
		return ErrInvalidRecord
	}
	return nil
}

func NewSalt() ([]byte, error) {
	salt := make([]byte, MinSaltBytes)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, errors.New("salt generation failed")
	}
	return salt, nil
}

// VerifyPassword checks the password against one stored PHC string. Mismatch is an
// expected os-independent result (false, nil); any parse failure is (false, err)
// so callers fail closed instead of authenticating on a corrupt record.
func VerifyPassword(password, encoded string) (bool, error) {
	if len(encoded) < 1 || len(encoded) > MaxHashLen {
		return false, ErrInvalidCredentialHash
	}
	if err := ValidatePassword(password); err != nil {
		return false, err
	}
	fields := strings.Split(encoded, "$")
	if len(fields) != 6 {
		return false, ErrInvalidCredentialHash
	}
	if fields[1] != "argon2id" {
		return false, ErrInvalidCredentialHash
	}
	version, err := strconv.Atoi(strings.TrimPrefix(fields[2], "v="))
	if err != nil || version != argon2.Version {
		return false, ErrInvalidCredentialHash
	}
	var memoryKiB, time uint32
	var threads uint8
	for _, part := range strings.Split(fields[3], ",") {
		key, value, ok := strings.Cut(part, "=")
		if !ok {
			return false, ErrInvalidCredentialHash
		}
		parsed, parseErr := strconv.ParseUint(value, 10, 32)
		if parseErr != nil {
			return false, ErrInvalidCredentialHash
		}
		switch key {
		case "m":
			memoryKiB = uint32(parsed)
		case "t":
			time = uint32(parsed)
		case "p":
			if parsed > uint64(MaxArgonThreads) {
				return false, ErrInvalidCredentialHash
			}
			threads = uint8(parsed)
		default:
			return false, ErrInvalidCredentialHash
		}
	}
	if err := validateParams(ArgonParams{MemoryKiB: memoryKiB, Time: time, Threads: threads}); err != nil {
		return false, ErrInvalidCredentialHash
	}
	salt, err := base64.RawStdEncoding.DecodeString(fields[4])
	if err != nil || len(salt) < MinSaltBytes {
		return false, ErrInvalidCredentialHash
	}
	key, err := base64.RawStdEncoding.DecodeString(fields[5])
	if err != nil || len(key) < MinHashBytes || len(key) > MaxHashBytes {
		return false, ErrInvalidCredentialHash
	}
	computed := argon2.IDKey([]byte(password), salt, time, memoryKiB, threads, uint32(len(key)))
	if len(computed) != len(key) || subtle.ConstantTimeCompare(computed, key) != 1 {
		return false, nil
	}
	return true, nil
}

// CredentialMatches reports whether two stored hash strings are byte-identical,
// used by sibling slices replacing credentials. It never re-derives a key.
func CredentialMatches(a, b string) bool {
	return len(a) > 0 && len(a) <= MaxHashLen && len(b) == len(a) && bytes.Equal([]byte(a), []byte(b))
}
