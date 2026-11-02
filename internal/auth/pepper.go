package auth

import (
	"errors"
	"os"
	"strings"
)

// ReadPepperFile loads a deployment-time pepper from a secret file. The file
// is never committed; operators mount it like the OnCall integration URLs
// (/run/secrets/*). Content is trimmed of surrounding whitespace and must
// decode to at least MinPepperBytes of raw material. Failure is explicit so
// callers fail closed instead of running with a weak or missing pepper.
func ReadPepperFile(path string) ([]byte, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("identity pepper file path is required")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	trimmed := strings.TrimSpace(string(raw))
	if len(trimmed) < MinPepperBytes {
		return nil, ErrInvalidPepper
	}
	if len(trimmed) > 1024 {
		return nil, ErrInvalidPepper
	}
	return []byte(trimmed), nil
}
