package webhook

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeKeyFile(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "keys.json")
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func keyFileSecret() string {
	return base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 32)))
}

func TestLoadKeyringFromFileLoadsActiveAndPrevious(t *testing.T) {
	previous := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("p", 32)))
	ring, err := LoadKeyringFromFile(writeKeyFile(t,
		`{"active":{"id":"key_2026","secret_b64":"`+keyFileSecret()+`"},`+
			`"previous":{"id":"key_2025","secret_b64":"`+previous+`"}}`))
	if err != nil {
		t.Fatalf("LoadKeyringFromFile: %v", err)
	}
	if ring.ActiveKeyID() != "key_2026" {
		t.Fatalf("active key = %q", ring.ActiveKeyID())
	}
	if _, ok := ring.keyFor("key_2025"); !ok {
		t.Fatal("previous key was not loaded")
	}
}

func TestLoadKeyringFromFileAcceptsActiveOnly(t *testing.T) {
	ring, err := LoadKeyringFromFile(writeKeyFile(t,
		`{"active":{"id":"key_2026","secret_b64":"`+keyFileSecret()+`"}}`))
	if err != nil {
		t.Fatalf("LoadKeyringFromFile: %v", err)
	}
	if ring.ActiveKeyID() != "key_2026" {
		t.Fatalf("active key = %q", ring.ActiveKeyID())
	}
}

func TestLoadKeyringFromFileRejectsBadFiles(t *testing.T) {
	for _, test := range []struct {
		name string
		body string
	}{
		{"empty", ``},
		{"bad json", `{`},
		{"unknown field", `{"active":{"id":"key_2026","secret_b64":"` + keyFileSecret() + `"},"extra":1}`},
		{"missing active id", `{"active":{"id":"","secret_b64":"` + keyFileSecret() + `"}}`},
		{"missing secret", `{"active":{"id":"key_2026","secret_b64":""}}`},
		{"bad base64", `{"active":{"id":"key_2026","secret_b64":"not base64!"}}`},
		{"short secret", `{"active":{"id":"key_2026","secret_b64":"` +
			base64.StdEncoding.EncodeToString([]byte("short")) + `"}}`},
		{"duplicate ids", `{"active":{"id":"key_2026","secret_b64":"` + keyFileSecret() + `"},` +
			`"previous":{"id":"key_2026","secret_b64":"` + keyFileSecret() + `"}}`},
		{"bad previous id", `{"active":{"id":"key_2026","secret_b64":"` + keyFileSecret() + `"},` +
			`"previous":{"id":"k","secret_b64":"` + keyFileSecret() + `"}}`},
		{"trailing value", `{"active":{"id":"key_2026","secret_b64":"` + keyFileSecret() + `"}} {}`},
		{"empty array", `[]`},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := LoadKeyringFromFile(writeKeyFile(t, test.body)); err == nil {
				t.Fatal("bad key file was accepted")
			}
		})
	}
	if _, err := LoadKeyringFromFile(""); err == nil {
		t.Fatal("empty path was accepted")
	}
	if _, err := LoadKeyringFromFile(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Fatal("missing file was accepted")
	}
	if _, err := LoadKeyringFromFile(t.TempDir()); err == nil {
		t.Fatal("directory was accepted")
	}
	big := filepath.Join(t.TempDir(), "big.json")
	if err := os.WriteFile(big, make([]byte, MaxKeyFileBytes+1), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKeyringFromFile(big); err == nil {
		t.Fatal("oversized file was accepted")
	}
}
