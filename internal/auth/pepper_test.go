package auth

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadPepperFileLoadsTrimmedMaterial(t *testing.T) {
	pepper := strings.Repeat("p", MinPepperBytes)
	path := filepath.Join(t.TempDir(), "pepper")
	if err := os.WriteFile(path, []byte("  "+pepper+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := ReadPepperFile(path)
	if err != nil || string(loaded) != pepper {
		t.Fatalf("load: %q err=%v", loaded, err)
	}
}

func TestReadPepperFileRejectsWeakOrMissing(t *testing.T) {
	if _, err := ReadPepperFile(""); err == nil {
		t.Fatal("empty path accepted")
	}
	if _, err := ReadPepperFile(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing file accepted")
	}
	short := filepath.Join(t.TempDir(), "short")
	if err := os.WriteFile(short, []byte("short"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPepperFile(short); err == nil {
		t.Fatal("short pepper accepted")
	}
	huge := filepath.Join(t.TempDir(), "huge")
	if err := os.WriteFile(huge, []byte(strings.Repeat("x", 1025)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPepperFile(huge); err == nil {
		t.Fatal("oversized pepper accepted")
	}
}
