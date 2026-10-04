package intake

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestLocalQuarantineStorePublishesPrivateBoundedObjects(t *testing.T) {
	root := t.TempDir()
	store, err := NewLocalStore(filepath.Join(root, "quarantine"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	key := "11111111-1111-4111-8111-111111111111"
	data := []byte("synthetic quarantined evidence")
	size, digest, err := store.Put(ctx, key, bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	wantDigest := sha256.Sum256(data)
	if size != int64(len(data)) || digest != wantDigest {
		t.Fatalf("stored size/digest = %d/%s", size, hex.EncodeToString(digest[:]))
	}
	info, err := os.Stat(filepath.Join(root, "quarantine", key))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("object mode = %o, want 600", info.Mode().Perm())
	}
	file, err := store.Open(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	got, readErr := io.ReadAll(file)
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || !bytes.Equal(got, data) {
		t.Fatalf("read object = %q; read err=%v close err=%v", got, readErr, closeErr)
	}
	if _, _, err := store.Put(ctx, key, bytes.NewReader(data), int64(len(data))); err == nil {
		t.Fatal("existing object was overwritten")
	}
	if _, _, err := store.Put(ctx, "../../outside", bytes.NewReader(data), int64(len(data))); err == nil {
		t.Fatal("path traversal key was accepted")
	}
	if _, _, err := store.Put(ctx, "22222222-2222-4222-8222-222222222222", bytes.NewReader(data), int64(len(data)-1)); err == nil {
		t.Fatal("over-limit object was published")
	}
	if err := store.Delete(ctx, key); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Open(ctx, key); err == nil {
		t.Fatal("deleted object remained readable")
	}
}

func TestLocalQuarantineStoreRejectsSymlinkRootAndCanceledOperations(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "real")
	if err := os.Mkdir(real, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "linked")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if _, err := NewLocalStore(link); err == nil {
		t.Fatal("symlink quarantine root was accepted")
	}
	store, err := NewLocalStore(filepath.Join(base, "safe"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := store.Put(ctx, "11111111-1111-4111-8111-111111111111", bytes.NewReader([]byte("x")), 1); err == nil {
		t.Fatal("canceled write succeeded")
	}
	if err := store.Delete(ctx, "11111111-1111-4111-8111-111111111111"); err == nil {
		t.Fatal("canceled deletion succeeded")
	}
}
