package intake

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

// BlobStore is the narrow quarantine boundary needed by the upload and processor workflows.
// Production implementations must enforce tenant/object authorization, encryption at rest,
// immutable object versions, and lifecycle retention in the backing object store.
type BlobStore interface {
	Put(context.Context, string, io.Reader, int64) (int64, [sha256.Size]byte, error)
	Open(context.Context, string) (io.ReadCloser, error)
	Delete(context.Context, string) error
}

// LocalStore is for the local synthetic profile only. It uses a private directory, UUID keys,
// atomic create-if-absent publication, and 0600 files; it is not a production object-store adapter.
type LocalStore struct {
	root *os.Root
}

func NewLocalStore(directory string) (*LocalStore, error) {
	if directory == "" || !filepath.IsAbs(directory) {
		return nil, errors.New("quarantine directory must be an absolute path")
	}
	if err := os.MkdirAll(directory, 0700); err != nil {
		return nil, errors.New("quarantine directory could not be prepared")
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("quarantine directory must be a real directory")
	}
	if err := os.Chmod(directory, 0700); err != nil {
		return nil, errors.New("quarantine directory permissions could not be restricted")
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, errors.New("quarantine directory could not be opened safely")
	}
	return &LocalStore{root: root}, nil
}

func (s *LocalStore) Close() error {
	if s == nil || s.root == nil {
		return nil
	}
	return s.root.Close()
}

func (s *LocalStore) Put(ctx context.Context, key string, source io.Reader, limit int64) (int64, [sha256.Size]byte, error) {
	if s == nil || s.root == nil || ctx == nil || !validObjectKey(key) || source == nil || limit < 1 || limit > MaxUploadBytes {
		return 0, [sha256.Size]byte{}, errors.New("quarantine write arguments are invalid")
	}
	var zero [sha256.Size]byte
	temporary := ".pending-" + key
	file, err := s.root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return 0, zero, errors.New("quarantine object could not be created")
	}
	published := false
	defer func() {
		_ = file.Close()
		if !published {
			_ = s.root.Remove(temporary)
		}
	}()
	hash := sha256.New()
	count, err := copyContext(ctx, io.MultiWriter(file, hash), io.LimitReader(source, limit+1))
	if err != nil || count > limit {
		return 0, zero, errors.New("quarantine object exceeded its size limit or could not be read")
	}
	if err := file.Sync(); err != nil {
		return 0, zero, errors.New("quarantine object could not be synchronized")
	}
	if err := file.Close(); err != nil {
		return 0, zero, errors.New("quarantine object could not be closed")
	}
	if err := s.root.Link(temporary, key); err != nil {
		return 0, zero, errors.New("quarantine object already exists or could not be published")
	}
	if err := s.root.Remove(temporary); err != nil {
		_ = s.root.Remove(key)
		return 0, zero, errors.New("quarantine temporary object could not be removed")
	}
	published = true
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	return count, digest, nil
}

func (s *LocalStore) Open(ctx context.Context, key string) (io.ReadCloser, error) {
	if s == nil || s.root == nil || ctx == nil || ctx.Err() != nil || !validObjectKey(key) {
		return nil, errors.New("quarantine read arguments are invalid")
	}
	info, err := s.root.Lstat(key)
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("quarantine object was not found")
	}
	file, err := s.root.Open(key)
	if err != nil {
		return nil, errors.New("quarantine object could not be opened")
	}
	return file, nil
}

func (s *LocalStore) Delete(ctx context.Context, key string) error {
	if s == nil || s.root == nil || ctx == nil || ctx.Err() != nil || !validObjectKey(key) {
		return errors.New("quarantine delete arguments are invalid")
	}
	if err := s.root.Remove(key); err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.New("quarantine object could not be deleted")
	}
	return nil
}

func copyContext(ctx context.Context, dst io.Writer, src io.Reader) (int64, error) {
	buffer := make([]byte, 64<<10)
	var total int64
	noProgress := 0
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		n, readErr := src.Read(buffer)
		if n == 0 && readErr == nil {
			noProgress++
			if noProgress >= 100 {
				return total, io.ErrNoProgress
			}
			continue
		}
		noProgress = 0
		if n > 0 {
			written, writeErr := dst.Write(buffer[:n])
			total += int64(written)
			if writeErr != nil {
				return total, writeErr
			}
			if written != n {
				return total, io.ErrShortWrite
			}
		}
		if readErr == io.EOF {
			return total, nil
		}
		if readErr != nil {
			return total, readErr
		}
	}
}

func validObjectKey(value string) bool {
	if len(value) != 36 {
		return false
	}
	if _, err := tenancy.ParseTenantID(value); err != nil {
		return false
	}
	return strings.ToLower(value) == value && !containsPathSeparator(value)
}

func containsPathSeparator(value string) bool {
	for _, r := range value {
		if r == '/' || r == '\\' {
			return true
		}
	}
	return false
}
