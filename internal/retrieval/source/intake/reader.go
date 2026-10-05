// Package intake resolves citation ranges from extracted supplier uploads.
// The adapter is suitable for Keel's local synthetic profile; its BlobStore
// must provide tenant-isolated, encrypted, versioned storage in production.
package intake

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
	"github.com/sanskarpan/keel/internal/retrieval/hybrid"
	"github.com/sanskarpan/keel/internal/retrieval/index"
	retrievalpostgres "github.com/sanskarpan/keel/internal/retrieval/postgres"
	supplierintake "github.com/sanskarpan/keel/internal/supplier/intake"
)

type blobReader interface {
	Open(context.Context, string) (io.ReadCloser, error)
}

// Reader resolves DocumentVersionID as the immutable supplier_uploads.upload_id.
// Eligibility is checked inside tenant and visibility scoped forced-RLS access
// before upload metadata or content is read. It intentionally has no cache.
type Reader struct {
	db      *sql.DB
	objects blobReader
}

var _ retrievalpostgres.CitationRangeReader = (*Reader)(nil)

func NewReader(db *sql.DB, objects blobReader) (*Reader, error) {
	if db == nil || objects == nil {
		return nil, errors.New("citation database and extracted object reader are required")
	}
	return &Reader{db: db, objects: objects}, nil
}

func (r *Reader) ReadCitationRange(ctx context.Context, tenant tenancy.TenantID, visibility string, ref hybrid.CitationRef) ([]byte, error) {
	if ctx == nil || r == nil || r.db == nil || r.objects == nil {
		return nil, errors.New("citation reader is unavailable")
	}
	tenantID, err := tenancy.ParseTenantID(string(tenant))
	if err != nil {
		return nil, errors.New("citation tenant is invalid")
	}
	visibility, err = index.ParseVisibilityKey(visibility)
	if err != nil {
		return nil, errors.New("citation visibility is invalid")
	}
	if ref.ChunkID == uuid.Nil || ref.DocumentVersionID == uuid.Nil || ref.Ordinal < 0 ||
		ref.StartByte < 0 || ref.EndByte <= ref.StartByte ||
		ref.EndByte-ref.StartByte > hybrid.MaxCitationExcerptBytes || ref.ContentDigest == ([32]byte{}) {
		return nil, errors.New("citation identity or byte range is invalid")
	}
	var objectKey string
	var extractedBytes int64
	var storedDigest []byte
	err = tenancy.WithTenantTx(ctx, r.db, tenantID, &sql.TxOptions{Isolation: sql.LevelRepeatableRead}, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `SELECT set_config('keel.visibility_key',$1,true)`, visibility); err != nil {
			return fmt.Errorf("set citation visibility scope: %w", err)
		}
		var authorized bool
		err := tx.QueryRowContext(ctx, `SELECT state='active' FROM keel_meta.retrieval_source_eligibility
			WHERE tenant_id=$1 AND visibility_key=$2 AND document_version_id=$3 FOR SHARE`,
			string(tenantID), visibility, ref.DocumentVersionID).Scan(&authorized)
		if errors.Is(err, sql.ErrNoRows) || (err == nil && !authorized) {
			return hybrid.ErrCitationNotAuthorized
		}
		if err != nil {
			return fmt.Errorf("check current citation eligibility: %w", err)
		}
		var chunkExists bool
		err = tx.QueryRowContext(ctx, `SELECT EXISTS (
			SELECT 1 FROM keel_meta.retrieval_chunks
			WHERE tenant_id=$1 AND visibility_key=$2 AND chunk_id=$3 AND document_version_id=$4
			  AND chunk_ordinal=$5 AND source_start_byte=$6 AND source_end_byte=$7 AND content_sha256=$8
		)`, string(tenantID), visibility, ref.ChunkID, ref.DocumentVersionID, ref.Ordinal,
			ref.StartByte, ref.EndByte, ref.ContentDigest[:]).Scan(&chunkExists)
		if err != nil {
			return fmt.Errorf("check immutable citation chunk: %w", err)
		}
		if !chunkExists {
			return hybrid.ErrCitationNotAuthorized
		}
		err = tx.QueryRowContext(ctx, `SELECT extracted_object_key::text,extracted_bytes,extracted_sha256
			FROM keel_meta.supplier_uploads
			WHERE tenant_id=$1 AND upload_id=$2 AND upload_state='extracted'`, string(tenantID), ref.DocumentVersionID).
			Scan(&objectKey, &extractedBytes, &storedDigest)
		if errors.Is(err, sql.ErrNoRows) {
			return hybrid.ErrCitationNotAuthorized
		}
		if err != nil {
			return fmt.Errorf("load extracted citation source metadata: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if extractedBytes < 1 || extractedBytes > supplierintake.MaxExtractedSize || len(storedDigest) != sha256.Size {
		return nil, errors.New("extracted citation source metadata is invalid")
	}
	if _, err := uuid.Parse(objectKey); err != nil {
		return nil, errors.New("extracted citation object identity is invalid")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	object, err := r.objects.Open(ctx, objectKey)
	if err != nil {
		return nil, errors.New("extracted citation object is unavailable")
	}
	content, readErr := io.ReadAll(io.LimitReader(object, supplierintake.MaxExtractedSize+1))
	closeErr := object.Close()
	if readErr != nil || closeErr != nil {
		return nil, errors.New("extracted citation object could not be read")
	}
	if int64(len(content)) != extractedBytes || len(content) > int(supplierintake.MaxExtractedSize) ||
		sha256.Sum256(content) != bytesToDigest(storedDigest) {
		return nil, errors.New("extracted citation object does not match stored integrity metadata")
	}
	if ref.EndByte > len(content) {
		return nil, errors.New("citation range exceeds extracted source bounds")
	}
	excerpt := content[ref.StartByte:ref.EndByte]
	if !utf8.Valid(excerpt) {
		return nil, errors.New("citation range is not valid UTF-8")
	}
	return append([]byte(nil), excerpt...), nil
}

func bytesToDigest(value []byte) [sha256.Size]byte {
	var digest [sha256.Size]byte
	copy(digest[:], value)
	return digest
}
