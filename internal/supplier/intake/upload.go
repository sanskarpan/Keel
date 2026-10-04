// Package intake implements the supplier evidence ingestion boundary. Uploads remain
// quarantined until malware scanning and bounded extraction both complete successfully.
package intake

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

const (
	MaxUploadBytes   int64 = 20 << 20
	MaxExtractedSize int64 = 4 << 20
	MaxDOCXEntries         = 128
	MaxDOCXExpanded  int64 = 40 << 20
)

var (
	ErrInvalidUpload  = errors.New("invalid supplier upload")
	ErrUploadTooLarge = errors.New("supplier upload exceeds the configured size limit")
)
var (
	ErrScannerUnavailable = errors.New("malware scanning is unavailable")
	ErrExtractionFailed   = errors.New("sandboxed extraction failed")
	ErrOutputLimit        = errors.New("extracted output exceeds the configured limit")
	ErrNoJob              = errors.New("no supplier upload job is available")
)

type Format string

const (
	FormatPDF  Format = "application/pdf"
	FormatDOCX Format = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
	FormatText Format = "text/plain"
)

// UploadMetadata contains claims made before bytes arrive. The server independently checks
// the uploaded length, checksum, and detected type before it schedules scanning.
type UploadMetadata struct {
	Filename    string
	ContentType string
	Size        int64
	SHA256      string
}

func ValidateUploadMetadata(m UploadMetadata) error {
	if m.Size < 1 || m.Size > MaxUploadBytes {
		if m.Size > MaxUploadBytes {
			return ErrUploadTooLarge
		}
		return fmt.Errorf("%w: size must be between 1 and %d bytes", ErrInvalidUpload, MaxUploadBytes)
	}
	if m.Filename == "" || len(m.Filename) > 160 || filepath.Base(m.Filename) != m.Filename || strings.ContainsAny(m.Filename, "/\\") {
		return fmt.Errorf("%w: filename is invalid", ErrInvalidUpload)
	}
	for _, r := range m.Filename {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%w: filename contains control characters", ErrInvalidUpload)
		}
	}
	if m.ContentType != string(FormatPDF) && m.ContentType != string(FormatDOCX) && m.ContentType != string(FormatText) {
		return fmt.Errorf("%w: content type is not supported", ErrInvalidUpload)
	}
	if len(m.SHA256) != sha256.Size*2 || strings.ToLower(m.SHA256) != m.SHA256 {
		return fmt.Errorf("%w: checksum must be lowercase SHA-256 hex", ErrInvalidUpload)
	}
	if _, err := hex.DecodeString(m.SHA256); err != nil {
		return fmt.Errorf("%w: checksum must be lowercase SHA-256 hex", ErrInvalidUpload)
	}
	return nil
}

// VerifyObject independently validates the uploaded bytes against their capability-bound
// metadata. It consumes at most the fixed 20 MiB upload budget plus one byte.
func VerifyObject(m UploadMetadata, source io.Reader) ([]byte, Format, error) {
	if err := ValidateUploadMetadata(m); err != nil {
		return nil, "", err
	}
	if source == nil {
		return nil, "", fmt.Errorf("%w: upload body is required", ErrInvalidUpload)
	}
	data, err := io.ReadAll(io.LimitReader(source, MaxUploadBytes+1))
	if err != nil {
		return nil, "", fmt.Errorf("%w: upload could not be read", ErrInvalidUpload)
	}
	if int64(len(data)) != m.Size || int64(len(data)) > MaxUploadBytes {
		if int64(len(data)) > MaxUploadBytes {
			return nil, "", ErrUploadTooLarge
		}
		return nil, "", fmt.Errorf("%w: uploaded size differs from the declared size", ErrInvalidUpload)
	}
	digest := sha256.Sum256(data)
	if !bytes.Equal([]byte(hex.EncodeToString(digest[:])), []byte(m.SHA256)) {
		return nil, "", fmt.Errorf("%w: uploaded checksum differs from the declared checksum", ErrInvalidUpload)
	}
	format, err := DetectFormat(data, m.ContentType)
	if err != nil {
		return nil, "", err
	}
	return data, format, nil
}

func DetectFormat(data []byte, claimedType string) (Format, error) {
	if len(data) == 0 {
		return "", fmt.Errorf("%w: empty content", ErrInvalidUpload)
	}
	switch claimedType {
	case string(FormatPDF):
		if !bytes.HasPrefix(data, []byte("%PDF-")) {
			return "", fmt.Errorf("%w: PDF signature is missing", ErrInvalidUpload)
		}
		return FormatPDF, nil
	case string(FormatDOCX):
		if !bytes.HasPrefix(data, []byte{'P', 'K', 3, 4}) {
			return "", fmt.Errorf("%w: Office document container signature is missing", ErrInvalidUpload)
		}
		if err := validateDOCX(data); err != nil {
			return "", err
		}
		return FormatDOCX, nil
	case string(FormatText):
		if !utf8.Valid(data) || bytes.IndexByte(data, 0) >= 0 || http.DetectContentType(data[:min(len(data), 512)]) != "text/plain; charset=utf-8" {
			return "", fmt.Errorf("%w: plain text is not valid UTF-8 text", ErrInvalidUpload)
		}
		return FormatText, nil
	default:
		return "", fmt.Errorf("%w: content type is not supported", ErrInvalidUpload)
	}
}

func validateDOCX(data []byte) error {
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil || len(reader.File) == 0 || len(reader.File) > MaxDOCXEntries {
		return fmt.Errorf("%w: Office document archive is malformed or has too many entries", ErrInvalidUpload)
	}
	var expanded int64
	seen := make(map[string]struct{}, len(reader.File))
	contentTypes, documentXML := false, false
	for _, file := range reader.File {
		name := filepath.ToSlash(file.Name)
		cleanName := strings.TrimSuffix(name, "/")
		if cleanName == "" || strings.HasPrefix(name, "/") || path.Clean(cleanName) != cleanName || hasParentSegment(cleanName) || strings.ContainsRune(name, '\\') || file.Mode()&os.ModeSymlink != 0 || (!file.Mode().IsRegular() && !file.Mode().IsDir()) || (strings.HasSuffix(name, "/") && !file.Mode().IsDir()) {
			return fmt.Errorf("%w: Office document contains an unsafe archive path", ErrInvalidUpload)
		}
		if _, ok := seen[cleanName]; ok {
			return fmt.Errorf("%w: Office document contains duplicate archive paths", ErrInvalidUpload)
		}
		seen[cleanName] = struct{}{}
		if strings.HasPrefix(cleanName, "word/vbaProject") || cleanName == "word/vbaProject.bin" {
			return fmt.Errorf("%w: macro-enabled Office documents are not accepted", ErrInvalidUpload)
		}
		if file.UncompressedSize64 > uint64(MaxDOCXExpanded) || expanded > MaxDOCXExpanded-int64(file.UncompressedSize64) {
			return fmt.Errorf("%w: Office document expands beyond the archive budget", ErrInvalidUpload)
		}
		expanded += int64(file.UncompressedSize64)
		if cleanName == "[Content_Types].xml" {
			contentTypes = true
		}
		if cleanName == "word/document.xml" {
			documentXML = true
		}
	}
	if !contentTypes || !documentXML {
		return fmt.Errorf("%w: Office document is missing required document parts", ErrInvalidUpload)
	}
	return nil
}

func hasParentSegment(name string) bool {
	for _, segment := range strings.Split(name, "/") {
		if segment == ".." {
			return true
		}
	}
	return false
}

// Scanner must return ErrMalwareFound for a positive malware verdict. Infrastructure and
// protocol errors must remain errors so the caller can retry without publishing the file.
type Scanner interface {
	Scan(context.Context, io.Reader) error
}

var ErrMalwareFound = errors.New("malware detected")

// Extractor runs behind a sandboxed adapter and must honor outputLimit. The caller never
// publishes bytes unless both scanning and extraction finish successfully.
type Extractor interface {
	Extract(context.Context, Format, io.Reader, int64) ([]byte, error)
}

type ProcessedDocument struct {
	Format       Format
	Text         []byte
	TextSHA256   [sha256.Size]byte
	SourceSHA256 [sha256.Size]byte
}

type UploadJob struct {
	TenantID     tenancy.TenantID
	UploadID     string
	InvitationID string
	ObjectKey    string
	Metadata     UploadMetadata
	ClaimOwner   string
	ClaimEpoch   int64
	Attempt      int
	LeaseUntil   time.Time
}

func NewObjectID(source io.Reader) (string, error) {
	if source == nil {
		source = rand.Reader
	}
	var value [16]byte
	if _, err := io.ReadFull(source, value[:]); err != nil {
		return "", errors.New("secure object ID generation failed")
	}
	value[6] = value[6]&0x0f | 0x40
	value[8] = value[8]&0x3f | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", value[0:4], value[4:6], value[6:8], value[8:10], value[10:16]), nil
}

func Process(ctx context.Context, metadata UploadMetadata, source io.Reader, scanner Scanner, extractor Extractor) (ProcessedDocument, error) {
	if ctx == nil || scanner == nil || extractor == nil {
		return ProcessedDocument{}, errors.New("upload context, scanner, and extractor are required")
	}
	data, format, err := VerifyObject(metadata, source)
	if err != nil {
		return ProcessedDocument{}, err
	}
	if err := scanner.Scan(ctx, bytes.NewReader(data)); err != nil {
		if errors.Is(err, ErrMalwareFound) {
			return ProcessedDocument{}, ErrMalwareFound
		}
		return ProcessedDocument{}, ErrScannerUnavailable
	}
	text, err := extractor.Extract(ctx, format, bytes.NewReader(data), MaxExtractedSize)
	if err != nil {
		return ProcessedDocument{}, ErrExtractionFailed
	}
	if int64(len(text)) > MaxExtractedSize {
		return ProcessedDocument{}, ErrOutputLimit
	}
	if !utf8ValidText(text) {
		return ProcessedDocument{}, ErrExtractionFailed
	}
	sourceHash := sha256.Sum256(data)
	textHash := sha256.Sum256(text)
	return ProcessedDocument{Format: format, Text: append([]byte(nil), text...), TextSHA256: textHash, SourceSHA256: sourceHash}, nil
}
