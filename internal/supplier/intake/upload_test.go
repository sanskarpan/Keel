package intake

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

func metadataFor(data []byte, format Format) UploadMetadata {
	digest := sha256.Sum256(data)
	name := "evidence.txt"
	if format == FormatPDF {
		name = "evidence.pdf"
	}
	if format == FormatDOCX {
		name = "evidence.docx"
	}
	return UploadMetadata{Filename: name, ContentType: string(format), Size: int64(len(data)), SHA256: hex.EncodeToString(digest[:])}
}

func TestUploadMetadataRejectsUnboundedOrPathLikeInputs(t *testing.T) {
	valid := metadataFor([]byte("supplier certificate"), FormatText)
	tests := map[string]func(*UploadMetadata){
		"empty":                 func(m *UploadMetadata) { m.Size = 0 },
		"oversize":              func(m *UploadMetadata) { m.Size = MaxUploadBytes + 1 },
		"parent path":           func(m *UploadMetadata) { m.Filename = "../private.pdf" },
		"windows path":          func(m *UploadMetadata) { m.Filename = `C:\private.pdf` },
		"control character":     func(m *UploadMetadata) { m.Filename = "name\n.pdf" },
		"unknown media type":    func(m *UploadMetadata) { m.ContentType = "application/zip" },
		"uppercase checksum":    func(m *UploadMetadata) { m.SHA256 = strings.ToUpper(m.SHA256) },
		"malformed checksum":    func(m *UploadMetadata) { m.SHA256 = "sha256:abcd" },
		"overlong display name": func(m *UploadMetadata) { m.Filename = strings.Repeat("a", 161) },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			input := valid
			mutate(&input)
			want := ErrInvalidUpload
			if name == "oversize" {
				want = ErrUploadTooLarge
			}
			if err := ValidateUploadMetadata(input); !errors.Is(err, want) {
				t.Fatalf("error=%v, want invalid upload", err)
			}
		})
	}
}

func TestVerifyObjectBindsActualLengthChecksumAndMagic(t *testing.T) {
	data := []byte("%PDF-1.7\nminimal synthetic PDF marker")
	metadata := metadataFor(data, FormatPDF)
	got, format, err := VerifyObject(metadata, bytes.NewReader(data))
	if err != nil || format != FormatPDF || !bytes.Equal(got, data) {
		t.Fatalf("verified document format=%q err=%v", format, err)
	}
	if _, _, err := VerifyObject(metadata, bytes.NewReader(append(data, '!'))); !errors.Is(err, ErrInvalidUpload) {
		t.Fatalf("length mismatch error=%v", err)
	}
	metadata = metadataFor(data, FormatPDF)
	metadata.SHA256 = strings.Repeat("0", 64)
	if _, _, err := VerifyObject(metadata, bytes.NewReader(data)); !errors.Is(err, ErrInvalidUpload) {
		t.Fatalf("checksum mismatch error=%v", err)
	}
	metadata = metadataFor([]byte("not really a pdf"), FormatPDF)
	if _, _, err := VerifyObject(metadata, strings.NewReader("not really a pdf")); !errors.Is(err, ErrInvalidUpload) {
		t.Fatalf("type spoof error=%v", err)
	}
	metadata = metadataFor([]byte("%PDF-1.7"), FormatText)
	if _, _, err := VerifyObject(metadata, strings.NewReader("%PDF-1.7")); !errors.Is(err, ErrInvalidUpload) {
		t.Fatalf("format mismatch error=%v", err)
	}
}

func TestDOCXContainerBudgetAndMacroChecks(t *testing.T) {
	valid := docxFixture(t, "word/document.xml", "[Content_Types].xml")
	if _, err := DetectFormat(valid, string(FormatDOCX)); err != nil {
		t.Fatalf("valid DOCX rejected: %v", err)
	}
	for name, data := range map[string][]byte{
		"not a zip":        []byte("PK\x03\x04junk"),
		"missing document": docxFixture(t, "[Content_Types].xml"),
		"macro":            docxFixture(t, "word/document.xml", "[Content_Types].xml", "word/vbaProject.bin"),
		"unsafe path":      docxFixture(t, "word/document.xml", "[Content_Types].xml", "../escape"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DetectFormat(data, string(FormatDOCX)); !errors.Is(err, ErrInvalidUpload) {
				t.Fatalf("error=%v, want invalid upload", err)
			}
		})
	}
}

func TestProcessScansBeforeExtractionAndFailsClosed(t *testing.T) {
	data := []byte("supplier evidence text")
	metadata := metadataFor(data, FormatText)
	var order []string
	scanner := scannerFunc(func(_ context.Context, src io.Reader) error {
		order = append(order, "scan")
		got, _ := io.ReadAll(src)
		if !bytes.Equal(got, data) {
			t.Fatal("scanner received different bytes")
		}
		return nil
	})
	extractor := extractorFunc(func(_ context.Context, format Format, src io.Reader, limit int64) ([]byte, error) {
		order = append(order, "extract")
		if format != FormatText || limit != MaxExtractedSize {
			t.Fatalf("extractor format/limit=%s/%d", format, limit)
		}
		if _, err := io.ReadAll(src); err != nil {
			t.Fatal(err)
		}
		return []byte("bounded extracted text"), nil
	})
	processed, err := Process(context.Background(), metadata, bytes.NewReader(data), scanner, extractor)
	if err != nil || strings.Join(order, ",") != "scan,extract" || string(processed.Text) != "bounded extracted text" || processed.SourceSHA256 != sha256.Sum256(data) {
		t.Fatalf("processed=%+v order=%v err=%v", processed, order, err)
	}

	order = nil
	malware := scannerFunc(func(context.Context, io.Reader) error { order = append(order, "scan"); return ErrMalwareFound })
	if _, err := Process(context.Background(), metadata, bytes.NewReader(data), malware, extractor); !errors.Is(err, ErrMalwareFound) || strings.Join(order, ",") != "scan" {
		t.Fatalf("malware disposition/order=%v err=%v", order, err)
	}

	unavailable := scannerFunc(func(context.Context, io.Reader) error { return errors.New("scanner DSN must not escape") })
	if _, err := Process(context.Background(), metadata, bytes.NewReader(data), unavailable, extractor); err == nil || strings.Contains(err.Error(), "DSN") {
		t.Fatalf("scanner outage was not fail-closed and redacted: %v", err)
	}
	oversizedOutput := extractorFunc(func(context.Context, Format, io.Reader, int64) ([]byte, error) {
		return bytes.Repeat([]byte("x"), int(MaxExtractedSize+1)), nil
	})
	if _, err := Process(context.Background(), metadata, bytes.NewReader(data), scanner, oversizedOutput); !errors.Is(err, ErrOutputLimit) {
		t.Fatalf("oversized extraction error=%v", err)
	}
}

type scannerFunc func(context.Context, io.Reader) error

func (f scannerFunc) Scan(ctx context.Context, src io.Reader) error { return f(ctx, src) }

type extractorFunc func(context.Context, Format, io.Reader, int64) ([]byte, error)

func (f extractorFunc) Extract(ctx context.Context, format Format, src io.Reader, limit int64) ([]byte, error) {
	return f(ctx, format, src, limit)
}

func docxFixture(t *testing.T, names ...string) []byte {
	t.Helper()
	var out bytes.Buffer
	writer := zip.NewWriter(&out)
	for _, name := range names {
		file, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fmt.Fprintf(file, "<document>%s</document>", name); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}
