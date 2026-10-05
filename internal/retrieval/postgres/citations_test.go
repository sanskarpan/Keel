package postgres

import (
	"context"
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
	"github.com/sanskarpan/keel/internal/retrieval/hybrid"
)

type staticCitationRangeReader struct {
	content map[uuid.UUID][]byte
	calls   int
}

func (r *staticCitationRangeReader) ReadCitationRange(_ context.Context, _ tenancy.TenantID, _ string, reference hybrid.CitationRef) ([]byte, error) {
	r.calls++
	return r.content[reference.DocumentVersionID], nil
}

func TestValidateCitationBytesRequiresExactDigestRangeAndUTF8(t *testing.T) {
	content := []byte("safe source excerpt")
	reference := hybrid.CitationRef{StartByte: 10, EndByte: 10 + len(content), ContentDigest: sha256.Sum256(content)}
	if got, err := validateCitationBytes(reference, content); err != nil || got != string(content) {
		t.Fatalf("valid citation content rejected: got=%q err=%v", got, err)
	}
	for name, pair := range map[string]struct {
		reference hybrid.CitationRef
		content   []byte
	}{
		"wrong digest":     {reference: hybrid.CitationRef{StartByte: 0, EndByte: len(content), ContentDigest: sha256.Sum256([]byte("other"))}, content: content},
		"wrong range size": {reference: hybrid.CitationRef{StartByte: 0, EndByte: len(content) + 1, ContentDigest: sha256.Sum256(content)}, content: content},
		"invalid UTF8":     {reference: hybrid.CitationRef{StartByte: 0, EndByte: 1, ContentDigest: sha256.Sum256([]byte{0xff})}, content: []byte{0xff}},
		"blank":            {reference: hybrid.CitationRef{StartByte: 0, EndByte: 3, ContentDigest: sha256.Sum256([]byte(" \t\n"))}, content: []byte(" \t\n")},
		"oversized":        {reference: hybrid.CitationRef{StartByte: 0, EndByte: hybrid.MaxCitationExcerptBytes + 1, ContentDigest: sha256.Sum256([]byte(strings.Repeat("x", hybrid.MaxCitationExcerptBytes+1)))}, content: []byte(strings.Repeat("x", hybrid.MaxCitationExcerptBytes+1))},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := validateCitationBytes(pair.reference, pair.content); err == nil {
				t.Fatal("invalid citation content was accepted")
			}
		})
	}
}
