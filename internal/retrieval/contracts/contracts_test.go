package contracts

import (
	"strings"
	"testing"
)

func TestTokenizeUsesCompatibilityNormalizationAndRawByteOffsets(t *testing.T) {
	source := "  ＡＣＭＥ-42 café e\u0301 供应商 "
	tokens, err := Tokenize(source)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"acme", "42", "café", "é", "供应商"}
	if len(tokens) != len(want) {
		t.Fatalf("got %d tokens: %#v", len(tokens), tokens)
	}
	for i, token := range tokens {
		if token.Term != want[i] {
			t.Errorf("token %d = %q, want %q", i, token.Term, want[i])
		}
		if source[token.StartByte:token.EndByte] == "" {
			t.Errorf("token %d has empty original span", i)
		}
	}
}

func TestTokenizeRejectsInvalidUTF8AndOversizedSource(t *testing.T) {
	if _, err := Tokenize(string([]byte{0xff})); err != ErrInvalidUTF8 {
		t.Fatalf("invalid UTF-8 error = %v", err)
	}
	if _, err := Tokenize(strings.Repeat("x", MaxDocumentBytes+1)); err == nil {
		t.Fatal("oversized source accepted")
	}
}

func TestChunkDocumentBoundsAndPreservesCitations(t *testing.T) {
	source := "# Heading\n\n" + strings.Repeat("alpha beta gamma ", 8)
	cfg := ChunkConfig{ID: ChunkerID, MaxTokens: 6, OverlapTokens: 2, MaxSourceBytes: 1024, HeadingContext: true}
	chunks, err := ChunkDocument(source, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(chunks) < 2 {
		t.Fatalf("expected bounded windows, got %d", len(chunks))
	}
	for _, chunk := range chunks {
		if chunk.TokenCount > cfg.MaxTokens {
			t.Errorf("chunk exceeds bound: %+v", chunk)
		}
		if chunk.HeadingContext != "Heading" {
			t.Errorf("heading context = %q", chunk.HeadingContext)
		}
		if source[chunk.StartByte:chunk.EndByte] != chunk.Text {
			t.Errorf("citation span does not recover chunk %d", chunk.Ordinal)
		}
	}
	if _, err := ChunkDocument(source, ChunkConfig{ID: ChunkerID, MaxTokens: 4, OverlapTokens: 4, MaxSourceBytes: 1024}); err == nil {
		t.Fatal("invalid overlap accepted")
	}
}
