package index

import (
	"bytes"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/sanskarpan/keel/internal/retrieval/contracts"
)

func TestTermHMACIsDeterministicAndKeyScoped(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	tenant := uuid.NewString()
	a, err := NewHMACTermHasher(tenant, "term-key.v1", key)
	if err != nil {
		t.Fatal(err)
	}
	uppercaseTenant, err := NewHMACTermHasher(strings.ToUpper(tenant), "term-key.v1", key)
	if err != nil {
		t.Fatal(err)
	}
	if uppercaseTenant.TenantID() != tenant || uppercaseTenant.ID("invoice") != a.ID("invoice") {
		t.Fatal("tenant UUID textual case changed the canonical term identity")
	}
	b, err := NewHMACTermHasher(tenant, "term-key.v1", key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewHMACTermHasher(tenant, "term-key.v2", bytes.Repeat([]byte{0x24}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if a.ID("invoice") != b.ID("invoice") {
		t.Fatal("same key did not produce a stable term ID")
	}
	if a.ID("invoice") == c.ID("invoice") {
		t.Fatal("different key produced the same term ID")
	}
	otherTenant, err := NewHMACTermHasher(uuid.NewString(), "term-key.v1", key)
	if err != nil {
		t.Fatal(err)
	}
	if a.ID("invoice") == otherTenant.ID("invoice") {
		t.Fatal("same key leaked cross-tenant term equality")
	}
	if a.ID("invoice") == a.ID("Invoice") {
		t.Fatal("term hasher unexpectedly performs normalization")
	}
}

func TestPrepareChunkPinsOffsetsDigestAndTermFrequencies(t *testing.T) {
	hasher, err := NewHMACTermHasher(uuid.NewString(), "term-key.v1", bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	source := contracts.Chunk{Ordinal: 3, Text: "invoice invoice café", StartByte: 10, EndByte: 31, TokenCount: 3}
	prepared, err := PrepareChunk(uuid.New(), source, hasher)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.Ordinal != 3 || prepared.StartByte != 10 || prepared.EndByte != 31 || prepared.TokenCount != 3 {
		t.Fatalf("source metadata changed: %+v", prepared)
	}
	if len(prepared.Terms) != 2 {
		t.Fatalf("got %d term IDs, want repeated invoice folded to one", len(prepared.Terms))
	}
	if err := ValidateChunk(prepared); err != nil {
		t.Fatal(err)
	}
	source.TokenCount = 2
	if _, err := PrepareChunk(uuid.New(), source, hasher); err == nil {
		t.Fatal("wrong K3.1 token count accepted")
	}
}

func TestValidateChunkRejectsMismatchedFrequencies(t *testing.T) {
	term := TermID{1}
	chunk := Chunk{ID: uuid.New(), DocumentVersionID: uuid.New(), Ordinal: 0, StartByte: 0, EndByte: 5, TokenCount: 2, ContentDigest: [32]byte{1}, Terms: []TermFrequency{{Term: term, Frequency: 1}}}
	if err := ValidateChunk(chunk); err == nil {
		t.Fatal("posting frequency mismatch accepted")
	}
}
