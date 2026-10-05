// Package index defines the provider-independent tenant-local lexical index.
package index

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"regexp"
	"sort"

	"github.com/google/uuid"
	"github.com/sanskarpan/keel/internal/retrieval/contracts"
)

var stableIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]{1,159}$`)
var visibilityPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]{1,63}$`)

type TermID [32]byte
type TermFrequency struct {
	Term      TermID
	Frequency int
}
type Chunk struct {
	ID                uuid.UUID
	DocumentVersionID uuid.UUID
	Ordinal           int
	StartByte         int
	EndByte           int
	TokenCount        int
	ContentDigest     [32]byte
	TermTenantID      string
	TermKeyID         string
	Terms             []TermFrequency
}
type BuildSpec struct {
	ID             uuid.UUID
	AnalyzerID     string
	ChunkerID      string
	TermKeyID      string
	ManifestDigest [32]byte
	ExpectedChunks int
}
type Build struct {
	ID              uuid.UUID
	Visibility      string
	AnalyzerID      string
	ChunkerID       string
	TermKeyID       string
	ManifestDigest  [32]byte
	ExpectedChunks  int
	ChunkCount      int
	TotalTokenCount int64
	TermCount       int
	State           string
	Generation      int64
}
type TermHasher interface {
	TenantID() string
	KeyID() string
	ID(normalizedTerm string) TermID
}

type HMACTermHasher struct {
	tenantID string
	keyID    string
	key      []byte
}

func NewHMACTermHasher(tenantID, keyID string, key []byte) (HMACTermHasher, error) {
	tenantUUID, err := uuid.Parse(tenantID)
	if err != nil {
		return HMACTermHasher{}, errors.New("term HMAC tenant ID must be a canonical UUID")
	}
	if !stableIDPattern.MatchString(keyID) {
		return HMACTermHasher{}, errors.New("term key ID must be a stable immutable ID")
	}
	if len(key) < 32 {
		return HMACTermHasher{}, errors.New("term HMAC key must contain at least 32 bytes")
	}
	return HMACTermHasher{tenantID: tenantUUID.String(), keyID: keyID, key: append([]byte(nil), key...)}, nil
}
func (h HMACTermHasher) TenantID() string { return h.tenantID }
func (h HMACTermHasher) KeyID() string    { return h.keyID }
func (h HMACTermHasher) ID(term string) TermID {
	mac := hmac.New(sha256.New, h.key)
	_, _ = mac.Write([]byte("keel.retrieval.term.v1\x00"))
	_, _ = mac.Write([]byte(h.tenantID))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(h.keyID))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(term))
	var out TermID
	copy(out[:], mac.Sum(nil))
	return out
}

func ParseVisibilityKey(value string) (string, error) {
	if !visibilityPattern.MatchString(value) {
		return "", errors.New("visibility key must be a stable authorized cohort ID")
	}
	return value, nil
}
func ValidateBuildSpec(s BuildSpec, hasherKeyID string) error {
	if s.ID == uuid.Nil {
		return errors.New("build ID is required")
	}
	if !stableIDPattern.MatchString(s.AnalyzerID) || !stableIDPattern.MatchString(s.ChunkerID) {
		return errors.New("analyzer and chunker IDs must be stable immutable IDs")
	}
	if !stableIDPattern.MatchString(s.TermKeyID) || s.TermKeyID != hasherKeyID {
		return errors.New("build term-key identity does not match hasher")
	}
	if s.ManifestDigest == ([32]byte{}) {
		return errors.New("manifest digest is required")
	}
	if s.ExpectedChunks < 1 || s.ExpectedChunks > 100000 {
		return errors.New("expected chunk count outside [1,100000]")
	}
	return nil
}

// PrepareChunk derives opaque keyed term IDs and a content digest from a K3.1
// chunk; plaintext text and terms are never persisted by the lexical index.
func PrepareChunk(documentVersion uuid.UUID, source contracts.Chunk, hasher TermHasher) (Chunk, error) {
	if documentVersion == uuid.Nil {
		return Chunk{}, errors.New("document version ID is required")
	}
	if hasher == nil || !stableIDPattern.MatchString(hasher.KeyID()) {
		return Chunk{}, errors.New("stable term hasher is required")
	}
	if _, err := uuid.Parse(hasher.TenantID()); err != nil {
		return Chunk{}, errors.New("term hasher must be tenant-bound")
	}
	if source.Ordinal < 0 || source.StartByte < 0 || source.EndByte <= source.StartByte || source.TokenCount < 1 || source.TokenCount > 2048 || len(source.Text) == 0 {
		return Chunk{}, errors.New("source chunk metadata is invalid")
	}
	tokens, err := contracts.Tokenize(source.Text)
	if err != nil {
		return Chunk{}, err
	}
	if len(tokens) != source.TokenCount {
		return Chunk{}, fmt.Errorf("chunk token count mismatch: got %d want %d", len(tokens), source.TokenCount)
	}
	frequencies := map[TermID]int{}
	for _, token := range tokens {
		frequencies[hasher.ID(token.Term)]++
	}
	terms := make([]TermFrequency, 0, len(frequencies))
	for term, frequency := range frequencies {
		terms = append(terms, TermFrequency{Term: term, Frequency: frequency})
	}
	sort.Slice(terms, func(i, j int) bool { return bytes.Compare(terms[i].Term[:], terms[j].Term[:]) < 0 })
	digest := sha256.Sum256([]byte(source.Text))
	return Chunk{ID: uuid.New(), DocumentVersionID: documentVersion, Ordinal: source.Ordinal, StartByte: source.StartByte, EndByte: source.EndByte, TokenCount: source.TokenCount, ContentDigest: digest, TermTenantID: hasher.TenantID(), TermKeyID: hasher.KeyID(), Terms: terms}, nil
}

func ValidateChunk(c Chunk) error {
	if c.ID == uuid.Nil || c.DocumentVersionID == uuid.Nil {
		return errors.New("chunk and document version IDs are required")
	}
	if c.Ordinal < 0 || c.Ordinal > 99999 || c.StartByte < 0 || c.EndByte <= c.StartByte || c.TokenCount < 1 || c.TokenCount > 2048 {
		return errors.New("chunk ordinal, source offsets or token count are invalid")
	}
	if c.ContentDigest == ([32]byte{}) {
		return errors.New("chunk content digest is required")
	}
	if _, err := uuid.Parse(c.TermTenantID); err != nil || !stableIDPattern.MatchString(c.TermKeyID) {
		return errors.New("chunk terms lack tenant/key provenance")
	}
	if len(c.Terms) == 0 || len(c.Terms) > c.TokenCount {
		return errors.New("chunk terms do not fit token count")
	}
	seen := map[TermID]bool{}
	sum := 0
	for _, term := range c.Terms {
		if term.Term == ([32]byte{}) || term.Frequency < 1 || term.Frequency > c.TokenCount || seen[term.Term] {
			return errors.New("invalid or duplicate term frequency")
		}
		seen[term.Term] = true
		sum += term.Frequency
	}
	if sum != c.TokenCount {
		return fmt.Errorf("term frequencies sum to %d, chunk has %d tokens", sum, c.TokenCount)
	}
	return nil
}
