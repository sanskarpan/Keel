// Package vector defines immutable embedding identities and validated vectors.
package vector

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"regexp"

	"github.com/google/uuid"
)

const MaxDimensions = 16000

var stableIdentity = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]{1,159}$`)

type Manifest struct {
	ID             string `json:"id"`
	Revision       string `json:"revision"`
	Provider       string `json:"provider"`
	ArtifactSHA256 string `json:"artifact_sha256"`
	TokenizerID    string `json:"tokenizer_id"`
	AnalyzerID     string `json:"analyzer_id"`
	MaxInputTokens int    `json:"max_input_tokens"`
	Dimensions     int    `json:"dimensions"`
	Distance       string `json:"distance"`
	Normalization  string `json:"normalization"`
}

type Input struct {
	ChunkID    uuid.UUID
	Text       string
	TokenCount int
}

// Embedder is the provider boundary. Implementations must preserve input order;
// the K3.3 core deliberately ships no provider adapter or credentials.
type Embedder interface {
	Manifest() Manifest
	Embed(context.Context, []Input) ([][]float32, error)
}

func (m Manifest) Validate() error {
	if !stableIdentity.MatchString(m.ID) || !stableIdentity.MatchString(m.Revision) || !stableIdentity.MatchString(m.Provider) ||
		!stableIdentity.MatchString(m.TokenizerID) || !stableIdentity.MatchString(m.AnalyzerID) {
		return errors.New("model, provider, tokenizer and analyzer identities must be stable immutable IDs")
	}
	digest, err := hex.DecodeString(m.ArtifactSHA256)
	if err != nil || len(digest) != sha256.Size || m.ArtifactSHA256 != hex.EncodeToString(digest) {
		return errors.New("model artifact digest must be canonical lowercase SHA-256")
	}
	if m.MaxInputTokens < 1 || m.MaxInputTokens > 1_000_000 || m.Dimensions < 1 || m.Dimensions > MaxDimensions {
		return errors.New("model input bound or vector dimension is outside the supported range")
	}
	if m.Distance != "cosine" || m.Normalization != "unit_l2" {
		return errors.New("this retrieval contract requires cosine distance and unit_l2 normalization")
	}
	return nil
}

// Digest returns the canonical manifest digest. The struct field order and
// JSON tags are part of the v1 encoding contract.
func (m Manifest) Digest() ([32]byte, error) {
	if err := m.Validate(); err != nil {
		return [32]byte{}, err
	}
	b, err := json.Marshal(m)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(b), nil
}

// ValidateVector rejects malformed provider or indexer output before it is
// persisted. Unit length tolerance accommodates float32 serialization.
func ValidateVector(values []float32, dimensions int) error {
	if dimensions < 1 || dimensions > MaxDimensions || len(values) != dimensions {
		return errors.New("embedding dimension does not match the immutable model manifest")
	}
	normSquared := 0.0
	for _, value := range values {
		v := float64(value)
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return errors.New("embedding elements must be finite")
		}
		normSquared += v * v
	}
	norm := math.Sqrt(normSquared)
	if norm < 1e-12 || math.Abs(norm-1) > 1e-3 {
		return errors.New("embedding must be nonzero and unit_l2 normalized")
	}
	return nil
}

func ValidateResponse(m Manifest, inputs []Input, vectors [][]float32) error {
	if err := m.Validate(); err != nil {
		return err
	}
	if len(inputs) == 0 || len(inputs) > 512 || len(vectors) != len(inputs) {
		return errors.New("embedding response count must match a nonempty bounded input batch")
	}
	seen := make(map[uuid.UUID]bool, len(inputs))
	for i, input := range inputs {
		if input.ChunkID == uuid.Nil || seen[input.ChunkID] || len(input.Text) == 0 || input.TokenCount < 1 || input.TokenCount > m.MaxInputTokens {
			return errors.New("embedding input has duplicate identity, empty text or exceeds the immutable model input bound")
		}
		seen[input.ChunkID] = true
		if err := ValidateVector(vectors[i], m.Dimensions); err != nil {
			return err
		}
	}
	return nil
}

func CosineDistance(a, b []float32) (float64, error) {
	if len(a) == 0 || len(a) != len(b) {
		return 0, errors.New("cosine vectors must have equal nonzero dimensions")
	}
	var dot, normA, normB float64
	for i := range a {
		x, y := float64(a[i]), float64(b[i])
		if math.IsNaN(x) || math.IsInf(x, 0) || math.IsNaN(y) || math.IsInf(y, 0) {
			return 0, errors.New("cosine vector elements must be finite")
		}
		dot += x * y
		normA += x * x
		normB += y * y
	}
	if normA < 1e-24 || normB < 1e-24 {
		return 0, errors.New("cosine distance is undefined for a zero vector")
	}
	distance := 1 - dot/math.Sqrt(normA*normB)
	if distance < 0 && distance > -1e-12 {
		distance = 0
	}
	if distance > 2 && distance < 2+1e-12 {
		distance = 2
	}
	return distance, nil
}
