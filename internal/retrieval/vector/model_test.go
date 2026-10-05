package vector

import (
	"math"
	"testing"

	"github.com/google/uuid"
)

func testManifest() Manifest {
	return Manifest{ID: "model.unit-test.v1", Revision: "revision-1", Provider: "synthetic-fixture", ArtifactSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", TokenizerID: "tokenizer.v1", AnalyzerID: "keel.unicode-words.v1", MaxInputTokens: 8192, Dimensions: 3, Distance: "cosine", Normalization: "unit_l2"}
}

func TestManifestIdentityIsStrictAndDeterministic(t *testing.T) {
	m := testManifest()
	a, err := m.Digest()
	if err != nil {
		t.Fatal(err)
	}
	b, err := m.Digest()
	if err != nil || a != b {
		t.Fatalf("manifest digest was not deterministic: %x %x %v", a, b, err)
	}
	m.ID = "model-latest"
	if err := m.Validate(); err != nil {
		t.Fatal(err)
	}
	m.Revision = "default"
	m.ArtifactSHA256 = "not-a-digest"
	if err := m.Validate(); err == nil {
		t.Fatal("mutable alias and malformed artifact identity were accepted")
	}
	m = testManifest()
	m.Distance = "l2"
	if err := m.Validate(); err == nil {
		t.Fatal("manifest metric outside the pinned scoring contract was accepted")
	}
}

func TestVectorValidationAndIndependentCosineDistance(t *testing.T) {
	query := []float32{1, 0, 0}
	if err := ValidateVector(query, 3); err != nil {
		t.Fatal(err)
	}
	for name, invalid := range map[string][]float32{
		"wrong dimensions": {1, 0},
		"non-unit":         {1, 1, 0},
		"zero":             {0, 0, 0},
		"nan":              {float32(math.NaN()), 0, 0},
		"infinity":         {float32(math.Inf(1)), 0, 0},
	} {
		t.Run(name, func(t *testing.T) {
			if err := ValidateVector(invalid, 3); err == nil {
				t.Fatal("invalid embedding was accepted")
			}
		})
	}
	distance, err := CosineDistance(query, []float32{0, 1, 0})
	if err != nil || math.Abs(distance-1) > 1e-12 {
		t.Fatalf("orthogonal cosine distance=%v err=%v", distance, err)
	}
	distance, err = CosineDistance(query, []float32{-1, 0, 0})
	if err != nil || math.Abs(distance-2) > 1e-12 {
		t.Fatalf("opposite cosine distance=%v err=%v", distance, err)
	}
}

func TestEmbeddingResponseBindsCountOrderIdentityAndInputBudget(t *testing.T) {
	m := testManifest()
	first, second := uuid.New(), uuid.New()
	inputs := []Input{{ChunkID: first, Text: "first synthetic source", TokenCount: 3}, {ChunkID: second, Text: "second synthetic source", TokenCount: 3}}
	vectors := [][]float32{{1, 0, 0}, {0, 1, 0}}
	if err := ValidateResponse(m, inputs, vectors); err != nil {
		t.Fatal(err)
	}
	if err := ValidateResponse(m, inputs, vectors[:1]); err == nil {
		t.Fatal("provider output count mismatch was accepted")
	}
	inputs[1].ChunkID = first
	if err := ValidateResponse(m, inputs, vectors); err == nil {
		t.Fatal("duplicate source chunk identity was accepted")
	}
	inputs[1].ChunkID = second
	inputs[1].TokenCount = m.MaxInputTokens + 1
	if err := ValidateResponse(m, inputs, vectors); err == nil {
		t.Fatal("model input bound overflow was accepted")
	}
}
