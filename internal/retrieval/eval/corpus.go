// Package eval validates the small, explicitly non-production retrieval corpus.
package eval

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/sanskarpan/keel/internal/retrieval/contracts"
)

const SchemaVersion = "keel.retrieval-eval.v1"
const maxCorpusBytes = 16 << 20

type Corpus struct {
	SchemaVersion string         `json:"schema_version"`
	DatasetID     string         `json:"dataset_id"`
	License       string         `json:"license"`
	SyntheticOnly bool           `json:"synthetic_only"`
	Documents     []Document     `json:"documents"`
	Queries       []Query        `json:"queries"`
	AccessDenials []AccessDenial `json:"access_denials"`
}
type Document struct {
	ID         string `json:"id"`
	Version    string `json:"version"`
	Tenant     string `json:"tenant"`
	Visibility string `json:"visibility"`
	Published  bool   `json:"published"`
	Text       string `json:"text"`
}
type Query struct {
	ID         string     `json:"id"`
	Partition  string     `json:"partition"`
	Text       string     `json:"text"`
	Tenant     string     `json:"tenant"`
	Visibility string     `json:"visibility"`
	Rationale  string     `json:"rationale"`
	NoAnswer   bool       `json:"no_answer"`
	Judgments  []Judgment `json:"judgments"`
}
type Judgment struct {
	DocumentID      string `json:"document_id"`
	DocumentVersion string `json:"document_version"`
	Grade           int    `json:"grade"`
	StartByte       int    `json:"start_byte"`
	EndByte         int    `json:"end_byte"`
	Rationale       string `json:"rationale"`
}
type AccessDenial struct {
	QueryID         string `json:"query_id"`
	DocumentID      string `json:"document_id"`
	DocumentVersion string `json:"document_version"`
	Rationale       string `json:"rationale"`
}
type BuildManifest struct {
	ManifestVersion        string                `json:"manifest_version"`
	AnalyzerID             string                `json:"analyzer_id"`
	Chunker                contracts.ChunkConfig `json:"chunker"`
	EmbeddingModel         ModelManifest         `json:"embedding_model"`
	CorpusBuildID          string                `json:"corpus_build_id"`
	Distance               string                `json:"distance"`
	EvaluationDatasetID    string                `json:"evaluation_dataset_id"`
	EvaluationCorpusSHA256 string                `json:"evaluation_corpus_sha256"`
	EvaluationOnly         bool                  `json:"evaluation_only"`
}
type ModelManifest struct {
	ID             string `json:"id"`
	Provider       string `json:"provider"`
	Revision       string `json:"revision"`
	ArtifactSHA256 string `json:"artifact_sha256"`
	TokenizerID    string `json:"tokenizer_id"`
	Dimensions     int    `json:"dimensions"`
	MaxInputTokens int    `json:"max_input_tokens"`
	Normalize      bool   `json:"normalize"`
}

// Load uses strict JSON decoding so an accidental/unsupported field cannot be
// silently omitted from a corpus review or digest.
func Load(path string) (Corpus, []byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return Corpus{}, nil, err
	}
	if info.Size() > maxCorpusBytes {
		return Corpus{}, nil, fmt.Errorf("corpus file exceeds %d bytes", maxCorpusBytes)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return Corpus{}, nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var c Corpus
	if err := dec.Decode(&c); err != nil {
		return c, nil, fmt.Errorf("decode corpus: %w", err)
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return c, nil, errors.New("corpus must contain exactly one JSON value")
	}
	return c, b, nil
}

func ValidateManifest(m BuildManifest) error {
	if m.ManifestVersion != "keel.retrieval-build.v1" {
		return errors.New("unsupported manifest_version")
	}
	if m.AnalyzerID != contracts.AnalyzerID {
		return errors.New("analyzer_id must pin a supported immutable analyzer")
	}
	if m.Chunker.ID != contracts.ChunkerID || m.Chunker.MaxTokens < 1 || m.Chunker.MaxTokens > 2048 || m.Chunker.OverlapTokens >= m.Chunker.MaxTokens || m.Chunker.OverlapTokens < 0 || m.Chunker.MaxSourceBytes < 1 || m.Chunker.MaxSourceBytes > contracts.MaxDocumentBytes {
		return errors.New("chunker identity or bounds are invalid")
	}
	x := m.EmbeddingModel
	if !stableID(x.ID) || !stableID(x.Revision) || !stableID(x.TokenizerID) {
		return errors.New("embedding model, revision and tokenizer must be immutable IDs")
	}
	if x.Provider == "" || x.Dimensions < 1 || x.Dimensions > 8192 || x.MaxInputTokens < 1 || x.MaxInputTokens > 1_000_000 || x.TokenizerID != m.AnalyzerID {
		return errors.New("embedding model provider/dimensions/input limit are invalid")
	}
	if len(x.ArtifactSHA256) != 64 {
		return errors.New("embedding artifact SHA-256 must be pinned")
	}
	if _, err := hex.DecodeString(x.ArtifactSHA256); err != nil {
		return errors.New("embedding artifact SHA-256 is malformed")
	}
	if m.Distance != "cosine" && m.Distance != "dot" && m.Distance != "l2" {
		return errors.New("distance must be cosine, dot or l2")
	}
	if !stableID(m.CorpusBuildID) || !stableID(m.EvaluationDatasetID) {
		return errors.New("corpus build and evaluation dataset IDs must be immutable")
	}
	if len(m.EvaluationCorpusSHA256) != 64 {
		return errors.New("evaluation corpus SHA-256 must be pinned")
	}
	if _, err := hex.DecodeString(m.EvaluationCorpusSHA256); err != nil {
		return errors.New("evaluation corpus SHA-256 is malformed")
	}
	if !m.EvaluationOnly {
		return errors.New("K3.1 model identity must remain evaluation_only")
	}
	return nil
}

func stableID(v string) bool {
	if len(v) < 2 || len(v) > 160 || strings.Contains(strings.ToLower(v), "latest") || strings.Contains(strings.ToLower(v), "default") {
		return false
	}
	for _, r := range v {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._:-", r)) {
			return false
		}
	}
	return true
}

// Validate checks source references, eligibility, offsets, label completeness,
// split integrity and exact/near-duplicate leakage. It is intentionally O(n²)
// with strict count, text-byte and token bounds for a reviewable seed corpus.
func Validate(c Corpus) error {
	if c.SchemaVersion != SchemaVersion {
		return errors.New("unsupported corpus schema_version")
	}
	if !stableID(c.DatasetID) {
		return errors.New("dataset_id must be immutable")
	}
	if c.License != "CC0-1.0" || !c.SyntheticOnly {
		return errors.New("corpus must be synthetic-only and licensed CC0-1.0")
	}
	if len(c.Documents) == 0 || len(c.Documents) > 1000 || len(c.Queries) == 0 || len(c.Queries) > 512 {
		return errors.New("corpus size outside deterministic validation bounds")
	}
	docs := make(map[string]Document, len(c.Documents))
	docTerms := make(map[string][]string, len(c.Documents))
	totalBytes, totalTokens := 0, 0
	for _, d := range c.Documents {
		key := d.ID + "@" + d.Version
		if !stableID(d.ID) || !stableID(d.Version) || len(d.Text) == 0 || len(d.Text) > contracts.MaxDocumentBytes {
			return fmt.Errorf("invalid document identity or text for %q", d.ID)
		}
		if !d.Published || d.Tenant == "" || d.Visibility == "" {
			return fmt.Errorf("document %q is not eligible or lacks access scope", d.ID)
		}
		if _, ok := docs[key]; ok {
			return fmt.Errorf("duplicate document version %q", key)
		}
		totalBytes += len(d.Text)
		tokens, err := contracts.Tokenize(d.Text)
		if err != nil {
			return fmt.Errorf("document %q: %w", d.ID, err)
		}
		if len(tokens) > 10000 {
			return fmt.Errorf("document %q exceeds evaluation corpus token bound", d.ID)
		}
		terms := make([]string, len(tokens))
		for i, t := range tokens {
			terms[i] = t.Term
		}
		docTerms[key] = terms
		totalTokens += len(terms)
		docs[key] = d
	}
	seen := map[string]bool{}
	var queries []Query
	queryTermsByID := make(map[string][]string, len(c.Queries))
	for _, q := range c.Queries {
		if !stableID(q.ID) || seen[q.ID] {
			return fmt.Errorf("invalid or duplicate query ID %q", q.ID)
		}
		seen[q.ID] = true
		if q.Partition != "train" && q.Partition != "dev" && q.Partition != "holdout" {
			return fmt.Errorf("query %q has invalid partition", q.ID)
		}
		terms, err := contracts.NormalizeQuery(q.Text, 64)
		if err != nil || len(terms) == 0 {
			return fmt.Errorf("query %q must have 1-64 valid terms", q.ID)
		}
		queryTermsByID[q.ID] = terms
		totalBytes += len(q.Text)
		totalTokens += len(terms)
		if q.Tenant == "" || q.Visibility == "" || strings.TrimSpace(q.Rationale) == "" || len(q.Judgments) == 0 {
			return fmt.Errorf("query %q lacks access scope, rationale or judgments", q.ID)
		}
		judged, positive := map[string]bool{}, false
		for _, j := range q.Judgments {
			key := j.DocumentID + "@" + j.DocumentVersion
			d, ok := docs[key]
			if !ok || judged[key] {
				return fmt.Errorf("query %q refers to missing or duplicate source %q", q.ID, key)
			}
			judged[key] = true
			if j.Grade < 0 || j.Grade > 3 || strings.TrimSpace(j.Rationale) == "" {
				return fmt.Errorf("query %q has invalid relevance judgment", q.ID)
			}
			if d.Tenant != q.Tenant || d.Visibility != q.Visibility {
				return fmt.Errorf("query %q judgment crosses its tenant/visibility scope", q.ID)
			}
			if j.Grade > 0 {
				positive = true
				if j.StartByte < 0 || j.EndByte <= j.StartByte || j.EndByte > len(d.Text) || !isRuneBoundary(d.Text, j.StartByte) || !isRuneBoundary(d.Text, j.EndByte) {
					return fmt.Errorf("query %q has invalid citation span", q.ID)
				}
				if strings.TrimSpace(d.Text[j.StartByte:j.EndByte]) == "" {
					return fmt.Errorf("query %q has empty citation span", q.ID)
				}
			} else if j.StartByte != 0 || j.EndByte != 0 {
				return fmt.Errorf("query %q hard negative must not include a relevant span", q.ID)
			}
		}
		// A no-answer query is represented by hard-negative labels only.
		if q.NoAnswer && positive {
			return fmt.Errorf("query %q is no-answer but has positive labels", q.ID)
		}
		if !q.NoAnswer && !positive {
			return fmt.Errorf("query %q requires at least one positive relevance label", q.ID)
		}
		queries = append(queries, q)
	}
	if totalBytes > maxCorpusBytes || totalTokens > 500000 {
		return errors.New("corpus exceeds total byte/token validation bounds")
	}
	queryByID := map[string]Query{}
	for _, q := range queries {
		queryByID[q.ID] = q
	}
	denied := map[string]bool{}
	denialsPerQuery := map[string]int{}
	for _, x := range c.AccessDenials {
		q, qok := queryByID[x.QueryID]
		key := x.DocumentID + "@" + x.DocumentVersion
		d, dok := docs[key]
		if !qok || !dok || strings.TrimSpace(x.Rationale) == "" {
			return errors.New("access denial fixture must reference a query, document and rationale")
		}
		if d.Tenant == q.Tenant && d.Visibility == q.Visibility {
			return fmt.Errorf("access denial %s/%s is actually in scope", x.QueryID, key)
		}
		if denied[x.QueryID+"|"+key] {
			return fmt.Errorf("duplicate access denial fixture %s/%s", x.QueryID, key)
		}
		denied[x.QueryID+"|"+key] = true
		denialsPerQuery[x.QueryID]++
		for _, j := range q.Judgments {
			if j.DocumentID == x.DocumentID && j.DocumentVersion == x.DocumentVersion {
				return fmt.Errorf("ineligible source %s appears in query judgments", key)
			}
		}
	}
	for i := 0; i < len(queries); i++ {
		for j := i + 1; j < len(queries); j++ {
			if queries[i].Partition == queries[j].Partition {
				continue
			}
			if nearDuplicateTerms(queryTermsByID[queries[i].ID], queryTermsByID[queries[j].ID]) {
				return fmt.Errorf("near-duplicate queries leak across %s and %s", queries[i].Partition, queries[j].Partition)
			}
		}
	}
	for _, q := range queries {
		if denialsPerQuery[q.ID] == 0 {
			return fmt.Errorf("query %q is missing an out-of-scope access denial fixture", q.ID)
		}
	}
	// A version belongs to one partition only, preventing source memorization.
	docPartitions := map[string]string{}
	partitionDocs := map[string][][]string{}
	for _, q := range queries {
		for _, label := range q.Judgments {
			key := label.DocumentID + "@" + label.DocumentVersion
			if prior, ok := docPartitions[key]; ok && prior != q.Partition {
				return fmt.Errorf("document version %q leaks across partitions", key)
			}
			docPartitions[key] = q.Partition
			partitionDocs[q.Partition] = append(partitionDocs[q.Partition], docTerms[key])
		}
	}
	partitions := []string{"train", "dev", "holdout"}
	for i := 0; i < len(partitions); i++ {
		for j := i + 1; j < len(partitions); j++ {
			for _, a := range partitionDocs[partitions[i]] {
				for _, b := range partitionDocs[partitions[j]] {
					if nearDuplicateTerms(a, b) {
						return fmt.Errorf("near-duplicate source documents leak across %s and %s", partitions[i], partitions[j])
					}
				}
			}
		}
	}
	return nil
}

func isRuneBoundary(s string, i int) bool {
	return i >= 0 && i <= len(s) && (i == len(s) || i == 0 || s[i]&0xc0 != 0x80)
}
func nearDuplicateTerms(ta, tb []string) bool {
	// Compare token bigram sets. Similarity >= .80 flags near copies while
	// ordinary shared topic vocabulary remains below the threshold.
	shingles := func(t []string) map[string]bool {
		out := map[string]bool{}
		if len(t) < 2 {
			for _, x := range t {
				out[x] = true
			}
			return out
		}
		for i := 0; i < len(t)-1; i++ {
			out[t[i]+" "+t[i+1]] = true
		}
		return out
	}
	sa, sb := shingles(ta), shingles(tb)
	if len(sa) == 0 || len(sb) == 0 {
		return false
	}
	inter := 0
	for x := range sa {
		if sb[x] {
			inter++
		}
	}
	return float64(inter)/float64(len(sa)+len(sb)-inter) >= .80
}

func CanonicalDigest(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}

func Partitions(c Corpus) []string {
	set := map[string]bool{}
	for _, q := range c.Queries {
		set[q.Partition] = true
	}
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}
