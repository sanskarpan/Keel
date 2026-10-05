// Package hybrid combines bounded lexical and vector rankings without
// comparing their incompatible native scores.
package hybrid

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/google/uuid"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

const (
	PolicyVersion       = "rrf-v1"
	RRFConstant         = 60
	MaxSourceCandidates = 500
	MaxTopK             = 100
)

type Source string

const (
	Lexical Source = "lexical"
	Vector  Source = "vector"
)

type SourceStatus string

const (
	SourceReady       SourceStatus = "ready"
	SourcePartial     SourceStatus = "partial"
	SourceUnavailable SourceStatus = "unavailable"
)

type Outcome string

const (
	OutcomeComplete    Outcome = "complete"
	OutcomeDegraded    Outcome = "degraded"
	OutcomeUnavailable Outcome = "unavailable"
)

type RerankerStatus string

const (
	RerankerSkipped RerankerStatus = "skipped"
	RerankerApplied RerankerStatus = "applied"
	RerankerFailed  RerankerStatus = "failed"
)

type Scope struct {
	TenantID      tenancy.TenantID
	VisibilityKey string
}

// Snapshot records the immutable publication used by one ranked source.
type Snapshot struct {
	Source           Source
	Status           SourceStatus
	Scope            Scope
	BuildID          uuid.UUID
	Generation       int64
	CorpusBuildID    uuid.UUID // required for an available vector source
	CorpusGeneration int64     // must match the active lexical snapshot
	ModelID          string    // required for vector; forbidden for lexical
	ModelRevision    string    // required for vector; forbidden for lexical
}

// CitationRef is immutable source identity; content is resolved separately
// through an authorization-aware resolver before it is returned to a caller.
type CitationRef struct {
	ChunkID           uuid.UUID
	DocumentVersionID uuid.UUID
	Ordinal           int
	StartByte         int
	EndByte           int
	ContentDigest     [32]byte
}

type SourceCandidate struct {
	Citation CitationRef
}

type SourceResults struct {
	Snapshot   Snapshot
	Candidates []SourceCandidate // ordered best-first; native scores are ignored
}

type Policy struct {
	Version string
	TopK    int
}

func DefaultPolicy(topK int) Policy { return Policy{Version: PolicyVersion, TopK: topK} }

type Candidate struct {
	Citation    CitationRef
	LexicalRank int
	VectorRank  int
	FusedRank   int
	RerankRank  int
	Score       float64
}

type Result struct {
	Outcome         Outcome
	Candidates      []Candidate
	Snapshots       []Snapshot
	DegradedReasons []string
	PolicyVersion   string
	RerankerStatus  RerankerStatus
}

func Fuse(scope Scope, lexical, vector SourceResults, policy Policy) (Result, error) {
	if err := validateScope(scope); err != nil {
		return Result{}, err
	}
	if policy.Version != PolicyVersion || policy.TopK < 1 || policy.TopK > MaxTopK {
		return Result{}, errors.New("unsupported fusion policy or top-k bound")
	}
	if lexical.Snapshot.Source != Lexical || vector.Snapshot.Source != Vector {
		return Result{}, errors.New("fusion requires one lexical and one vector source")
	}
	if err := validateSource(scope, lexical); err != nil {
		return Result{}, fmt.Errorf("lexical source: %w", err)
	}
	if err := validateSource(scope, vector); err != nil {
		return Result{}, fmt.Errorf("vector source: %w", err)
	}
	result := Result{Outcome: OutcomeComplete, PolicyVersion: policy.Version, RerankerStatus: RerankerSkipped}
	for _, source := range []SourceResults{lexical, vector} {
		result.Snapshots = append(result.Snapshots, source.Snapshot)
		if source.Snapshot.Status != SourceReady {
			result.DegradedReasons = append(result.DegradedReasons, string(source.Snapshot.Source)+"_"+string(source.Snapshot.Status))
		}
	}
	if lexical.Snapshot.Status == SourceUnavailable && vector.Snapshot.Status == SourceUnavailable {
		result.Outcome = OutcomeUnavailable
		result.DegradedReasons = []string{"all_sources_unavailable"}
		return result, nil
	}
	if lexical.Snapshot.Status != SourceUnavailable && vector.Snapshot.Status != SourceUnavailable &&
		(vector.Snapshot.CorpusBuildID != lexical.Snapshot.BuildID || vector.Snapshot.CorpusGeneration != lexical.Snapshot.Generation) {
		return Result{}, errors.New("vector source is not bound to the active lexical corpus generation")
	}
	byChunk := make(map[uuid.UUID]*Candidate, len(lexical.Candidates)+len(vector.Candidates))
	lexicalSeen := make(map[uuid.UUID]struct{}, len(lexical.Candidates))
	for rank, sourceCandidate := range lexical.Candidates {
		c := sourceCandidate.Citation
		if err := validateCitation(c); err != nil {
			return Result{}, fmt.Errorf("lexical candidate %d: %w", rank+1, err)
		}
		if _, ok := lexicalSeen[c.ChunkID]; ok {
			return Result{}, errors.New("lexical source returned a duplicate chunk")
		}
		lexicalSeen[c.ChunkID] = struct{}{}
		item := byChunk[c.ChunkID]
		if item == nil {
			item = &Candidate{Citation: c}
			byChunk[c.ChunkID] = item
		} else if item.Citation != c {
			return Result{}, errors.New("duplicate chunk has conflicting immutable citation metadata")
		}
		item.LexicalRank = rank + 1
		item.Score += 1 / float64(RRFConstant+rank+1)
	}
	vectorSeen := make(map[uuid.UUID]struct{}, len(vector.Candidates))
	for rank, sourceCandidate := range vector.Candidates {
		c := sourceCandidate.Citation
		if err := validateCitation(c); err != nil {
			return Result{}, fmt.Errorf("vector candidate %d: %w", rank+1, err)
		}
		if _, ok := vectorSeen[c.ChunkID]; ok {
			return Result{}, errors.New("vector source returned a duplicate chunk")
		}
		vectorSeen[c.ChunkID] = struct{}{}
		item := byChunk[c.ChunkID]
		if item == nil {
			item = &Candidate{Citation: c}
			byChunk[c.ChunkID] = item
		} else if item.Citation != c {
			return Result{}, errors.New("duplicate chunk has conflicting immutable citation metadata")
		}
		item.VectorRank = rank + 1
		item.Score += 1 / float64(RRFConstant+rank+1)
	}
	result.Candidates = make([]Candidate, 0, len(byChunk))
	for _, candidate := range byChunk {
		result.Candidates = append(result.Candidates, *candidate)
	}
	sort.Slice(result.Candidates, func(i, j int) bool {
		if result.Candidates[i].Score != result.Candidates[j].Score {
			return result.Candidates[i].Score > result.Candidates[j].Score
		}
		return result.Candidates[i].Citation.ChunkID.String() < result.Candidates[j].Citation.ChunkID.String()
	})
	if len(result.Candidates) > policy.TopK {
		result.Candidates = result.Candidates[:policy.TopK]
	}
	for i := range result.Candidates {
		result.Candidates[i].FusedRank = i + 1
	}
	if lexical.Snapshot.Status != SourceReady || vector.Snapshot.Status != SourceReady {
		result.Outcome = OutcomeDegraded
	}
	if len(lexical.Candidates) < policy.TopK && lexical.Snapshot.Status != SourceUnavailable {
		result.DegradedReasons = append(result.DegradedReasons, "lexical_underfilled")
		result.Outcome = OutcomeDegraded
	}
	if len(vector.Candidates) < policy.TopK && vector.Snapshot.Status != SourceUnavailable {
		result.DegradedReasons = append(result.DegradedReasons, "vector_underfilled")
		result.Outcome = OutcomeDegraded
	}
	if len(result.Candidates) == 0 {
		if result.Outcome == OutcomeComplete {
			result.Outcome = OutcomeDegraded
		}
		result.DegradedReasons = append(result.DegradedReasons, "no_candidates")
	}
	return result, nil
}

func validateScope(scope Scope) error {
	if _, err := tenancy.ParseTenantID(string(scope.TenantID)); err != nil {
		return errors.New("trusted canonical tenant scope is required")
	}
	if len(scope.VisibilityKey) < 2 || len(scope.VisibilityKey) > 64 {
		return errors.New("visibility cohort is outside supported bounds")
	}
	for i, r := range scope.VisibilityKey {
		if !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') && !strings.ContainsRune("._:-", r) {
			return errors.New("visibility cohort contains an invalid character")
		}
		if i == 0 && !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') {
			return errors.New("visibility cohort must start with a lowercase letter or digit")
		}
	}
	return nil
}

func validateSource(scope Scope, source SourceResults) error {
	s := source.Snapshot
	if s.Status != SourceReady && s.Status != SourcePartial && s.Status != SourceUnavailable {
		return errors.New("unknown source status")
	}
	if s.Scope != scope {
		return errors.New("source scope or immutable build generation does not match request")
	}
	if s.Status == SourceUnavailable {
		if len(source.Candidates) != 0 {
			return errors.New("unavailable source cannot contribute candidates")
		}
		return nil // a failed source may have no active publication to identify
	}
	if s.BuildID == uuid.Nil || s.Generation < 1 {
		return errors.New("available source requires an immutable build generation")
	}
	if s.Source == Lexical && (s.ModelID != "" || s.ModelRevision != "") {
		return errors.New("lexical source cannot claim a vector model identity")
	}
	if s.Source == Vector && (s.ModelID == "" || s.ModelRevision == "") {
		return errors.New("vector source requires a model identity")
	}
	if s.Source == Vector && (s.CorpusBuildID == uuid.Nil || s.CorpusGeneration < 1) {
		return errors.New("vector source requires its exact lexical corpus snapshot")
	}
	if s.Source == Lexical && (s.CorpusBuildID != uuid.Nil || s.CorpusGeneration != 0) {
		return errors.New("lexical source cannot claim a vector corpus snapshot")
	}
	if len(source.Candidates) > MaxSourceCandidates {
		return errors.New("source candidate count exceeds fusion bound")
	}
	return nil
}

func validateCitation(c CitationRef) error {
	if c.ChunkID == uuid.Nil || c.DocumentVersionID == uuid.Nil || c.Ordinal < 0 || c.StartByte < 0 || c.EndByte <= c.StartByte ||
		c.ContentDigest == [32]byte{} {
		return errors.New("citation must identify an immutable nonempty source range")
	}
	return nil
}

// Check that floating point scores stay finite if policy changes are added in a
// future, versioned contract. It is kept separate so callers can validate
// serialized results at the API boundary too.
func ValidateResult(result Result) error {
	if result.PolicyVersion != PolicyVersion || (result.Outcome != OutcomeComplete && result.Outcome != OutcomeDegraded && result.Outcome != OutcomeUnavailable) {
		return errors.New("hybrid result has an unsupported policy or outcome")
	}
	if result.Outcome == OutcomeUnavailable && len(result.Candidates) != 0 {
		return errors.New("unavailable hybrid result cannot contain candidates")
	}
	if result.RerankerStatus != RerankerSkipped && result.RerankerStatus != RerankerApplied && result.RerankerStatus != RerankerFailed {
		return errors.New("hybrid result has an unsupported reranker status")
	}
	if len(result.Snapshots) != 2 || result.Snapshots[0].Source != Lexical || result.Snapshots[1].Source != Vector ||
		result.Snapshots[0].Scope != result.Snapshots[1].Scope {
		return errors.New("hybrid result must retain scoped lexical and vector snapshots")
	}
	lexical, vector := result.Snapshots[0], result.Snapshots[1]
	if err := validateScope(lexical.Scope); err != nil {
		return err
	}
	if err := validateSource(lexical.Scope, SourceResults{Snapshot: lexical}); err != nil {
		return fmt.Errorf("invalid lexical snapshot: %w", err)
	}
	if err := validateSource(lexical.Scope, SourceResults{Snapshot: vector}); err != nil {
		return fmt.Errorf("invalid vector snapshot: %w", err)
	}
	if lexical.Status != SourceUnavailable && vector.Status != SourceUnavailable &&
		(vector.CorpusBuildID != lexical.BuildID || vector.CorpusGeneration != lexical.Generation) {
		return errors.New("hybrid result source snapshots have mismatched corpus generations")
	}
	ranks := make(map[int]struct{}, len(result.Candidates))
	rerankRanks := make(map[int]struct{}, len(result.Candidates))
	chunks := make(map[uuid.UUID]struct{}, len(result.Candidates))
	for _, candidate := range result.Candidates {
		if err := validateCitation(candidate.Citation); err != nil {
			return err
		}
		if candidate.FusedRank < 1 || candidate.Score <= 0 || candidate.Score > 2 || candidate.Score != candidate.Score {
			return errors.New("hybrid result rank or score is invalid")
		}
		if _, ok := ranks[candidate.FusedRank]; ok {
			return errors.New("hybrid result has duplicate fused ranks")
		}
		if candidate.RerankRank < 0 || candidate.RerankRank > MaxRerankCandidates {
			return errors.New("hybrid result rerank rank is outside the bounded range")
		}
		if candidate.RerankRank > 0 {
			if _, ok := rerankRanks[candidate.RerankRank]; ok {
				return errors.New("hybrid result has duplicate rerank ranks")
			}
			rerankRanks[candidate.RerankRank] = struct{}{}
		}
		if _, ok := chunks[candidate.Citation.ChunkID]; ok {
			return errors.New("hybrid result has duplicate chunk IDs")
		}
		ranks[candidate.FusedRank] = struct{}{}
		chunks[candidate.Citation.ChunkID] = struct{}{}
	}
	return nil
}
