package hybrid

import (
	"context"
	"errors"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
)

const (
	MaxRerankCandidates = 50
	MaxRerankItemBytes  = 8192
	MaxRerankBatchBytes = 64 << 10
	MaxRerankDeadline   = 500 * time.Millisecond
)

type RerankInput struct {
	ChunkID uuid.UUID
	Text    string
}

// Reranker adapters must honor context cancellation, avoid logging input text,
// and return only a permutation of the bounded candidate IDs they received.
type Reranker interface {
	Rerank(context.Context, []RerankInput) ([]uuid.UUID, error)
}

// ApplyReranker accepts only citation-resolved candidates and never retrieves
// or authorizes source text itself.
func ApplyReranker(ctx context.Context, result Result, reranker Reranker, cited []CitedCandidate, deadline time.Duration) (Result, error) {
	if ctx == nil {
		return Result{}, errors.New("reranker context is required")
	}
	if err := ValidateResult(result); err != nil {
		return Result{}, err
	}
	if result.Outcome == OutcomeUnavailable {
		result.RerankerStatus = RerankerSkipped
		return result, nil
	}
	if reranker == nil {
		result.RerankerStatus = RerankerSkipped
		result.DegradedReasons = appendReason(result.DegradedReasons, "reranker_skipped")
		return result, nil
	}
	if deadline <= 0 || deadline > MaxRerankDeadline {
		return Result{}, errors.New("reranker deadline exceeds supported bound")
	}
	count := len(result.Candidates)
	if count > MaxRerankCandidates {
		count = MaxRerankCandidates
	}
	if count == 0 {
		result.RerankerStatus = RerankerSkipped
		result.DegradedReasons = appendReason(result.DegradedReasons, "reranker_no_candidates")
		return result, nil
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if len(cited) != count {
		return rerankerFailure(result, errors.New("reranker input count must equal its capped candidate set")), nil
	}
	inputs := make([]RerankInput, count)
	seen := make(map[uuid.UUID]struct{}, len(inputs))
	ids := make(map[uuid.UUID]struct{}, len(inputs))
	totalBytes := 0
	for i, authorized := range cited {
		if authorized.Candidate.Citation != result.Candidates[i].Citation {
			return rerankerFailure(result, errors.New("reranker citation candidates must match fused order")), nil
		}
		input := RerankInput{ChunkID: authorized.Candidate.Citation.ChunkID, Text: authorized.Excerpt}
		if input.ChunkID == uuid.Nil || input.Text == "" || len(input.Text) > MaxRerankItemBytes || !utf8.ValidString(input.Text) {
			return rerankerFailure(result, errors.New("reranker candidates must match fused order and per-item byte limit")), nil
		}
		if _, ok := seen[input.ChunkID]; ok {
			return rerankerFailure(result, errors.New("reranker input contains duplicate chunk IDs")), nil
		}
		seen[input.ChunkID] = struct{}{}
		ids[input.ChunkID] = struct{}{}
		totalBytes += len(input.Text)
		if totalBytes > MaxRerankBatchBytes {
			return rerankerFailure(result, errors.New("reranker input exceeds aggregate byte limit")), nil
		}
		inputs[i] = input
	}
	rankCtx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()
	ranked, err := reranker.Rerank(rankCtx, append([]RerankInput(nil), inputs...))
	if err != nil {
		return rerankerFailure(result, err), nil
	}
	if len(ranked) != count {
		return rerankerFailure(result, errors.New("reranker must return every capped candidate exactly once")), nil
	}
	positions := make(map[uuid.UUID]int, len(ranked))
	for i, id := range ranked {
		if _, ok := ids[id]; !ok {
			return rerankerFailure(result, errors.New("reranker returned a foreign candidate ID")), nil
		}
		if _, ok := positions[id]; ok {
			return rerankerFailure(result, errors.New("reranker returned a duplicate candidate ID")), nil
		}
		positions[id] = i + 1
	}
	for i := range result.Candidates[:count] {
		result.Candidates[i].RerankRank = positions[result.Candidates[i].Citation.ChunkID]
	}
	sortCandidatesByRerank(result.Candidates[:count])
	result.RerankerStatus = RerankerApplied
	return result, nil
}

func rerankerFailure(result Result, cause error) Result {
	result.RerankerStatus = RerankerFailed
	result.Outcome = OutcomeDegraded
	result.DegradedReasons = appendReason(result.DegradedReasons, "reranker_failed")
	_ = cause // never expose provider details, text, or secrets in the result
	return result
}

func sortCandidatesByRerank(candidates []Candidate) {
	// All reranked candidates have a unique positive rank.
	for i := 1; i < len(candidates); i++ {
		for j := i; j > 0 && candidates[j].RerankRank < candidates[j-1].RerankRank; j-- {
			candidates[j], candidates[j-1] = candidates[j-1], candidates[j]
		}
	}
}
