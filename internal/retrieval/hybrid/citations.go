package hybrid

import (
	"context"
	"errors"
	"strings"
	"unicode/utf8"
)

const MaxCitationExcerptBytes = 4096

var ErrCitationNotAuthorized = errors.New("citation is not currently authorized")

// CitationResolver MUST re-read current source visibility/ACL and withdrawal
// state on every call. It is the K3.5 integration boundary, not a cached build
// membership check. The returned reference must exactly match the input.
type CitationResolver interface {
	ResolveCitation(context.Context, Scope, CitationRef) (ResolvedCitation, error)
}

type ResolvedCitation struct {
	Reference CitationRef
	Excerpt   string
}

type CitedCandidate struct {
	Candidate Candidate
	Excerpt   string
}

func ResolveCitations(ctx context.Context, resolver CitationResolver, scope Scope, result Result) (Result, []CitedCandidate, error) {
	if ctx == nil || resolver == nil {
		return Result{}, nil, errors.New("citation context and resolver are required")
	}
	if err := validateScope(scope); err != nil {
		return Result{}, nil, err
	}
	if err := ValidateResult(result); err != nil {
		return Result{}, nil, err
	}
	if len(result.Snapshots) != 2 || result.Snapshots[0].Source != Lexical || result.Snapshots[1].Source != Vector ||
		result.Snapshots[0].Scope != scope || result.Snapshots[1].Scope != scope {
		return Result{}, nil, errors.New("citation resolution requires both source snapshots in the authorized scope")
	}
	if result.Outcome == OutcomeUnavailable {
		return result, []CitedCandidate{}, nil
	}
	hadCandidates := len(result.Candidates) > 0
	resolved := make([]CitedCandidate, 0, len(result.Candidates))
	authorized := make([]Candidate, 0, len(result.Candidates))
	for _, candidate := range result.Candidates {
		if err := ctx.Err(); err != nil {
			return Result{}, nil, err
		}
		citation, err := resolver.ResolveCitation(ctx, scope, candidate.Citation)
		if err != nil {
			if errors.Is(err, ErrCitationNotAuthorized) {
				result.DegradedReasons = appendReason(result.DegradedReasons, "citation_suppressed")
				result.Outcome = OutcomeDegraded
				continue
			}
			if ctx.Err() != nil {
				return Result{}, nil, ctx.Err()
			}
			// If current authorization cannot be checked, fail closed for the
			// entire response; stale rank snippets must not escape.
			result.DegradedReasons = appendReason(result.DegradedReasons, "citation_resolution_failed")
			result.Outcome = OutcomeUnavailable
			result.Candidates = []Candidate{}
			return result, []CitedCandidate{}, nil
		}
		if citation.Reference != candidate.Citation || len(citation.Excerpt) > MaxCitationExcerptBytes ||
			!utf8.ValidString(citation.Excerpt) || strings.TrimSpace(citation.Excerpt) == "" {
			result.DegradedReasons = appendReason(result.DegradedReasons, "citation_integrity_failed")
			result.Outcome = OutcomeDegraded
			continue
		}
		resolved = append(resolved, CitedCandidate{Candidate: candidate, Excerpt: citation.Excerpt})
		authorized = append(authorized, candidate)
	}
	result.Candidates = authorized
	if len(resolved) == 0 && hadCandidates {
		result.DegradedReasons = appendReason(result.DegradedReasons, "no_authorized_citations")
		result.Outcome = OutcomeUnavailable
		result.Candidates = []Candidate{}
	}
	return result, resolved, nil
}

func appendReason(reasons []string, reason string) []string {
	for _, existing := range reasons {
		if existing == reason {
			return reasons
		}
	}
	return append(reasons, reason)
}
