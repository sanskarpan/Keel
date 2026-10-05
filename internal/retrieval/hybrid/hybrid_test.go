package hybrid

import (
	"context"
	"crypto/sha256"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

func TestFuseUsesDeterministicRRFAndBoundSourceSnapshots(t *testing.T) {
	scope, lexical, vector, ids := fixture()
	result, err := Fuse(scope, lexical, vector, DefaultPolicy(3))
	if err != nil {
		t.Fatal(err)
	}
	if result.Outcome != OutcomeComplete || result.PolicyVersion != PolicyVersion || len(result.Candidates) != 3 {
		t.Fatalf("unexpected fusion result: %+v", result)
	}
	// b is first in both lists and therefore outranks each single-source result.
	if result.Candidates[0].Citation.ChunkID != ids[1] || result.Candidates[0].LexicalRank != 2 || result.Candidates[0].VectorRank != 1 ||
		result.Candidates[1].Citation.ChunkID != ids[0] || result.Candidates[1].LexicalRank != 1 || result.Candidates[1].VectorRank != 3 {
		t.Fatalf("RRF rank/provenance mismatch: %+v", result.Candidates)
	}
	if math.Abs(result.Candidates[0].Score-(1.0/62+1.0/61)) > 1e-15 || math.Abs(result.Candidates[1].Score-(1.0/61+1.0/63)) > 1e-15 {
		t.Fatalf("unexpected RRF scores: %+v", result.Candidates)
	}
	if err := ValidateResult(result); err != nil {
		t.Fatal(err)
	}
}

func TestFuseFailsClosedForScopeGenerationDuplicatesAndCitationConflict(t *testing.T) {
	scope, lexical, vector, _ := fixture()
	wrongScope := vector
	wrongScope.Snapshot.Scope.VisibilityKey = "other-cohort"
	if _, err := Fuse(scope, lexical, wrongScope, DefaultPolicy(5)); err == nil {
		t.Fatal("cross-cohort source was accepted")
	}
	stale := vector
	stale.Snapshot.CorpusGeneration++
	if _, err := Fuse(scope, lexical, stale, DefaultPolicy(5)); err == nil {
		t.Fatal("vector generation not bound to lexical generation")
	}
	duplicate := lexical
	duplicate.Candidates = append(append([]SourceCandidate(nil), lexical.Candidates...), lexical.Candidates[0])
	if _, err := Fuse(scope, duplicate, vector, DefaultPolicy(5)); err == nil {
		t.Fatal("duplicate source candidate was accepted")
	}
	conflict := vector
	conflict.Candidates = append([]SourceCandidate(nil), vector.Candidates...)
	conflict.Candidates[0].Citation.ContentDigest[0]++
	if _, err := Fuse(scope, lexical, conflict, DefaultPolicy(5)); err == nil {
		t.Fatal("same chunk with conflicting immutable citation was accepted")
	}
}

func TestFuseRepresentsMissingPartialAndUnavailableSources(t *testing.T) {
	scope, lexical, vector, _ := fixture()
	vector.Snapshot.Status = SourceUnavailable
	vector.Snapshot.BuildID = uuid.Nil
	vector.Snapshot.Generation = 0
	vector.Snapshot.CorpusBuildID = uuid.Nil
	vector.Snapshot.CorpusGeneration = 0
	vector.Candidates = nil
	result, err := Fuse(scope, lexical, vector, DefaultPolicy(5))
	if err != nil || result.Outcome != OutcomeDegraded || len(result.Candidates) == 0 {
		t.Fatalf("one-source fallback not explicit: result=%+v err=%v", result, err)
	}
	lexical.Snapshot.Status = SourceUnavailable
	lexical.Snapshot.BuildID = uuid.Nil
	lexical.Snapshot.Generation = 0
	lexical.Candidates = nil
	allDown, err := Fuse(scope, lexical, vector, DefaultPolicy(5))
	if err != nil || allDown.Outcome != OutcomeUnavailable || len(allDown.Candidates) != 0 {
		t.Fatalf("all-source outage not explicit: result=%+v err=%v", allDown, err)
	}
	_, lexical, vector, _ = fixture()
	lexical.Snapshot.Status = SourcePartial
	partial, err := Fuse(scope, lexical, vector, DefaultPolicy(5))
	if err != nil || partial.Outcome != OutcomeDegraded {
		t.Fatalf("partial source not marked degraded: result=%+v err=%v", partial, err)
	}
}

func TestApplyRerankerCapsAndPreservesFusedProvenance(t *testing.T) {
	scope, lexical, vector, ids := fixture()
	result, err := Fuse(scope, lexical, vector, DefaultPolicy(3))
	if err != nil {
		t.Fatal(err)
	}
	inputs := authorizedCitations(result, "safe authorized excerpt")
	fake := &fakeReranker{rank: []uuid.UUID{ids[2], ids[1], ids[0]}}
	got, err := ApplyReranker(context.Background(), result, fake, inputs, 100*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if got.RerankerStatus != RerankerApplied || got.Candidates[0].Citation.ChunkID != ids[2] || got.Candidates[0].FusedRank != 3 || got.Candidates[0].RerankRank != 1 {
		t.Fatalf("reranker order/provenance mismatch: %+v", got)
	}
	if fake.count != 3 {
		t.Fatalf("reranker received %d candidates, want capped set of 3", fake.count)
	}
}

func TestApplyRerankerFailureAndBypassRemainExplicitAndSafe(t *testing.T) {
	scope, lexical, vector, _ := fixture()
	result, _ := Fuse(scope, lexical, vector, DefaultPolicy(3))
	original := result.Candidates[0].Citation.ChunkID
	inputs := authorizedCitations(result, "a", "b", "c")
	failed, err := ApplyReranker(context.Background(), result, &fakeReranker{err: errors.New("provider secret")}, inputs, 50*time.Millisecond)
	if err != nil || failed.Outcome != OutcomeDegraded || failed.RerankerStatus != RerankerFailed || failed.Candidates[0].Citation.ChunkID != original {
		t.Fatalf("reranker failure changed safe fused result: result=%+v err=%v", failed, err)
	}
	skipped, err := ApplyReranker(context.Background(), result, nil, nil, 0)
	if err != nil || skipped.RerankerStatus != RerankerSkipped || skipped.Outcome != OutcomeComplete || len(skipped.DegradedReasons) == 0 {
		t.Fatalf("optional bypass not explicit: result=%+v err=%v", skipped, err)
	}
	bad := &fakeReranker{rank: []uuid.UUID{uuid.New(), uuid.New(), uuid.New()}}
	invalid, err := ApplyReranker(context.Background(), result, bad, inputs, 50*time.Millisecond)
	if err != nil || invalid.RerankerStatus != RerankerFailed || invalid.Candidates[0].Citation.ChunkID != original {
		t.Fatalf("foreign reranker IDs were not safely ignored: result=%+v err=%v", invalid, err)
	}
}

func TestApplyRerankerRejectsOversizedPayloadAndDeadline(t *testing.T) {
	_, lexical, vector, _ := fixture()
	result, _ := Fuse(lexical.Snapshot.Scope, lexical, vector, DefaultPolicy(3))
	inputs := authorizedCitations(result, strings.Repeat("x", MaxRerankItemBytes+1), "b", "c")
	got, err := ApplyReranker(context.Background(), result, &fakeReranker{rank: []uuid.UUID{}}, inputs, 50*time.Millisecond)
	if err != nil || got.RerankerStatus != RerankerFailed {
		t.Fatalf("oversized reranker payload accepted: result=%+v err=%v", got, err)
	}
	if _, err := ApplyReranker(context.Background(), result, &fakeReranker{}, nil, MaxRerankDeadline+time.Nanosecond); err == nil {
		t.Fatal("unbounded reranker deadline accepted")
	}
}

func TestApplyRerankerDeadlineFallsBackWithoutChangingFusedOrder(t *testing.T) {
	_, lexical, vector, _ := fixture()
	result, _ := Fuse(lexical.Snapshot.Scope, lexical, vector, DefaultPolicy(3))
	first := result.Candidates[0].Citation.ChunkID
	inputs := authorizedCitations(result, "first", "second", "third")
	got, err := ApplyReranker(context.Background(), result, blockingReranker{}, inputs, 5*time.Millisecond)
	if err != nil || got.RerankerStatus != RerankerFailed || got.Outcome != OutcomeDegraded || got.Candidates[0].Citation.ChunkID != first {
		t.Fatalf("reranker timeout did not preserve safe fused order: result=%+v err=%v", got, err)
	}
}

func TestApplyRerankerCapsCandidatesAndAggregateTextBytes(t *testing.T) {
	scope, lexical, vector, _ := largeFixture(60)
	result, err := Fuse(scope, lexical, vector, DefaultPolicy(60))
	if err != nil {
		t.Fatal(err)
	}
	inputs := make([]CitedCandidate, MaxRerankCandidates)
	rankedIDs := make([]uuid.UUID, MaxRerankCandidates)
	for i := range inputs {
		inputs[i] = CitedCandidate{Candidate: result.Candidates[i], Excerpt: strings.Repeat("x", 2048)}
		rankedIDs[MaxRerankCandidates-1-i] = inputs[i].Candidate.Citation.ChunkID
	}
	tooLarge, err := ApplyReranker(context.Background(), result, &fakeReranker{rank: rankedIDs}, inputs, 50*time.Millisecond)
	if err != nil || tooLarge.RerankerStatus != RerankerFailed {
		t.Fatalf("aggregate reranker byte limit was not enforced: result=%+v err=%v", tooLarge, err)
	}
	for i := range inputs {
		inputs[i].Excerpt = "short excerpt"
	}
	fake := &fakeReranker{rank: rankedIDs}
	bounded, err := ApplyReranker(context.Background(), result, fake, inputs, 50*time.Millisecond)
	if err != nil || bounded.RerankerStatus != RerankerApplied || fake.count != MaxRerankCandidates ||
		bounded.Candidates[0].Citation.ChunkID != rankedIDs[0] || len(bounded.Candidates) != 60 {
		t.Fatalf("reranker candidate cap not preserved: received=%d result=%+v err=%v", fake.count, bounded, err)
	}
}

func TestCitationResolutionRechecksAuthorizationAndSuppressesFailures(t *testing.T) {
	scope, lexical, vector, _ := fixture()
	result, _ := Fuse(scope, lexical, vector, DefaultPolicy(3))
	authorized, cited, err := ResolveCitations(context.Background(), fakeCitationResolver{}, scope, result)
	if err != nil || len(cited) != 3 || authorized.Outcome != OutcomeComplete {
		t.Fatalf("authorized citations not resolved: result=%+v cited=%d err=%v", authorized, len(cited), err)
	}
	partial, cited, err := ResolveCitations(context.Background(), fakeCitationResolver{denyFirst: true}, scope, result)
	if err != nil || len(cited) != 2 || partial.Outcome != OutcomeDegraded {
		t.Fatalf("revoked citation was not suppressed: result=%+v cited=%d err=%v", partial, len(cited), err)
	}
	unavailable, cited, err := ResolveCitations(context.Background(), fakeCitationResolver{fail: true}, scope, result)
	if err != nil || unavailable.Outcome != OutcomeUnavailable || len(unavailable.Candidates) != 0 || len(cited) != 0 {
		t.Fatalf("authorization infrastructure failure did not fail closed: result=%+v cited=%d err=%v", unavailable, len(cited), err)
	}
	if _, cited, err := ResolveCitations(context.Background(), fakeCitationResolver{mutate: true}, scope, result); err != nil || len(cited) != 2 {
		t.Fatalf("citation digest mismatch was not suppressed: cited=%d err=%v", len(cited), err)
	}
}

func fixture() (Scope, SourceResults, SourceResults, []uuid.UUID) {
	tenant := tenancy.TenantID("11111111-1111-4111-8111-111111111111")
	scope := Scope{TenantID: tenant, VisibilityKey: "finance-private"}
	ids := []uuid.UUID{uuid.MustParse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"), uuid.MustParse("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"), uuid.MustParse("cccccccc-cccc-4ccc-8ccc-cccccccccccc")}
	doc := uuid.MustParse("dddddddd-dddd-4ddd-8ddd-dddddddddddd")
	chunk := func(i int) CitationRef {
		return CitationRef{ChunkID: ids[i], DocumentVersionID: doc, Ordinal: i, StartByte: i * 20, EndByte: i*20 + 10, ContentDigest: sha256.Sum256([]byte{byte(i + 1)})}
	}
	lexID := uuid.MustParse("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee")
	vecID := uuid.MustParse("ffffffff-ffff-4fff-8fff-ffffffffffff")
	lexical := SourceResults{Snapshot: Snapshot{Source: Lexical, Status: SourceReady, Scope: scope, BuildID: lexID, Generation: 4}, Candidates: []SourceCandidate{{Citation: chunk(0)}, {Citation: chunk(1)}, {Citation: chunk(2)}}}
	vector := SourceResults{Snapshot: Snapshot{Source: Vector, Status: SourceReady, Scope: scope, BuildID: vecID, Generation: 2, CorpusBuildID: lexID, CorpusGeneration: 4, ModelID: "test-v1", ModelRevision: "rev1"}, Candidates: []SourceCandidate{{Citation: chunk(1)}, {Citation: chunk(2)}, {Citation: chunk(0)}}}
	return scope, lexical, vector, ids
}

func largeFixture(n int) (Scope, SourceResults, SourceResults, []uuid.UUID) {
	scope := Scope{TenantID: "11111111-1111-4111-8111-111111111111", VisibilityKey: "finance-private"}
	lexID, vecID, docID := uuid.New(), uuid.New(), uuid.New()
	ids := make([]uuid.UUID, n)
	lexical := SourceResults{Snapshot: Snapshot{Source: Lexical, Status: SourceReady, Scope: scope, BuildID: lexID, Generation: 1}, Candidates: make([]SourceCandidate, n)}
	vector := SourceResults{Snapshot: Snapshot{Source: Vector, Status: SourceReady, Scope: scope, BuildID: vecID, Generation: 1, CorpusBuildID: lexID, CorpusGeneration: 1, ModelID: "test-v1", ModelRevision: "rev1"}, Candidates: make([]SourceCandidate, n)}
	for i := 0; i < n; i++ {
		id := uuid.New()
		ids[i] = id
		citation := CitationRef{ChunkID: id, DocumentVersionID: docID, Ordinal: i, StartByte: i * 8, EndByte: i*8 + 8, ContentDigest: sha256.Sum256([]byte(id.String()))}
		lexical.Candidates[i] = SourceCandidate{Citation: citation}
		vector.Candidates[n-1-i] = SourceCandidate{Citation: citation}
	}
	return scope, lexical, vector, ids
}

func authorizedCitations(result Result, excerpts ...string) []CitedCandidate {
	if len(excerpts) == 1 {
		value := excerpts[0]
		excerpts = make([]string, len(result.Candidates))
		for i := range excerpts {
			excerpts[i] = value
		}
	}
	if len(excerpts) != len(result.Candidates) {
		panic("test citation excerpt count must match result candidates")
	}
	cited := make([]CitedCandidate, len(result.Candidates))
	for i, candidate := range result.Candidates {
		cited[i] = CitedCandidate{Candidate: candidate, Excerpt: excerpts[i]}
	}
	return cited
}

type fakeReranker struct {
	rank  []uuid.UUID
	err   error
	count int
}

type blockingReranker struct{}

func (blockingReranker) Rerank(ctx context.Context, _ []RerankInput) ([]uuid.UUID, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (f *fakeReranker) Rerank(_ context.Context, in []RerankInput) ([]uuid.UUID, error) {
	f.count = len(in)
	return f.rank, f.err
}

type fakeCitationResolver struct {
	denyFirst bool
	fail      bool
	mutate    bool
}

func (f fakeCitationResolver) ResolveCitation(_ context.Context, _ Scope, ref CitationRef) (ResolvedCitation, error) {
	if f.fail {
		return ResolvedCitation{}, errors.New("database details not exposed")
	}
	if f.denyFirst && ref.Ordinal == 0 {
		return ResolvedCitation{}, ErrCitationNotAuthorized
	}
	if f.mutate && ref.Ordinal == 0 {
		ref.ContentDigest[0]++
	}
	return ResolvedCitation{Reference: ref, Excerpt: "authorized excerpt"}, nil
}
