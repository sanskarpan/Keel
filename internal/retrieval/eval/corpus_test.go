package eval

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

func TestCheckedInCorpusAndManifestValidate(t *testing.T) {
	c, _, err := Load("../../../research/retrieval/v1/corpus.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(c); err != nil {
		t.Fatal(err)
	}
	mBytes, err := os.ReadFile("../../../research/retrieval/v1/build-manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	var m BuildManifest
	if err = json.Unmarshal(mBytes, &m); err != nil {
		t.Fatal(err)
	}
	if err = ValidateManifest(m); err != nil {
		t.Fatal(err)
	}
}

func TestRejectsNearDuplicateQueryAcrossPartitions(t *testing.T) {
	c := Corpus{SchemaVersion: SchemaVersion, DatasetID: "dataset.v1", License: "CC0-1.0", SyntheticOnly: true,
		Documents: []Document{{ID: "d1", Version: "v1", Tenant: "t", Visibility: "v", Published: true, Text: "alpha beta gamma delta"}, {ID: "d2", Version: "v1", Tenant: "t", Visibility: "v", Published: true, Text: "alpha beta gamma epsilon"}},
		Queries:   []Query{{ID: "q1", Partition: "train", Text: "how does alpha beta work", Tenant: "t", Visibility: "v", Rationale: "synthetic", Judgments: []Judgment{{DocumentID: "d1", DocumentVersion: "v1", Grade: 3, StartByte: 0, EndByte: 5, Rationale: "synthetic"}}}, {ID: "q2", Partition: "holdout", Text: "how does alpha beta work please", Tenant: "t", Visibility: "v", Rationale: "synthetic", Judgments: []Judgment{{DocumentID: "d2", DocumentVersion: "v1", Grade: 3, StartByte: 0, EndByte: 5, Rationale: "synthetic"}}}}}
	if err := Validate(c); err == nil {
		t.Fatal("near duplicate split leakage accepted")
	}
}

func TestRejectsPositiveJudgmentOutsideAccessScope(t *testing.T) {
	c := Corpus{SchemaVersion: SchemaVersion, DatasetID: "dataset.v1", License: "CC0-1.0", SyntheticOnly: true,
		Documents: []Document{{ID: "d1", Version: "v1", Tenant: "other", Visibility: "v", Published: true, Text: "answer"}},
		Queries:   []Query{{ID: "q1", Partition: "train", Text: "where answer", Tenant: "tenant", Visibility: "v", Rationale: "synthetic", Judgments: []Judgment{{DocumentID: "d1", DocumentVersion: "v1", Grade: 3, StartByte: 0, EndByte: 6, Rationale: "synthetic"}}}}}
	if err := Validate(c); err == nil {
		t.Fatal("cross-tenant label accepted")
	}
}

func TestManifestRejectsMutableProviderAliases(t *testing.T) {
	c, _, err := Load("../../../research/retrieval/v1/corpus.json")
	if err != nil {
		t.Fatal(err)
	}
	mBytes, err := os.ReadFile("../../../research/retrieval/v1/build-manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	var m BuildManifest
	if err := json.Unmarshal(mBytes, &m); err != nil {
		t.Fatal(err)
	}
	m.EmbeddingModel.ID = "embedding-latest"
	if err := ValidateManifest(m); err == nil {
		t.Fatal("mutable model alias was accepted")
	}
	if m.EvaluationDatasetID != c.DatasetID {
		t.Fatal("manifest/corpus dataset identity mismatch")
	}
}

func TestReferenceBM25IsDeterministicAndTenantVisibilityScoped(t *testing.T) {
	c, _, err := Load("../../../research/retrieval/v1/corpus.json")
	if err != nil {
		t.Fatal(err)
	}
	one, err := EvaluateBM25(c, 5)
	if err != nil {
		t.Fatal(err)
	}
	two, err := EvaluateBM25(c, 5)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(one, two) {
		t.Fatal("reference evaluation is not deterministic")
	}
	if one.QueryCount != 9 || one.NoAnswerCount != 2 {
		t.Fatalf("unexpected evaluation coverage: %+v", one)
	}
	if one.AnswerableQueryCount != 7 || one.NoAnswerTrueNegativeCount != 0 || one.NoAnswerFalsePositiveCount != 2 {
		t.Fatalf("unexpected no-answer/answerable accounting: %+v", one)
	}
	for _, result := range one.Results {
		if result.NoAnswer && result.NoAnswerCorrect && len(result.Top) > 0 && result.Top[0].Score != 0 {
			t.Errorf("no-answer %q marked correct with a positive top score", result.QueryID)
		}
		for _, candidate := range result.Top {
			allowed := false
			for _, doc := range c.Documents {
				if doc.ID == candidate.DocumentID && doc.Version == candidate.DocumentVersion {
					for _, q := range c.Queries {
						if q.ID == result.QueryID && q.Tenant == doc.Tenant && q.Visibility == doc.Visibility {
							allowed = true
						}
					}
				}
			}
			if !allowed {
				t.Errorf("query %q received out-of-scope source %q", result.QueryID, candidate.DocumentID)
			}
		}
	}
}
