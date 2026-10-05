package eval

import (
	"errors"
	"math"
	"sort"

	"github.com/sanskarpan/keel/internal/retrieval/contracts"
)

const ReferenceEvaluatorID = "keel.reference-bm25.v1"

type RankedResult struct {
	DocumentID      string  `json:"document_id"`
	DocumentVersion string  `json:"document_version"`
	Score           float64 `json:"score"`
	Grade           int     `json:"grade"`
}
type QueryResult struct {
	QueryID           string         `json:"query_id"`
	Partition         string         `json:"partition"`
	NoAnswer          bool           `json:"no_answer"`
	Top               []RankedResult `json:"top"`
	ReciprocalRankAt5 float64        `json:"reciprocal_rank_at_5"`
	NDCGAt5           float64        `json:"ndcg_at_5"`
	RecallAt5         float64        `json:"recall_at_5"`
	NoAnswerCorrect   bool           `json:"no_answer_correct"`
}
type EvaluationReport struct {
	EvaluatorID                string        `json:"evaluator_id"`
	K                          int           `json:"k"`
	Results                    []QueryResult `json:"results"`
	QueryCount                 int           `json:"query_count"`
	AnswerableQueryCount       int           `json:"answerable_query_count"`
	MRRAt5                     float64       `json:"mrr_at_5"`
	MeanNDCGAt5                float64       `json:"mean_ndcg_at_5"`
	MeanRecallAt5              float64       `json:"mean_recall_at_5"`
	NoAnswerCount              int           `json:"no_answer_count"`
	NoAnswerTrueNegativeCount  int           `json:"no_answer_true_negative_count"`
	NoAnswerFalsePositiveCount int           `json:"no_answer_false_positive_count"`
}
type termDoc struct {
	tf     map[string]int
	length int
}

// EvaluateBM25 is a small independent, in-memory reference scorer. It uses the
// current full eligible synthetic corpus per exact tenant/visibility cohort,
// K1=1.2, B=.75, and no stemming, stopwords, postings, vectors or reranker.
// It is for reproducible fixture inspection, not production-quality evidence.
func EvaluateBM25(c Corpus, k int) (EvaluationReport, error) {
	if err := Validate(c); err != nil {
		return EvaluationReport{}, err
	}
	if k < 1 || k > 100 {
		return EvaluationReport{}, errors.New("k must be in [1,100]")
	}
	cohortDocs := map[string][]Document{}
	for _, d := range c.Documents {
		cohort := d.Tenant + "\x00" + d.Visibility
		cohortDocs[cohort] = append(cohortDocs[cohort], d)
	}
	judgments := map[string]map[string]int{}
	for _, q := range c.Queries {
		labels := map[string]int{}
		for _, j := range q.Judgments {
			labels[j.DocumentID+"@"+j.DocumentVersion] = j.Grade
		}
		judgments[q.ID] = labels
	}
	report := EvaluationReport{EvaluatorID: ReferenceEvaluatorID, K: k, QueryCount: len(c.Queries)}
	for _, q := range c.Queries {
		cohort := q.Tenant + "\x00" + q.Visibility
		eligible := cohortDocs[cohort]
		stats := make(map[string]termDoc, len(eligible))
		df := map[string]int{}
		totalLen := 0
		for _, d := range eligible {
			terms, err := contracts.Tokenize(d.Text)
			if err != nil {
				return report, err
			}
			tf := map[string]int{}
			for _, t := range terms {
				tf[t.Term]++
			}
			stats[d.ID+"@"+d.Version] = termDoc{tf: tf, length: len(terms)}
			totalLen += len(terms)
			for term := range tf {
				df[term]++
			}
		}
		avgLen := float64(totalLen) / float64(max(1, len(eligible)))
		queryTerms, err := contracts.NormalizeQuery(q.Text, 64)
		if err != nil {
			return report, err
		}
		results := make([]RankedResult, 0, len(eligible))
		for _, d := range eligible {
			key := d.ID + "@" + d.Version
			td := stats[key]
			score := 0.0
			for _, term := range queryTerms {
				freq := td.tf[term]
				if freq == 0 {
					continue
				}
				n := float64(len(eligible))
				frequency := float64(df[term])
				idf := math.Log(1 + (n-frequency+.5)/(frequency+.5))
				tf := float64(freq)
				denom := tf + 1.2*(1-.75+.75*float64(td.length)/maxFloat(avgLen, 1))
				score += idf * tf * 2.2 / denom
			}
			results = append(results, RankedResult{DocumentID: d.ID, DocumentVersion: d.Version, Score: score, Grade: judgments[q.ID][key]})
		}
		sort.Slice(results, func(i, j int) bool {
			if results[i].Score == results[j].Score {
				return results[i].DocumentID < results[j].DocumentID
			}
			return results[i].Score > results[j].Score
		})
		qr := QueryResult{QueryID: q.ID, Partition: q.Partition, NoAnswer: q.NoAnswer}
		limit := min(k, len(results))
		qr.Top = append(qr.Top, results[:limit]...)
		positiveCount := 0
		for _, grade := range judgments[q.ID] {
			if grade > 0 {
				positiveCount++
			}
		}
		firstRelevant := 0
		dcg := 0.0
		retrievedRelevant := 0
		for i, r := range qr.Top {
			if r.Grade > 0 {
				retrievedRelevant++
				if firstRelevant == 0 {
					firstRelevant = i + 1
				}
				dcg += (math.Pow(2, float64(r.Grade)) - 1) / math.Log2(float64(i+2))
			}
		}
		idealGrades := make([]int, 0, positiveCount)
		for _, grade := range judgments[q.ID] {
			if grade > 0 {
				idealGrades = append(idealGrades, grade)
			}
		}
		sort.Sort(sort.Reverse(sort.IntSlice(idealGrades)))
		idcg := 0.0
		for i, grade := range idealGrades {
			if i >= k {
				break
			}
			idcg += (math.Pow(2, float64(grade)) - 1) / math.Log2(float64(i+2))
		}
		if firstRelevant > 0 {
			qr.ReciprocalRankAt5 = 1 / float64(firstRelevant)
		}
		if idcg > 0 {
			qr.NDCGAt5 = dcg / idcg
		}
		if positiveCount > 0 {
			qr.RecallAt5 = float64(retrievedRelevant) / float64(positiveCount)
		}
		qr.NoAnswerCorrect = q.NoAnswer && (len(qr.Top) == 0 || qr.Top[0].Score == 0)
		if q.NoAnswer {
			report.NoAnswerCount++
			if qr.NoAnswerCorrect {
				report.NoAnswerTrueNegativeCount++
			} else {
				report.NoAnswerFalsePositiveCount++
			}
		}
		if positiveCount > 0 {
			report.AnswerableQueryCount++
			report.MRRAt5 += qr.ReciprocalRankAt5
			report.MeanNDCGAt5 += qr.NDCGAt5
			report.MeanRecallAt5 += qr.RecallAt5
		}
		report.Results = append(report.Results, qr)
	}
	if report.AnswerableQueryCount > 0 {
		n := float64(report.AnswerableQueryCount)
		report.MRRAt5 /= n
		report.MeanNDCGAt5 /= n
		report.MeanRecallAt5 /= n
	}
	return report, nil
}
func maxFloat(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}
