// keel-corpus-eval emits reproducible reference BM25 results for a synthetic corpus.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/sanskarpan/keel/internal/retrieval/eval"
)

type artifact struct {
	DatasetID           string                `json:"dataset_id"`
	CorpusSHA256        string                `json:"corpus_sha256"`
	BuildManifestSHA256 string                `json:"build_manifest_sha256"`
	Report              eval.EvaluationReport `json:"report"`
}

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintln(os.Stderr, "usage: keel-corpus-eval <corpus.json> <manifest.json> <results.json>")
		os.Exit(2)
	}
	if err := run(os.Args[1], os.Args[2], os.Args[3]); err != nil {
		fmt.Fprintln(os.Stderr, "evaluation failed:", err)
		os.Exit(1)
	}
}
func run(corpusPath, manifestPath, outputPath string) error {
	c, corpusBytes, err := eval.Load(corpusPath)
	if err != nil {
		return err
	}
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(strings.NewReader(string(manifestBytes)))
	dec.DisallowUnknownFields()
	var manifest eval.BuildManifest
	if err = dec.Decode(&manifest); err != nil {
		return fmt.Errorf("decode build manifest: %w", err)
	}
	if err = dec.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("manifest must contain exactly one JSON value")
	}
	if err = eval.ValidateManifest(manifest); err != nil {
		return err
	}
	if manifest.EvaluationDatasetID != c.DatasetID {
		return fmt.Errorf("manifest dataset does not match corpus")
	}
	corpusHash := sha256.Sum256(corpusBytes)
	if manifest.EvaluationCorpusSHA256 != hex.EncodeToString(corpusHash[:]) {
		return fmt.Errorf("manifest corpus digest mismatch")
	}
	report, err := eval.EvaluateBM25(c, 5)
	if err != nil {
		return err
	}
	manifestHash := sha256.Sum256(manifestBytes)
	result := artifact{DatasetID: c.DatasetID, CorpusSHA256: hex.EncodeToString(corpusHash[:]), BuildManifestSHA256: hex.EncodeToString(manifestHash[:]), Report: report}
	encoded, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	return os.WriteFile(outputPath, encoded, 0644)
}
