// keel-corpus-lint validates the synthetic K3.1 retrieval evaluation bundle.
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

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintln(os.Stderr, "usage: keel-corpus-lint <corpus.json> <manifest.json> <sha256-dir>")
		os.Exit(2)
	}
	if err := run(os.Args[1], os.Args[2], os.Args[3]); err != nil {
		fmt.Fprintln(os.Stderr, "corpus validation failed:", err)
		os.Exit(1)
	}
}
func run(corpusPath, manifestPath, digestDir string) error {
	c, corpusBytes, err := eval.Load(corpusPath)
	if err != nil {
		return err
	}
	if err = eval.Validate(c); err != nil {
		return err
	}
	mb, err := os.ReadFile(manifestPath)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(strings.NewReader(string(mb)))
	dec.DisallowUnknownFields()
	var m eval.BuildManifest
	if err = dec.Decode(&m); err != nil {
		return fmt.Errorf("decode manifest: %w", err)
	}
	if err = dec.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("manifest must contain exactly one JSON value")
	}
	if err = eval.ValidateManifest(m); err != nil {
		return err
	}
	if m.EvaluationDatasetID != c.DatasetID {
		return fmt.Errorf("manifest dataset %q does not match corpus %q", m.EvaluationDatasetID, c.DatasetID)
	}
	corpusSum := sha256.Sum256(corpusBytes)
	if m.EvaluationCorpusSHA256 != hex.EncodeToString(corpusSum[:]) {
		return fmt.Errorf("manifest corpus digest does not match corpus bytes")
	}
	if err = checkDigest(digestDir+"/corpus.sha256", corpusBytes); err != nil {
		return err
	}
	if err = checkDigest(digestDir+"/build-manifest.sha256", mb); err != nil {
		return err
	}
	corpusDigest := sha256.Sum256(corpusBytes)
	manifestDigest := sha256.Sum256(mb)
	fmt.Printf("valid %s: %d queries, %d source versions, partitions=%s\n", c.DatasetID, len(c.Queries), len(c.Documents), strings.Join(eval.Partitions(c), ","))
	fmt.Printf("corpus_sha256=%s\nmanifest_sha256=%s\n", hex.EncodeToString(corpusDigest[:]), hex.EncodeToString(manifestDigest[:]))
	return nil
}
func checkDigest(path string, content []byte) error {
	want, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	expected := strings.TrimSpace(string(want))
	sum := sha256.Sum256(content)
	if expected != hex.EncodeToString(sum[:]) {
		return fmt.Errorf("digest mismatch for %s", path)
	}
	return nil
}
