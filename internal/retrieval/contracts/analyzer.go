// Package contracts defines provider-neutral, reproducible inputs to retrieval.
package contracts

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

const (
	AnalyzerID        = "keel.unicode-words.v1"
	MaxDocumentBytes  = 1 << 20
	MaxDocumentTokens = 100_000
)

var ErrInvalidUTF8 = errors.New("input is not valid UTF-8")

// Token retains offsets into the original UTF-8 source. EndByte is exclusive.
// Normalization affects Term only, never the source or its citation offsets.
type Token struct {
	Term      string `json:"term"`
	StartByte int    `json:"start_byte"`
	EndByte   int    `json:"end_byte"`
}

// Tokenize applies NFKC, Unicode case folding, and Unicode letter/number
// segmentation. Combining marks remain attached to their preceding token.
// Punctuation and control characters are separators; offsets remain raw bytes.
func Tokenize(source string) ([]Token, error) {
	if !utf8.ValidString(source) {
		return nil, ErrInvalidUTF8
	}
	if len(source) > MaxDocumentBytes {
		return nil, fmt.Errorf("input exceeds %d bytes", MaxDocumentBytes)
	}
	c := cases.Fold()
	var out []Token
	start := -1
	flush := func(end int) error {
		if start < 0 {
			return nil
		}
		raw := source[start:end]
		term := c.String(norm.NFKC.String(raw))
		if term != "" {
			out = append(out, Token{Term: term, StartByte: start, EndByte: end})
		}
		start = -1
		if len(out) > MaxDocumentTokens {
			return fmt.Errorf("input exceeds %d tokens", MaxDocumentTokens)
		}
		return nil
	}
	for offset, r := range source {
		word := unicode.IsLetter(r) || unicode.IsNumber(r) || (unicode.IsMark(r) && start >= 0)
		if word {
			if start < 0 {
				start = offset
			}
			continue
		}
		if err := flush(offset); err != nil {
			return nil, err
		}
	}
	if err := flush(len(source)); err != nil {
		return nil, err
	}
	return out, nil
}

// NormalizeQuery applies the same analyzer and returns its bounded term form.
func NormalizeQuery(query string, maxTerms int) ([]string, error) {
	if maxTerms < 1 {
		return nil, errors.New("maxTerms must be positive")
	}
	tokens, err := Tokenize(query)
	if err != nil {
		return nil, err
	}
	if len(tokens) > maxTerms {
		return nil, fmt.Errorf("query exceeds %d terms", maxTerms)
	}
	terms := make([]string, 0, len(tokens))
	for _, token := range tokens {
		if strings.TrimSpace(token.Term) == "" {
			continue
		}
		terms = append(terms, token.Term)
	}
	return terms, nil
}
