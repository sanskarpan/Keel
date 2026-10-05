package contracts

import (
	"errors"
	"fmt"
	"strings"
)

const ChunkerID = "keel.paragraph-window.v1"

// ChunkConfig is an immutable part of a corpus build identity.
type ChunkConfig struct {
	ID             string `json:"id"`
	MaxTokens      int    `json:"max_tokens"`
	OverlapTokens  int    `json:"overlap_tokens"`
	MaxSourceBytes int    `json:"max_source_bytes"`
	HeadingContext bool   `json:"heading_context"`
}

// Chunk offsets identify body text in the original source. HeadingContext is
// separately carried as metadata and is never included in citation offsets.
type Chunk struct {
	Ordinal        int    `json:"ordinal"`
	Text           string `json:"text"`
	HeadingContext string `json:"heading_context,omitempty"`
	StartByte      int    `json:"start_byte"`
	EndByte        int    `json:"end_byte"`
	TokenCount     int    `json:"token_count"`
}

func DefaultChunkConfig() ChunkConfig {
	return ChunkConfig{ID: ChunkerID, MaxTokens: 200, OverlapTokens: 30, MaxSourceBytes: MaxDocumentBytes, HeadingContext: true}
}

// ChunkDocument divides source into bounded token windows without splitting a
// token. Markdown headings provide context to following paragraphs. Empty and
// malformed UTF-8 input is rejected or produces no chunks as documented.
func ChunkDocument(source string, cfg ChunkConfig) ([]Chunk, error) {
	if cfg.ID != ChunkerID {
		return nil, fmt.Errorf("unsupported chunker ID %q", cfg.ID)
	}
	if cfg.MaxTokens < 1 || cfg.MaxTokens > 2048 {
		return nil, errors.New("max_tokens must be in [1,2048]")
	}
	if cfg.OverlapTokens < 0 || cfg.OverlapTokens >= cfg.MaxTokens {
		return nil, errors.New("overlap_tokens must be in [0,max_tokens)")
	}
	if cfg.MaxSourceBytes < 1 || cfg.MaxSourceBytes > MaxDocumentBytes {
		return nil, errors.New("max_source_bytes outside supported bound")
	}
	if len(source) > cfg.MaxSourceBytes {
		return nil, fmt.Errorf("source exceeds %d bytes", cfg.MaxSourceBytes)
	}
	if _, err := Tokenize(source); err != nil {
		return nil, err
	}
	if strings.TrimSpace(source) == "" {
		return nil, nil
	}
	type paragraph struct {
		start, end int
		heading    string
	}
	var ps []paragraph
	heading := ""
	paragraphStart := 0
	paragraphHeading := ""
	inParagraph := false
	flushParagraph := func(end int) {
		if inParagraph && end > paragraphStart {
			ps = append(ps, paragraph{start: paragraphStart, end: end, heading: paragraphHeading})
		}
		inParagraph = false
	}
	lineStart := 0
	for lineStart < len(source) {
		lineEnd := strings.IndexByte(source[lineStart:], '\n')
		if lineEnd < 0 {
			lineEnd = len(source)
		} else {
			lineEnd += lineStart
		}
		line := strings.TrimSuffix(source[lineStart:lineEnd], "\r")
		trim := strings.TrimSpace(line)
		if strings.HasPrefix(trim, "#") && len(strings.TrimLeft(trim, "#")) > 0 {
			flushParagraph(lineStart)
			heading = strings.TrimSpace(strings.TrimLeft(trim, "#"))
		} else if trim != "" {
			if !inParagraph {
				paragraphStart, paragraphHeading, inParagraph = lineStart, heading, true
			}
		} else {
			flushParagraph(lineStart)
		}
		if lineEnd == len(source) {
			flushParagraph(lineEnd)
			break
		}
		lineStart = lineEnd + 1
	}
	var chunks []Chunk
	for _, p := range ps {
		tokens, err := Tokenize(source[p.start:p.end])
		if err != nil {
			return nil, err
		}
		for base := 0; base < len(tokens); {
			end := base + cfg.MaxTokens
			if end > len(tokens) {
				end = len(tokens)
			}
			startByte := p.start + tokens[base].StartByte
			endByte := p.start + tokens[end-1].EndByte
			context := ""
			if cfg.HeadingContext {
				context = p.heading
			}
			chunks = append(chunks, Chunk{Ordinal: len(chunks), Text: source[startByte:endByte], HeadingContext: context, StartByte: startByte, EndByte: endByte, TokenCount: end - base})
			if end == len(tokens) {
				break
			}
			base = end - cfg.OverlapTokens
		}
	}
	return chunks, nil
}
