package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
	"github.com/sanskarpan/keel/internal/retrieval/hybrid"
)

// CitationRangeReader is the boundary to the encrypted source/content system.
// Implementations must enforce the exact tenant/cohort/source version and
// return only the requested half-open UTF-8 byte range. They must not log text.
type CitationRangeReader interface {
	ReadCitationRange(context.Context, tenancy.TenantID, string, hybrid.CitationRef) ([]byte, error)
}

type currentCitationResolver struct {
	db     *sql.DB
	reader CitationRangeReader
}

// NewCitationResolver binds live Keel withdrawal eligibility to an injected
// source reader. It is not a per-user ACL resolver; the exact cohort scope is
// supplied by the trusted caller and the source adapter must enforce its own
// upstream ACLs before returning bytes.
func (r *Repository) NewCitationResolver(reader CitationRangeReader) (hybrid.CitationResolver, error) {
	if r == nil || r.db == nil || reader == nil {
		return nil, errors.New("retrieval repository and citation range reader are required")
	}
	return currentCitationResolver{db: r.db, reader: reader}, nil
}

func (r currentCitationResolver) ResolveCitation(ctx context.Context, hybridScope hybrid.Scope, reference hybrid.CitationRef) (hybrid.ResolvedCitation, error) {
	if ctx == nil {
		return hybrid.ResolvedCitation{}, errors.New("citation context is required")
	}
	if r.db == nil || r.reader == nil {
		return hybrid.ResolvedCitation{}, errors.New("citation resolver is unavailable")
	}
	s, err := newScope(hybridScope.TenantID, hybridScope.VisibilityKey)
	if err != nil {
		return hybrid.ResolvedCitation{}, err
	}
	if reference.ChunkID == uuid.Nil || reference.DocumentVersionID == uuid.Nil || reference.Ordinal < 0 ||
		reference.StartByte < 0 || reference.EndByte <= reference.StartByte || reference.EndByte-reference.StartByte > hybrid.MaxCitationExcerptBytes ||
		reference.ContentDigest == [32]byte{} {
		return hybrid.ResolvedCitation{}, errors.New("citation identity or byte range is invalid")
	}
	var resolved hybrid.ResolvedCitation
	err = withScope(ctx, r.db, s, &sql.TxOptions{Isolation: sql.LevelRepeatableRead}, func(tx *sql.Tx) error {
		var generation int64
		err := tx.QueryRowContext(ctx, `SELECT generation FROM keel_meta.retrieval_source_eligibility
			WHERE tenant_id=$1 AND visibility_key=$2 AND document_version_id=$3 AND state='active' FOR SHARE`,
			string(s.tenant), s.visibility, reference.DocumentVersionID).Scan(&generation)
		if errors.Is(err, sql.ErrNoRows) {
			return hybrid.ErrCitationNotAuthorized
		}
		if err != nil {
			return fmt.Errorf("recheck current citation eligibility: %w", err)
		}
		content, err := r.reader.ReadCitationRange(ctx, s.tenant, s.visibility, reference)
		if err != nil {
			return fmt.Errorf("read authorized citation range: %w", err)
		}
		excerpt, err := validateCitationBytes(reference, content)
		if err != nil {
			return err
		}
		resolved = hybrid.ResolvedCitation{Reference: reference, Excerpt: excerpt}
		return nil
	})
	if err != nil {
		return hybrid.ResolvedCitation{}, err
	}
	return resolved, nil
}

func validateCitationBytes(reference hybrid.CitationRef, content []byte) (string, error) {
	if len(content) == 0 || len(content) > hybrid.MaxCitationExcerptBytes ||
		len(content) != reference.EndByte-reference.StartByte || !utf8.Valid(content) ||
		sha256.Sum256(content) != reference.ContentDigest || strings.TrimSpace(string(content)) == "" {
		return "", errors.New("source content does not match the immutable citation range and digest")
	}
	return string(content), nil
}
