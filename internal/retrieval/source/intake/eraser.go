package intake

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
	"github.com/sanskarpan/keel/internal/retrieval/index"
)

var ErrSourceErasureNotAuthorized = errors.New("source erasure requires the matching withdrawal fence")

// ObjectDeleter is the narrow storage operation required by Eraser.
type ObjectDeleter interface {
	Delete(context.Context, string) error
}

// Eraser removes the raw and extracted supplier upload objects for one
// withdrawn source. It is an idempotent source-store action, not an erasure
// processor: callers must enforce legal hold and record an action receipt,
// and must not complete the durable erasure job based on this action alone.
type Eraser struct {
	db      *sql.DB
	objects ObjectDeleter
}

func NewEraser(db *sql.DB, objects ObjectDeleter) (*Eraser, error) {
	if db == nil || objects == nil {
		return nil, errors.New("erasure database and object deleter are required")
	}
	return &Eraser{db: db, objects: objects}, nil
}

// Erase deletes both supplier object versions after validating the exact
// tenant, cohort, immutable source ID, and withdrawn eligibility generation.
// Object deletion is outside PostgreSQL's transaction and must be idempotent;
// a partial delete is safely retried by calling Erase again with the same IDs.
func (e *Eraser) Erase(ctx context.Context, tenant tenancy.TenantID, visibility string, documentVersionID uuid.UUID, generation int64) error {
	if ctx == nil || e == nil || e.db == nil || e.objects == nil || documentVersionID == uuid.Nil || generation < 2 {
		return errors.New("source erasure arguments are invalid")
	}
	tenantID, err := tenancy.ParseTenantID(string(tenant))
	if err != nil {
		return errors.New("source erasure tenant is invalid")
	}
	visibility, err = index.ParseVisibilityKey(visibility)
	if err != nil {
		return errors.New("source erasure visibility is invalid")
	}
	var rawKey, extractedKey string
	err = tenancy.WithTenantTx(ctx, e.db, tenantID, &sql.TxOptions{Isolation: sql.LevelRepeatableRead}, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `SELECT set_config('keel.visibility_key',$1,true)`, visibility); err != nil {
			return fmt.Errorf("set source erasure visibility scope: %w", err)
		}
		var state string
		var currentGeneration int64
		err := tx.QueryRowContext(ctx, `SELECT state,generation FROM keel_meta.retrieval_source_eligibility
			WHERE tenant_id=$1 AND visibility_key=$2 AND document_version_id=$3 FOR SHARE`,
			string(tenantID), visibility, documentVersionID).Scan(&state, &currentGeneration)
		if errors.Is(err, sql.ErrNoRows) || (err == nil && (state != "withdrawn" || currentGeneration != generation)) {
			return ErrSourceErasureNotAuthorized
		}
		if err != nil {
			return fmt.Errorf("read source withdrawal fence: %w", err)
		}
		err = tx.QueryRowContext(ctx, `SELECT object_key::text,extracted_object_key::text
			FROM keel_meta.supplier_uploads
			WHERE tenant_id=$1 AND upload_id=$2 AND upload_state='extracted'`,
			string(tenantID), documentVersionID).Scan(&rawKey, &extractedKey)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrSourceErasureNotAuthorized
		}
		if err != nil {
			return fmt.Errorf("read supplier source object identities: %w", err)
		}
		return nil
	})
	if err != nil {
		return err
	}
	if _, err := uuid.Parse(rawKey); err != nil {
		return errors.New("supplier raw object identity is invalid")
	}
	if _, err := uuid.Parse(extractedKey); err != nil {
		return errors.New("supplier extracted object identity is invalid")
	}
	if err := e.objects.Delete(ctx, extractedKey); err != nil {
		return errors.New("supplier extracted source object could not be erased")
	}
	if err := e.objects.Delete(ctx, rawKey); err != nil {
		return errors.New("supplier raw source object could not be erased")
	}
	return nil
}
