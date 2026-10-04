// Package postgres persists orders behind Keel's tenant transaction and RLS boundary.
package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/sanskarpan/keel/internal/orders"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

const (
	createRoute   = "POST /v1/orders"
	submitRoute   = "POST /v1/orders/{order_id}/submit"
	maxPruneBatch = 1000
)

var (
	ErrIdempotencyConflict      = errors.New("idempotency key conflicts with an earlier request")
	ErrIdempotencyInProgress    = errors.New("idempotent operation is still in progress")
	ErrIdempotencyRecordExpired = errors.New("idempotency result expired; operation was not re-executed")
	ErrNaturalReferenceConflict = errors.New("external reference already exists for this tenant")
	ErrNotFound                 = errors.New("order not found")
	ErrCorruptState             = errors.New("stored order state failed integrity validation")
	idempotencyKeyPattern       = regexp.MustCompile(`^[A-Za-z0-9._~-]{16,128}$`)
	principalPattern            = regexp.MustCompile(`^(principal|service-principal):[A-Za-z0-9._~-]{1,120}$`)
)

// Result identifies the authoritative order state. Replayed is true when the key already
// committed; DetailsExpired distinguishes a compact-registry lookup from the 7-day response.
type Result struct {
	Snapshot       orders.Snapshot `json:"order"`
	Replayed       bool            `json:"replayed"`
	DetailsExpired bool            `json:"details_expired"`
}

type Repository struct{ db *sql.DB }

func NewRepository(db *sql.DB) (*Repository, error) {
	if db == nil {
		return nil, errors.New("order database is required")
	}
	return &Repository{db: db}, nil
}

// Create atomically claims an idempotency key, enforces the tenant's stable natural reference,
// appends version one, stores the command snapshot and response, and retains a permanent dedup
// tombstone linked to the order. principalBinding must be the trusted authenticated actor ref.
func (r *Repository) Create(ctx context.Context, tenant tenancy.TenantID, command orders.CreateOrder, metadata orders.EventMetadata, idempotencyKey, principalBinding string) (Result, error) {
	canonical, err := orders.CanonicalizeCreateOrder(command)
	if err != nil {
		return Result{}, err
	}
	metadata.OccurredAt = metadata.OccurredAt.UTC().Truncate(time.Microsecond)
	if err := validateScope(tenant, metadata, idempotencyKey, principalBinding); err != nil {
		return Result{}, err
	}
	if metadata.OrderID == "" {
		return Result{}, fmt.Errorf("%w: candidate order ID is required", orders.ErrInvalidCommand)
	}
	requestHash, err := hashRequest("POST", createRoute, canonical)
	if err != nil {
		return Result{}, err
	}
	keyHash := digest([]byte(idempotencyKey))
	principalHash := digest([]byte(principalBinding))
	snapshot, event, err := orders.Create(metadata, canonical)
	if err != nil {
		return Result{}, err
	}
	var result Result
	var commandErr error
	err = tenancy.WithTenantTx(ctx, r.db, tenant, nil, func(tx *sql.Tx) error {
		claimed, prior, err := claimOrReplay(ctx, tx, tenant, createRoute, keyHash, principalHash, requestHash)
		if err != nil {
			return err
		}
		if !claimed {
			result = prior
			return nil
		}

		created, err := insertOrder(ctx, tx, snapshot, event)
		if err != nil {
			return err
		}
		if !created {
			commandErr = ErrNaturalReferenceConflict
			return storeRejected(ctx, tx, tenant, createRoute, keyHash, requestHash, "natural_reference_conflict")
		}
		if err := completeClaim(ctx, tx, tenant, createRoute, keyHash, snapshot.OrderID); err != nil {
			return err
		}
		if err := storeResponse(ctx, tx, tenant, createRoute, keyHash, requestHash, snapshot, ""); err != nil {
			return err
		}
		result = Result{Snapshot: snapshot}
		return nil
	})
	if err != nil {
		return Result{}, err
	}
	if commandErr != nil {
		return Result{}, commandErr
	}
	return result, nil
}

// Submit serializes on the order head, checks the expected aggregate version, and atomically
// appends the submit event with both the current snapshot and idempotency result.
func (r *Repository) Submit(ctx context.Context, tenant tenancy.TenantID, orderID string, expectedVersion uint64, command orders.SubmitOrder, metadata orders.EventMetadata, idempotencyKey, principalBinding string) (Result, error) {
	canonical, _, err := orders.CanonicalizeSubmitOrder(command)
	if err != nil {
		return Result{}, err
	}
	metadata.OccurredAt = metadata.OccurredAt.UTC().Truncate(time.Microsecond)
	if err := validateScope(tenant, metadata, idempotencyKey, principalBinding); err != nil {
		return Result{}, err
	}
	if metadata.OrderID != orderID {
		return Result{}, fmt.Errorf("%w: command order scope does not match", orders.ErrInvalidCommand)
	}
	requestHash, err := hashRequest("POST", submitRoute, struct {
		OrderID         string             `json:"order_id"`
		ExpectedVersion uint64             `json:"expected_version"`
		Command         orders.SubmitOrder `json:"command"`
	}{orderID, expectedVersion, canonical})
	if err != nil {
		return Result{}, err
	}
	keyHash := digest([]byte(idempotencyKey))
	principalHash := digest([]byte(principalBinding))
	var result Result
	var commandErr error
	err = tenancy.WithTenantTx(ctx, r.db, tenant, nil, func(tx *sql.Tx) error {
		claimed, prior, err := claimOrReplay(ctx, tx, tenant, submitRoute, keyHash, principalHash, requestHash)
		if err != nil {
			return err
		}
		if !claimed {
			result = prior
			return nil
		}

		current, err := loadSnapshotForUpdate(ctx, tx, tenant, orderID)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				commandErr = ErrNotFound
				return storeRejected(ctx, tx, tenant, submitRoute, keyHash, requestHash, "resource_not_found")
			}
			return err
		}
		next, event, transitionErr := orders.Submit(current, expectedVersion, canonical, metadata)
		if transitionErr != nil {
			commandErr = transitionErr
			return storeRejected(ctx, tx, tenant, submitRoute, keyHash, requestHash, rejectionCode(transitionErr))
		}
		if err := updateSnapshot(ctx, tx, tenant, current, next); err != nil {
			return err
		}
		if err := insertEvent(ctx, tx, event); err != nil {
			return err
		}
		if err := completeClaim(ctx, tx, tenant, submitRoute, keyHash, next.OrderID); err != nil {
			return err
		}
		if err := storeResponse(ctx, tx, tenant, submitRoute, keyHash, requestHash, next, ""); err != nil {
			return err
		}
		result = Result{Snapshot: next}
		return nil
	})
	if err != nil {
		return Result{}, err
	}
	if commandErr != nil {
		return Result{}, commandErr
	}
	return result, nil
}

// Load returns the current authoritative command snapshot under the caller's tenant context.
func (r *Repository) Load(ctx context.Context, tenant tenancy.TenantID, orderID string) (orders.Snapshot, error) {
	var snapshot orders.Snapshot
	err := tenancy.WithTenantTx(ctx, r.db, tenant, &sql.TxOptions{ReadOnly: true}, func(tx *sql.Tx) error {
		var err error
		snapshot, err = loadSnapshot(ctx, tx, tenant, orderID, false)
		return err
	})
	return snapshot, err
}

// Events reads and integrity-checks the immutable aggregate history. Callers must already be
// authorized to read that order; PostgreSQL RLS still enforces tenant containment.
func (r *Repository) Events(ctx context.Context, tenant tenancy.TenantID, orderID string) ([]orders.Event, error) {
	var events []orders.Event
	err := tenancy.WithTenantTx(ctx, r.db, tenant, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead}, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT aggregate_version,event_id::text,event_type,occurred_at,event_data,event_hash
			FROM keel_meta.order_events WHERE tenant_id=$1 AND order_id=$2 ORDER BY aggregate_version`, string(tenant), orderID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var raw, storedHash []byte
			var version int64
			var eventID, eventType string
			var occurredAt time.Time
			var event orders.Event
			if err := rows.Scan(&version, &eventID, &eventType, &occurredAt, &raw, &storedHash); err != nil {
				return err
			}
			if err := json.Unmarshal(raw, &event); err != nil {
				return fmt.Errorf("%w: decode event", ErrCorruptState)
			}
			canonical, err := json.Marshal(event)
			if err != nil || !bytes.Equal(digest(canonical), storedHash) {
				return fmt.Errorf("%w: event digest mismatch", ErrCorruptState)
			}
			if version < 1 || uint64(version) != event.Version || eventID != event.Metadata.EventID || eventType != string(event.Type) || !occurredAt.Equal(event.Metadata.OccurredAt) {
				return fmt.Errorf("%w: indexed event metadata differs from its payload", ErrCorruptState)
			}
			events = append(events, event)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		if err := rows.Close(); err != nil {
			return err
		}
		if len(events) == 0 {
			return ErrNotFound
		}
		replayed, err := orders.Replay(events)
		if err != nil {
			return fmt.Errorf("%w: event history cannot be replayed", ErrCorruptState)
		}
		stored, err := loadSnapshot(ctx, tx, tenant, orderID, false)
		if err != nil {
			return err
		}
		if err := orders.VerifySnapshot(stored, events); err != nil || stored.Version != replayed.Version {
			return fmt.Errorf("%w: event history differs from the current command snapshot", ErrCorruptState)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return events, nil
}

// PruneExpiredResponses removes at most limit response details for one tenant. Compact dedup
// tombstones are never deleted here. The worker runs one bounded tenant batch per transaction.
func (r *Repository) PruneExpiredResponses(ctx context.Context, tenant tenancy.TenantID, limit int) (int64, error) {
	if limit < 1 || limit > maxPruneBatch {
		return 0, fmt.Errorf("prune limit must be in [1,%d]", maxPruneBatch)
	}
	var deleted int64
	err := tenancy.WithTenantTx(ctx, r.db, tenant, nil, func(tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx, `WITH expired AS (
			SELECT tenant_id,route,key_digest FROM keel_meta.idempotency_requests
			WHERE tenant_id=$1 AND expires_at <= clock_timestamp()
			ORDER BY expires_at, route, key_digest
			LIMIT $2
		)
		DELETE FROM keel_meta.idempotency_requests AS requests USING expired
		WHERE requests.tenant_id=expired.tenant_id AND requests.route=expired.route AND requests.key_digest=expired.key_digest`, string(tenant), limit)
		if err != nil {
			return err
		}
		deleted, err = result.RowsAffected()
		return err
	})
	return deleted, err
}

func validateScope(tenant tenancy.TenantID, metadata orders.EventMetadata, key, principal string) error {
	if tenant == "" || metadata.TenantID != string(tenant) {
		return fmt.Errorf("%w: authenticated tenant and command metadata must match", orders.ErrInvalidCommand)
	}
	if !idempotencyKeyPattern.MatchString(key) {
		return fmt.Errorf("%w: idempotency key must be 16-128 safe characters", orders.ErrInvalidCommand)
	}
	if !principalPattern.MatchString(principal) || principal != metadata.ActorRef {
		return fmt.Errorf("%w: authenticated principal binding must match event actor", orders.ErrInvalidCommand)
	}
	return nil
}

func hashRequest(method, route string, payload any) ([]byte, error) {
	canonical, err := json.Marshal(struct {
		Method  string `json:"method"`
		Route   string `json:"route"`
		Payload any    `json:"payload"`
	}{method, route, payload})
	if err != nil {
		return nil, fmt.Errorf("canonicalize idempotency request: %w", err)
	}
	return digest(canonical), nil
}

func digest(value []byte) []byte { sum := sha256.Sum256(value); return sum[:] }

func claimOrReplay(ctx context.Context, tx *sql.Tx, tenant tenancy.TenantID, route string, keyHash, principalHash, requestHash []byte) (bool, Result, error) {
	var claimed []byte
	err := tx.QueryRowContext(ctx, `INSERT INTO keel_meta.idempotency_dedup
		(tenant_id,route,key_digest,principal_binding_hash,request_hash,outcome_state)
		VALUES ($1,$2,$3,$4,$5,'in_progress')
		ON CONFLICT (tenant_id,route,key_digest) DO NOTHING
		RETURNING key_digest`, string(tenant), route, keyHash, principalHash, requestHash).Scan(&claimed)
	if err == nil {
		return true, Result{}, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return false, Result{}, err
	}
	var storedPrincipal, storedHash []byte
	var operationRef sql.NullString
	var outcome string
	err = tx.QueryRowContext(ctx, `SELECT principal_binding_hash,request_hash,operation_ref::text,outcome_state
		FROM keel_meta.idempotency_dedup WHERE tenant_id=$1 AND route=$2 AND key_digest=$3 FOR UPDATE`, string(tenant), route, keyHash).
		Scan(&storedPrincipal, &storedHash, &operationRef, &outcome)
	if err != nil {
		return false, Result{}, err
	}
	if !bytes.Equal(storedPrincipal, principalHash) || !bytes.Equal(storedHash, requestHash) {
		return false, Result{}, ErrIdempotencyConflict
	}
	if outcome == "in_progress" {
		return false, Result{}, ErrIdempotencyInProgress
	}
	result, err := replayExisting(ctx, tx, tenant, route, keyHash, requestHash, outcome, operationRef)
	return false, result, err
}

func replayExisting(ctx context.Context, tx *sql.Tx, tenant tenancy.TenantID, route string, keyHash, requestHash []byte, outcome string, operationRef sql.NullString) (Result, error) {
	var storedHash, responseBody []byte
	var errorCode sql.NullString
	var valid bool
	err := tx.QueryRowContext(ctx, `SELECT request_hash,response_body,error_code,(expires_at > clock_timestamp())
		FROM keel_meta.idempotency_requests WHERE tenant_id=$1 AND route=$2 AND key_digest=$3`, string(tenant), route, keyHash).
		Scan(&storedHash, &responseBody, &errorCode, &valid)
	if err == nil && !bytes.Equal(storedHash, requestHash) {
		return Result{}, ErrCorruptState
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return Result{}, err
	}
	if err == nil && valid {
		if errorCode.Valid {
			return Result{}, errorForCode(errorCode.String)
		}
		var snapshot orders.Snapshot
		if err := json.Unmarshal(responseBody, &snapshot); err != nil {
			return Result{}, fmt.Errorf("%w: decode response detail", ErrCorruptState)
		}
		if !operationRef.Valid || snapshot.TenantID != string(tenant) || snapshot.OrderID != operationRef.String {
			return Result{}, ErrCorruptState
		}
		return Result{Snapshot: snapshot, Replayed: true}, nil
	}
	if outcome != "completed" || !operationRef.Valid {
		return Result{}, ErrIdempotencyRecordExpired
	}
	snapshot, err := loadSnapshot(ctx, tx, tenant, operationRef.String, false)
	if errors.Is(err, ErrNotFound) {
		return Result{}, ErrIdempotencyRecordExpired
	}
	if err != nil {
		return Result{}, err
	}
	return Result{Snapshot: snapshot, Replayed: true, DetailsExpired: true}, nil
}

func insertOrder(ctx context.Context, tx *sql.Tx, snapshot orders.Snapshot, event orders.Event) (bool, error) {
	snapshotJSON, snapshotHash, err := marshalSnapshot(snapshot)
	if err != nil {
		return false, err
	}
	var inserted string
	err = tx.QueryRowContext(ctx, `INSERT INTO keel_meta.order_heads
		(tenant_id,order_id,external_reference,supplier_id,status,version,command_snapshot,snapshot_hash)
		VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8)
		ON CONFLICT (tenant_id,external_reference) DO NOTHING
		RETURNING order_id::text`, snapshot.TenantID, snapshot.OrderID, snapshot.ExternalReference, snapshot.SupplierID, string(snapshot.Status), snapshot.Version, snapshotJSON, snapshotHash).Scan(&inserted)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if inserted != snapshot.OrderID {
		return false, ErrCorruptState
	}
	if err := insertEvent(ctx, tx, event); err != nil {
		return false, err
	}
	return true, nil
}

func insertEvent(ctx context.Context, tx *sql.Tx, event orders.Event) error {
	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("encode order event: %w", err)
	}
	eventHash := digest(data)
	_, err = tx.ExecContext(ctx, `INSERT INTO keel_meta.order_events
		(tenant_id,order_id,aggregate_version,event_id,event_type,event_data,event_hash,occurred_at)
		VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7,$8)`, event.Metadata.TenantID, event.Metadata.OrderID, event.Version,
		event.Metadata.EventID, string(event.Type), data, eventHash, event.Metadata.OccurredAt)
	return err
}

func loadSnapshotForUpdate(ctx context.Context, tx *sql.Tx, tenant tenancy.TenantID, orderID string) (orders.Snapshot, error) {
	return loadSnapshotWithLock(ctx, tx, tenant, orderID, true)
}

func loadSnapshot(ctx context.Context, tx *sql.Tx, tenant tenancy.TenantID, orderID string, lock bool) (orders.Snapshot, error) {
	return loadSnapshotWithLock(ctx, tx, tenant, orderID, lock)
}

func loadSnapshotWithLock(ctx context.Context, tx *sql.Tx, tenant tenancy.TenantID, orderID string, lock bool) (orders.Snapshot, error) {
	query := `SELECT version,status,command_snapshot,snapshot_hash FROM keel_meta.order_heads WHERE tenant_id=$1 AND order_id=$2`
	if lock {
		query += ` FOR UPDATE`
	}
	var version int64
	var storedStatus string
	var raw, storedHash []byte
	if err := tx.QueryRowContext(ctx, query, string(tenant), orderID).Scan(&version, &storedStatus, &raw, &storedHash); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return orders.Snapshot{}, ErrNotFound
		}
		return orders.Snapshot{}, err
	}
	var snapshot orders.Snapshot
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&snapshot); err != nil {
		return orders.Snapshot{}, fmt.Errorf("%w: decode snapshot", ErrCorruptState)
	}
	_, computedHash, err := marshalSnapshot(snapshot)
	if err != nil || !bytes.Equal(computedHash, storedHash) || version < 1 || uint64(version) != snapshot.Version || storedStatus != string(snapshot.Status) {
		return orders.Snapshot{}, ErrCorruptState
	}
	return snapshot, nil
}

func marshalSnapshot(snapshot orders.Snapshot) ([]byte, []byte, error) {
	data, err := json.Marshal(snapshot)
	if err != nil {
		return nil, nil, fmt.Errorf("encode command snapshot: %w", err)
	}
	return data, digest(data), nil
}

func updateSnapshot(ctx context.Context, tx *sql.Tx, tenant tenancy.TenantID, current, next orders.Snapshot) error {
	data, snapshotHash, err := marshalSnapshot(next)
	if err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `UPDATE keel_meta.order_heads SET version=$1,status=$2,command_snapshot=$3::jsonb,snapshot_hash=$4,updated_at=clock_timestamp()
		WHERE tenant_id=$5 AND order_id=$6 AND version=$7`, next.Version, string(next.Status), data, snapshotHash, string(tenant), current.OrderID, current.Version)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return orders.ErrVersionConflict
	}
	return nil
}

func completeClaim(ctx context.Context, tx *sql.Tx, tenant tenancy.TenantID, route string, keyHash []byte, operationRef string) error {
	result, err := tx.ExecContext(ctx, `UPDATE keel_meta.idempotency_dedup SET outcome_state='completed',operation_ref=$1,completed_at=clock_timestamp()
		WHERE tenant_id=$2 AND route=$3 AND key_digest=$4 AND outcome_state='in_progress'`, operationRef, string(tenant), route, keyHash)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return ErrCorruptState
	}
	return nil
}

func storeResponse(ctx context.Context, tx *sql.Tx, tenant tenancy.TenantID, route string, keyHash, requestHash []byte, snapshot orders.Snapshot, errorCode string) error {
	body, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO keel_meta.idempotency_requests
		(tenant_id,route,key_digest,request_hash,response_body,error_code,expires_at)
		VALUES ($1,$2,$3,$4,$5::jsonb,NULLIF($6,''),clock_timestamp()+interval '7 days')`, string(tenant), route, keyHash, requestHash, body, errorCode)
	return err
}

func storeRejected(ctx context.Context, tx *sql.Tx, tenant tenancy.TenantID, route string, keyHash, requestHash []byte, code string) error {
	if code == "" {
		return ErrCorruptState
	}
	result, err := tx.ExecContext(ctx, `UPDATE keel_meta.idempotency_dedup SET outcome_state='rejected',completed_at=clock_timestamp()
		WHERE tenant_id=$1 AND route=$2 AND key_digest=$3 AND outcome_state='in_progress'`, string(tenant), route, keyHash)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return ErrCorruptState
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO keel_meta.idempotency_requests
		(tenant_id,route,key_digest,request_hash,response_body,error_code,expires_at)
		VALUES ($1,$2,$3,$4,'{}'::jsonb,$5,clock_timestamp()+interval '7 days')`, string(tenant), route, keyHash, requestHash, code)
	return err
}

func rejectionCode(err error) string {
	switch {
	case errors.Is(err, orders.ErrVersionConflict):
		return "version_conflict"
	case errors.Is(err, orders.ErrIllegalTransition):
		return "invalid_state_transition"
	case errors.Is(err, orders.ErrInvalidCommand):
		return "invalid_command"
	default:
		return "command_rejected"
	}
}

func errorForCode(code string) error {
	switch code {
	case "version_conflict":
		return orders.ErrVersionConflict
	case "invalid_state_transition":
		return orders.ErrIllegalTransition
	case "invalid_command":
		return orders.ErrInvalidCommand
	case "resource_not_found":
		return ErrNotFound
	case "natural_reference_conflict":
		return ErrNaturalReferenceConflict
	default:
		return fmt.Errorf("%w: unknown stored outcome", ErrCorruptState)
	}
}

// KeyDigest returns a non-reversible digest; raw idempotency keys are never persisted.
func KeyDigest(key string) ([]byte, error) {
	if !idempotencyKeyPattern.MatchString(key) {
		return nil, fmt.Errorf("%w: idempotency key must be 16-128 safe characters", orders.ErrInvalidCommand)
	}
	return digest([]byte(key)), nil
}

func RequestHash(method, route string, payload any) ([]byte, error) {
	if strings.TrimSpace(method) == "" || strings.TrimSpace(route) == "" {
		return nil, errors.New("canonical method and route are required")
	}
	return hashRequest(method, route, payload)
}
