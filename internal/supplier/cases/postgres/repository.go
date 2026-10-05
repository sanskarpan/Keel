// Package postgres persists supplier cases, immutable evidence and workflow intents.
package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/sanskarpan/keel/internal/platform/tenancy"
	"github.com/sanskarpan/keel/internal/supplier/cases"
)

var (
	ErrNotFound = errors.New("supplier case or policy not found")
	ErrConflict = errors.New("supplier case or policy conflict")
)

var idempotencyKeyPattern = regexp.MustCompile(`^[A-Za-z0-9._~-]{16,128}$`)

type Repository struct{ db *sql.DB }

func New(db *sql.DB) (*Repository, error) {
	if db == nil {
		return nil, errors.New("supplier case database is required")
	}
	return &Repository{db: db}, nil
}

type CaseView struct {
	Case     cases.Case
	Evidence []cases.Evidence
	Events   []cases.Event
}

// PublishPolicy stores an immutable, versioned declarative policy. Publication time is taken
// from PostgreSQL, never from the request, and later edits require a new version.
func (r *Repository) PublishPolicy(ctx context.Context, tenant tenancy.TenantID, policy cases.Policy, actor string) (cases.Policy, error) {
	tenant = tenancy.TenantID(strings.ToLower(string(tenant)))
	policy.TenantID = strings.ToLower(policy.TenantID)
	policy.PolicyID = strings.ToLower(policy.PolicyID)
	if r == nil || r.db == nil || strings.ToLower(policy.TenantID) != string(tenant) {
		return cases.Policy{}, cases.ErrInvalidPolicy
	}
	var result cases.Policy
	err := tenancy.WithTenantTx(ctx, r.db, tenant, nil, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended($1, 0))`, string(tenant)+":"+policy.PolicyID); err != nil {
			return errors.New("policy version lock unavailable")
		}
		var maxVersion uint32
		if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(version),0)::int FROM keel_meta.supplier_review_policies WHERE tenant_id=$1 AND policy_id=$2`, string(tenant), policy.PolicyID).Scan(&maxVersion); err != nil {
			return errors.New("policy version could not be read")
		}
		if policy.Version <= maxVersion {
			existing, err := loadPolicy(ctx, tx, tenant, policy.PolicyID, policy.Version)
			if err != nil {
				return ErrConflict
			}
			policy.PublishedAt = existing.PublishedAt
			canonical, _, err := policy.Canonical()
			if err != nil || canonical.Digest != existing.Digest {
				return ErrConflict
			}
			result = existing
			return nil
		}
		if policy.Version != maxVersion+1 {
			return ErrConflict
		}
		var publishedAt time.Time
		if err := tx.QueryRowContext(ctx, `SELECT date_trunc('microseconds', clock_timestamp())`).Scan(&publishedAt); err != nil {
			return errors.New("policy publication time unavailable")
		}
		policy.PublishedAt = publishedAt.UTC()
		canonical, definition, err := policy.Canonical()
		if err != nil {
			return err
		}
		digest, _ := hex.DecodeString(canonical.Digest)
		required := append([]string{}, canonical.RequiredEvidence...)
		if _, err := tx.ExecContext(ctx, `INSERT INTO keel_meta.supplier_review_policies
			(tenant_id,policy_id,version,name,deadline_seconds,required_evidence,policy_definition,policy_digest,published_at,created_by_ref)
			VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9,$10)`, string(tenant), canonical.PolicyID, canonical.Version,
			canonical.Name, int64(canonical.Deadline/time.Second), required, string(definition), digest, canonical.PublishedAt, actor); err != nil {
			return classify(err)
		}
		result = canonical
		return nil
	})
	return result, err
}

func (r *Repository) Create(ctx context.Context, tenant tenancy.TenantID, idempotencyKey, supplierID, policyID string, policyVersion uint32, actor string) (cases.Case, error) {
	if r == nil || r.db == nil {
		return cases.Case{}, cases.ErrInvalidCase
	}
	tenant = tenancy.TenantID(strings.ToLower(string(tenant)))
	if !idempotencyKeyPattern.MatchString(idempotencyKey) {
		return cases.Case{}, cases.ErrInvalidCase
	}
	supplierID, policyID = strings.ToLower(supplierID), strings.ToLower(policyID)
	caseID := deterministicUUID(tenant, "supplier-case-create:"+actor+":"+idempotencyKey)
	var result cases.Case
	err := tenancy.WithTenantTx(ctx, r.db, tenant, nil, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended($1,0))`, string(tenant)+":"+caseID); err != nil {
			return errors.New("case idempotency lock unavailable")
		}
		if existing, err := lockCase(ctx, tx, tenant, caseID); err == nil {
			if existing.SupplierID != supplierID || existing.PolicyID != policyID || existing.PolicyVersion != policyVersion {
				return ErrConflict
			}
			evidence, err := loadEvidence(ctx, tx, tenant, caseID)
			if err != nil {
				return err
			}
			events, err := loadEvents(ctx, tx, tenant, caseID)
			if err != nil {
				return err
			}
			if err := verifyHistory(CaseView{Case: existing, Evidence: evidence, Events: events}); err != nil {
				return err
			}
			result = existing
			return nil
		} else if !errors.Is(err, ErrNotFound) {
			return err
		}
		policy, err := loadPolicy(ctx, tx, tenant, policyID, policyVersion)
		if err != nil {
			return err
		}
		var now time.Time
		if err := tx.QueryRowContext(ctx, `SELECT date_trunc('microseconds', clock_timestamp())`).Scan(&now); err != nil {
			return errors.New("case creation time unavailable")
		}
		created, event, err := cases.NewCase(string(tenant), caseID, supplierID, actor, policy, now)
		if err != nil {
			return err
		}
		policyDigest, _ := hex.DecodeString(created.PolicyDigest)
		evidenceDigest, _ := hex.DecodeString(created.EvidenceDigest)
		eventHash, _ := hex.DecodeString(event.Hash)
		if _, err := tx.ExecContext(ctx, `INSERT INTO keel_meta.supplier_cases
			(tenant_id,case_id,supplier_id,policy_id,policy_version,policy_digest,case_state,aggregate_version,
			 evidence_epoch,evidence_digest,last_event_hash,deadline_at,created_at,updated_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$13)`, string(tenant), created.CaseID,
			created.SupplierID, created.PolicyID, created.PolicyVersion, policyDigest, string(created.Status), created.Version,
			created.EvidenceEpoch, evidenceDigest, eventHash, created.DeadlineAt, created.CreatedAt); err != nil {
			return classify(err)
		}
		if err := insertEvent(ctx, tx, tenant, event); err != nil {
			return err
		}
		if err := insertIntent(ctx, tx, tenant, event); err != nil {
			return err
		}
		result = created
		return nil
	})
	return result, err
}

// AttachEvidence references only an already extracted upload belonging to an invitation for
// this exact case. All evidence facts are read from PostgreSQL rather than trusted from the caller.
func (r *Repository) AttachEvidence(ctx context.Context, tenant tenancy.TenantID, caseID, evidenceID, slot, kind, uploadID, actor string) (cases.Case, error) {
	if r == nil || r.db == nil {
		return cases.Case{}, cases.ErrInvalidCase
	}
	tenant = tenancy.TenantID(strings.ToLower(string(tenant)))
	caseID, evidenceID, uploadID = strings.ToLower(caseID), strings.ToLower(evidenceID), strings.ToLower(uploadID)
	slot, kind = strings.ToLower(strings.TrimSpace(slot)), strings.ToLower(strings.TrimSpace(kind))
	var result cases.Case
	err := tenancy.WithTenantTx(ctx, r.db, tenant, nil, func(tx *sql.Tx) error {
		current, err := lockCase(ctx, tx, tenant, caseID)
		if err != nil {
			return err
		}
		var priorCaseID, priorSlot, priorKind string
		priorErr := tx.QueryRowContext(ctx, `SELECT case_id::text,evidence_slot,evidence_kind FROM keel_meta.supplier_case_evidence WHERE tenant_id=$1 AND upload_id=$2`, string(tenant), uploadID).Scan(&priorCaseID, &priorSlot, &priorKind)
		if priorErr == nil {
			if priorCaseID != caseID || priorSlot != slot || priorKind != kind {
				return ErrConflict
			}
			evidence, err := loadEvidence(ctx, tx, tenant, caseID)
			if err != nil {
				return err
			}
			events, err := loadEvents(ctx, tx, tenant, caseID)
			if err != nil {
				return err
			}
			if err := verifyHistory(CaseView{Case: current, Evidence: evidence, Events: events}); err != nil {
				return err
			}
			result = current
			return nil
		}
		if !errors.Is(priorErr, sql.ErrNoRows) {
			return errors.New("case evidence idempotency lookup failed")
		}
		var media string
		var size int64
		var digest []byte
		err = tx.QueryRowContext(ctx, `SELECT u.detected_media_type,u.expected_bytes,u.expected_sha256
			FROM keel_meta.supplier_uploads u
			JOIN keel_meta.supplier_invitations i ON i.tenant_id=u.tenant_id AND i.invitation_id=u.invitation_id
			WHERE u.tenant_id=$1 AND u.upload_id=$2 AND i.case_id=$3 AND u.upload_state='extracted'
			  AND i.invitation_state='accepted' AND i.expires_at>clock_timestamp() AND i.revoked_at IS NULL`,
			string(tenant), uploadID, caseID).Scan(&media, &size, &digest)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrNotFound
			}
			return errors.New("case evidence source could not be verified")
		}
		evidence, err := loadEvidence(ctx, tx, tenant, caseID)
		if err != nil {
			return err
		}
		events, err := loadEvents(ctx, tx, tenant, caseID)
		if err != nil {
			return err
		}
		if err := verifyHistory(CaseView{Case: current, Evidence: evidence, Events: events}); err != nil {
			return err
		}
		version := uint32(1)
		for _, item := range evidence {
			if item.Slot == slot && item.Version >= version {
				version = item.Version + 1
			}
		}
		next := cases.Evidence{EvidenceID: evidenceID, Slot: slot, Kind: kind, UploadID: uploadID, Version: version, MediaType: media, Bytes: size, SHA256: hex.EncodeToString(digest), AddedBy: actor}
		now, err := dbNow(ctx, tx)
		if err != nil {
			return err
		}
		updated, event, err := cases.AddEvidence(current, evidence, next, actor, now, current.LastEventHash)
		if err != nil {
			return err
		}
		if err := insertEvent(ctx, tx, tenant, event); err != nil {
			return err
		}
		rawDigest, _ := hex.DecodeString(next.SHA256)
		if _, err := tx.ExecContext(ctx, `INSERT INTO keel_meta.supplier_case_evidence
			(tenant_id,case_id,evidence_id,evidence_slot,evidence_kind,slot_version,upload_id,media_type,content_bytes,content_sha256,added_by_ref)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, string(tenant), caseID, evidenceID, next.Slot, next.Kind,
			next.Version, uploadID, media, size, rawDigest, actor); err != nil {
			return classify(err)
		}
		if err := updateCase(ctx, tx, tenant, current, updated); err != nil {
			return err
		}
		if err := insertIntent(ctx, tx, tenant, event); err != nil {
			return err
		}
		result = updated
		return nil
	})
	return result, err
}

func (r *Repository) Submit(ctx context.Context, tenant tenancy.TenantID, caseID, actor string) (cases.Case, error) {
	if r == nil || r.db == nil {
		return cases.Case{}, cases.ErrInvalidCase
	}
	tenant = tenancy.TenantID(strings.ToLower(string(tenant)))
	caseID = strings.ToLower(caseID)
	var result cases.Case
	err := tenancy.WithTenantTx(ctx, r.db, tenant, nil, func(tx *sql.Tx) error {
		current, err := lockCase(ctx, tx, tenant, caseID)
		if err != nil {
			return err
		}
		if current.Status == cases.Submitted {
			evidence, err := loadEvidence(ctx, tx, tenant, caseID)
			if err != nil {
				return err
			}
			events, err := loadEvents(ctx, tx, tenant, caseID)
			if err != nil {
				return err
			}
			if err := verifyHistory(CaseView{Case: current, Evidence: evidence, Events: events}); err != nil {
				return err
			}
			result = current
			return nil
		}
		policy, err := loadPolicy(ctx, tx, tenant, current.PolicyID, current.PolicyVersion)
		if err != nil {
			return err
		}
		evidence, err := loadEvidence(ctx, tx, tenant, caseID)
		if err != nil {
			return err
		}
		events, err := loadEvents(ctx, tx, tenant, caseID)
		if err != nil {
			return err
		}
		if err := verifyHistory(CaseView{Case: current, Evidence: evidence, Events: events}); err != nil {
			return err
		}
		now, err := dbNow(ctx, tx)
		if err != nil {
			return err
		}
		updated, event, err := cases.Submit(current, evidence, policy, actor, now, current.LastEventHash)
		if err != nil {
			return err
		}
		if err := insertApprovalPlan(ctx, tx, tenant, current, policy); err != nil {
			return err
		}
		if err := insertEvent(ctx, tx, tenant, event); err != nil {
			return err
		}
		if err := updateCase(ctx, tx, tenant, current, updated); err != nil {
			return err
		}
		if err := insertIntent(ctx, tx, tenant, event); err != nil {
			return err
		}
		result = updated
		return nil
	})
	return result, err
}

func (r *Repository) Get(ctx context.Context, tenant tenancy.TenantID, caseID string) (CaseView, error) {
	if r == nil || r.db == nil {
		return CaseView{}, cases.ErrInvalidCase
	}
	tenant = tenancy.TenantID(strings.ToLower(string(tenant)))
	caseID = strings.ToLower(caseID)
	var view CaseView
	err := tenancy.WithTenantTx(ctx, r.db, tenant, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead}, func(tx *sql.Tx) error {
		var err error
		view.Case, err = loadCase(ctx, tx, tenant, caseID)
		if err != nil {
			return err
		}
		view.Evidence, err = loadEvidence(ctx, tx, tenant, caseID)
		if err != nil {
			return err
		}
		view.Events, err = loadEvents(ctx, tx, tenant, caseID)
		if err != nil {
			return err
		}
		if err := verifyHistory(view); err != nil {
			return err
		}
		return nil
	})
	return view, err
}

func loadPolicy(ctx context.Context, tx *sql.Tx, tenant tenancy.TenantID, policyID string, version uint32) (cases.Policy, error) {
	var raw []byte
	var storedDigest []byte
	err := tx.QueryRowContext(ctx, `SELECT policy_definition,policy_digest FROM keel_meta.supplier_review_policies
		WHERE tenant_id=$1 AND policy_id=$2 AND version=$3`, string(tenant), policyID, version).Scan(&raw, &storedDigest)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return cases.Policy{}, ErrNotFound
		}
		return cases.Policy{}, errors.New("supplier policy could not be read")
	}
	var policy cases.Policy
	if json.Unmarshal(raw, &policy) != nil {
		return cases.Policy{}, cases.ErrInvalidPolicy
	}
	canonical, _, err := policy.Canonical()
	if err != nil || !equalBytes(storedDigest, mustDecode(canonical.Digest)) {
		return cases.Policy{}, cases.ErrInvalidPolicy
	}
	return canonical, nil
}

func lockCase(ctx context.Context, tx *sql.Tx, tenant tenancy.TenantID, caseID string) (cases.Case, error) {
	return scanCase(ctx, tx, tenant, caseID, true)
}

func scanCase(ctx context.Context, tx *sql.Tx, tenant tenancy.TenantID, caseID string, lock bool) (cases.Case, error) {
	var value cases.Case
	var state string
	var policyDigest, evidenceDigest, lastHash []byte
	query := `SELECT tenant_id::text,case_id::text,supplier_id::text,policy_id::text,policy_version,
		policy_digest,case_state,aggregate_version,evidence_epoch,evidence_digest,last_event_hash,deadline_at,created_at,updated_at
		FROM keel_meta.supplier_cases WHERE tenant_id=$1 AND case_id=$2`
	if lock {
		query += ` FOR UPDATE`
	}
	err := tx.QueryRowContext(ctx, query, string(tenant), caseID).Scan(
		&value.TenantID, &value.CaseID, &value.SupplierID, &value.PolicyID, &value.PolicyVersion, &policyDigest, &state,
		&value.Version, &value.EvidenceEpoch, &evidenceDigest, &lastHash, &value.DeadlineAt, &value.CreatedAt, &value.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return cases.Case{}, ErrNotFound
		}
		return cases.Case{}, errors.New("supplier case could not be read")
	}
	value.Status = cases.Status(state)
	value.PolicyDigest, value.EvidenceDigest, value.LastEventHash = hex.EncodeToString(policyDigest), hex.EncodeToString(evidenceDigest), hex.EncodeToString(lastHash)
	return value, nil
}

func loadCase(ctx context.Context, tx *sql.Tx, tenant tenancy.TenantID, caseID string) (cases.Case, error) {
	return scanCase(ctx, tx, tenant, caseID, false)
}

func loadEvidence(ctx context.Context, tx *sql.Tx, tenant tenancy.TenantID, caseID string) ([]cases.Evidence, error) {
	rows, err := tx.QueryContext(ctx, `SELECT evidence_id::text,evidence_slot,evidence_kind,upload_id::text,slot_version,media_type,content_bytes,content_sha256,added_by_ref
		FROM keel_meta.supplier_case_evidence WHERE tenant_id=$1 AND case_id=$2 ORDER BY evidence_slot,slot_version`, string(tenant), caseID)
	if err != nil {
		return nil, errors.New("supplier case evidence could not be read")
	}
	defer rows.Close()
	var evidence []cases.Evidence
	for rows.Next() {
		var item cases.Evidence
		var version int64
		var digest []byte
		if err := rows.Scan(&item.EvidenceID, &item.Slot, &item.Kind, &item.UploadID, &version, &item.MediaType, &item.Bytes, &digest, &item.AddedBy); err != nil {
			return nil, errors.New("supplier case evidence row is invalid")
		}
		if version < 1 || version > int64(^uint32(0)) {
			return nil, cases.ErrEvidence
		}
		item.Version, item.SHA256 = uint32(version), hex.EncodeToString(digest)
		if err := item.Validate(); err != nil {
			return nil, err
		}
		evidence = append(evidence, item)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.New("supplier case evidence could not be read")
	}
	return evidence, nil
}

func loadEvents(ctx context.Context, tx *sql.Tx, tenant tenancy.TenantID, caseID string) ([]cases.Event, error) {
	rows, err := tx.QueryContext(ctx, `SELECT case_id::text,aggregate_version,event_type,actor_ref,occurred_at,event_data,previous_hash,event_hash
		FROM keel_meta.supplier_case_events WHERE tenant_id=$1 AND case_id=$2 ORDER BY aggregate_version`, string(tenant), caseID)
	if err != nil {
		return nil, errors.New("supplier case history could not be read")
	}
	defer rows.Close()
	var events []cases.Event
	for rows.Next() {
		var event cases.Event
		var version int64
		var prev []byte
		var hash []byte
		if err := rows.Scan(&event.CaseID, &version, &event.Type, &event.Actor, &event.OccurredAt, &event.Data, &prev, &hash); err != nil {
			return nil, errors.New("supplier case history row is invalid")
		}
		if version < 1 {
			return nil, cases.ErrInvalidCase
		}
		event.Version = uint64(version)
		if len(prev) > 0 {
			event.PrevHash = hex.EncodeToString(prev)
		}
		event.Hash = hex.EncodeToString(hash)
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.New("supplier case history could not be read")
	}
	return events, nil
}

func insertEvent(ctx context.Context, tx *sql.Tx, tenant tenancy.TenantID, event cases.Event) error {
	var previous []byte
	if event.PrevHash != "" {
		previous = mustDecode(event.PrevHash)
	}
	var evidenceID any
	var decisionID any
	if event.Type == "supplier.case.evidence-added" {
		var data cases.EvidenceAddedData
		if err := json.Unmarshal(event.Data, &data); err != nil {
			return cases.ErrInvalidCase
		}
		evidenceID = data.Evidence.EvidenceID
	}
	if event.Type == "supplier.case.approval-decided" {
		var data cases.CaseDecisionData
		if err := json.Unmarshal(event.Data, &data); err != nil {
			return cases.ErrInvalidCase
		}
		decisionID = data.DecisionID
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO keel_meta.supplier_case_events
		(tenant_id,case_id,aggregate_version,event_type,actor_ref,occurred_at,event_data,evidence_id,previous_hash,event_hash,decision_id)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, string(tenant), event.CaseID, event.Version, event.Type, event.Actor, event.OccurredAt, []byte(event.Data), evidenceID, previous, mustDecode(event.Hash), decisionID)
	if err != nil {
		return classify(err)
	}
	return nil
}

func insertApprovalPlan(ctx context.Context, tx *sql.Tx, tenant tenancy.TenantID, current cases.Case, policy cases.Policy) error {
	planHash := sha256.Sum256([]byte(current.PolicyDigest + ":" + current.EvidenceDigest))
	for _, step := range policy.Steps {
		dependencies := append([]string{}, step.DependsOn...)
		if _, err := tx.ExecContext(ctx, `INSERT INTO keel_meta.supplier_case_approval_plans
			(tenant_id,case_id,step_key,required_role,depends_on,policy_version,policy_digest,evidence_digest,plan_digest)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`, string(tenant), current.CaseID, step.Key, step.Role, dependencies,
			current.PolicyVersion, mustDecode(current.PolicyDigest), mustDecode(current.EvidenceDigest), planHash[:]); err != nil {
			return classify(err)
		}
	}
	return nil
}

// Decide records one human decision while holding the case row lock. The caller
// must pass the principal resolved from trusted request context; the DB rechecks
// active reviewer assignment/delegation and the frozen plan before insert.
func (r *Repository) Decide(ctx context.Context, tenant tenancy.TenantID, caseID string, decision cases.StepDecision) (cases.Case, error) {
	if r == nil || r.db == nil {
		return cases.Case{}, cases.ErrInvalidCase
	}
	tenant = tenancy.TenantID(strings.ToLower(string(tenant)))
	caseID = strings.ToLower(caseID)
	decision.DecisionID = strings.ToLower(decision.DecisionID)
	decision.StepKey = strings.ToLower(strings.TrimSpace(decision.StepKey))
	decision.Actor = strings.TrimSpace(decision.Actor)
	decision.Outcome = strings.ToLower(strings.TrimSpace(decision.Outcome))
	decision.Reason = strings.TrimSpace(decision.Reason)
	var result cases.Case
	err := tenancy.WithTenantTx(ctx, r.db, tenant, nil, func(tx *sql.Tx) error {
		current, err := lockCase(ctx, tx, tenant, caseID)
		if err != nil {
			return err
		}
		requestDigest := decisionDigest(tenant, caseID, decision)
		var storedDigest []byte
		var storedActor, storedStep, storedOutcome string
		lookupErr := tx.QueryRowContext(ctx, `SELECT request_digest,actor_ref,step_key,outcome
			FROM keel_meta.supplier_case_decisions WHERE tenant_id=$1 AND case_id=$2 AND decision_id=$3`,
			string(tenant), caseID, decision.DecisionID).Scan(&storedDigest, &storedActor, &storedStep, &storedOutcome)
		if lookupErr == nil {
			if equalBytes(storedDigest, requestDigest[:]) && storedActor == decision.Actor && storedStep == decision.StepKey && storedOutcome == decision.Outcome {
				result = current
				return nil
			}
			return ErrConflict
		}
		if !errors.Is(lookupErr, sql.ErrNoRows) {
			return errors.New("supplier decision idempotency record could not be read")
		}
		evidence, err := loadEvidence(ctx, tx, tenant, caseID)
		if err != nil {
			return err
		}
		events, err := loadEvents(ctx, tx, tenant, caseID)
		if err != nil {
			return err
		}
		if err := verifyHistory(CaseView{Case: current, Evidence: evidence, Events: events}); err != nil {
			return err
		}
		policy, err := loadPolicy(ctx, tx, tenant, current.PolicyID, current.PolicyVersion)
		if err != nil {
			return err
		}
		decisions, err := loadDecisions(ctx, tx, tenant, caseID)
		if err != nil {
			return err
		}
		var step cases.ReviewStep
		found := false
		for _, candidate := range policy.Steps {
			if candidate.Key == decision.StepKey {
				step, found = candidate, true
				break
			}
		}
		if !found {
			return ErrConflict
		}
		decision.Role = step.Role // request-supplied role is never authoritative
		now, err := dbNow(ctx, tx)
		if err != nil {
			return err
		}
		decision.DecidedAt = now
		_, _, err = cases.Decide(current, policy, decisions, decision, submittedBy(events), events[0].Actor, now, current.LastEventHash)
		if err != nil {
			return err
		}
		var acceptedAt time.Time
		if err := tx.QueryRowContext(ctx, `INSERT INTO keel_meta.supplier_case_decisions
			(tenant_id,case_id,decision_id,step_key,actor_ref,effective_role,outcome,reason,request_digest,aggregate_version,accepted_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING accepted_at`, string(tenant), caseID, decision.DecisionID, decision.StepKey,
			decision.Actor, decision.Role, decision.Outcome, decision.Reason, requestDigest[:], current.Version+1, now).Scan(&acceptedAt); err != nil {
			return classify(err)
		}
		decision.DecidedAt = acceptedAt
		updated, event, err := cases.Decide(current, policy, decisions, decision, submittedBy(events), events[0].Actor, acceptedAt, current.LastEventHash)
		if err != nil {
			return err
		}
		if err := insertEvent(ctx, tx, tenant, event); err != nil {
			return err
		}
		if err := updateCase(ctx, tx, tenant, current, updated); err != nil {
			return err
		}
		if err := insertIntent(ctx, tx, tenant, event); err != nil {
			return err
		}
		result = updated
		return nil
	})
	return result, err
}

// Expire is invoked by the durable Temporal deadline timer. It shares the case
// lock and transaction with Decide, making the pre-deadline DB timestamp decisive.
func (r *Repository) Expire(ctx context.Context, tenant tenancy.TenantID, caseID string) (cases.Case, error) {
	if r == nil || r.db == nil {
		return cases.Case{}, cases.ErrInvalidCase
	}
	tenant = tenancy.TenantID(strings.ToLower(string(tenant)))
	caseID = strings.ToLower(caseID)
	var result cases.Case
	err := tenancy.WithTenantTx(ctx, r.db, tenant, nil, func(tx *sql.Tx) error {
		current, err := lockCase(ctx, tx, tenant, caseID)
		if err != nil {
			return err
		}
		if current.Status == cases.Expired || current.Status == cases.Approved || current.Status == cases.Rejected || current.Status == cases.Canceled {
			result = current
			return nil
		}
		evidence, err := loadEvidence(ctx, tx, tenant, caseID)
		if err != nil {
			return err
		}
		events, err := loadEvents(ctx, tx, tenant, caseID)
		if err != nil {
			return err
		}
		if err := verifyHistory(CaseView{Case: current, Evidence: evidence, Events: events}); err != nil {
			return err
		}
		now, err := dbNow(ctx, tx)
		if err != nil {
			return err
		}
		updated, event, err := cases.Expire(current, now, current.LastEventHash)
		if err != nil {
			return err
		}
		if err := insertEvent(ctx, tx, tenant, event); err != nil {
			return err
		}
		if err := updateCase(ctx, tx, tenant, current, updated); err != nil {
			return err
		}
		if err := insertIntent(ctx, tx, tenant, event); err != nil {
			return err
		}
		result = updated
		return nil
	})
	return result, err
}

func submittedBy(events []cases.Event) string {
	for _, event := range events {
		if event.Type == "supplier.case.submitted" {
			return event.Actor
		}
	}
	return ""
}

func loadDecisions(ctx context.Context, tx *sql.Tx, tenant tenancy.TenantID, caseID string) ([]cases.StepDecision, error) {
	rows, err := tx.QueryContext(ctx, `SELECT decision_id::text,step_key,actor_ref,outcome,effective_role,reason,accepted_at
		FROM keel_meta.supplier_case_decisions WHERE tenant_id=$1 AND case_id=$2 ORDER BY accepted_at,decision_id`, string(tenant), caseID)
	if err != nil {
		return nil, errors.New("supplier decisions could not be read")
	}
	defer rows.Close()
	var result []cases.StepDecision
	for rows.Next() {
		var item cases.StepDecision
		if err := rows.Scan(&item.DecisionID, &item.StepKey, &item.Actor, &item.Outcome, &item.Role, &item.Reason, &item.DecidedAt); err != nil {
			return nil, errors.New("supplier decision row is invalid")
		}
		result = append(result, item)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.New("supplier decisions could not be read")
	}
	return result, nil
}

func decisionDigest(tenant tenancy.TenantID, caseID string, decision cases.StepDecision) [32]byte {
	canonical, _ := json.Marshal([]string{string(tenant), caseID, decision.DecisionID, decision.StepKey, decision.Actor, decision.Outcome, decision.Reason})
	return sha256.Sum256(canonical)
}

func insertIntent(ctx context.Context, tx *sql.Tx, tenant tenancy.TenantID, event cases.Event) error {
	payload, err := json.Marshal(struct {
		CaseID           string          `json:"case_id"`
		AggregateVersion uint64          `json:"aggregate_version"`
		EventHash        string          `json:"event_hash"`
		Data             json.RawMessage `json:"data"`
	}{event.CaseID, event.Version, event.Hash, event.Data})
	if err != nil {
		return err
	}
	logicalKey := fmt.Sprintf("%s:%d", event.CaseID, event.Version)
	intentID := deterministicUUID(tenant, logicalKey)
	_, err = tx.ExecContext(ctx, `INSERT INTO keel_meta.supplier_workflow_intents
		(tenant_id,intent_id,case_id,aggregate_version,intent_type,logical_key,payload)
		VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb)`, string(tenant), intentID, event.CaseID, event.Version, event.Type, logicalKey, string(payload))
	if err != nil {
		return classify(err)
	}
	return nil
}

func updateCase(ctx context.Context, tx *sql.Tx, tenant tenancy.TenantID, old, next cases.Case) error {
	evidenceDigest, _ := hex.DecodeString(next.EvidenceDigest)
	lastHash, _ := hex.DecodeString(next.LastEventHash)
	res, err := tx.ExecContext(ctx, `UPDATE keel_meta.supplier_cases SET case_state=$4,aggregate_version=$5,
		evidence_epoch=$6,evidence_digest=$7,last_event_hash=$8,updated_at=$9
		WHERE tenant_id=$1 AND case_id=$2 AND aggregate_version=$3`, string(tenant), old.CaseID, old.Version, string(next.Status), next.Version, next.EvidenceEpoch, evidenceDigest, lastHash, next.UpdatedAt)
	if err != nil {
		return classify(err)
	}
	count, err := res.RowsAffected()
	if err != nil || count != 1 {
		return ErrConflict
	}
	return nil
}

func dbNow(ctx context.Context, tx *sql.Tx) (time.Time, error) {
	var now time.Time
	if err := tx.QueryRowContext(ctx, `SELECT date_trunc('microseconds',clock_timestamp())`).Scan(&now); err != nil {
		return time.Time{}, errors.New("database time unavailable")
	}
	return now.UTC(), nil
}

func verifyHistory(view CaseView) error {
	if len(view.Events) == 0 || uint64(len(view.Events)) != view.Case.Version {
		return fmt.Errorf("%w: case event count does not match snapshot version", cases.ErrInvalidCase)
	}
	var previous string
	orderedEvidence := []cases.Evidence{}
	versions := make(map[string]uint32)
	status := cases.Collecting
	for i, event := range view.Events {
		if event.Version != uint64(i+1) || event.PrevHash != previous || !event.Verify() {
			return fmt.Errorf("%w: event %d hash, sequence, or predecessor is invalid", cases.ErrInvalidCase, i+1)
		}
		if i == 0 {
			if event.Type != "supplier.case.created" {
				return fmt.Errorf("%w: first event is not case creation", cases.ErrInvalidCase)
			}
			var data cases.CaseCreatedData
			if json.Unmarshal(event.Data, &data) != nil {
				return fmt.Errorf("%w: case creation data is invalid", cases.ErrInvalidCase)
			}
			deadline, err := time.Parse(time.RFC3339Nano, data.DeadlineAt)
			if err != nil || data.SupplierID != view.Case.SupplierID || data.PolicyID != view.Case.PolicyID || data.PolicyVersion != view.Case.PolicyVersion || data.PolicyDigest != view.Case.PolicyDigest || !deadline.Equal(view.Case.DeadlineAt) || !event.OccurredAt.Equal(view.Case.CreatedAt) {
				return fmt.Errorf("%w: case creation data does not match snapshot", cases.ErrInvalidCase)
			}
		} else if event.Type == "supplier.case.evidence-added" {
			if status != cases.Collecting {
				return cases.ErrInvalidCase
			}
			var data cases.EvidenceAddedData
			if json.Unmarshal(event.Data, &data) != nil || data.Evidence.AddedBy != event.Actor || data.Epoch != uint64(len(orderedEvidence))+1 {
				return fmt.Errorf("%w: evidence event data is invalid", cases.ErrInvalidCase)
			}
			if err := data.Evidence.Validate(); err != nil {
				return err
			}
			if data.Evidence.Version != versions[data.Evidence.Slot]+1 {
				return fmt.Errorf("%w: evidence slot version is not contiguous", cases.ErrInvalidCase)
			}
			versions[data.Evidence.Slot] = data.Evidence.Version
			orderedEvidence = append(orderedEvidence, data.Evidence)
			sortEvidence(orderedEvidence)
			encoded, err := json.Marshal(orderedEvidence)
			if err != nil {
				return err
			}
			digest := sha256.Sum256(encoded)
			if hex.EncodeToString(digest[:]) != data.Digest {
				return fmt.Errorf("%w: evidence event digest is invalid", cases.ErrInvalidCase)
			}
		} else if event.Type == "supplier.case.submitted" {
			if status != cases.Collecting {
				return cases.ErrInvalidCase
			}
			var data cases.CaseSubmittedData
			if json.Unmarshal(event.Data, &data) != nil || data.PolicyVersion != view.Case.PolicyVersion || data.PolicyDigest != view.Case.PolicyDigest || data.EvidenceEpoch != view.Case.EvidenceEpoch || data.EvidenceDigest != view.Case.EvidenceDigest {
				return fmt.Errorf("%w: submission does not match frozen policy and evidence", cases.ErrInvalidCase)
			}
			status = cases.Submitted
		} else if event.Type == "supplier.case.approval-decided" {
			if status != cases.Submitted {
				return cases.ErrInvalidCase
			}
			var data cases.CaseDecisionData
			if json.Unmarshal(event.Data, &data) != nil || data.DecisionID == "" || data.StepKey == "" ||
				(data.Outcome != "approve" && data.Outcome != "reject") || data.PolicyDigest != view.Case.PolicyDigest ||
				data.EvidenceDigest != view.Case.EvidenceDigest || (data.ResultingState != cases.Submitted && data.ResultingState != cases.Approved && data.ResultingState != cases.Rejected) {
				return fmt.Errorf("%w: approval decision event is invalid", cases.ErrInvalidCase)
			}
			if data.Outcome == "reject" && data.ResultingState != cases.Rejected {
				return cases.ErrInvalidCase
			}
			status = data.ResultingState
		} else if event.Type == "supplier.case.expired" {
			if status != cases.Submitted && status != cases.Collecting {
				return cases.ErrInvalidCase
			}
			var data cases.CaseExpiredData
			if json.Unmarshal(event.Data, &data) != nil {
				return cases.ErrInvalidCase
			}
			deadline, err := time.Parse(time.RFC3339Nano, data.DeadlineAt)
			if err != nil || !deadline.Equal(view.Case.DeadlineAt) || event.Actor != "service-principal:keel-supplier-case-expirer" {
				return cases.ErrInvalidCase
			}
			status = cases.Expired
		} else {
			return fmt.Errorf("%w: unsupported event type", cases.ErrInvalidCase)
		}
		previous = event.Hash
	}
	if previous != view.Case.LastEventHash {
		return fmt.Errorf("%w: tail event hash differs from snapshot", cases.ErrInvalidCase)
	}
	items := append([]cases.Evidence{}, view.Evidence...)
	encoded, err := json.Marshal(items)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(encoded)
	if hex.EncodeToString(digest[:]) != view.Case.EvidenceDigest || uint64(len(orderedEvidence)) != view.Case.EvidenceEpoch {
		return fmt.Errorf("%w: evidence collection does not match snapshot epoch and digest", cases.ErrInvalidCase)
	}
	encodedEventsEvidence, err := json.Marshal(orderedEvidence)
	if err != nil || !bytes.Equal(encoded, encodedEventsEvidence) {
		return fmt.Errorf("%w: persisted evidence rows differ from immutable history", cases.ErrInvalidCase)
	}
	last := view.Events[len(view.Events)-1]
	switch last.Type {
	case "supplier.case.created", "supplier.case.evidence-added":
		if view.Case.Status != cases.Collecting {
			return fmt.Errorf("%w: non-collecting snapshot has a collecting event tail", cases.ErrInvalidCase)
		}
	case "supplier.case.submitted":
		if view.Case.Status != cases.Submitted {
			return fmt.Errorf("%w: submitted event tail has a different snapshot state", cases.ErrInvalidCase)
		}
	case "supplier.case.approval-decided":
		var data cases.CaseDecisionData
		if json.Unmarshal(last.Data, &data) != nil || view.Case.Status != data.ResultingState {
			return cases.ErrInvalidCase
		}
	case "supplier.case.expired":
		if view.Case.Status != cases.Expired {
			return cases.ErrInvalidCase
		}
	default:
		return fmt.Errorf("%w: unsupported snapshot state", cases.ErrInvalidCase)
	}
	if status != view.Case.Status {
		return fmt.Errorf("%w: replayed status differs from case snapshot", cases.ErrInvalidCase)
	}
	if !last.OccurredAt.Equal(view.Case.UpdatedAt) {
		return fmt.Errorf("%w: snapshot update time differs from event tail", cases.ErrInvalidCase)
	}
	return nil
}

func sortEvidence(items []cases.Evidence) {
	sort.Slice(items, func(i, j int) bool {
		if items[i].Slot != items[j].Slot {
			return items[i].Slot < items[j].Slot
		}
		return items[i].Version < items[j].Version
	})
}

func classify(err error) error {
	var state interface{ SQLState() string }
	if errors.As(err, &state) {
		switch state.SQLState() {
		case "23505", "23503", "23514", "40001":
			return ErrConflict
		}
	}
	return fmt.Errorf("supplier case persistence failed: %w", err)
}

func mustDecode(value string) []byte { b, _ := hex.DecodeString(value); return b }
func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func deterministicUUID(tenant tenancy.TenantID, key string) string {
	sum := sha256.Sum256([]byte(string(tenant) + "\x00" + key))
	value := hex.EncodeToString(sum[:16])
	return value[:8] + "-" + value[8:12] + "-5" + value[13:16] + "-8" + value[17:20] + "-" + value[20:32]
}
