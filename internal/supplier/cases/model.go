// Package cases contains the deterministic supplier-assessment case model.
// It has no database, network, clock, or identity-provider dependencies.
package cases

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

var (
	ErrInvalidPolicy = errors.New("invalid supplier review policy")
	ErrInvalidCase   = errors.New("invalid supplier case")
	ErrConflict      = errors.New("supplier case state conflict")
	ErrEvidence      = errors.New("invalid supplier evidence")
	uuidPattern      = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	keyPattern       = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,63}$`)
	rolePattern      = regexp.MustCompile(`^[a-z][a-z0-9:_-]{0,63}$`)
	actorPattern     = regexp.MustCompile(`^(principal|service-principal):[A-Za-z0-9._~-]{1,120}$`)
)

const (
	DefaultDeadline  = 72 * time.Hour
	MaxEvidence      = 100
	MaxEvidenceBytes = 100 << 20
	MaxPolicySteps   = 32
	MaxCaseEvents    = 135 // create + 100 evidence revisions + submit + 32 decisions + expiry
)

type Status string

const (
	Collecting Status = "collecting"
	Submitted  Status = "submitted"
	Approved   Status = "approved"
	Rejected   Status = "rejected"
	Canceled   Status = "canceled"
	Expired    Status = "expired"
)

type ReviewStep struct {
	Key        string   `json:"key"`
	Role       string   `json:"role"`
	DependsOn  []string `json:"depends_on,omitempty"`
	ParallelID string   `json:"parallel_id,omitempty"`
}

// Policy is an immutable, bounded declarative review definition. It cannot execute tenant code.
type Policy struct {
	TenantID         string        `json:"tenant_id"`
	PolicyID         string        `json:"policy_id"`
	Version          uint32        `json:"version"`
	Name             string        `json:"name"`
	Deadline         time.Duration `json:"deadline_ns"`
	RequiredEvidence []string      `json:"required_evidence"`
	Steps            []ReviewStep  `json:"steps"`
	PublishedAt      time.Time     `json:"published_at"`
	Digest           string        `json:"digest"`
}

func (p Policy) Canonical() (Policy, []byte, error) {
	p.TenantID = strings.ToLower(strings.TrimSpace(p.TenantID))
	p.PolicyID = strings.ToLower(strings.TrimSpace(p.PolicyID))
	p.Name = strings.TrimSpace(p.Name)
	p.RequiredEvidence = append([]string{}, p.RequiredEvidence...)
	if !uuidPattern.MatchString(p.TenantID) || !uuidPattern.MatchString(p.PolicyID) || p.Version == 0 || len(p.Name) == 0 || len(p.Name) > 120 || !utf8.ValidString(p.Name) || p.PublishedAt.IsZero() {
		return Policy{}, nil, ErrInvalidPolicy
	}
	if p.Deadline == 0 {
		p.Deadline = DefaultDeadline
	}
	if p.RequiredEvidence == nil {
		p.RequiredEvidence = []string{}
	}
	if p.Deadline < time.Hour || p.Deadline > DefaultDeadline || p.Deadline%time.Minute != 0 {
		return Policy{}, nil, ErrInvalidPolicy
	}
	if len(p.RequiredEvidence) > MaxEvidence || len(p.Steps) == 0 || len(p.Steps) > MaxPolicySteps {
		return Policy{}, nil, ErrInvalidPolicy
	}
	for i, kind := range p.RequiredEvidence {
		p.RequiredEvidence[i] = strings.ToLower(strings.TrimSpace(kind))
		if !keyPattern.MatchString(p.RequiredEvidence[i]) {
			return Policy{}, nil, ErrInvalidPolicy
		}
	}
	sort.Strings(p.RequiredEvidence)
	for i := 1; i < len(p.RequiredEvidence); i++ {
		if p.RequiredEvidence[i] == p.RequiredEvidence[i-1] {
			return Policy{}, nil, ErrInvalidPolicy
		}
	}
	steps := append([]ReviewStep(nil), p.Steps...)
	for i := range steps {
		steps[i].DependsOn = append([]string{}, steps[i].DependsOn...)
	}
	seen := make(map[string]struct{}, len(steps))
	for i := range steps {
		steps[i].Key = strings.ToLower(strings.TrimSpace(steps[i].Key))
		steps[i].Role = strings.ToLower(strings.TrimSpace(steps[i].Role))
		steps[i].ParallelID = strings.ToLower(strings.TrimSpace(steps[i].ParallelID))
		if !keyPattern.MatchString(steps[i].Key) || !rolePattern.MatchString(steps[i].Role) || (steps[i].ParallelID != "" && !keyPattern.MatchString(steps[i].ParallelID)) {
			return Policy{}, nil, ErrInvalidPolicy
		}
		if _, exists := seen[steps[i].Key]; exists {
			return Policy{}, nil, ErrInvalidPolicy
		}
		seen[steps[i].Key] = struct{}{}
		sort.Strings(steps[i].DependsOn)
	}
	for _, step := range steps {
		for i, dependency := range step.DependsOn {
			if !keyPattern.MatchString(dependency) || dependency == step.Key || (i > 0 && dependency == step.DependsOn[i-1]) {
				return Policy{}, nil, ErrInvalidPolicy
			}
			if _, exists := seen[dependency]; !exists {
				return Policy{}, nil, ErrInvalidPolicy
			}
		}
	}
	if hasDependencyCycle(steps) {
		return Policy{}, nil, ErrInvalidPolicy
	}
	sort.Slice(steps, func(i, j int) bool { return steps[i].Key < steps[j].Key })
	p.Steps = steps
	p.PublishedAt = p.PublishedAt.UTC().Truncate(time.Microsecond)
	p.Digest = ""
	encoded, err := json.Marshal(p)
	if err != nil {
		return Policy{}, nil, fmt.Errorf("encode supplier review policy: %w", err)
	}
	digest := sha256.Sum256(encoded)
	p.Digest = hex.EncodeToString(digest[:])
	return p, encoded, nil
}

func hasDependencyCycle(steps []ReviewStep) bool {
	deps := make(map[string][]string, len(steps))
	for _, step := range steps {
		deps[step.Key] = step.DependsOn
	}
	visiting, visited := map[string]bool{}, map[string]bool{}
	var visit func(string) bool
	visit = func(key string) bool {
		if visiting[key] {
			return true
		}
		if visited[key] {
			return false
		}
		visiting[key] = true
		for _, dep := range deps[key] {
			if visit(dep) {
				return true
			}
		}
		delete(visiting, key)
		visited[key] = true
		return false
	}
	for key := range deps {
		if visit(key) {
			return true
		}
	}
	return false
}

type Evidence struct {
	EvidenceID string `json:"evidence_id"`
	Slot       string `json:"slot"`
	Kind       string `json:"kind"`
	UploadID   string `json:"upload_id"`
	Version    uint32 `json:"version"`
	MediaType  string `json:"media_type"`
	Bytes      int64  `json:"bytes"`
	SHA256     string `json:"sha256"`
	AddedBy    string `json:"added_by"`
}

func (e Evidence) Validate() error {
	e.Slot = strings.ToLower(strings.TrimSpace(e.Slot))
	e.Kind = strings.ToLower(strings.TrimSpace(e.Kind))
	if !uuidPattern.MatchString(strings.ToLower(e.EvidenceID)) || !uuidPattern.MatchString(strings.ToLower(e.UploadID)) || !keyPattern.MatchString(e.Slot) || !keyPattern.MatchString(e.Kind) || e.Version == 0 || e.Bytes < 1 || e.Bytes > 20<<20 || !validSHA256(e.SHA256) || !actorPattern.MatchString(e.AddedBy) {
		return ErrEvidence
	}
	switch e.MediaType {
	case "application/pdf", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "text/plain":
	default:
		return ErrEvidence
	}
	return nil
}

type Case struct {
	TenantID       string    `json:"tenant_id"`
	CaseID         string    `json:"case_id"`
	SupplierID     string    `json:"supplier_id"`
	PolicyID       string    `json:"policy_id"`
	PolicyVersion  uint32    `json:"policy_version"`
	PolicyDigest   string    `json:"policy_digest"`
	Status         Status    `json:"status"`
	Version        uint64    `json:"version"`
	EvidenceEpoch  uint64    `json:"evidence_epoch"`
	EvidenceDigest string    `json:"evidence_digest"`
	LastEventHash  string    `json:"last_event_hash"`
	DeadlineAt     time.Time `json:"deadline_at"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

type Event struct {
	CaseID     string          `json:"case_id"`
	Version    uint64          `json:"version"`
	Type       string          `json:"type"`
	Actor      string          `json:"actor"`
	OccurredAt time.Time       `json:"occurred_at"`
	Data       json.RawMessage `json:"data"`
	PrevHash   string          `json:"prev_hash,omitempty"`
	Hash       string          `json:"hash"`
}

type CaseCreatedData struct {
	SupplierID    string `json:"supplier_id"`
	PolicyID      string `json:"policy_id"`
	PolicyVersion uint32 `json:"policy_version"`
	PolicyDigest  string `json:"policy_digest"`
	DeadlineAt    string `json:"deadline_at"`
}

type EvidenceAddedData struct {
	Evidence Evidence `json:"evidence"`
	Epoch    uint64   `json:"evidence_epoch"`
	Digest   string   `json:"evidence_digest"`
}

type CaseSubmittedData struct {
	PolicyVersion  uint32 `json:"policy_version"`
	PolicyDigest   string `json:"policy_digest"`
	EvidenceEpoch  uint64 `json:"evidence_epoch"`
	EvidenceDigest string `json:"evidence_digest"`
}

type StepDecision struct {
	DecisionID string    `json:"decision_id"`
	StepKey    string    `json:"step_key"`
	Actor      string    `json:"actor"`
	Outcome    string    `json:"outcome"`
	Role       string    `json:"role"`
	Reason     string    `json:"reason,omitempty"`
	DecidedAt  time.Time `json:"decided_at"`
}

type CaseDecisionData struct {
	DecisionID     string `json:"decision_id"`
	StepKey        string `json:"step_key"`
	Outcome        string `json:"outcome"`
	ResultingState Status `json:"resulting_state"`
	PolicyDigest   string `json:"policy_digest"`
	EvidenceDigest string `json:"evidence_digest"`
}

type CaseExpiredData struct {
	DeadlineAt string `json:"deadline_at"`
}

func NewCase(tenantID, caseID, supplierID, actor string, policy Policy, now time.Time) (Case, Event, error) {
	tenantID = strings.ToLower(tenantID)
	caseID = strings.ToLower(caseID)
	supplierID = strings.ToLower(supplierID)
	policy, _, err := policy.Canonical()
	if err != nil || policy.TenantID != tenantID || !uuidPattern.MatchString(caseID) || !uuidPattern.MatchString(supplierID) || !validActor(actor) || now.IsZero() {
		return Case{}, Event{}, ErrInvalidCase
	}
	now = now.UTC().Truncate(time.Microsecond)
	emptyEvidence, _ := json.Marshal([]Evidence{})
	empty := sha256.Sum256(emptyEvidence)
	result := Case{
		TenantID: strings.ToLower(tenantID), CaseID: caseID, SupplierID: supplierID,
		PolicyID: policy.PolicyID, PolicyVersion: policy.Version, PolicyDigest: policy.Digest,
		Status: Collecting, Version: 1, EvidenceDigest: hex.EncodeToString(empty[:]),
		DeadlineAt: now.Add(policy.Deadline), CreatedAt: now, UpdatedAt: now,
	}
	data, _ := json.Marshal(CaseCreatedData{SupplierID: supplierID, PolicyID: policy.PolicyID, PolicyVersion: policy.Version, PolicyDigest: policy.Digest, DeadlineAt: result.DeadlineAt.Format(time.RFC3339Nano)})
	event, err := (Event{CaseID: caseID, Version: 1, Type: "supplier.case.created", Actor: actor, OccurredAt: now, Data: data}).Seal()
	if err == nil {
		result.LastEventHash = event.Hash
	}
	return result, event, err
}

func AddEvidence(current Case, evidence []Evidence, next Evidence, actor string, now time.Time, previousHash string) (Case, Event, error) {
	if !uuidPattern.MatchString(current.CaseID) || current.Version == 0 || current.Status != Collecting || !validActor(actor) || now.IsZero() || !current.DeadlineAt.After(now) || !validPreviousHash(current, previousHash) {
		return Case{}, Event{}, ErrConflict
	}
	next.EvidenceID = strings.ToLower(next.EvidenceID)
	next.UploadID = strings.ToLower(next.UploadID)
	next.Slot = strings.ToLower(strings.TrimSpace(next.Slot))
	next.Kind = strings.ToLower(strings.TrimSpace(next.Kind))
	next.SHA256 = strings.ToLower(next.SHA256)
	next.AddedBy = actor
	if err := next.Validate(); err != nil {
		return Case{}, Event{}, err
	}
	var prior uint32
	var priorKind string
	var totalBytes int64
	for _, item := range evidence {
		totalBytes += item.Bytes
		if item.Slot == next.Slot && item.Version > prior {
			prior = item.Version
			priorKind = item.Kind
		}
	}
	if next.Version != prior+1 || len(evidence) >= MaxEvidence || totalBytes+next.Bytes > MaxEvidenceBytes || (prior > 0 && priorKind != next.Kind) {
		return Case{}, Event{}, ErrEvidence
	}
	all := append(append([]Evidence(nil), evidence...), next)
	sort.Slice(all, func(i, j int) bool {
		if all[i].Slot != all[j].Slot {
			return all[i].Slot < all[j].Slot
		}
		return all[i].Version < all[j].Version
	})
	encoded, err := json.Marshal(all)
	if err != nil {
		return Case{}, Event{}, err
	}
	digest := sha256.Sum256(encoded)
	updated := current
	updated.Version++
	updated.EvidenceEpoch++
	updated.EvidenceDigest = hex.EncodeToString(digest[:])
	updated.UpdatedAt = now.UTC().Truncate(time.Microsecond)
	data, _ := json.Marshal(EvidenceAddedData{Evidence: next, Epoch: updated.EvidenceEpoch, Digest: updated.EvidenceDigest})
	event, err := (Event{CaseID: current.CaseID, Version: updated.Version, Type: "supplier.case.evidence-added", Actor: actor, OccurredAt: updated.UpdatedAt, Data: data, PrevHash: previousHash}).Seal()
	if err == nil {
		updated.LastEventHash = event.Hash
	}
	return updated, event, err
}

func validPreviousHash(current Case, previousHash string) bool {
	return previousHash == current.LastEventHash && validSHA256(previousHash)
}

func Submit(current Case, evidence []Evidence, policy Policy, actor string, now time.Time, previousHash string) (Case, Event, error) {
	if current.Status != Collecting || !current.DeadlineAt.After(now) || !validActor(actor) || now.IsZero() || !validPreviousHash(current, previousHash) {
		return Case{}, Event{}, ErrConflict
	}
	canonical, _, err := policy.Canonical()
	if err != nil || canonical.PolicyID != current.PolicyID || canonical.Version != current.PolicyVersion || canonical.Digest != current.PolicyDigest {
		return Case{}, Event{}, ErrInvalidPolicy
	}
	latest := make(map[string]Evidence, len(evidence))
	for _, item := range evidence {
		previous, ok := latest[item.Slot]
		if !ok || item.Version > previous.Version {
			latest[item.Slot] = item
		}
	}
	kinds := make(map[string]bool, len(latest))
	for _, item := range latest {
		kinds[item.Kind] = true
	}
	for _, required := range canonical.RequiredEvidence {
		if !kinds[required] {
			return Case{}, Event{}, ErrEvidence
		}
	}
	updated := current
	updated.Status = Submitted
	updated.Version++
	updated.UpdatedAt = now.UTC().Truncate(time.Microsecond)
	data, _ := json.Marshal(CaseSubmittedData{PolicyVersion: current.PolicyVersion, PolicyDigest: current.PolicyDigest, EvidenceEpoch: current.EvidenceEpoch, EvidenceDigest: current.EvidenceDigest})
	event, err := (Event{CaseID: current.CaseID, Version: updated.Version, Type: "supplier.case.submitted", Actor: actor, OccurredAt: updated.UpdatedAt, Data: data, PrevHash: previousHash}).Seal()
	if err == nil {
		updated.LastEventHash = event.Hash
	}
	return updated, event, err
}

// EligibleSteps returns the frozen policy steps whose dependencies have all been
// approved. A rejection is terminal and therefore unlocks no dependent step.
func EligibleSteps(policy Policy, decisions []StepDecision) []ReviewStep {
	approved := make(map[string]bool, len(decisions))
	decided := make(map[string]bool, len(decisions))
	for _, decision := range decisions {
		decided[decision.StepKey] = true
		approved[decision.StepKey] = decision.Outcome == "approve"
	}
	steps := make([]ReviewStep, 0, len(policy.Steps))
	for _, step := range policy.Steps {
		if decided[step.Key] {
			continue
		}
		ready := true
		for _, dependency := range step.DependsOn {
			if !approved[dependency] {
				ready = false
				break
			}
		}
		if ready {
			steps = append(steps, step)
		}
	}
	return steps
}

// Decide records one authorized human step decision. Authorization is checked by
// the persistence boundary in the same locked transaction; this pure transition
// rechecks separation of duties, plan eligibility and the database timestamp.
func Decide(current Case, policy Policy, decisions []StepDecision, decision StepDecision, submitter, creator string, now time.Time, previousHash string) (Case, Event, error) {
	if current.Status != Submitted || now.IsZero() || !current.DeadlineAt.After(now) ||
		!validPreviousHash(current, previousHash) || !uuidPattern.MatchString(strings.ToLower(decision.DecisionID)) ||
		!validActor(decision.Actor) || !strings.HasPrefix(decision.Actor, "principal:") ||
		decision.Actor == submitter || decision.Actor == creator ||
		(decision.Outcome != "approve" && decision.Outcome != "reject") {
		return Case{}, Event{}, ErrConflict
	}
	canonical, _, err := policy.Canonical()
	if err != nil || canonical.Digest != current.PolicyDigest || canonical.Version != current.PolicyVersion || canonical.PolicyID != current.PolicyID {
		return Case{}, Event{}, ErrInvalidPolicy
	}
	decision.DecisionID = strings.ToLower(decision.DecisionID)
	decision.StepKey = strings.ToLower(strings.TrimSpace(decision.StepKey))
	decision.DecidedAt = now.UTC().Truncate(time.Microsecond)
	var step *ReviewStep
	for i := range canonical.Steps {
		if canonical.Steps[i].Key == decision.StepKey {
			step = &canonical.Steps[i]
			break
		}
	}
	if step == nil || decision.Role != step.Role || len(decision.Reason) > 500 || !utf8.ValidString(decision.Reason) {
		return Case{}, Event{}, ErrConflict
	}
	eligible := false
	for _, ready := range EligibleSteps(canonical, decisions) {
		if ready.Key == step.Key {
			eligible = true
			break
		}
	}
	if !eligible || len(decisions) >= len(canonical.Steps) || current.Version >= MaxCaseEvents {
		return Case{}, Event{}, ErrConflict
	}
	for _, previous := range decisions {
		if previous.StepKey == decision.StepKey || previous.DecisionID == decision.DecisionID {
			return Case{}, Event{}, ErrConflict
		}
	}
	allApproved := decision.Outcome == "approve" && len(decisions)+1 == len(canonical.Steps)
	if allApproved {
		for _, old := range decisions {
			if old.Outcome != "approve" {
				allApproved = false
				break
			}
		}
	}
	updated := current
	if decision.Outcome == "reject" {
		updated.Status = Rejected
	} else if allApproved {
		updated.Status = Approved
	}
	updated.Version++
	updated.UpdatedAt = decision.DecidedAt
	data, _ := json.Marshal(CaseDecisionData{DecisionID: decision.DecisionID, StepKey: decision.StepKey,
		Outcome: decision.Outcome, ResultingState: updated.Status, PolicyDigest: current.PolicyDigest, EvidenceDigest: current.EvidenceDigest})
	event, err := (Event{CaseID: current.CaseID, Version: updated.Version, Type: "supplier.case.approval-decided", Actor: decision.Actor,
		OccurredAt: updated.UpdatedAt, Data: data, PrevHash: previousHash}).Seal()
	if err == nil {
		updated.LastEventHash = event.Hash
	}
	return updated, event, err
}

// Expire is the deterministic state transition for a deadline operation. The
// repository supplies PostgreSQL time while holding the authoritative case lock.
func Expire(current Case, now time.Time, previousHash string) (Case, Event, error) {
	if (current.Status != Submitted && current.Status != Collecting) || now.IsZero() || current.DeadlineAt.After(now) || !validPreviousHash(current, previousHash) || current.Version >= MaxCaseEvents {
		return Case{}, Event{}, ErrConflict
	}
	updated := current
	updated.Status = Expired
	updated.Version++
	updated.UpdatedAt = now.UTC().Truncate(time.Microsecond)
	data, _ := json.Marshal(CaseExpiredData{DeadlineAt: current.DeadlineAt.UTC().Format(time.RFC3339Nano)})
	event, err := (Event{CaseID: current.CaseID, Version: updated.Version, Type: "supplier.case.expired", Actor: "service-principal:keel-supplier-case-expirer",
		OccurredAt: updated.UpdatedAt, Data: data, PrevHash: previousHash}).Seal()
	if err == nil {
		updated.LastEventHash = event.Hash
	}
	return updated, event, err
}

func (e Event) Seal() (Event, error) {
	if !uuidPattern.MatchString(e.CaseID) || e.Version == 0 || !keyPattern.MatchString(strings.ReplaceAll(e.Type, ".", "-")) || !validActor(e.Actor) || e.OccurredAt.IsZero() || !json.Valid(e.Data) || (e.Version == 1 && e.PrevHash != "") || (e.Version > 1 && !validSHA256(e.PrevHash)) {
		return Event{}, ErrInvalidCase
	}
	e.OccurredAt = e.OccurredAt.UTC().Truncate(time.Microsecond)
	e.Hash = ""
	b, err := json.Marshal(e)
	if err != nil {
		return Event{}, err
	}
	hash := sha256.Sum256(b)
	e.Hash = hex.EncodeToString(hash[:])
	return e, nil
}

func (e Event) Verify() bool {
	want := e.Hash
	sealed, err := e.Seal()
	return err == nil && validSHA256(want) && sealed.Hash == want
}

func validActor(actor string) bool { return actorPattern.MatchString(actor) }

func validSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
