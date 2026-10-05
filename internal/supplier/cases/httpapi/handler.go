// Package httpapi exposes the authenticated supplier-case domain contract.
// The package is not mounted by the Keel runtime until K0 identity wiring is complete.
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"time"

	"github.com/sanskarpan/keel/internal/platform/tenancy"
	"github.com/sanskarpan/keel/internal/supplier/cases"
	"github.com/sanskarpan/keel/internal/supplier/cases/postgres"
	"github.com/sanskarpan/keel/internal/supplier/intake"
)

const maxBodyBytes = 24 << 10

var uuid = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
var actorRef = regexp.MustCompile(`^(principal|service-principal):[A-Za-z0-9._~-]{1,120}$`)
var idempotencyKey = regexp.MustCompile(`^[A-Za-z0-9._~-]{16,128}$`)

type Principal struct {
	TenantID tenancy.TenantID
	ActorRef string
}

type PrincipalResolver interface {
	Resolve(context.Context, *http.Request) (Principal, bool)
}

type Authorizer interface {
	CanPublishReviewPolicy(context.Context, Principal) bool
	CanCreateSupplierCase(context.Context, Principal, string, string) bool
	CanManageSupplierCase(context.Context, Principal, string) bool
	CanSubmitSupplierCase(context.Context, Principal, string) bool
	CanDecideSupplierCase(context.Context, Principal, string) bool
}

type Repository interface {
	PublishPolicy(context.Context, tenancy.TenantID, cases.Policy, string) (cases.Policy, error)
	Create(context.Context, tenancy.TenantID, string, string, string, uint32, string) (cases.Case, error)
	AttachEvidence(context.Context, tenancy.TenantID, string, string, string, string, string, string) (cases.Case, error)
	Submit(context.Context, tenancy.TenantID, string, string) (cases.Case, error)
	Decide(context.Context, tenancy.TenantID, string, cases.StepDecision) (cases.Case, error)
	Cancel(context.Context, tenancy.TenantID, string, string, string, string) (cases.Case, error)
	RequestManualReview(context.Context, tenancy.TenantID, string, cases.ManualReviewData, string) (cases.Case, error)
	ResolveManualReview(context.Context, tenancy.TenantID, string, cases.ManualReviewData, string) (cases.Case, error)
	Expire(context.Context, tenancy.TenantID, string) (cases.Case, error)
	Get(context.Context, tenancy.TenantID, string) (postgres.CaseView, error)
}

type Handler struct {
	repo       Repository
	principals PrincipalResolver
	authz      Authorizer
	now        func() time.Time
	mux        *http.ServeMux
}

func New(repo Repository, principals PrincipalResolver, authz Authorizer, clock func() time.Time) (*Handler, error) {
	if repo == nil || principals == nil || authz == nil {
		return nil, errors.New("supplier case HTTP dependencies are incomplete")
	}
	if clock == nil {
		clock = time.Now
	}
	h := &Handler{repo: repo, principals: principals, authz: authz, now: clock, mux: http.NewServeMux()}
	h.mux.HandleFunc("POST /v1/supplier-review-policies", h.publishPolicy)
	h.mux.HandleFunc("POST /v1/supplier-cases", h.createCase)
	h.mux.HandleFunc("GET /v1/supplier-cases/{case_id}", h.getCase)
	h.mux.HandleFunc("POST /v1/supplier-cases/{case_id}/evidence", h.attachEvidence)
	h.mux.HandleFunc("POST /v1/supplier-cases/{case_id}/submit", h.submitCase)
	h.mux.HandleFunc("POST /v1/supplier-cases/{case_id}/decisions", h.decideCase)
	h.mux.HandleFunc("POST /v1/supplier-cases/{case_id}/cancel", h.cancelCase)
	h.mux.HandleFunc("POST /v1/supplier-cases/{case_id}/manual-reviews", h.requestManualReview)
	h.mux.HandleFunc("POST /v1/supplier-cases/{case_id}/manual-reviews/{review_id}/resolution", h.resolveManualReview)
	return h, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
	h.mux.ServeHTTP(w, r)
}

type policyRequest struct {
	PolicyID         string             `json:"policy_id"`
	Version          uint32             `json:"version"`
	Name             string             `json:"name"`
	DeadlineSeconds  int64              `json:"deadline_seconds"`
	RequiredEvidence []string           `json:"required_evidence"`
	Steps            []cases.ReviewStep `json:"steps"`
}

func (h *Handler) publishPolicy(w http.ResponseWriter, r *http.Request) {
	principal, ok := h.principal(w, r)
	if !ok {
		return
	}
	if !h.authz.CanPublishReviewPolicy(r.Context(), principal) {
		writeProblem(w, 403, "forbidden")
		return
	}
	var input policyRequest
	if decode(w, r, &input) != nil || !uuid.MatchString(input.PolicyID) || (input.DeadlineSeconds != 0 && (input.DeadlineSeconds < 3600 || input.DeadlineSeconds > 259200)) {
		writeProblem(w, 400, "invalid_request")
		return
	}
	policy := cases.Policy{TenantID: string(principal.TenantID), PolicyID: input.PolicyID, Version: input.Version, Name: input.Name, Deadline: time.Duration(input.DeadlineSeconds) * time.Second, RequiredEvidence: input.RequiredEvidence, Steps: input.Steps, PublishedAt: h.now().UTC()}
	result, err := h.repo.PublishPolicy(r.Context(), principal.TenantID, policy, principal.ActorRef)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, 201, map[string]any{"policy_id": result.PolicyID, "version": result.Version, "name": result.Name, "deadline_seconds": int64(result.Deadline / time.Second), "required_evidence": result.RequiredEvidence, "steps": result.Steps, "digest": result.Digest, "published_at": result.PublishedAt})
}

type createCaseRequest struct {
	SupplierID    string `json:"supplier_id"`
	PolicyID      string `json:"policy_id"`
	PolicyVersion uint32 `json:"policy_version"`
}

func (h *Handler) createCase(w http.ResponseWriter, r *http.Request) {
	principal, ok := h.principal(w, r)
	if !ok {
		return
	}
	var input createCaseRequest
	if decode(w, r, &input) != nil || !uuid.MatchString(input.SupplierID) || !uuid.MatchString(input.PolicyID) || input.PolicyVersion == 0 {
		writeProblem(w, 400, "invalid_request")
		return
	}
	if !h.authz.CanCreateSupplierCase(r.Context(), principal, input.SupplierID, input.PolicyID) {
		writeProblem(w, 404, "resource_not_found")
		return
	}
	key := r.Header.Get("Idempotency-Key")
	if !idempotencyKey.MatchString(key) {
		writeProblem(w, 400, "invalid_idempotency_key")
		return
	}
	result, err := h.repo.Create(r.Context(), principal.TenantID, key, input.SupplierID, input.PolicyID, input.PolicyVersion, principal.ActorRef)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, 201, caseResponse{CaseID: result.CaseID, SupplierID: result.SupplierID, Status: result.Status, Version: result.Version, PolicyID: result.PolicyID, PolicyVersion: result.PolicyVersion, DeadlineAt: result.DeadlineAt, CreatedAt: result.CreatedAt})
}

type attachEvidenceRequest struct {
	UploadID string `json:"upload_id"`
	Slot     string `json:"slot"`
	Kind     string `json:"kind"`
}

func (h *Handler) attachEvidence(w http.ResponseWriter, r *http.Request) {
	principal, caseID, ok := h.casePrincipal(w, r)
	if !ok {
		return
	}
	if !h.authz.CanManageSupplierCase(r.Context(), principal, caseID) {
		writeProblem(w, 404, "resource_not_found")
		return
	}
	var input attachEvidenceRequest
	if decode(w, r, &input) != nil || !uuid.MatchString(input.UploadID) {
		writeProblem(w, 400, "invalid_request")
		return
	}
	evidenceID, err := intake.NewObjectID(nil)
	if err != nil {
		writeProblem(w, 500, "request_failed")
		return
	}
	result, err := h.repo.AttachEvidence(r.Context(), principal.TenantID, caseID, evidenceID, input.Slot, input.Kind, input.UploadID, principal.ActorRef)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, 200, caseResponse{CaseID: result.CaseID, SupplierID: result.SupplierID, Status: result.Status, Version: result.Version, EvidenceEpoch: result.EvidenceEpoch, EvidenceDigest: result.EvidenceDigest, PolicyID: result.PolicyID, PolicyVersion: result.PolicyVersion, DeadlineAt: result.DeadlineAt, UpdatedAt: result.UpdatedAt})
}

func (h *Handler) submitCase(w http.ResponseWriter, r *http.Request) {
	principal, caseID, ok := h.casePrincipal(w, r)
	if !ok {
		return
	}
	if !h.authz.CanSubmitSupplierCase(r.Context(), principal, caseID) {
		writeProblem(w, 404, "resource_not_found")
		return
	}
	if err := ensureEmptyBody(r); err != nil {
		writeProblem(w, 400, "invalid_request")
		return
	}
	result, err := h.repo.Submit(r.Context(), principal.TenantID, caseID, principal.ActorRef)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, 200, caseResponse{CaseID: result.CaseID, SupplierID: result.SupplierID, Status: result.Status, Version: result.Version, EvidenceEpoch: result.EvidenceEpoch, EvidenceDigest: result.EvidenceDigest, PolicyID: result.PolicyID, PolicyVersion: result.PolicyVersion, DeadlineAt: result.DeadlineAt, UpdatedAt: result.UpdatedAt})
}

type decisionRequest struct {
	DecisionID string `json:"decision_id"`
	StepKey    string `json:"step_key"`
	Outcome    string `json:"outcome"`
	Reason     string `json:"reason,omitempty"`
}

func (h *Handler) decideCase(w http.ResponseWriter, r *http.Request) {
	principal, caseID, ok := h.casePrincipal(w, r)
	if !ok {
		return
	}
	if !h.authz.CanDecideSupplierCase(r.Context(), principal, caseID) {
		writeProblem(w, 404, "resource_not_found")
		return
	}
	var input decisionRequest
	if decode(w, r, &input) != nil || !uuid.MatchString(input.DecisionID) {
		writeProblem(w, 400, "invalid_request")
		return
	}
	result, err := h.repo.Decide(r.Context(), principal.TenantID, caseID, cases.StepDecision{
		DecisionID: input.DecisionID, StepKey: input.StepKey, Outcome: input.Outcome,
		Reason: input.Reason, Actor: principal.ActorRef,
	})
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, 200, caseResponse{CaseID: result.CaseID, SupplierID: result.SupplierID, Status: result.Status,
		Version: result.Version, EvidenceEpoch: result.EvidenceEpoch, EvidenceDigest: result.EvidenceDigest,
		PolicyID: result.PolicyID, PolicyVersion: result.PolicyVersion, DeadlineAt: result.DeadlineAt, UpdatedAt: result.UpdatedAt})
}

type cancelRequest struct {
	CancellationID string `json:"cancellation_id"`
	Reason         string `json:"reason"`
}

func (h *Handler) cancelCase(w http.ResponseWriter, r *http.Request) {
	principal, caseID, ok := h.casePrincipal(w, r)
	if !ok {
		return
	}
	if !h.authz.CanManageSupplierCase(r.Context(), principal, caseID) {
		writeProblem(w, 404, "resource_not_found")
		return
	}
	var input cancelRequest
	if decode(w, r, &input) != nil || !uuid.MatchString(input.CancellationID) || len(input.Reason) == 0 || len(input.Reason) > 500 {
		writeProblem(w, 400, "invalid_request")
		return
	}
	result, err := h.repo.Cancel(r.Context(), principal.TenantID, caseID, input.CancellationID, input.Reason, principal.ActorRef)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, 200, caseResponse{CaseID: result.CaseID, SupplierID: result.SupplierID, Status: result.Status, Version: result.Version, PolicyID: result.PolicyID, PolicyVersion: result.PolicyVersion, DeadlineAt: result.DeadlineAt, UpdatedAt: result.UpdatedAt})
}

type manualReviewRequest struct {
	ReviewID   string `json:"review_id"`
	EvidenceID string `json:"evidence_id"`
	Reason     string `json:"reason"`
}

func (h *Handler) requestManualReview(w http.ResponseWriter, r *http.Request) {
	principal, caseID, ok := h.casePrincipal(w, r)
	if !ok {
		return
	}
	if !h.authz.CanDecideSupplierCase(r.Context(), principal, caseID) {
		writeProblem(w, 404, "resource_not_found")
		return
	}
	var input manualReviewRequest
	if decode(w, r, &input) != nil || !uuid.MatchString(input.ReviewID) || !uuid.MatchString(input.EvidenceID) || len(input.Reason) == 0 || len(input.Reason) > 500 {
		writeProblem(w, 400, "invalid_request")
		return
	}
	result, err := h.repo.RequestManualReview(r.Context(), principal.TenantID, caseID, cases.ManualReviewData{ReviewID: input.ReviewID, EvidenceID: input.EvidenceID, Reason: input.Reason}, principal.ActorRef)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, 200, caseResponse{CaseID: result.CaseID, SupplierID: result.SupplierID, Status: result.Status, Version: result.Version, DeadlineAt: result.DeadlineAt, UpdatedAt: result.UpdatedAt})
}

type manualReviewResolutionRequest struct {
	Outcome    string `json:"outcome"`
	Reason     string `json:"reason"`
	EvidenceID string `json:"evidence_id"`
}

func (h *Handler) resolveManualReview(w http.ResponseWriter, r *http.Request) {
	principal, caseID, ok := h.casePrincipal(w, r)
	if !ok {
		return
	}
	if !h.authz.CanDecideSupplierCase(r.Context(), principal, caseID) {
		writeProblem(w, 404, "resource_not_found")
		return
	}
	reviewID := r.PathValue("review_id")
	var input manualReviewResolutionRequest
	if !uuid.MatchString(reviewID) || decode(w, r, &input) != nil || !uuid.MatchString(input.EvidenceID) || len(input.Reason) == 0 || len(input.Reason) > 500 || (input.Outcome != "confirmed" && input.Outcome != "replacement-required") {
		writeProblem(w, 400, "invalid_request")
		return
	}
	result, err := h.repo.ResolveManualReview(r.Context(), principal.TenantID, caseID, cases.ManualReviewData{ReviewID: reviewID, EvidenceID: input.EvidenceID, Outcome: input.Outcome, Reason: input.Reason}, principal.ActorRef)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, 200, caseResponse{CaseID: result.CaseID, SupplierID: result.SupplierID, Status: result.Status, Version: result.Version, DeadlineAt: result.DeadlineAt, UpdatedAt: result.UpdatedAt})
}

func (h *Handler) getCase(w http.ResponseWriter, r *http.Request) {
	principal, caseID, ok := h.casePrincipal(w, r)
	if !ok {
		return
	}
	if !h.authz.CanManageSupplierCase(r.Context(), principal, caseID) {
		writeProblem(w, 404, "resource_not_found")
		return
	}
	view, err := h.repo.Get(r.Context(), principal.TenantID, caseID)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	evidence := make([]evidenceResponse, 0, len(view.Evidence))
	for _, item := range view.Evidence {
		evidence = append(evidence, evidenceResponse{EvidenceID: item.EvidenceID, Slot: item.Slot, Kind: item.Kind, UploadID: item.UploadID, Version: item.Version, MediaType: item.MediaType, Bytes: item.Bytes, SHA256: item.SHA256})
	}
	result := view.Case
	writeJSON(w, 200, caseResponse{CaseID: result.CaseID, SupplierID: result.SupplierID, Status: result.Status, Version: result.Version, EvidenceEpoch: result.EvidenceEpoch, EvidenceDigest: result.EvidenceDigest, PolicyID: result.PolicyID, PolicyVersion: result.PolicyVersion, DeadlineAt: result.DeadlineAt, CreatedAt: result.CreatedAt, UpdatedAt: result.UpdatedAt, Evidence: evidence})
}

type evidenceResponse struct {
	EvidenceID string `json:"evidence_id"`
	Slot       string `json:"slot"`
	Kind       string `json:"kind"`
	UploadID   string `json:"upload_id"`
	Version    uint32 `json:"version"`
	MediaType  string `json:"media_type"`
	Bytes      int64  `json:"bytes"`
	SHA256     string `json:"sha256"`
}
type caseResponse struct {
	CaseID         string             `json:"case_id"`
	SupplierID     string             `json:"supplier_id"`
	Status         cases.Status       `json:"status"`
	Version        uint64             `json:"version"`
	EvidenceEpoch  uint64             `json:"evidence_epoch,omitempty"`
	EvidenceDigest string             `json:"evidence_digest,omitempty"`
	PolicyID       string             `json:"policy_id"`
	PolicyVersion  uint32             `json:"policy_version"`
	DeadlineAt     time.Time          `json:"deadline_at"`
	CreatedAt      time.Time          `json:"created_at,omitempty"`
	UpdatedAt      time.Time          `json:"updated_at,omitempty"`
	Evidence       []evidenceResponse `json:"evidence,omitempty"`
}

func (h *Handler) principal(w http.ResponseWriter, r *http.Request) (Principal, bool) {
	p, ok := h.principals.Resolve(r.Context(), r)
	if !ok || p.TenantID == "" || !actorRef.MatchString(p.ActorRef) {
		writeProblem(w, 401, "unauthenticated")
		return Principal{}, false
	}
	return p, true
}
func (h *Handler) casePrincipal(w http.ResponseWriter, r *http.Request) (Principal, string, bool) {
	p, ok := h.principal(w, r)
	if !ok {
		return Principal{}, "", false
	}
	id := r.PathValue("case_id")
	if !uuid.MatchString(id) {
		writeProblem(w, 404, "resource_not_found")
		return Principal{}, "", false
	}
	return p, id, true
}
func decode(w http.ResponseWriter, r *http.Request, destination any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("request must contain one JSON value")
	}
	return nil
}
func ensureEmptyBody(r *http.Request) error {
	if r.Body == nil {
		return nil
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, 1))
	if err != nil {
		return err
	}
	if len(data) > 0 {
		return errors.New("request body must be empty")
	}
	return nil
}
func writeDomainError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, postgres.ErrNotFound):
		writeProblem(w, 404, "resource_not_found")
	case errors.Is(err, postgres.ErrConflict), errors.Is(err, cases.ErrConflict):
		writeProblem(w, 409, "state_conflict")
	case errors.Is(err, cases.ErrEvidence), errors.Is(err, cases.ErrInvalidPolicy), errors.Is(err, cases.ErrInvalidCase):
		writeProblem(w, 422, "validation_failed")
	default:
		writeProblem(w, 500, "request_failed")
	}
}
func writeProblem(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	requestID, err := intake.NewObjectID(nil)
	if err != nil {
		requestID = "00000000-0000-4000-8000-000000000000"
	}
	_ = json.NewEncoder(w).Encode(problemResponse{Type: "about:blank", Title: http.StatusText(status), Status: status, Code: code, RequestID: requestID})
}

type problemResponse struct {
	Type      string `json:"type"`
	Title     string `json:"title"`
	Status    int    `json:"status"`
	Code      string `json:"code"`
	RequestID string `json:"request_id"`
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
