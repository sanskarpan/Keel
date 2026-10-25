// Package httpapi provides the unmounted operator replay surface. Trusted authentication and
// authorization adapters are injected by the caller; the runtime does not mount these routes.
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/sanskarpan/keel/internal/delivery/webhook"
	webhookpostgres "github.com/sanskarpan/keel/internal/delivery/webhook/postgres"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

const (
	defaultCandidateLimit = 100
	defaultRunLimit       = 100
	maxBodyBytes          = 8 << 10
)

var (
	actorPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}$`)
	replayID     = regexp.MustCompile(`^[A-Za-z0-9_-]{8,64}$`)
	deliveryID   = regexp.MustCompile(`^[A-Za-z0-9_-]{8,64}$`)
)

// Principal is established by trusted authentication middleware. Tenant identity is never read
// from a request parameter, header or body.
type Principal struct {
	TenantID tenancy.TenantID
	ActorRef string
}

// PrincipalResolver establishes the trusted principal.
type PrincipalResolver interface {
	Resolve(context.Context, *http.Request) (Principal, bool)
}

// Authorizer enforces the operator replay permission.
type Authorizer interface {
	CanReplayWebhooks(context.Context, Principal) bool
}

// Repository is the operator replay and reconciliation data surface. The store must use the
// operator capability.
type Repository interface {
	ReplayCandidates(context.Context, tenancy.TenantID, int) ([]webhookpostgres.ReplayCandidateRecord, error)
	AuthorizeReplay(context.Context, webhook.ReplayRequest) (webhook.ReplayAuthorization, error)
	ReconciliationRuns(context.Context, tenancy.TenantID, int) ([]webhook.ReconciliationRunSummary, error)
}

// KeyReady reports whether the configured signing keyring holds a key reference.
type KeyReady func(string) bool

type Handler struct {
	repo       Repository
	principals PrincipalResolver
	authz      Authorizer
	keyReady   KeyReady
	mux        *http.ServeMux
}

// New builds the unmounted replay handler.
func New(repo Repository, principals PrincipalResolver, authz Authorizer, keyReady KeyReady) (*Handler, error) {
	if repo == nil || principals == nil || authz == nil || keyReady == nil {
		return nil, errors.New("webhook replay HTTP dependencies are incomplete")
	}
	h := &Handler{repo: repo, principals: principals, authz: authz, keyReady: keyReady, mux: http.NewServeMux()}
	h.mux.HandleFunc("GET /v1/webhooks/replay-candidates", h.listCandidates)
	h.mux.HandleFunc("POST /v1/webhooks/replays", h.replay)
	h.mux.HandleFunc("GET /v1/webhooks/reconciliation-runs", h.listRuns)
	return h, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
	h.mux.ServeHTTP(w, r)
}

type candidateResponse struct {
	Limit    int                `json:"limit"`
	Selected []selectedDelivery `json:"selected"`
	Skipped  []skippedDelivery  `json:"skipped"`
}

type skippedDelivery struct {
	DeliveryID string `json:"delivery_id"`
	Reason     string `json:"reason"`
}

type selectedDelivery struct {
	DeliveryID          string `json:"delivery_id"`
	EventID             string `json:"event_id"`
	EndpointID          string `json:"endpoint_id"`
	SubscriptionVersion uint32 `json:"subscription_version"`
}

func skipped(items []webhook.ReplaySkip) []skippedDelivery {
	result := make([]skippedDelivery, 0, len(items))
	for _, item := range items {
		result = append(result, skippedDelivery{DeliveryID: item.DeliveryID, Reason: string(item.Reason)})
	}
	return result
}

func (h *Handler) listCandidates(w http.ResponseWriter, r *http.Request) {
	principal, ok := h.principal(w, r)
	if !ok {
		return
	}
	if !h.authz.CanReplayWebhooks(r.Context(), principal) {
		writeProblem(w, http.StatusForbidden, "forbidden")
		return
	}
	limit, filter, ok := candidateFilters(r)
	if !ok {
		writeProblem(w, http.StatusBadRequest, "invalid_request")
		return
	}
	records, err := h.repo.ReplayCandidates(r.Context(), principal.TenantID, webhook.MaxReplayCandidates)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "request_failed")
		return
	}
	candidates := make([]webhook.ReplayCandidate, 0, len(records))
	for _, record := range records {
		if filter != nil {
			if _, keep := filter[record.Delivery.ID]; !keep {
				continue
			}
		}
		candidates = append(candidates, webhook.ReplayCandidate{
			Delivery: record.Delivery,
			State:    record.State,
			Attempts: record.Attempts,
			Replayed: record.Replayed,
			Endpoint: webhook.EndpointEligibility{
				Status:              record.EndpointStatus,
				SubscriptionVersion: record.Delivery.Identity.SubscriptionVersion,
				SignatureKeyReady: record.EndpointStatus == webhook.EndpointActive &&
					record.KeyID != "" && h.keyReady(record.KeyID),
			},
		})
	}
	selection, err := webhook.SelectReplay(candidates, limit)
	if err != nil {
		if errors.Is(err, webhook.ErrReplayTooLarge) {
			writeProblem(w, http.StatusConflict, "replay_cap_exceeded")
			return
		}
		writeProblem(w, http.StatusBadRequest, "invalid_request")
		return
	}
	response := candidateResponse{Limit: limit, Selected: make([]selectedDelivery, 0, len(selection.Deliveries)), Skipped: skipped(selection.Skipped)}
	for _, delivery := range selection.Deliveries {
		response.Selected = append(response.Selected, selectedDelivery{
			DeliveryID: delivery.ID, EventID: delivery.Identity.EventID,
			EndpointID:          delivery.Identity.EndpointID,
			SubscriptionVersion: delivery.Identity.SubscriptionVersion,
		})
	}
	writeJSON(w, http.StatusOK, response)
}

func candidateFilters(r *http.Request) (int, map[string]struct{}, bool) {
	query := r.URL.Query()
	for key := range query {
		if key != "limit" && key != "delivery_id" {
			return 0, nil, false
		}
	}
	limit := defaultCandidateLimit
	if values, present := query["limit"]; present {
		if len(values) != 1 {
			return 0, nil, false
		}
		parsed, err := strconv.Atoi(values[0])
		if err != nil || parsed < 1 || parsed > webhook.MaxReplayBatch {
			return 0, nil, false
		}
		limit = parsed
	}
	var filter map[string]struct{}
	if values, present := query["delivery_id"]; present {
		if len(values) < 1 || len(values) > webhook.MaxReplayBatch {
			return 0, nil, false
		}
		filter = make(map[string]struct{}, len(values))
		for _, value := range values {
			if !deliveryID.MatchString(value) {
				return 0, nil, false
			}
			filter[value] = struct{}{}
		}
	}
	return limit, filter, true
}

type runSummaryResponse struct {
	RunID              string     `json:"run_id"`
	RequestedBy        string     `json:"requested_by"`
	FromCreatedAt      time.Time  `json:"from_created_at"`
	CursorToCreatedAt  *time.Time `json:"cursor_to_created_at,omitempty"`
	CursorToEventID    string     `json:"cursor_to_event_id,omitempty"`
	EventsScanned      int        `json:"events_scanned"`
	GapEvents          int        `json:"gap_events"`
	MissingDeliveries  int64      `json:"missing_deliveries"`
	RepairedDeliveries int        `json:"repaired_deliveries"`
	SkippedIdentities  int        `json:"skipped_identities"`
	CreatedAt          time.Time  `json:"created_at"`
}

type runsResponse struct {
	Limit int                  `json:"limit"`
	Runs  []runSummaryResponse `json:"runs"`
}

func (h *Handler) listRuns(w http.ResponseWriter, r *http.Request) {
	principal, ok := h.principal(w, r)
	if !ok {
		return
	}
	if !h.authz.CanReplayWebhooks(r.Context(), principal) {
		writeProblem(w, http.StatusForbidden, "forbidden")
		return
	}
	limit, ok := runLimit(r)
	if !ok {
		writeProblem(w, http.StatusBadRequest, "invalid_request")
		return
	}
	summaries, err := h.repo.ReconciliationRuns(r.Context(), principal.TenantID, limit)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "request_failed")
		return
	}
	response := runsResponse{Limit: limit, Runs: make([]runSummaryResponse, 0, len(summaries))}
	for _, summary := range summaries {
		entry := runSummaryResponse{
			RunID: summary.RunID, RequestedBy: summary.RequestedBy,
			FromCreatedAt:   summary.FromCreatedAt,
			CursorToEventID: summary.CursorToEventID,
			EventsScanned:   summary.EventsScanned, GapEvents: summary.GapEvents,
			MissingDeliveries:  summary.MissingDeliveries,
			RepairedDeliveries: summary.RepairedDeliveries,
			SkippedIdentities:  summary.SkippedIdentities, CreatedAt: summary.CreatedAt,
		}
		if summary.CursorToEventID != "" {
			cursorAt := summary.CursorToCreatedAt
			entry.CursorToCreatedAt = &cursorAt
		}
		response.Runs = append(response.Runs, entry)
	}
	writeJSON(w, http.StatusOK, response)
}

func runLimit(r *http.Request) (int, bool) {
	query := r.URL.Query()
	for key := range query {
		if key != "limit" {
			return 0, false
		}
	}
	limit := defaultRunLimit
	if values, present := query["limit"]; present {
		if len(values) != 1 {
			return 0, false
		}
		parsed, err := strconv.Atoi(values[0])
		if err != nil || parsed < 1 || parsed > webhook.MaxReconciliationRunHistory {
			return 0, false
		}
		limit = parsed
	}
	return limit, true
}

type replayRequest struct {
	ReplayID   string `json:"replay_id"`
	DeliveryID string `json:"delivery_id"`
	Reason     string `json:"reason"`
}

type replayResponse struct {
	ReplayID      string    `json:"replay_id"`
	DeliveryID    string    `json:"delivery_id"`
	PriorState    string    `json:"prior_state"`
	PriorAttempts int       `json:"prior_attempts"`
	AuthorizedAt  time.Time `json:"authorized_at"`
	Created       bool      `json:"created"`
}

func (h *Handler) replay(w http.ResponseWriter, r *http.Request) {
	principal, ok := h.principal(w, r)
	if !ok {
		return
	}
	if !h.authz.CanReplayWebhooks(r.Context(), principal) {
		writeProblem(w, http.StatusForbidden, "forbidden")
		return
	}
	var input replayRequest
	if decode(w, r, &input) != nil || !replayID.MatchString(input.ReplayID) ||
		!deliveryID.MatchString(input.DeliveryID) {
		writeProblem(w, http.StatusBadRequest, "invalid_request")
		return
	}
	request := webhook.ReplayRequest{
		Tenant: principal.TenantID, ReplayID: input.ReplayID, DeliveryID: input.DeliveryID,
		RequestedBy: principal.ActorRef, Reason: input.Reason,
	}
	if err := request.Validate(); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_request")
		return
	}
	authorization, err := h.repo.AuthorizeReplay(r.Context(), request)
	if err != nil {
		writeReplayError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, replayResponse{
		ReplayID: authorization.ReplayID, DeliveryID: authorization.DeliveryID,
		PriorState: string(authorization.PriorState), PriorAttempts: authorization.PriorAttempts,
		AuthorizedAt: authorization.AuthorizedAt, Created: authorization.Created,
	})
}

func (h *Handler) principal(w http.ResponseWriter, r *http.Request) (Principal, bool) {
	principal, ok := h.principals.Resolve(r.Context(), r)
	if !ok || !actorPattern.MatchString(principal.ActorRef) {
		writeProblem(w, http.StatusUnauthorized, "unauthenticated")
		return Principal{}, false
	}
	if string(principal.TenantID) == "" || string(principal.TenantID) == "00000000-0000-0000-0000-000000000000" {
		writeProblem(w, http.StatusUnauthorized, "unauthenticated")
		return Principal{}, false
	}
	if _, err := tenancy.ParseTenantID(string(principal.TenantID)); err != nil {
		writeProblem(w, http.StatusUnauthorized, "unauthenticated")
		return Principal{}, false
	}
	return principal, true
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

func writeReplayError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, webhook.ErrReplayUnauthorized):
		writeProblem(w, http.StatusForbidden, "forbidden")
	case errors.Is(err, webhook.ErrReplayNotFound):
		writeProblem(w, http.StatusNotFound, "not_found")
	case errors.Is(err, webhook.ErrReplayNotEligible), errors.Is(err, webhook.ErrReplayConflict):
		writeProblem(w, http.StatusConflict, "replay_conflict")
	case errors.Is(err, webhook.ErrInvalidReplay):
		writeProblem(w, http.StatusBadRequest, "invalid_request")
	default:
		writeProblem(w, http.StatusInternalServerError, "request_failed")
	}
}

type problemResponse struct {
	Type   string `json:"type"`
	Title  string `json:"title"`
	Status int    `json:"status"`
	Code   string `json:"code"`
}

func writeProblem(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(problemResponse{
		Type: "about:blank", Title: http.StatusText(status), Status: status, Code: code,
	})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
