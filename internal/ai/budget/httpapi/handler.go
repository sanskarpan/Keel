// Package httpapi provides the trusted-context tenant cost read surface. Production
// authentication middleware must establish Identity and the authorizer must enforce
// tenant cost visibility. The handler is not mounted by any runtime yet.
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/sanskarpan/keel/internal/ai/budget"
	"github.com/sanskarpan/keel/internal/platform/observability"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

const defaultEntryLimit = 25

var (
	periodIDPattern     = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	principalRefPattern = regexp.MustCompile(`^(principal|service-principal):[A-Za-z0-9._~-]{1,120}$`)
)

type identityKey struct{}

// Identity is created by trusted authentication middleware; tenant identifiers from request
// parameters, headers, and bodies are intentionally never considered.
type Identity struct {
	TenantID     tenancy.TenantID
	PrincipalRef string
}

// WithIdentity binds the authenticated identity to a request context.
func WithIdentity(ctx context.Context, identity Identity) context.Context {
	return context.WithValue(ctx, identityKey{}, identity)
}

// Reader reads the tenant cost ledger. A reader must scope every read to the tenant it is
// given and must never return another tenant's cost.
type Reader interface {
	CostBreakdown(context.Context, tenancy.TenantID, string) (budget.CostBreakdown, error)
	CostEntries(context.Context, tenancy.TenantID, string, int) ([]budget.CostEntry, error)
}

// Authorizer decides whether the authenticated principal may read the tenant cost view.
type Authorizer interface {
	CanReadCost(context.Context, Identity) (bool, error)
}

// Handler serves the tenant cost dashboard reads.
type Handler struct {
	reader     Reader
	authorizer Authorizer
	handler    http.Handler
}

// NewHandler creates the cost read handler. The handler is safe to serve but is not mounted
// by any runtime until identity resolution and authorization are wired.
func NewHandler(reader Reader, authorizer Authorizer) (*Handler, error) {
	if reader == nil || authorizer == nil {
		return nil, errors.New("cost reader and authorizer are required")
	}
	h := &Handler{reader: reader, authorizer: authorizer}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/costs", h.getCurrentCosts)
	mux.HandleFunc("GET /v1/costs/{period_id}", h.getPeriodCosts)
	mux.HandleFunc("GET /v1/costs/{period_id}/entries", h.getCostEntries)
	h.handler = observability.HTTP(nil, securityHeaders(mux))
	return h, nil
}

// ServeHTTP routes only read operations.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.handler.ServeHTTP(w, r)
}

func (h *Handler) getCurrentCosts(w http.ResponseWriter, r *http.Request) {
	identity, ok := h.authorized(w, r)
	if !ok {
		return
	}
	if r.URL.RawQuery != "" {
		h.fail(w, r, http.StatusBadRequest, "invalid_query", "This cost read does not accept query parameters.")
		return
	}
	breakdown, err := h.reader.CostBreakdown(r.Context(), identity.TenantID, "")
	if err != nil {
		h.writeReadError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, newCostResponse(breakdown))
}

func (h *Handler) getPeriodCosts(w http.ResponseWriter, r *http.Request) {
	identity, periodID, ok := h.authorizedPeriod(w, r)
	if !ok {
		return
	}
	if r.URL.RawQuery != "" {
		h.fail(w, r, http.StatusBadRequest, "invalid_query", "This cost read does not accept query parameters.")
		return
	}
	breakdown, err := h.reader.CostBreakdown(r.Context(), identity.TenantID, periodID)
	if err != nil {
		h.writeReadError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, newCostResponse(breakdown))
}

func (h *Handler) getCostEntries(w http.ResponseWriter, r *http.Request) {
	identity, periodID, ok := h.authorizedPeriod(w, r)
	if !ok {
		return
	}
	limit, ok := parseLimit(r)
	if !ok {
		h.fail(w, r, http.StatusBadRequest, "invalid_limit", "The cost entry limit is invalid.")
		return
	}
	entries, err := h.reader.CostEntries(r.Context(), identity.TenantID, periodID, limit)
	if err != nil {
		h.writeReadError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, costEntriesResponse{PeriodID: periodID, Entries: costEntryResponses(entries)})
}

// authorized resolves the authenticated tenant and its cost visibility.
func (h *Handler) authorized(w http.ResponseWriter, r *http.Request) (Identity, bool) {
	identity, ok := r.Context().Value(identityKey{}).(Identity)
	if !ok || !principalRefPattern.MatchString(identity.PrincipalRef) {
		h.fail(w, r, http.StatusUnauthorized, "not_authenticated", "Authentication is required.")
		return Identity{}, false
	}
	tenant, err := tenancy.ParseTenantID(string(identity.TenantID))
	if err != nil {
		h.fail(w, r, http.StatusUnauthorized, "not_authenticated", "Authentication is required.")
		return Identity{}, false
	}
	identity.TenantID = tenancy.TenantID(strings.ToLower(string(tenant)))
	allowed, err := h.authorizer.CanReadCost(r.Context(), identity)
	if err != nil {
		h.fail(w, r, http.StatusServiceUnavailable, "authorization_unavailable", "Cost access could not be verified.")
		return Identity{}, false
	}
	if !allowed {
		h.fail(w, r, http.StatusNotFound, "resource_not_found", "The requested cost view was not found.")
		return Identity{}, false
	}
	return identity, true
}

// authorizedPeriod resolves the authenticated tenant and a valid period identifier.
func (h *Handler) authorizedPeriod(w http.ResponseWriter, r *http.Request) (Identity, string, bool) {
	identity, ok := h.authorized(w, r)
	if !ok {
		return Identity{}, "", false
	}
	periodID := strings.ToLower(r.PathValue("period_id"))
	if !periodIDPattern.MatchString(periodID) {
		h.fail(w, r, http.StatusBadRequest, "invalid_period_id", "The period identifier is invalid.")
		return Identity{}, "", false
	}
	return identity, periodID, true
}

// writeReadError maps a read failure to a non-enumerating response.
func (h *Handler) writeReadError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, budget.ErrCostUnavailable) {
		h.fail(w, r, http.StatusNotFound, "resource_not_found", "The requested cost view was not found.")
		return
	}
	h.fail(w, r, http.StatusServiceUnavailable, "cost_read_unavailable", "Cost data is temporarily unavailable.")
}

func (h *Handler) fail(w http.ResponseWriter, r *http.Request, status int, code, detail string) {
	writeProblem(w, r, status, code, detail)
}

// parseLimit reads the bounded cost entry limit.
func parseLimit(r *http.Request) (int, bool) {
	values := r.URL.Query()["limit"]
	for key := range r.URL.Query() {
		if key != "limit" {
			return 0, false
		}
	}
	if len(values) > 1 {
		return 0, false
	}
	if len(values) == 0 {
		return defaultEntryLimit, true
	}
	raw := values[0]
	if raw == "" || len(raw) > 3 || (len(raw) > 1 && raw[0] == '0') {
		return 0, false
	}
	for _, char := range raw {
		if char < '0' || char > '9' {
			return 0, false
		}
	}
	limit, err := strconv.Atoi(raw)
	if err != nil || limit < 1 || limit > budget.MaxCostEntries {
		return 0, false
	}
	return limit, true
}

type costWatermarkResponse struct {
	AccountVersion int64     `json:"account_version"`
	Entries        int64     `json:"entries"`
	LastEntryAt    time.Time `json:"last_entry_at,omitempty"`
}

type costResponse struct {
	PeriodID            string                `json:"period_id"`
	Scope               string                `json:"scope"`
	Currency            string                `json:"currency"`
	PeriodStart         time.Time             `json:"period_start"`
	PeriodEnd           time.Time             `json:"period_end"`
	HardLimitMicroUSD   int64                 `json:"hard_limit_micro_usd"`
	ConfirmedMicroUSD   int64                 `json:"confirmed_micro_usd"`
	CarriedMicroUSD     int64                 `json:"carried_micro_usd"`
	EstimatedMicroUSD   int64                 `json:"estimated_micro_usd"`
	UnknownMicroUSD     int64                 `json:"unknown_micro_usd"`
	OutstandingMicroUSD int64                 `json:"outstanding_micro_usd"`
	OverrunBlocked      bool                  `json:"overrun_blocked"`
	Watermark           costWatermarkResponse `json:"watermark"`
}

type costEntryResponse struct {
	InferenceID       string    `json:"inference_id"`
	ConfirmedMicroUSD int64     `json:"confirmed_micro_usd"`
	EstimatedMicroUSD int64     `json:"estimated_micro_usd"`
	UnknownMicroUSD   int64     `json:"unknown_micro_usd"`
	ReservedMicroUSD  int64     `json:"reserved_micro_usd"`
	LiabilityState    string    `json:"liability_state"`
	LastActivityAt    time.Time `json:"last_activity_at"`
}

type costEntriesResponse struct {
	PeriodID string              `json:"period_id"`
	Entries  []costEntryResponse `json:"entries"`
}

func newCostResponse(breakdown budget.CostBreakdown) costResponse {
	return costResponse{
		PeriodID: breakdown.PeriodID, Scope: breakdown.Scope, Currency: breakdown.Currency,
		PeriodStart: breakdown.PeriodStart, PeriodEnd: breakdown.PeriodEnd,
		HardLimitMicroUSD: breakdown.HardLimitMicroUSD, ConfirmedMicroUSD: breakdown.ConfirmedMicroUSD,
		CarriedMicroUSD: breakdown.CarriedMicroUSD, EstimatedMicroUSD: breakdown.EstimatedMicroUSD,
		UnknownMicroUSD: breakdown.UnknownMicroUSD, OutstandingMicroUSD: breakdown.OutstandingMicroUSD,
		OverrunBlocked: breakdown.OverrunBlocked,
		Watermark: costWatermarkResponse{AccountVersion: breakdown.Watermark.AccountVersion,
			Entries: breakdown.Watermark.Entries, LastEntryAt: breakdown.Watermark.LastEntryAt},
	}
}

func costEntryResponses(entries []budget.CostEntry) []costEntryResponse {
	responses := make([]costEntryResponse, 0, len(entries))
	for _, entry := range entries {
		responses = append(responses, costEntryResponse{
			InferenceID: entry.InferenceID, ConfirmedMicroUSD: entry.ConfirmedMicroUSD,
			EstimatedMicroUSD: entry.EstimatedMicroUSD, UnknownMicroUSD: entry.UnknownMicroUSD,
			ReservedMicroUSD: entry.ReservedMicroUSD, LiabilityState: entry.LiabilityState,
			LastActivityAt: entry.LastActivityAt,
		})
	}
	return responses
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "private, no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

type problem struct {
	Type      string `json:"type"`
	Title     string `json:"title"`
	Status    int    `json:"status"`
	Code      string `json:"code"`
	Detail    string `json:"detail,omitempty"`
	RequestID string `json:"request_id"`
}

func writeProblem(w http.ResponseWriter, r *http.Request, status int, code, detail string) {
	requestID := ""
	if r != nil {
		correlation, ok := observability.RequestContextFromContext(r.Context())
		if ok {
			requestID = correlation.RequestID
		}
	}
	w.Header().Set("Content-Type", "application/problem+json; charset=utf-8")
	w.Header().Set("Cache-Control", "private, no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(problem{Type: "about:blank", Title: http.StatusText(status), Status: status, Code: code, Detail: detail, RequestID: requestID})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'none'; object-src 'none'; style-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
		w.Header().Set("Vary", "Authorization, Cookie")
		next.ServeHTTP(w, r)
	})
}
