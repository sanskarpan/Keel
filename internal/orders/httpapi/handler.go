// Package httpapi provides the trusted-context order read surface. Production authentication
// middleware must establish Identity and the authorizer must enforce resource permissions.
package httpapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/sanskarpan/keel/internal/orders"
	"github.com/sanskarpan/keel/internal/orders/historycursor"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

const defaultHistoryLimit = 25

var (
	orderIDPattern      = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	principalRefPattern = regexp.MustCompile(`^(principal|service-principal):[A-Za-z0-9._~-]{1,120}$`)
)

type identityKey struct{}

// Identity is created by trusted authentication middleware; tenant identifiers from request
// parameters, headers, and bodies are intentionally never considered.
type Identity struct {
	TenantID     tenancy.TenantID
	PrincipalRef string
}

func WithIdentity(ctx context.Context, identity Identity) context.Context {
	return context.WithValue(ctx, identityKey{}, identity)
}

type Reader interface {
	ReadOrder(context.Context, tenancy.TenantID, string) (orders.ReadView, error)
	PageEvents(context.Context, tenancy.TenantID, string, uint64, int) (orders.HistoryPage, error)
	ReadOrderWithHistory(context.Context, tenancy.TenantID, string, uint64, int) (orders.ReadView, orders.HistoryPage, error)
	ReadStateUpdates(context.Context, tenancy.TenantID, uint64, int) (orders.StateFeedBatch, error)
	ReadOrderStateStreamSnapshot(context.Context, tenancy.TenantID, string) (orders.StateStreamSnapshot, error)
}

type Authorizer interface {
	CanReadOrder(context.Context, Identity, string) (bool, error)
}

type Handler struct {
	reader     Reader
	authorizer Authorizer
	cursors    *historycursor.Codec
	template   *template.Template
	errorPage  *template.Template
	handler    http.Handler
}

//go:embed ui/order.html ui/order.css ui/error.html
var uiFiles embed.FS

func NewHandler(reader Reader, authorizer Authorizer, cursors *historycursor.Codec) (*Handler, error) {
	if reader == nil || authorizer == nil || cursors == nil {
		return nil, errors.New("order reader, authorizer, and cursor codec are required")
	}
	page, err := fs.ReadFile(uiFiles, "ui/order.html")
	if err != nil {
		return nil, errors.New("order UI template is unavailable")
	}
	parsed, err := template.New("order").Parse(string(page))
	if err != nil {
		return nil, errors.New("order UI template is invalid")
	}
	errorHTML, err := fs.ReadFile(uiFiles, "ui/error.html")
	if err != nil {
		return nil, errors.New("order UI error template is unavailable")
	}
	parsedError, err := template.New("error").Parse(string(errorHTML))
	if err != nil {
		return nil, errors.New("order UI error template is invalid")
	}
	h := &Handler{reader: reader, authorizer: authorizer, cursors: cursors, template: parsed, errorPage: parsedError}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/orders/{order_id}", h.getOrder)
	mux.HandleFunc("GET /v1/orders/{order_id}/events", h.getOrderEvents)
	mux.HandleFunc("GET /v1/orders/{order_id}/stream", h.streamOrderState)
	mux.HandleFunc("GET /app/orders/{order_id}", h.getOrderPage)
	mux.HandleFunc("GET /app/orders/assets/order.css", h.getCSS)
	h.handler = securityHeaders(mux)
	return h, nil
}

// ServeHTTP routes only read operations. Command mutation routes are implemented separately.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.handler.ServeHTTP(w, r)
}

func (h *Handler) getOrder(w http.ResponseWriter, r *http.Request) {
	identity, orderID, ok := h.authorized(w, r)
	if !ok {
		return
	}
	if r.URL.RawQuery != "" {
		h.fail(w, r, http.StatusBadRequest, "invalid_query", "This order read does not accept query parameters.")
		return
	}
	view, err := h.reader.ReadOrder(r.Context(), identity.TenantID, orderID)
	if err != nil {
		h.writeReadError(w, r, err)
		return
	}
	version := view.Snapshot.Version
	watermark := view.ProjectionWatermark
	w.Header().Set("ETag", `"`+strconv.FormatUint(version, 10)+`-`+strconv.FormatUint(watermark, 10)+`"`)
	w.Header().Set("X-Order-Version", strconv.FormatUint(version, 10))
	writeJSON(w, http.StatusOK, orderResponse{
		OrderID: view.Snapshot.OrderID, Status: view.Snapshot.Status, Version: version,
		ExternalReference: view.Snapshot.ExternalReference, SupplierID: view.Snapshot.SupplierID,
		Currency: view.Snapshot.Currency, AmountMinor: view.Snapshot.AmountMinor,
		LineItems:           append([]orders.LineItem(nil), view.Snapshot.LineItems...),
		ProjectionWatermark: watermark, ProjectionLagVersions: version - watermark,
		UpdatedAt: view.UpdatedAt,
	})
}

func (h *Handler) getOrderEvents(w http.ResponseWriter, r *http.Request) {
	identity, orderID, ok := h.authorized(w, r)
	if !ok {
		return
	}
	limit, cursor, valid := parsePageQuery(r)
	if !valid {
		h.fail(w, r, http.StatusBadRequest, "invalid_pagination", "The history page request is invalid.")
		return
	}
	var before uint64
	if cursor != "" {
		var err error
		before, err = h.cursors.Decode(cursor, string(identity.TenantID), orderID, limit)
		if err != nil {
			h.fail(w, r, http.StatusBadRequest, "invalid_cursor", "The history cursor is invalid or expired.")
			return
		}
	}
	page, err := h.reader.PageEvents(r.Context(), identity.TenantID, orderID, before, limit)
	if err != nil {
		h.writeReadError(w, r, err)
		return
	}
	response := eventPageResponse{Items: page.Items}
	if page.HasMore {
		response.NextCursor, err = h.cursors.Encode(string(identity.TenantID), orderID, page.NextFrom, limit)
		if err != nil {
			h.fail(w, r, http.StatusServiceUnavailable, "history_unavailable", "Order history is temporarily unavailable.")
			return
		}
	}
	writeJSON(w, http.StatusOK, response)
}

func (h *Handler) getOrderPage(w http.ResponseWriter, r *http.Request) {
	identity, orderID, ok := h.authorized(w, r)
	if !ok {
		return
	}
	limit, cursor, valid := parsePageQuery(r)
	if !valid {
		h.fail(w, r, http.StatusBadRequest, "invalid_pagination", "The history page request is invalid.")
		return
	}
	var before uint64
	if cursor != "" {
		var err error
		before, err = h.cursors.Decode(cursor, string(identity.TenantID), orderID, limit)
		if err != nil {
			h.fail(w, r, http.StatusBadRequest, "invalid_cursor", "The history cursor is invalid or expired.")
			return
		}
	}
	view, page, err := h.reader.ReadOrderWithHistory(r.Context(), identity.TenantID, orderID, before, limit)
	if err != nil {
		h.writeReadError(w, r, err)
		return
	}
	nextURL := ""
	if page.HasMore {
		next, err := h.cursors.Encode(string(identity.TenantID), orderID, page.NextFrom, limit)
		if err != nil {
			h.fail(w, r, http.StatusServiceUnavailable, "history_unavailable", "Order history is temporarily unavailable.")
			return
		}
		nextURL = "/app/orders/" + orderID + "?limit=" + strconv.Itoa(limit) + "&cursor=" + next
	}
	status := view.Snapshot.Status
	data := orderPageData{
		OrderID: view.Snapshot.OrderID, ExternalReference: view.Snapshot.ExternalReference,
		SupplierID: view.Snapshot.SupplierID, Status: string(status), Version: view.Snapshot.Version,
		Currency: view.Snapshot.Currency, AmountMinor: view.Snapshot.AmountMinor,
		ProjectionWatermark: view.ProjectionWatermark, ProjectionLagVersions: view.Snapshot.Version - view.ProjectionWatermark,
		UpdatedAt: view.UpdatedAt.Format(time.RFC3339), UpdatedAtLabel: view.UpdatedAt.Format("Jan 2, 2006 · 3:04 PM MST"), HasProjectionLag: view.ProjectionWatermark < view.Snapshot.Version,
		LineItems: append([]orders.LineItem(nil), view.Snapshot.LineItems...),
		NextURL:   nextURL, Events: make([]orderPageEvent, 0, len(page.Items)),
	}
	for _, event := range page.Items {
		data.Events = append(data.Events, orderPageEvent{Version: event.Version, Title: eventTitle(event.Type), OccurredAt: event.OccurredAt.Format(time.RFC3339), OccurredAtLabel: event.OccurredAt.Format("Jan 2, 2006 · 3:04 PM MST")})
	}
	var rendered bytes.Buffer
	if err := h.template.Execute(&rendered, data); err != nil {
		h.fail(w, r, http.StatusServiceUnavailable, "order_view_unavailable", "The order view is temporarily unavailable.")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "private, no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(rendered.Bytes())
}

func (h *Handler) getCSS(w http.ResponseWriter, _ *http.Request) {
	data, err := fs.ReadFile(uiFiles, "ui/order.css")
	if err != nil {
		writeProblem(w, nil, http.StatusServiceUnavailable, "ui_unavailable", "The order view is temporarily unavailable.")
		return
	}
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (h *Handler) authorized(w http.ResponseWriter, r *http.Request) (Identity, string, bool) {
	identity, ok := r.Context().Value(identityKey{}).(Identity)
	if !ok || !principalRefPattern.MatchString(identity.PrincipalRef) {
		h.fail(w, r, http.StatusUnauthorized, "not_authenticated", "Authentication is required.")
		return Identity{}, "", false
	}
	tenant, err := tenancy.ParseTenantID(string(identity.TenantID))
	if err != nil {
		h.fail(w, r, http.StatusUnauthorized, "not_authenticated", "Authentication is required.")
		return Identity{}, "", false
	}
	identity.TenantID = tenancy.TenantID(strings.ToLower(string(tenant)))
	orderID := strings.ToLower(r.PathValue("order_id"))
	if !orderIDPattern.MatchString(orderID) {
		h.fail(w, r, http.StatusBadRequest, "invalid_order_id", "The order identifier is invalid.")
		return Identity{}, "", false
	}
	allowed, err := h.authorizer.CanReadOrder(r.Context(), identity, orderID)
	if err != nil {
		h.fail(w, r, http.StatusServiceUnavailable, "authorization_unavailable", "Order access could not be verified.")
		return Identity{}, "", false
	}
	if !allowed {
		h.fail(w, r, http.StatusNotFound, "resource_not_found", "The requested order was not found.")
		return Identity{}, "", false
	}
	return identity, orderID, true
}

func (h *Handler) writeReadError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, orders.ErrNotFound) {
		h.fail(w, r, http.StatusNotFound, "resource_not_found", "The requested order was not found.")
		return
	}
	h.fail(w, r, http.StatusServiceUnavailable, "order_read_unavailable", "Order data is temporarily unavailable.")
}

func (h *Handler) fail(w http.ResponseWriter, r *http.Request, status int, code, detail string) {
	if r != nil && strings.HasPrefix(r.URL.Path, "/app/orders/") && !strings.HasPrefix(r.URL.Path, "/app/orders/assets/") {
		var rendered bytes.Buffer
		if err := h.errorPage.Execute(&rendered, errorPageData{Title: http.StatusText(status), Detail: detail, Code: code}); err == nil {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Cache-Control", "private, no-store")
			w.WriteHeader(status)
			_, _ = w.Write(rendered.Bytes())
			return
		}
	}
	writeProblem(w, r, status, code, detail)
}

func parsePageQuery(r *http.Request) (int, string, bool) {
	for key := range r.URL.Query() {
		if key != "cursor" && key != "limit" {
			return 0, "", false
		}
	}
	limit := defaultHistoryLimit
	if values := r.URL.Query()["limit"]; len(values) > 1 {
		return 0, "", false
	} else if len(values) == 1 {
		raw := values[0]
		if raw == "" || len(raw) > 3 || (len(raw) > 1 && raw[0] == '0') {
			return 0, "", false
		}
		for _, char := range raw {
			if char < '0' || char > '9' {
				return 0, "", false
			}
		}
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 100 {
			return 0, "", false
		}
		limit = parsed
	}
	cursor := ""
	if values := r.URL.Query()["cursor"]; len(values) > 1 {
		return 0, "", false
	} else if len(values) == 1 {
		cursor = values[0]
		if len(cursor) == 0 || len(cursor) > 2048 {
			return 0, "", false
		}
	}
	return limit, cursor, true
}

type orderResponse struct {
	OrderID               string            `json:"order_id"`
	Status                orders.Status     `json:"status"`
	Version               uint64            `json:"version"`
	ExternalReference     string            `json:"external_reference"`
	SupplierID            string            `json:"supplier_id"`
	Currency              string            `json:"currency"`
	AmountMinor           int64             `json:"amount_minor"`
	LineItems             []orders.LineItem `json:"line_items"`
	ProjectionWatermark   uint64            `json:"projection_watermark"`
	ProjectionLagVersions uint64            `json:"projection_lag_versions"`
	UpdatedAt             time.Time         `json:"updated_at"`
}

type eventPageResponse struct {
	Items      []orders.HistoryEvent `json:"items"`
	NextCursor string                `json:"next_cursor,omitempty"`
}

type orderPageData struct {
	OrderID, ExternalReference, SupplierID, Status      string
	Version, ProjectionWatermark, ProjectionLagVersions uint64
	Currency                                            string
	AmountMinor                                         int64
	UpdatedAt, UpdatedAtLabel                           string
	HasProjectionLag                                    bool
	NextURL                                             string
	LineItems                                           []orders.LineItem
	Events                                              []orderPageEvent
}

type orderPageEvent struct {
	Version                     uint64
	Title                       string
	OccurredAt, OccurredAtLabel string
}

type errorPageData struct {
	Title, Detail, Code string
}

func eventTitle(eventType orders.EventType) string {
	switch eventType {
	case orders.OrderCreated:
		return "Order created"
	case orders.OrderSubmitted:
		return "Order submitted"
	case orders.OrderVerificationStarted:
		return "Verification started"
	case orders.OrderApproved:
		return "Order approved"
	case orders.OrderRejected:
		return "Order rejected"
	case orders.OrderCanceled:
		return "Order canceled"
	default:
		return "Order updated"
	}
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
	var requestID [16]byte
	if _, err := rand.Read(requestID[:]); err != nil {
		requestID = [16]byte{}
	}
	w.Header().Set("Content-Type", "application/problem+json; charset=utf-8")
	w.Header().Set("Cache-Control", "private, no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(problem{Type: "about:blank", Title: http.StatusText(status), Status: status, Code: code, Detail: detail, RequestID: fmt.Sprintf("%s-%s-%s-%s-%s", hex.EncodeToString(requestID[0:4]), hex.EncodeToString(requestID[4:6]), hex.EncodeToString(requestID[6:8]), hex.EncodeToString(requestID[8:10]), hex.EncodeToString(requestID[10:16]))})
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
