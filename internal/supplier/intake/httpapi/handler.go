package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/sanskarpan/keel/internal/platform/tenancy"
	"github.com/sanskarpan/keel/internal/supplier/intake"
	"github.com/sanskarpan/keel/internal/supplier/intake/postgres"
)

const maxJSONBody = 16 << 10

type Principal struct {
	TenantID tenancy.TenantID
	ActorRef string
}

type PrincipalResolver interface {
	Resolve(context.Context, *http.Request) (Principal, bool)
}

type Authorizer interface {
	CanInviteSupplier(context.Context, Principal, string, string) bool
}

type Repository interface {
	IssueInvitation(context.Context, tenancy.TenantID, string, string, string, string, [32]byte, string, time.Time, time.Time) error
	AcceptInvitation(context.Context, tenancy.TenantID, string, string, time.Time, io.Reader) (postgres.Invitation, string, error)
	CreateUpload(context.Context, tenancy.TenantID, string, string, string, intake.UploadMetadata, time.Time, time.Time, []byte) (postgres.Upload, string, error)
	RenewCapability(context.Context, tenancy.TenantID, string, string, time.Time, time.Time, []byte) (string, error)
	GetUploadStatus(context.Context, tenancy.TenantID, string, string, time.Time) (postgres.UploadStatus, error)
}

type Receiver interface {
	Receive(context.Context, tenancy.TenantID, string, string, io.Reader, time.Time) error
}

type Handler struct {
	repository Repository
	receiver   Receiver
	principals PrincipalResolver
	authorizer Authorizer
	pepper     []byte
	capKey     []byte
	now        func() time.Time
	mux        *http.ServeMux
}

func New(repository Repository, receiver Receiver, principals PrincipalResolver, authorizer Authorizer, recipientPepper, capabilityKey []byte, clock func() time.Time) (*Handler, error) {
	if repository == nil || receiver == nil || principals == nil || authorizer == nil || len(recipientPepper) < 32 || len(capabilityKey) < 32 {
		return nil, errors.New("supplier HTTP dependencies are incomplete")
	}
	if clock == nil {
		clock = time.Now
	}
	h := &Handler{
		repository: repository, receiver: receiver, principals: principals, authorizer: authorizer,
		pepper: append([]byte(nil), recipientPepper...), capKey: append([]byte(nil), capabilityKey...), now: clock,
		mux: http.NewServeMux(),
	}
	h.mux.HandleFunc("POST /v1/supplier-invitations", h.issueInvitation)
	h.mux.HandleFunc("POST /v1/public/tenants/{tenant_id}/supplier-invitations/accept", h.acceptInvitation)
	h.mux.HandleFunc("POST /v1/public/tenants/{tenant_id}/supplier-upload-sessions/uploads", h.createUpload)
	h.mux.HandleFunc("POST /v1/public/tenants/{tenant_id}/supplier-uploads/{upload_id}/capability", h.renewCapability)
	h.mux.HandleFunc("GET /v1/public/tenants/{tenant_id}/supplier-uploads/{upload_id}", h.uploadStatus)
	h.mux.HandleFunc("PUT /v1/public/tenants/{tenant_id}/supplier-uploads/{upload_id}/content", h.receiveUpload)
	return h, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	securityHeaders(w)
	h.mux.ServeHTTP(w, r)
}

type issueInvitationRequest struct {
	CaseID     string `json:"case_id"`
	SupplierID string `json:"supplier_id"`
	Recipient  string `json:"recipient_email"`
}

type issueInvitationResponse struct {
	InvitationID string    `json:"invitation_id"`
	ExpiresAt    time.Time `json:"expires_at"`
	Token        string    `json:"invitation_token"`
}

func (h *Handler) issueInvitation(w http.ResponseWriter, r *http.Request) {
	principal, ok := h.principals.Resolve(r.Context(), r)
	if !ok || !validPrincipal(principal) {
		writeError(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	var input issueInvitationRequest
	if err := decodeJSON(w, r, &input); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if !validUUID(input.CaseID) || !validUUID(input.SupplierID) || !h.authorizer.CanInviteSupplier(r.Context(), principal, input.CaseID, input.SupplierID) {
		writeError(w, http.StatusNotFound, "resource_not_found")
		return
	}
	recipientDigest, err := postgres.RecipientDigest(input.Recipient, h.pepper)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	invitationID, err := intake.NewObjectID(nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "request_failed")
		return
	}
	token, err := intake.NewSecret(nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "request_failed")
		return
	}
	now := h.now().UTC()
	expires := now.Add(7 * 24 * time.Hour)
	if err := h.repository.IssueInvitation(r.Context(), principal.TenantID, invitationID, input.CaseID, input.SupplierID, token, recipientDigest, principal.ActorRef, now, expires); err != nil {
		writeError(w, http.StatusInternalServerError, "request_failed")
		return
	}
	writeJSON(w, http.StatusCreated, issueInvitationResponse{InvitationID: invitationID, ExpiresAt: expires, Token: token})
}

type acceptInvitationResponse struct {
	InvitationID string `json:"invitation_id"`
	CaseID       string `json:"case_id"`
	SupplierID   string `json:"supplier_id"`
	SessionToken string `json:"upload_session_token"`
}

func (h *Handler) acceptInvitation(w http.ResponseWriter, r *http.Request) {
	tenant, ok := pathTenant(w, r)
	if !ok {
		return
	}
	token, ok := bearer(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	sessionID, err := intake.NewObjectID(nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "request_failed")
		return
	}
	invitation, session, err := h.repository.AcceptInvitation(r.Context(), tenant, token, sessionID, h.now().UTC(), nil)
	if err != nil {
		if errors.Is(err, intake.ErrInvalidInvitation) {
			writeError(w, http.StatusNotFound, "resource_not_found")
			return
		}
		writeError(w, http.StatusInternalServerError, "request_failed")
		return
	}
	writeJSON(w, http.StatusCreated, acceptInvitationResponse{InvitationID: invitation.InvitationID, CaseID: invitation.CaseID, SupplierID: invitation.SupplierID, SessionToken: session})
}

type createUploadRequest struct {
	Filename    string `json:"filename"`
	ContentType string `json:"content_type"`
	Size        int64  `json:"size_bytes"`
	SHA256      string `json:"sha256"`
}

type createUploadResponse struct {
	UploadID   string    `json:"upload_id"`
	State      string    `json:"state"`
	ExpiresAt  time.Time `json:"capability_expires_at"`
	Capability string    `json:"upload_capability"`
	ContentURL string    `json:"content_url"`
}

func (h *Handler) createUpload(w http.ResponseWriter, r *http.Request) {
	tenant, ok := pathTenant(w, r)
	if !ok {
		return
	}
	session, ok := bearer(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	var input createUploadRequest
	if err := decodeJSON(w, r, &input); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	metadata := intake.UploadMetadata{Filename: input.Filename, ContentType: input.ContentType, Size: input.Size, SHA256: input.SHA256}
	if err := intake.ValidateUploadMetadata(metadata); err != nil {
		if errors.Is(err, intake.ErrUploadTooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, "upload_too_large")
		} else {
			writeError(w, http.StatusBadRequest, "invalid_request")
		}
		return
	}
	uploadID, err := intake.NewObjectID(nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "request_failed")
		return
	}
	now := h.now().UTC()
	expires := now.Add(intake.MaxUploadCapabilityTTL)
	upload, capability, err := h.repository.CreateUpload(r.Context(), tenant, session, uploadID, uploadID, metadata, now, expires, h.capKey)
	if err != nil {
		if errors.Is(err, postgres.ErrConflict) {
			writeError(w, http.StatusConflict, "upload_limit_reached")
			return
		}
		if errors.Is(err, postgres.ErrNotFound) {
			writeError(w, http.StatusNotFound, "resource_not_found")
			return
		}
		writeError(w, http.StatusInternalServerError, "request_failed")
		return
	}
	contentURL := "/v1/public/tenants/" + string(tenant) + "/supplier-uploads/" + upload.UploadID + "/content"
	writeJSON(w, http.StatusCreated, createUploadResponse{UploadID: upload.UploadID, State: upload.State, ExpiresAt: expires, Capability: capability, ContentURL: contentURL})
}

func (h *Handler) receiveUpload(w http.ResponseWriter, r *http.Request) {
	tenant, ok := pathTenant(w, r)
	if !ok {
		return
	}
	uploadID := r.PathValue("upload_id")
	if !validUUID(uploadID) {
		writeError(w, http.StatusNotFound, "resource_not_found")
		return
	}
	capability, ok := bearer(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, intake.MaxUploadBytes+1)
	err := h.receiver.Receive(r.Context(), tenant, uploadID, capability, r.Body, h.now().UTC())
	if err != nil {
		switch {
		case errors.Is(err, intake.ErrUploadTooLarge):
			writeError(w, http.StatusRequestEntityTooLarge, "upload_too_large")
		case errors.Is(err, intake.ErrInvalidCapability):
			writeError(w, http.StatusNotFound, "resource_not_found")
		case errors.Is(err, intake.ErrInvalidUpload):
			writeError(w, http.StatusBadRequest, "invalid_upload")
		default:
			writeError(w, http.StatusConflict, "upload_not_accepted")
		}
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type capabilityResponse struct {
	UploadID   string    `json:"upload_id"`
	Capability string    `json:"upload_capability"`
	ExpiresAt  time.Time `json:"capability_expires_at"`
}

func (h *Handler) renewCapability(w http.ResponseWriter, r *http.Request) {
	tenant, ok := pathTenant(w, r)
	if !ok {
		return
	}
	uploadID := r.PathValue("upload_id")
	if !validUUID(uploadID) {
		writeError(w, http.StatusNotFound, "resource_not_found")
		return
	}
	session, ok := bearer(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	now := h.now().UTC()
	expires := now.Add(intake.MaxUploadCapabilityTTL).Truncate(time.Second)
	capability, err := h.repository.RenewCapability(r.Context(), tenant, session, uploadID, now, expires, h.capKey)
	if err != nil {
		if errors.Is(err, postgres.ErrConflict) {
			writeError(w, http.StatusConflict, "upload_not_renewable")
			return
		}
		if errors.Is(err, postgres.ErrNotFound) {
			writeError(w, http.StatusNotFound, "resource_not_found")
			return
		}
		writeError(w, http.StatusInternalServerError, "request_failed")
		return
	}
	writeJSON(w, http.StatusOK, capabilityResponse{UploadID: uploadID, Capability: capability, ExpiresAt: expires})
}

type uploadStatusResponse struct {
	UploadID  string    `json:"upload_id"`
	State     string    `json:"state"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (h *Handler) uploadStatus(w http.ResponseWriter, r *http.Request) {
	tenant, ok := pathTenant(w, r)
	if !ok {
		return
	}
	uploadID := r.PathValue("upload_id")
	if !validUUID(uploadID) {
		writeError(w, http.StatusNotFound, "resource_not_found")
		return
	}
	session, ok := bearer(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	status, err := h.repository.GetUploadStatus(r.Context(), tenant, session, uploadID, h.now().UTC())
	if err != nil {
		writeError(w, http.StatusNotFound, "resource_not_found")
		return
	}
	state := map[string]string{"awaiting_upload": "awaiting_upload", "queued": "processing", "scanning": "processing", "retryable": "processing", "extracted": "ready", "rejected": "rejected", "expired": "expired"}[status.State]
	if state == "" {
		writeError(w, http.StatusNotFound, "resource_not_found")
		return
	}
	writeJSON(w, http.StatusOK, uploadStatusResponse{UploadID: uploadID, State: state, UpdatedAt: status.UpdatedAt})
}

func decodeJSON(w http.ResponseWriter, r *http.Request, target any) error {
	if r.Body == nil {
		return errors.New("request body is required")
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxJSONBody))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("request body must contain exactly one JSON value")
	}
	return nil
}

func pathTenant(w http.ResponseWriter, r *http.Request) (tenancy.TenantID, bool) {
	tenant, err := tenancy.ParseTenantID(r.PathValue("tenant_id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "resource_not_found")
		return "", false
	}
	return tenant, true
}

func bearer(r *http.Request) (string, bool) {
	value := r.Header.Get("Authorization")
	if len(value) < 8 || !strings.EqualFold(value[:7], "Bearer ") {
		return "", false
	}
	token := strings.TrimSpace(value[7:])
	if token == "" || strings.ContainsAny(token, " \t\r\n") {
		return "", false
	}
	return token, true
}

func validPrincipal(principal Principal) bool {
	_, err := tenancy.ParseTenantID(string(principal.TenantID))
	return err == nil && principal.ActorRef != ""
}

func validUUID(value string) bool {
	_, err := tenancy.ParseTenantID(value)
	return err == nil
}

type problemResponse struct {
	Type      string `json:"type"`
	Title     string `json:"title"`
	Status    int    `json:"status"`
	Code      string `json:"code"`
	RequestID string `json:"request_id"`
}

func writeError(w http.ResponseWriter, status int, code string) {
	requestID, err := intake.NewObjectID(nil)
	if err != nil {
		requestID = "00000000-0000-4000-8000-000000000000"
	}
	w.Header().Set("Content-Type", "application/problem+json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(problemResponse{Type: "about:blank", Title: http.StatusText(status), Status: status, Code: code, RequestID: requestID})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func securityHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
}
