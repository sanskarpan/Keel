package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sanskarpan/keel/internal/platform/tenancy"
	"github.com/sanskarpan/keel/internal/supplier/intake"
	"github.com/sanskarpan/keel/internal/supplier/intake/postgres"
)

const tenantOne = "11111111-1111-4111-8111-111111111111"
const tenantTwo = "22222222-2222-4222-8222-222222222222"
const caseOne = "33333333-3333-4333-8333-333333333333"
const supplierOne = "44444444-4444-4444-8444-444444444444"
const uploadOne = "55555555-5555-4555-8555-555555555555"

func TestIssueInvitationUsesTrustedTenantAndReturnsOneTimeSecretWithoutCaching(t *testing.T) {
	repo := &fakeRepository{}
	handler := newTestHandler(t, repo, &fakeReceiver{}, true)
	body := `{"case_id":"` + caseOne + `","supplier_id":"` + supplierOne + `","recipient_email":"Supplier@example.test"}`
	request := httptest.NewRequest(http.MethodPost, "/v1/supplier-invitations", strings.NewReader(body))
	request.Header.Set("X-Tenant-ID", tenantTwo)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated || response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatalf("status=%d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
	}
	if repo.issuedTenant != tenantOne || repo.issuedActor != "principal:buyer-1" || repo.issuedRecipient == [32]byte{} || repo.issuedToken == "" || repo.issuedExpires.Sub(repo.issuedNow) != 7*24*time.Hour {
		t.Fatalf("invitation issuance did not use trusted identity or scoped secret: %+v", repo)
	}
	var result issueInvitationResponse
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Token != repo.issuedToken || result.InvitationID != repo.issuedID {
		t.Fatalf("one-time response differs from issuance result: %+v", result)
	}
}

func TestPublicUploadFlowRequiresBearerCapabilitiesAndTenantScope(t *testing.T) {
	repo := &fakeRepository{}
	receiver := &fakeReceiver{}
	handler := newTestHandler(t, repo, receiver, true)
	metadata := []byte("plain evidence content")
	digest := sha256.Sum256(metadata)
	createBody := `{"filename":"evidence.txt","content_type":"text/plain","size_bytes":` + strconv.Itoa(len(metadata)) + `,"sha256":"` + hex.EncodeToString(digest[:]) + `"}`
	create := httptest.NewRequest(http.MethodPost, "/v1/public/tenants/"+tenantOne+"/supplier-upload-sessions/uploads", strings.NewReader(createBody))
	create.Header.Set("Authorization", "Bearer session-secret")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, create)
	if response.Code != http.StatusCreated {
		t.Fatalf("create upload status=%d body=%s", response.Code, response.Body.String())
	}
	var created createUploadResponse
	if err := json.Unmarshal(response.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if repo.createdTenant != tenantOne || repo.createdSession != "session-secret" || !validUUID(created.UploadID) || created.ContentURL != "/v1/public/tenants/"+tenantOne+"/supplier-uploads/"+created.UploadID+"/content" || created.Capability != "opaque-capability" {
		t.Fatalf("unexpected upload creation: response=%+v repo=%+v", created, repo)
	}
	renew := httptest.NewRequest(http.MethodPost, "/v1/public/tenants/"+tenantOne+"/supplier-uploads/"+created.UploadID+"/capability", nil)
	renew.Header.Set("Authorization", "Bearer session-secret")
	renewResponse := httptest.NewRecorder()
	handler.ServeHTTP(renewResponse, renew)
	var renewed capabilityResponse
	if err := json.Unmarshal(renewResponse.Body.Bytes(), &renewed); err != nil || renewResponse.Code != http.StatusOK || renewed.Capability != "renewed-capability" || repo.renewedSession != "session-secret" {
		t.Fatalf("capability renewal status=%d response=%+v err=%v", renewResponse.Code, renewed, err)
	}
	status := httptest.NewRequest(http.MethodGet, "/v1/public/tenants/"+tenantOne+"/supplier-uploads/"+created.UploadID, nil)
	status.Header.Set("Authorization", "Bearer session-secret")
	statusResponse := httptest.NewRecorder()
	handler.ServeHTTP(statusResponse, status)
	if statusResponse.Code != http.StatusOK || !strings.Contains(statusResponse.Body.String(), `"state":"awaiting_upload"`) {
		t.Fatalf("upload status response=%d %s", statusResponse.Code, statusResponse.Body.String())
	}

	put := httptest.NewRequest(http.MethodPut, created.ContentURL, strings.NewReader(string(metadata)))
	put.Header.Set("Authorization", "Bearer opaque-capability")
	putResponse := httptest.NewRecorder()
	handler.ServeHTTP(putResponse, put)
	if putResponse.Code != http.StatusNoContent || receiver.tenant != tenantOne || receiver.uploadID != created.UploadID || receiver.capability != "opaque-capability" || receiver.content != string(metadata) {
		t.Fatalf("upload completion status=%d receiver=%+v body=%s", putResponse.Code, receiver, putResponse.Body.String())
	}

	crossTenant := httptest.NewRequest(http.MethodPut, "/v1/public/tenants/"+tenantTwo+"/supplier-uploads/"+created.UploadID+"/content", strings.NewReader(string(metadata)))
	crossTenant.Header.Set("Authorization", "Bearer opaque-capability")
	crossResponse := httptest.NewRecorder()
	handler.ServeHTTP(crossResponse, crossTenant)
	if crossResponse.Code != http.StatusNotFound || receiver.tenant != tenantOne {
		t.Fatalf("cross-tenant upload request was not denied: status=%d receiver=%+v", crossResponse.Code, receiver)
	}
}

func TestIssueInvitationRejectsUnauthenticatedAndUnknownFields(t *testing.T) {
	repo := &fakeRepository{}
	handler := newTestHandler(t, repo, &fakeReceiver{}, false)
	request := httptest.NewRequest(http.MethodPost, "/v1/supplier-invitations", strings.NewReader(`{}`))
	request.Header.Set("X-Tenant-ID", tenantOne)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || repo.issuedToken != "" {
		t.Fatalf("unauthenticated request status=%d body=%s", response.Code, response.Body.String())
	}

	repo = &fakeRepository{}
	handler = newTestHandler(t, repo, &fakeReceiver{}, true)
	request = httptest.NewRequest(http.MethodPost, "/v1/supplier-invitations", strings.NewReader(`{"case_id":"`+caseOne+`","supplier_id":"`+supplierOne+`","recipient_email":"supplier@example.test","tenant_id":"`+tenantOne+`"}`))
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || repo.issuedToken != "" {
		t.Fatalf("unknown client tenant field status=%d body=%s", response.Code, response.Body.String())
	}
}

type fakeRepository struct {
	issuedTenant    string
	issuedActor     string
	issuedRecipient [32]byte
	issuedToken     string
	issuedID        string
	issuedNow       time.Time
	issuedExpires   time.Time
	createdTenant   string
	createdSession  string
	renewedSession  string
}

func (r *fakeRepository) IssueInvitation(_ context.Context, tenant tenancy.TenantID, invitationID, _, _, token string, recipient [32]byte, actor string, now, expires time.Time) error {
	r.issuedTenant, r.issuedActor, r.issuedRecipient = string(tenant), actor, recipient
	r.issuedToken, r.issuedID, r.issuedNow, r.issuedExpires = token, invitationID, now, expires
	return nil
}
func (*fakeRepository) AcceptInvitation(_ context.Context, tenant tenancy.TenantID, _ string, invitationID string, _ time.Time, _ io.Reader) (postgres.Invitation, string, error) {
	return postgres.Invitation{TenantID: tenant, InvitationID: invitationID, CaseID: caseOne, SupplierID: supplierOne, State: "accepted"}, "session-secret", nil
}
func (r *fakeRepository) CreateUpload(_ context.Context, tenant tenancy.TenantID, session, uploadID, _ string, _ intake.UploadMetadata, _, _ time.Time, _ []byte) (postgres.Upload, string, error) {
	r.createdTenant, r.createdSession = string(tenant), session
	return postgres.Upload{TenantID: tenant, UploadID: uploadID, State: "awaiting_upload"}, "opaque-capability", nil
}
func (r *fakeRepository) RenewCapability(_ context.Context, _ tenancy.TenantID, session, _ string, _, _ time.Time, _ []byte) (string, error) {
	r.renewedSession = session
	return "renewed-capability", nil
}
func (*fakeRepository) GetUploadStatus(_ context.Context, _ tenancy.TenantID, _ string, _ string, now time.Time) (postgres.UploadStatus, error) {
	return postgres.UploadStatus{State: "awaiting_upload", UpdatedAt: now}, nil
}

type fakeReceiver struct {
	tenant     string
	uploadID   string
	capability string
	content    string
}

func (r *fakeReceiver) Receive(_ context.Context, tenant tenancy.TenantID, uploadID, capability string, source io.Reader, _ time.Time) error {
	if string(tenant) != tenantOne {
		return intake.ErrInvalidCapability
	}
	data, _ := io.ReadAll(source)
	r.tenant, r.uploadID, r.capability, r.content = string(tenant), uploadID, capability, string(data)
	return nil
}

type fixedPrincipal struct{ ok bool }

func (a fixedPrincipal) Resolve(context.Context, *http.Request) (Principal, bool) {
	if !a.ok {
		return Principal{}, false
	}
	return Principal{TenantID: tenancy.TenantID(tenantOne), ActorRef: "principal:buyer-1"}, true
}

type allowInvites struct{ allow bool }

func (a allowInvites) CanInviteSupplier(context.Context, Principal, string, string) bool {
	return a.allow
}

func newTestHandler(t *testing.T, repo Repository, receiver Receiver, authenticated bool) *Handler {
	t.Helper()
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	handler, err := New(repo, receiver, fixedPrincipal{ok: authenticated}, allowInvites{allow: true}, []byte(strings.Repeat("p", 32)), []byte(strings.Repeat("k", 32)), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	return handler
}
