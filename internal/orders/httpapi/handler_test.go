package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sanskarpan/keel/internal/orders"
	"github.com/sanskarpan/keel/internal/orders/historycursor"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

const (
	httpTestTenant = "11111111-1111-4111-8111-111111111111"
	httpTestOrder  = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
)

func TestGetOrderReturnsAuthoritativeSnapshotAndIndependentWatermark(t *testing.T) {
	reader := &fakeReader{view: testView(orders.Approved, 4, 2)}
	authorizer := &fakeAuthorizer{allow: true}
	handler := testHandler(t, reader, authorizer)

	unauthenticated := httptest.NewRecorder()
	handler.ServeHTTP(unauthenticated, httptest.NewRequest(http.MethodGet, "/v1/orders/"+httpTestOrder, nil))
	if unauthenticated.Code != http.StatusUnauthorized {
		t.Fatalf("missing trusted identity status=%d", unauthenticated.Code)
	}

	req := authenticatedRequest(http.MethodGet, "/v1/orders/"+httpTestOrder)
	req.Header.Set("X-Tenant-ID", "22222222-2222-4222-8222-222222222222")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["status"] != "approved" || body["version"] != float64(4) || body["projection_watermark"] != float64(2) || body["projection_lag_versions"] != float64(2) {
		t.Fatalf("response did not preserve command authority and lag: %#v", body)
	}
	for _, forbidden := range []string{"tenant_id", "requested_by_ref", "evidence_digest", "actor_ref", "traceparent"} {
		if _, present := body[forbidden]; present {
			t.Fatalf("response exposed private field %q", forbidden)
		}
	}
	if response.Header().Get("ETag") != `"4-2"` || response.Header().Get("X-Order-Version") != "4" || response.Header().Get("Cache-Control") != "private, no-store" {
		t.Fatalf("missing version/cache contract headers: %v", response.Header())
	}
	if reader.lastTenant != httpTestTenant || authorizer.lastIdentity.TenantID != httpTestTenant {
		t.Fatalf("tenant scope came from request input: repository=%q authorizer=%q", reader.lastTenant, authorizer.lastIdentity.TenantID)
	}
}

func TestHistoryPagesUseEncryptedCursorAndSafeEventProjection(t *testing.T) {
	reader := &fakeReader{page: orders.HistoryPage{
		Items:   []orders.HistoryEvent{{EventID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaa0003", Version: 3, Type: orders.OrderApproved, OccurredAt: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)}},
		HasMore: true, NextFrom: 3,
	}}
	handler := testHandler(t, reader, &fakeAuthorizer{allow: true})
	req := authenticatedRequest(http.MethodGet, "/v1/orders/"+httpTestOrder+"/events?limit=1")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var body eventPageResponse
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Items) != 1 || body.Items[0].Version != 3 || body.Items[0].Type != orders.OrderApproved || body.NextCursor == "" {
		t.Fatalf("unexpected history response: %+v", body)
	}
	if strings.Contains(body.NextCursor, httpTestTenant) || strings.Contains(body.NextCursor, httpTestOrder) {
		t.Fatal("history cursor disclosed its tenant/order scope")
	}
	if before, err := handler.cursors.Decode(body.NextCursor, httpTestTenant, httpTestOrder, 1); err != nil || before != 3 {
		t.Fatalf("next cursor before=%d err=%v", before, err)
	}
	for _, forbidden := range []string{"actor_ref", "tenant_id", "evidence_digest", "payload", "traceparent"} {
		if strings.Contains(response.Body.String(), forbidden) {
			t.Fatalf("history response contained forbidden field %q", forbidden)
		}
	}
	badLimit := authenticatedRequest(http.MethodGet, "/v1/orders/"+httpTestOrder+"/events?limit=2&cursor="+body.NextCursor)
	badLimitResponse := httptest.NewRecorder()
	handler.ServeHTTP(badLimitResponse, badLimit)
	if badLimitResponse.Code != http.StatusBadRequest {
		t.Fatalf("cursor reused with another page size status=%d", badLimitResponse.Code)
	}
}

func TestOrderAccessDenialIsNonEnumerating(t *testing.T) {
	reader := &fakeReader{}
	handler := testHandler(t, reader, &fakeAuthorizer{allow: false})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, authenticatedRequest(http.MethodGet, "/v1/orders/"+httpTestOrder))
	if response.Code != http.StatusNotFound || reader.readCalls != 0 {
		t.Fatalf("denial status=%d repository reads=%d", response.Code, reader.readCalls)
	}
}

func TestOrderPageEscapesDataAndExplainsProjectionLag(t *testing.T) {
	view := testView(orders.Submitted, 2, 1)
	view.Snapshot.ExternalReference = `<script>alert("x")</script>`
	reader := &fakeReader{view: view, page: orders.HistoryPage{
		Items:   []orders.HistoryEvent{{Version: 2, Type: orders.OrderSubmitted, OccurredAt: time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC)}},
		HasMore: true, NextFrom: 2,
	}}
	handler := testHandler(t, reader, &fakeAuthorizer{allow: true})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, authenticatedRequest(http.MethodGet, "/app/orders/"+httpTestOrder+"?limit=1"))
	page := response.Body.String()
	for _, expected := range []string{"authoritative command state", "projection is catching up", "Order submitted", "Load older activity", "&lt;script&gt;"} {
		if !strings.Contains(page, expected) {
			t.Fatalf("order page omitted %q", expected)
		}
	}
	if strings.Contains(page, `<script>alert`) || !strings.Contains(response.Header().Get("Content-Security-Policy"), "script-src 'none'") || response.Header().Get("Cache-Control") != "private, no-store" {
		t.Fatalf("unsafe/unprotected HTML response; headers=%v", response.Header())
	}
	css := httptest.NewRecorder()
	handler.ServeHTTP(css, httptest.NewRequest(http.MethodGet, "/app/orders/assets/order.css", nil))
	if css.Code != http.StatusOK || !strings.Contains(css.Body.String(), "@media (max-width: 720px)") || !strings.Contains(css.Body.String(), "focus-visible") {
		t.Fatal("responsive/accessibility UI stylesheet was not served")
	}
}

func TestOrderPageShowsAccessibleRedactedErrorStates(t *testing.T) {
	handler := testHandler(t, &fakeReader{}, &fakeAuthorizer{allow: true})
	unauthenticated := httptest.NewRecorder()
	handler.ServeHTTP(unauthenticated, httptest.NewRequest(http.MethodGet, "/app/orders/"+httpTestOrder, nil))
	if unauthenticated.Code != http.StatusUnauthorized || !strings.Contains(unauthenticated.Header().Get("Content-Type"), "text/html") || !strings.Contains(unauthenticated.Body.String(), `role="alert"`) {
		t.Fatalf("unauthenticated UI error=%d headers=%v body=%s", unauthenticated.Code, unauthenticated.Header(), unauthenticated.Body.String())
	}
	invalidCursor := httptest.NewRecorder()
	handler.ServeHTTP(invalidCursor, authenticatedRequest(http.MethodGet, "/app/orders/"+httpTestOrder+"?cursor=malformed"))
	if invalidCursor.Code != http.StatusBadRequest || !strings.Contains(invalidCursor.Body.String(), "The history cursor is invalid or expired.") || strings.Contains(invalidCursor.Body.String(), "tenant_id") {
		t.Fatalf("invalid-cursor UI state=%d body=%s", invalidCursor.Code, invalidCursor.Body.String())
	}
}

func TestMalformedOrderAndPaginationAreRejectedBeforeRead(t *testing.T) {
	reader := &fakeReader{}
	handler := testHandler(t, reader, &fakeAuthorizer{allow: true})
	for _, target := range []string{
		"/v1/orders/not-a-uuid",
		"/v1/orders/" + httpTestOrder + "/events?limit=101",
		"/v1/orders/" + httpTestOrder + "/events?limit=1&limit=2",
		"/v1/orders/" + httpTestOrder + "/events?unbounded=true",
		"/v1/orders/" + httpTestOrder + "?tenant_id=22222222-2222-4222-8222-222222222222",
	} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, authenticatedRequest(http.MethodGet, target))
		if response.Code != http.StatusBadRequest {
			t.Errorf("target %q status=%d want 400", target, response.Code)
		}
	}
	if reader.readCalls != 0 || reader.pageCalls != 0 {
		t.Fatalf("invalid requests reached repository: reads=%d pages=%d", reader.readCalls, reader.pageCalls)
	}
}

func TestRepositoryErrorsAreRedacted(t *testing.T) {
	reader := &fakeReader{readErr: errors.New("secret DSN and raw SQL")}
	handler := testHandler(t, reader, &fakeAuthorizer{allow: true})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, authenticatedRequest(http.MethodGet, "/v1/orders/"+httpTestOrder))
	if response.Code != http.StatusServiceUnavailable || strings.Contains(response.Body.String(), "secret DSN") || strings.Contains(response.Body.String(), "SELECT") {
		t.Fatalf("internal error was not redacted: %d %s", response.Code, response.Body.String())
	}
}

type fakeReader struct {
	view       orders.ReadView
	page       orders.HistoryPage
	readErr    error
	pageErr    error
	lastTenant string
	readCalls  int
	pageCalls  int
	stateBatches []orders.StateFeedBatch
	stateErr error
	stateCalls int
}

func (f *fakeReader) ReadOrder(_ context.Context, tenant tenancy.TenantID, _ string) (orders.ReadView, error) {
	f.readCalls++
	f.lastTenant = string(tenant)
	return f.view, f.readErr
}

func (f *fakeReader) PageEvents(_ context.Context, tenant tenancy.TenantID, _ string, _ uint64, _ int) (orders.HistoryPage, error) {
	f.pageCalls++
	f.lastTenant = string(tenant)
	return f.page, f.pageErr
}

func (f *fakeReader) ReadOrderWithHistory(ctx context.Context, tenant tenancy.TenantID, orderID string, _ uint64, limit int) (orders.ReadView, orders.HistoryPage, error) {
	view, err := f.ReadOrder(ctx, tenant, orderID)
	if err != nil {
		return orders.ReadView{}, orders.HistoryPage{}, err
	}
	page, err := f.PageEvents(ctx, tenant, orderID, 0, limit)
	return view, page, err
}

func (f *fakeReader) ReadStateUpdates(_ context.Context, tenant tenancy.TenantID, after uint64, _ int) (orders.StateFeedBatch, error) {
	f.stateCalls++
	f.lastTenant = string(tenant)
	if f.stateErr != nil {
		return orders.StateFeedBatch{}, f.stateErr
	}
	if len(f.stateBatches) == 0 {
		return orders.StateFeedBatch{Latest: after}, nil
	}
	index := f.stateCalls - 1
	if index >= len(f.stateBatches) {
		index = len(f.stateBatches) - 1
	}
	return f.stateBatches[index], nil
}

type fakeAuthorizer struct {
	allow        bool
	err          error
	lastIdentity Identity
}

func (f *fakeAuthorizer) CanReadOrder(_ context.Context, identity Identity, _ string) (bool, error) {
	f.lastIdentity = identity
	return f.allow, f.err
}

func testView(status orders.Status, version, watermark uint64) orders.ReadView {
	return orders.ReadView{
		Snapshot:            orders.Snapshot{TenantID: httpTestTenant, OrderID: httpTestOrder, SupplierID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", ExternalReference: "PO-2026-001", Currency: "USD", AmountMinor: 1200, LineItems: []orders.LineItem{{Description: "Consulting", Quantity: "2"}}, Status: status, Version: version, RequestedByRef: "principal:private-requester", EvidenceDigest: "sha256:private"},
		ProjectionWatermark: watermark,
		UpdatedAt:           time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC),
	}
}

func testHandler(t *testing.T, reader Reader, authorizer Authorizer) *Handler {
	t.Helper()
	codec, err := historycursor.New("test", map[string][]byte{"test": []byte("0123456789abcdef0123456789abcdef")})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(reader, authorizer, codec)
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func authenticatedRequest(method, target string) *http.Request {
	request := httptest.NewRequest(method, target, nil)
	return request.WithContext(WithIdentity(request.Context(), Identity{TenantID: tenancy.TenantID(httpTestTenant), PrincipalRef: "principal:reader-1"}))
}
