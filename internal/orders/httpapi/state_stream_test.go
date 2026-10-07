package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sanskarpan/keel/internal/orders"
)

func TestStateStreamUsesTrustedTenantAndAllowlistedOrderEvents(t *testing.T) {
	reader := &fakeReader{stateBatches: []orders.StateFeedBatch{{
		Oldest: 1,
		Latest: 3,
		Updates: []orders.StateFeedUpdate{
			{Sequence: 1, EventID: "event-other", AggregateID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", Version: 1, Kind: "order.changed", Status: orders.Draft},
			{Sequence: 2, EventID: "event-target", AggregateID: httpTestOrder, Version: 4, Kind: "order.changed", Status: orders.Approved},
			{Sequence: 3, EventID: "event-other-2", AggregateID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", Version: 2, Kind: "order.changed", Status: orders.Submitted},
		},
	}}}
	handler := testHandler(t, reader, &fakeAuthorizer{allow: true})
	ctx, cancel := context.WithCancel(authenticatedRequest(http.MethodGet, "/v1/orders/"+httpTestOrder+"/stream").Context())
	cancel()
	request := authenticatedRequest(http.MethodGet, "/v1/orders/"+httpTestOrder+"/stream").WithContext(ctx)
	request.Header.Set("X-Tenant-ID", "22222222-2222-4222-8222-222222222222")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK || response.Header().Get("Content-Type") != "text/event-stream; charset=utf-8" || response.Header().Get("Cache-Control") != "private, no-store" || response.Header().Get("X-Accel-Buffering") != "no" {
		t.Fatalf("unexpected stream response: status=%d headers=%v", response.Code, response.Header())
	}
	body := response.Body.String()
	if !strings.Contains(body, "id: state:"+httpTestOrder+":2\nevent: state\ndata: {\"sequence\":2,\"event_id\":\"event-target\"") || !strings.Contains(body, "event: cursor\ndata: {\"cursor\":\"state:"+httpTestOrder+":3\"}") {
		t.Fatalf("target update or durable cursor checkpoint missing: %s", body)
	}
	if strings.Contains(body, "event-other") || strings.Contains(body, "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb") {
		t.Fatalf("stream leaked another aggregate: %s", body)
	}
	if reader.lastTenant != httpTestTenant {
		t.Fatalf("stream tenant came from untrusted header: %q", reader.lastTenant)
	}
}

func TestStateStreamRejectsMalformedAndConflictingCursorsBeforeStreaming(t *testing.T) {
	for _, test := range []struct {
		path string
		lastEventID string
	}{
		{path: "/v1/orders/" + httpTestOrder + "/stream?cursor=state:" + httpTestOrder + ":01"},
		{path: "/v1/orders/" + httpTestOrder + "/stream?other=x"},
		{path: "/v1/orders/" + httpTestOrder + "/stream?cursor=state:" + httpTestOrder + ":1", lastEventID: "state:" + httpTestOrder + ":2"},
	} {
		reader := &fakeReader{}
		handler := testHandler(t, reader, &fakeAuthorizer{allow: true})
		request := authenticatedRequest(http.MethodGet, test.path)
		if test.lastEventID != "" {
			request.Header.Set("Last-Event-ID", test.lastEventID)
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest || reader.stateCalls != 0 {
			t.Fatalf("invalid cursor reached stream: path=%s status=%d calls=%d", test.path, response.Code, reader.stateCalls)
		}
	}
}

func TestStateStreamRequiresResyncAfterRetentionAndRejectsFutureCursor(t *testing.T) {
	for _, test := range []struct {
		name string
		cursor string
		batch orders.StateFeedBatch
		want string
	}{
		{name: "retention", batch: orders.StateFeedBatch{Oldest: 4, Latest: 8}, want: "event: resync_required"},
		{name: "future", cursor: "?cursor=state:" + httpTestOrder + ":9", batch: orders.StateFeedBatch{Oldest: 1, Latest: 8}, want: "ahead of the current feed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			reader := &fakeReader{stateBatches: []orders.StateFeedBatch{test.batch}}
			handler := testHandler(t, reader, &fakeAuthorizer{allow: true})
			request := authenticatedRequest(http.MethodGet, "/v1/orders/"+httpTestOrder+"/stream"+test.cursor)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if test.name == "future" {
				if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), test.want) {
					t.Fatalf("future cursor not rejected: status=%d body=%s", response.Code, response.Body.String())
				}
				return
			}
			if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), test.want) || !strings.Contains(response.Body.String(), "retention_exceeded") {
				t.Fatalf("expired cursor did not require resync: status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
}
