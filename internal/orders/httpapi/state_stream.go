package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	stateFeedPageSize     = 100
	stateFeedPoll         = time.Second
	stateFeedHeartbeat   = 15 * time.Second
	stateFeedWriteTimeout = 5 * time.Second
)

type stateCursor uint64

func stateCursorID(orderID string, sequence uint64) string {
	return fmt.Sprintf("state:%s:%d", orderID, sequence)
}

func parseStateCursor(raw, orderID string) (stateCursor, bool) {
	if raw == "" {
		return 0, true
	}
	prefix := "state:" + orderID + ":"
	if !strings.HasPrefix(raw, prefix) {
		return 0, false
	}
	value := strings.TrimPrefix(raw, prefix)
	if value == "" || (len(value) > 1 && value[0] == '0') {
		return 0, false
	}
	for _, digit := range value {
		if digit < '0' || digit > '9' {
			return 0, false
		}
	}
	sequence, err := strconv.ParseUint(value, 10, 63)
	return stateCursor(sequence), err == nil
}

func parseRequestStateCursor(r *http.Request, orderID string) (stateCursor, bool, bool) {
	query := r.URL.Query()
	for key := range query {
		if key != "cursor" {
			return 0, false, false
		}
	}
	values, hasQueryCursor := query["cursor"]
	if hasQueryCursor && len(values) != 1 {
		return 0, false, false
	}
	queryValue := ""
	if hasQueryCursor {
		queryValue = values[0]
		if queryValue == "" {
			return 0, false, false
		}
	}
	queryCursor, ok := parseStateCursor(queryValue, orderID)
	if !ok {
		return 0, false, false
	}
	header := r.Header.Get("Last-Event-ID")
	if header == "" {
		return queryCursor, true, hasQueryCursor
	}
	headerCursor, ok := parseStateCursor(header, orderID)
	if !ok || (hasQueryCursor && queryCursor != headerCursor) {
		return 0, false, false
	}
	return headerCursor, true, true
}

func (h *Handler) streamOrderState(w http.ResponseWriter, r *http.Request) {
	identity, orderID, ok := h.authorized(w, r)
	if !ok {
		return
	}
	cursor, hasCursor, ok := parseRequestStateCursor(r, orderID)
	if !ok {
		h.fail(w, r, http.StatusBadRequest, "invalid_state_cursor", "The state cursor is invalid.")
		return
	}
	if _, ok := w.(http.Flusher); !ok {
		h.fail(w, r, http.StatusInternalServerError, "stream_unavailable", "The state stream is unavailable.")
		return
	}
	controller := http.NewResponseController(w)
	if err := controller.SetWriteDeadline(time.Now().Add(stateFeedWriteTimeout)); err != nil {
		h.fail(w, r, http.StatusInternalServerError, "stream_unavailable", "The state stream is unavailable.")
		return
	}
	if err := controller.SetWriteDeadline(time.Time{}); err != nil {
		h.fail(w, r, http.StatusInternalServerError, "stream_unavailable", "The state stream is unavailable.")
		return
	}
	var snapshot orders.StateStreamSnapshot
	if !hasCursor {
		var err error
		snapshot, err = h.reader.ReadOrderStateStreamSnapshot(r.Context(), identity.TenantID, orderID)
		if err != nil {
			h.writeReadError(w, r, err)
			return
		}
		cursor = stateCursor(snapshot.Cursor)
	}
	batch, err := h.reader.ReadStateUpdates(r.Context(), identity.TenantID, uint64(cursor), stateFeedPageSize)
	if err != nil {
		h.writeReadError(w, r, err)
		return
	}
	if uint64(cursor) > batch.Latest {
		h.fail(w, r, http.StatusBadRequest, "invalid_state_cursor", "The state cursor is ahead of the current feed.")
		return
	}

	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	if err := writeStateFrame(w, ": connected\n\n"); err != nil {
		return
	}
	if !hasCursor {
		if err := writeStateEvent(w, "snapshot", stateCursorID(orderID, uint64(cursor)), snapshot); err != nil {
			return
		}
	}

	after := uint64(cursor)
	ticker := time.NewTicker(stateFeedPoll)
	defer ticker.Stop()
	heartbeat := time.NewTicker(stateFeedHeartbeat)
	defer heartbeat.Stop()
	for {
		if batch.Oldest > 0 && after < batch.Oldest-1 {
			_ = writeStateEvent(w, "resync_required", "", map[string]string{"reason": "retention_exceeded"})
			return
		}
		if batch.Latest < after {
			_ = writeStateEvent(w, "resync_required", "", map[string]string{"reason": "feed_regressed"})
			return
		}
		if len(batch.Updates) > 0 {
			lastDispatched := after
			for _, update := range batch.Updates {
				after = update.Sequence
				if strings.EqualFold(update.AggregateID, orderID) {
					if err := writeStateEvent(w, "state", stateCursorID(orderID, update.Sequence), update); err != nil {
						return
					}
					lastDispatched = update.Sequence
				}
			}
			// The tenant-global sequence can advance on other orders. A cursor-only
			// checkpoint lets this order's client resume without exposing their IDs.
			if after > lastDispatched {
				id := stateCursorID(orderID, after)
				if err := writeStateEvent(w, "cursor", id, map[string]string{"cursor": id}); err != nil {
					return
				}
			}
		}
		select {
		case <-r.Context().Done():
			return
		case <-heartbeat.C:
			if err := writeStateFrame(w, ": keepalive\n\n"); err != nil {
				return
			}
		case <-ticker.C:
			batch, err = h.reader.ReadStateUpdates(r.Context(), identity.TenantID, after, stateFeedPageSize)
			if err != nil {
				return
			}
		}
	}
}

func writeStateEvent(w http.ResponseWriter, event, id string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	var frame strings.Builder
	if id != "" {
		fmt.Fprintf(&frame, "id: %s\n", id)
	}
	fmt.Fprintf(&frame, "event: %s\ndata: %s\n\n", event, data)
	return writeStateFrame(w, frame.String())
}

func writeStateFrame(w http.ResponseWriter, frame string) error {
	controller := http.NewResponseController(w)
	if err := controller.SetWriteDeadline(time.Now().Add(stateFeedWriteTimeout)); err != nil {
		return err
	}
	if _, err := fmt.Fprint(w, frame); err != nil {
		return err
	}
	if err := controller.Flush(); err != nil {
		return err
	}
	return controller.SetWriteDeadline(time.Time{})
}
