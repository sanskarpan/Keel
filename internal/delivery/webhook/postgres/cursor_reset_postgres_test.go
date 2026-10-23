package postgres

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sanskarpan/keel/internal/delivery/webhook"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

func cursorResetRequest(tenant tenancy.TenantID, to time.Time) webhook.CursorResetRequest {
	return webhook.CursorResetRequest{
		Tenant:      tenant,
		ResetID:     "rst_" + strings.ReplaceAll(uuid.NewString(), "-", ""),
		RequestedBy: "operator@example.com",
		To:          to,
		Reason:      "rescan the known gap window",
	}
}

func TestPostgreSQLReconciliationCursorResetIsAuditedAndRescans(t *testing.T) {
	appDB, webhookDB, operatorDB, adminDB := reconciliationDatabases(t)
	store := newReconciliationStore(t, operatorDB)
	registry := newRegistry(t, appDB)
	tenant := payloadTenant(t)
	from := time.Now().Add(-time.Minute).Truncate(time.Microsecond)
	registerFanoutEndpoint(t, registry, tenant, 1)
	for range 2 {
		insertFanoutOutbox(t, adminDB, tenant, uuid.NewString())
	}
	plan := reconciliationRequest(tenant)
	plan.From = &from
	if _, err := store.PlanReconciliation(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	priorAt, priorID := reconciliationCursor(t, adminDB, tenant)

	request := cursorResetRequest(tenant, from)
	result, err := store.ResetReconciliationCursor(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if result.ResetID != request.ResetID || !result.PriorAt.Equal(priorAt) ||
		result.PriorEventID != priorID || !result.NewAt.Equal(from) {
		t.Fatalf("reset result = %+v", result)
	}
	newAt, newID := reconciliationCursor(t, adminDB, tenant)
	if !newAt.Equal(from) || newID != uuid.Nil.String() {
		t.Fatalf("cursor after reset = %v/%s", newAt, newID)
	}
	var requestedBy, reason string
	var priorRecorded, newRecorded time.Time
	if err := adminDB.QueryRowContext(context.Background(),
		`SELECT requested_by,reason,prior_created_at,new_created_at
		   FROM keel_meta.webhook_reconciliation_cursor_resets
		  WHERE tenant_id=$1 AND reset_id=$2`, string(tenant), request.ResetID).
		Scan(&requestedBy, &reason, &priorRecorded, &newRecorded); err != nil {
		t.Fatal(err)
	}
	if requestedBy != request.RequestedBy || reason != request.Reason ||
		!priorRecorded.Equal(priorAt) || !newRecorded.Equal(from) {
		t.Fatalf("reset audit requestedBy=%q reason=%q prior=%v new=%v", requestedBy, reason, priorRecorded, newRecorded)
	}

	replan := reconciliationRequest(tenant)
	page, err := store.PlanReconciliation(context.Background(), replan)
	if err != nil || page.Scanned != 2 || page.GapEvents != 2 {
		t.Fatalf("rescan page=%+v err=%v", page, err)
	}
	if _, err := store.ResetReconciliationCursor(context.Background(), request); !errors.Is(err, webhook.ErrReconciliationConflict) {
		t.Fatalf("duplicate reset error = %v, want conflict", err)
	}
	for _, db := range []*sql.DB{appDB, webhookDB} {
		if _, err := db.ExecContext(context.Background(),
			`SELECT keel_meta.reset_webhook_reconciliation_cursor($1,$2,$3,$4)`,
			request.ResetID, request.RequestedBy, request.To, request.Reason); err == nil {
			t.Fatal("cursor reset executed without the operator capability")
		}
	}
	if _, err := operatorDB.ExecContext(context.Background(),
		`SELECT count(*) FROM keel_meta.webhook_reconciliation_cursor_resets`); err == nil {
		t.Fatal("operator read reset audit directly")
	}
	if _, err := adminDB.ExecContext(context.Background(),
		`UPDATE keel_meta.webhook_reconciliation_cursor_resets SET reason='changed' WHERE tenant_id=$1`,
		string(tenant)); err == nil {
		t.Fatal("reset audit was mutable")
	}
	if _, err := adminDB.ExecContext(context.Background(),
		`UPDATE keel_meta.webhook_reconciliation_cursors SET last_event_created_at=$2,last_event_id=$3
		  WHERE tenant_id=$1`, string(tenant), from.Add(-time.Hour), uuid.Nil.String()); err == nil {
		t.Fatal("un-audited backward cursor update was accepted")
	}
}

func TestPostgreSQLReconciliationCursorResetRejectsInvalidTargets(t *testing.T) {
	_, _, operatorDB, adminDB := reconciliationDatabases(t)
	store := newReconciliationStore(t, operatorDB)
	tenant := payloadTenant(t)
	from := time.Now().Add(-time.Minute).Truncate(time.Microsecond)
	request := cursorResetRequest(tenant, from)
	if _, err := store.ResetReconciliationCursor(context.Background(), request); !errors.Is(err, webhook.ErrInvalidReconciliation) {
		t.Fatalf("reset without cursor error = %v, want invalid reconciliation", err)
	}
	insertFanoutOutbox(t, adminDB, tenant, uuid.NewString())
	plan := reconciliationRequest(tenant)
	plan.From = &from
	if _, err := store.PlanReconciliation(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	future := cursorResetRequest(tenant, time.Now().Add(time.Hour))
	if _, err := store.ResetReconciliationCursor(context.Background(), future); !errors.Is(err, webhook.ErrInvalidReconciliation) {
		t.Fatalf("future reset error = %v, want invalid reconciliation", err)
	}
}

func reconciliationCursor(t *testing.T, adminDB *sql.DB, tenant tenancy.TenantID) (time.Time, string) {
	t.Helper()
	var at time.Time
	var eventID string
	if err := adminDB.QueryRowContext(context.Background(),
		`SELECT last_event_created_at,last_event_id::text
		   FROM keel_meta.webhook_reconciliation_cursors WHERE tenant_id=$1`,
		string(tenant)).Scan(&at, &eventID); err != nil {
		t.Fatal(err)
	}
	return at, eventID
}
