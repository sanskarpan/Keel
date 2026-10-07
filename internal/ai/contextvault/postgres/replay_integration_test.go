package postgres

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sanskarpan/keel/internal/ai/contextvault/replay"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

func TestPostgreSQLContextReplayOneUseAuditTenantAndHoldBoundaries(t *testing.T) {
	vaultDB := openLegalHoldTestDB(t, "KEEL_TEST_CONTEXT_VAULT_DATABASE_URL")
	policyDB := openLegalHoldTestDB(t, "KEEL_TEST_CONTEXT_POLICY_DATABASE_URL")
	replayDB := openLegalHoldTestDB(t, "KEEL_TEST_CONTEXT_REPLAY_DATABASE_URL")
	holdDB := openLegalHoldTestDB(t, "KEEL_TEST_CONTEXT_LEGAL_HOLD_DATABASE_URL")
	adminDB := openLegalHoldTestDB(t, "KEEL_TEST_ADMIN_DATABASE_URL")
	vault, err := NewStore(vaultDB)
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewReplayStore(replayDB)
	if err != nil {
		t.Fatal(err)
	}
	holds, err := NewLegalHoldStore(holdDB)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	tenant := mustTenant(t, uuid.NewString())
	foreignTenant := mustTenant(t, uuid.NewString())
	actor := uuid.NewString()
	setRetentionPolicy(t, policyDB, tenant, PurposeReadOnlyReplay, 1, true, 2, uuid.NewString())
	scope := testScope(string(tenant), uuid.NewString(), 1)
	if err := vault.Put(ctx, tenant, scope, testEnvelope(), RetentionPolicy{Purpose: PurposeReadOnlyReplay, Version: 1}); err != nil {
		t.Fatal(err)
	}
	request := replay.Request{TenantID: string(tenant), ActorID: actor, RecordID: scope.RecordID,
		Version: 1, Purpose: PurposeReadOnlyReplay, Reason: "support_diagnostic", RequestID: "replay_0123456789abcdef"}
	gotScope, gotEnvelope, err := store.BeginReplay(ctx, request)
	if err != nil || gotScope.RecordID != scope.RecordID || gotScope.Version != 1 || gotEnvelope.Algorithm != testEnvelope().Algorithm {
		t.Fatalf("begin replay scope=%+v envelope=%+v err=%v", gotScope, gotEnvelope, err)
	}
	if err := store.FinishReplay(ctx, request, replay.OutcomeComplete); err != nil {
		t.Fatalf("finish replay: %v", err)
	}
	if _, _, err := store.BeginReplay(ctx, request); err == nil {
		t.Fatal("reused one-use replay request identity was accepted")
	}
	deniedRequest := request
	deniedRequest.RequestID = "replay_denied_0123456789"
	if err := store.RecordDenied(ctx, deniedRequest); err != nil {
		t.Fatalf("record content-free authorization denial: %v", err)
	}
	var deniedOutcome string
	if err := adminDB.QueryRow(`SELECT outcome FROM keel_meta.context_vault_replay_events
		WHERE tenant_id=$1 AND request_id=$2 AND event_no=1`, string(tenant), deniedRequest.RequestID).Scan(&deniedOutcome); err != nil || deniedOutcome != "unauthorized" {
		t.Fatalf("authorization denial outcome=%q err=%v", deniedOutcome, err)
	}

	heldScope := testScope(string(tenant), uuid.NewString(), 1)
	if err := vault.Put(ctx, tenant, heldScope, testEnvelope(), RetentionPolicy{Purpose: PurposeReadOnlyReplay, Version: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := holds.Create(ctx, tenant, heldScope.RecordID, 1, actor, LegalHoldLitigation, time.Hour); err != nil {
		t.Fatal(err)
	}
	heldRequest := request
	heldRequest.RecordID = heldScope.RecordID
	heldRequest.RequestID = "replay_held_0123456789"
	if _, _, err := store.BeginReplay(ctx, heldRequest); !errors.Is(err, ErrNotFound) {
		t.Fatalf("active legal hold replay error=%v, want unavailable", err)
	}

	lateHoldScope := testScope(string(tenant), uuid.NewString(), 1)
	if err := vault.Put(ctx, tenant, lateHoldScope, testEnvelope(), RetentionPolicy{Purpose: PurposeReadOnlyReplay, Version: 1}); err != nil {
		t.Fatal(err)
	}
	lateHoldRequest := request
	lateHoldRequest.RecordID = lateHoldScope.RecordID
	lateHoldRequest.RequestID = "replay_late_hold_0123456789"
	if _, _, err := store.BeginReplay(ctx, lateHoldRequest); err != nil {
		t.Fatalf("begin replay before late hold: %v", err)
	}
	if _, err := holds.Create(ctx, tenant, lateHoldScope.RecordID, 1, actor, LegalHoldLitigation, time.Hour); err != nil {
		t.Fatal(err)
	}
	lateHoldDelivered := false
	if err := store.DeliverReplay(ctx, lateHoldRequest, func() replay.Outcome {
		lateHoldDelivered = true
		return replay.OutcomeComplete
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("late legal hold release check error=%v, want unavailable", err)
	}
	if lateHoldDelivered {
		t.Fatal("plaintext delivery callback ran after a hold was placed")
	}

	raceScope := testScope(string(tenant), uuid.NewString(), 1)
	if err := vault.Put(ctx, tenant, raceScope, testEnvelope(), RetentionPolicy{Purpose: PurposeReadOnlyReplay, Version: 1}); err != nil {
		t.Fatal(err)
	}
	raceRequest := request
	raceRequest.RecordID = raceScope.RecordID
	raceRequest.RequestID = "replay_race_0123456789"
	if _, _, err := store.BeginReplay(ctx, raceRequest); err != nil {
		t.Fatalf("begin replay for hold race: %v", err)
	}
	deliveryStarted := make(chan struct{})
	releaseDelivery := make(chan struct{})
	deliveryDone := make(chan error, 1)
	go func() {
		deliveryDone <- store.DeliverReplay(ctx, raceRequest, func() replay.Outcome {
			close(deliveryStarted)
			<-releaseDelivery
			return replay.OutcomeComplete
		})
	}()
	<-deliveryStarted
	holdDone := make(chan error, 1)
	go func() {
		_, err := holds.Create(ctx, tenant, raceScope.RecordID, 1, actor, LegalHoldLitigation, time.Hour)
		holdDone <- err
	}()
	select {
	case err := <-holdDone:
		t.Fatalf("hold placement crossed an in-flight replay delivery lock: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(releaseDelivery)
	if err := <-deliveryDone; err != nil {
		t.Fatalf("finish serialized replay delivery: %v", err)
	}
	if err := <-holdDone; err != nil {
		t.Fatalf("place hold after replay delivery: %v", err)
	}

	if _, _, err := store.BeginReplay(ctx, replay.Request{TenantID: string(foreignTenant), ActorID: actor,
		RecordID: scope.RecordID, Version: 1, Purpose: PurposeReadOnlyReplay, Reason: "support_diagnostic",
		RequestID: "replay_foreign_0123456"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant replay error=%v, want unavailable", err)
	}

	var state string
	if err := adminDB.QueryRow(`SELECT state FROM keel_meta.context_vault_replay_attempts WHERE tenant_id=$1 AND request_id=$2`,
		string(tenant), request.RequestID).Scan(&state); err != nil || state != string(replay.OutcomeComplete) {
		t.Fatalf("terminal replay state=%q err=%v", state, err)
	}
	var eventCount int
	if err := adminDB.QueryRow(`SELECT count(*) FROM keel_meta.context_vault_replay_events WHERE tenant_id=$1 AND request_id=$2`,
		string(tenant), request.RequestID).Scan(&eventCount); err != nil || eventCount != 2 {
		t.Fatalf("append-only replay event count=%d err=%v", eventCount, err)
	}
	assertReplayCapabilityCannotReadTables(t, replayDB, tenant)
	assertReplayEventsAppendOnly(t, adminDB, tenant, request.RequestID)
}

func assertReplayCapabilityCannotReadTables(t *testing.T, db *sql.DB, tenant tenancy.TenantID) {
	t.Helper()
	for _, query := range []string{
		`SELECT count(*) FROM keel_meta.context_vault_replay_attempts`,
		`SELECT count(*) FROM keel_meta.context_vault_replay_events`,
	} {
		if err := tenancy.WithTenantTx(context.Background(), db, tenant, nil, func(tx *sql.Tx) error {
			var count int
			return tx.QueryRow(query).Scan(&count)
		}); err == nil {
			t.Fatalf("replay capability unexpectedly accessed audit table with %q", query)
		}
	}
}

func assertReplayEventsAppendOnly(t *testing.T, db *sql.DB, tenant tenancy.TenantID, requestID string) {
	t.Helper()
	if _, err := db.Exec(`UPDATE keel_meta.context_vault_replay_events SET outcome='delivery_failed'
		WHERE tenant_id=$1 AND request_id=$2 AND event_no=1`, string(tenant), requestID); err == nil {
		t.Fatal("replay event update succeeded")
	}
	if _, err := db.Exec(`DELETE FROM keel_meta.context_vault_replay_events WHERE tenant_id=$1 AND request_id=$2`,
		string(tenant), requestID); err == nil {
		t.Fatal("replay event delete succeeded")
	}
}
