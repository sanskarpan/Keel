package workflowdispatch

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
	"github.com/sanskarpan/keel/internal/supplier/cases"
	casepg "github.com/sanskarpan/keel/internal/supplier/cases/postgres"
	"github.com/sanskarpan/keel/internal/supplier/caseworkflow"
	dispatchpg "github.com/sanskarpan/keel/internal/supplier/workflowdispatch/postgres"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/worker"
)

func openIntegrationRole(t *testing.T, rawURL, role, password string) *sql.DB {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	parsed.User = url.UserPassword(role, password)
	db, err := sql.Open("pgx", parsed.String())
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(4)
	if err := db.PingContext(context.Background()); err != nil {
		_ = db.Close()
		t.Fatalf("connect with %s role: %v", role, err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func randomIntegrationUUID(t *testing.T) string {
	t.Helper()
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		t.Fatal(err)
	}
	raw[6] = (raw[6] & 0x0f) | 0x40
	raw[8] = (raw[8] & 0x3f) | 0x80
	encoded := hex.EncodeToString(raw[:])
	return fmt.Sprintf("%s-%s-%s-%s-%s", encoded[:8], encoded[8:12], encoded[12:16], encoded[16:20], encoded[20:])
}

func TestDispatchDurableIntentToTemporalHistory(t *testing.T) {
	appURL, workerURL, adminURL := os.Getenv("KEEL_TEST_DATABASE_URL"), os.Getenv("KEEL_TEST_WORKER_DATABASE_URL"), os.Getenv("KEEL_TEST_ADMIN_DATABASE_URL")
	address := os.Getenv("KEEL_TEST_TEMPORAL_ADDRESS")
	if appURL == "" || workerURL == "" || adminURL == "" || address == "" {
		t.Skip("set app, worker, admin PostgreSQL URLs and a local Temporal address for end-to-end workflow dispatch")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	appDB := openIntegrationRole(t, appURL, "keel_local_app", "keel-app-local-only")
	workerDB := openIntegrationRole(t, workerURL, "keel_local_worker", "keel-worker-local-only")
	adminDB := openIntegrationRole(t, adminURL, "postgres", "keel-local-only")
	caseRepo, err := casepg.New(appDB)
	if err != nil {
		t.Fatal(err)
	}
	dispatchRepo, err := dispatchpg.New(workerDB)
	if err != nil {
		t.Fatal(err)
	}
	namespace := os.Getenv("KEEL_TEST_TEMPORAL_NAMESPACE")
	if namespace == "" {
		namespace = "default"
	}
	temporalClient, err := caseworkflow.Dial(ctx, address, namespace)
	if err != nil {
		t.Fatal(err)
	}
	defer temporalClient.Close()
	sender, err := caseworkflow.NewSender(temporalClient)
	if err != nil {
		t.Fatal(err)
	}
	w := worker.New(temporalClient, caseworkflow.TaskQueue, worker.Options{})
	if err := caseworkflow.Register(w); err != nil {
		t.Fatal(err)
	}
	if err := w.Start(); err != nil {
		t.Fatal(err)
	}
	defer w.Stop()

	tenant, _ := tenancy.ParseTenantID(randomIntegrationUUID(t))
	policyID, supplierID := randomIntegrationUUID(t), randomIntegrationUUID(t)
	policy := cases.Policy{TenantID: string(tenant), PolicyID: policyID, Version: 1, Name: "Temporal integration", Deadline: 48 * time.Hour, Steps: []cases.ReviewStep{{Key: "review", Role: "risk:reviewer"}}}
	if _, err := caseRepo.PublishPolicy(ctx, tenant, policy, "principal:temporal-integration"); err != nil {
		t.Fatal(err)
	}
	created, err := caseRepo.Create(ctx, tenant, randomIntegrationUUID(t), supplierID, policyID, 1, "principal:temporal-integration")
	if err != nil {
		t.Fatal(err)
	}
	owner1, owner2 := randomIntegrationUUID(t), randomIntegrationUUID(t)
	first, found, err := dispatchRepo.Claim(ctx, tenant, owner1, time.Minute)
	if err != nil || !found || first.Version != 1 {
		t.Fatalf("claim create intent: lease=%+v found=%v err=%v", first, found, err)
	}
	firstSignal := caseworkflow.EventSignal{CaseID: first.CaseID, IntentID: first.IntentID, Version: first.Version, EventType: first.EventType, EventHash: first.EventHash}
	if err := sender.Deliver(ctx, tenant, firstSignal); err != nil {
		t.Fatal(err)
	}
	// Simulate losing the database acknowledgement after Temporal durably accepted the signal.
	if _, err := adminDB.ExecContext(ctx, `UPDATE keel_meta.supplier_workflow_dispatch SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE tenant_id=$1 AND intent_id=$2`, string(tenant), first.IntentID); err != nil {
		t.Fatal(err)
	}
	secondClaim, found, err := dispatchRepo.Claim(ctx, tenant, owner2, time.Minute)
	if err != nil || !found || secondClaim.Epoch != first.Epoch+1 {
		t.Fatalf("claim ambiguous outcome: lease=%+v found=%v err=%v", secondClaim, found, err)
	}
	if err := dispatchRepo.Complete(ctx, first); !errors.Is(err, dispatchpg.ErrStaleLease) {
		t.Fatalf("stale acknowledgement was accepted: %v", err)
	}
	if err := sender.Deliver(ctx, tenant, firstSignal); err != nil {
		t.Fatalf("retry after lost acknowledgement: %v", err)
	}
	if err := dispatchRepo.Complete(ctx, secondClaim); err != nil {
		t.Fatal(err)
	}
	awaitWorkflowVersion(ctx, t, temporalClient, tenant, created.CaseID, 1)

	if _, err := caseRepo.Submit(ctx, tenant, created.CaseID, "principal:temporal-integration"); err != nil {
		t.Fatal(err)
	}
	second, found, err := dispatchRepo.Claim(ctx, tenant, owner1, time.Minute)
	if err != nil || !found || second.Version != 2 {
		t.Fatalf("later intent not released after ordered acknowledgement: lease=%+v found=%v err=%v", second, found, err)
	}
	if err := sender.Deliver(ctx, tenant, caseworkflow.EventSignal{CaseID: second.CaseID, IntentID: second.IntentID, Version: second.Version, EventType: second.EventType, EventHash: second.EventHash}); err != nil {
		t.Fatal(err)
	}
	if err := dispatchRepo.Complete(ctx, second); err != nil {
		t.Fatal(err)
	}
	awaitWorkflowVersion(ctx, t, temporalClient, tenant, created.CaseID, 2)
}

func awaitWorkflowVersion(ctx context.Context, t *testing.T, c client.Client, tenant tenancy.TenantID, caseID string, wanted uint64) {
	t.Helper()
	id, err := caseworkflow.WorkflowID(tenant, caseID)
	if err != nil {
		t.Fatal(err)
	}
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		var state caseworkflow.State
		result, queryErr := c.QueryWorkflow(ctx, id, "", caseworkflow.StateQuery)
		if queryErr == nil && result.Get(&state) == nil && state.LastVersion >= wanted {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("workflow case state did not reach %d; query error=%v", wanted, queryErr)
		case <-ticker.C:
		}
	}
}
