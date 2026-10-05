package caseworkflow

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/sanskarpan/keel/internal/platform/tenancy"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/worker"
)

func newTestCaseID(t *testing.T) string {
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

func TestTemporalServerSignalWithStartDeduplicatesAndReplaysAfterWorkerRestart(t *testing.T) {
	address := os.Getenv("KEEL_TEST_TEMPORAL_ADDRESS")
	if address == "" {
		t.Skip("set KEEL_TEST_TEMPORAL_ADDRESS to a pinned local Temporal server")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	namespace := os.Getenv("KEEL_TEST_TEMPORAL_NAMESPACE")
	if namespace == "" {
		namespace = "default"
	}
	c, err := Dial(ctx, address, namespace)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	sender, err := NewSender(c)
	if err != nil {
		t.Fatal(err)
	}
	caseID := newTestCaseID(t)
	tenant, _ := tenancy.ParseTenantID("11111111-1111-4111-8111-111111111111")
	newWorker := func() worker.Worker {
		w := worker.New(c, TaskQueue, worker.Options{})
		if err := Register(w); err != nil {
			t.Fatal(err)
		}
		if err := w.Start(); err != nil {
			t.Fatal(err)
		}
		return w
	}
	w := newWorker()
	first := EventSignal{CaseID: caseID, IntentID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", Version: 1, EventType: "supplier.case.created", EventHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	if err := sender.Deliver(ctx, tenant, first); err != nil {
		w.Stop()
		t.Fatal(err)
	}
	if got := waitWorkflowVersion(ctx, t, c, tenant, caseID, 1); got != 1 {
		w.Stop()
		t.Fatalf("after start got version=%d, want 1", got)
	}
	w.Stop()
	w = newWorker()
	defer w.Stop()
	if got := waitWorkflowVersion(ctx, t, c, tenant, caseID, 1); got != 1 {
		t.Fatalf("worker restart replay got version=%d, want 1", got)
	}
	second := EventSignal{CaseID: caseID, IntentID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", Version: 2, EventType: "supplier.case.evidence-added", EventHash: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
	if err := sender.Deliver(ctx, tenant, second); err != nil {
		t.Fatal(err)
	}
	if err := sender.Deliver(ctx, tenant, second); err != nil {
		t.Fatal(err)
	}
	if got := waitWorkflowVersion(ctx, t, c, tenant, caseID, 2); got != 2 {
		t.Fatalf("duplicate signal changed workflow version to %d", got)
	}
}

func waitWorkflowVersion(ctx context.Context, t *testing.T, c client.Client, tenant tenancy.TenantID, caseID string, want uint64) uint64 {
	t.Helper()
	id, err := WorkflowID(tenant, caseID)
	if err != nil {
		t.Fatal(err)
	}
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		var state State
		result, err := c.QueryWorkflow(ctx, id, "", StateQuery)
		if err == nil && result.Get(&state) == nil && state.LastVersion >= want {
			return state.LastVersion
		}
		select {
		case <-ctx.Done():
			t.Fatalf("workflow did not reach version %d before timeout (last=%d, query error=%v)", want, state.LastVersion, err)
		case <-ticker.C:
		}
	}
}
