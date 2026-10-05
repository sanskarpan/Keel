package caseworkflow

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/sanskarpan/keel/internal/platform/tenancy"
	workpg "github.com/sanskarpan/keel/internal/supplier/workflowdispatch/postgres"
	enumspb "go.temporal.io/api/enums/v1"
	historypb "go.temporal.io/api/history/v1"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/worker"
	"go.temporal.io/sdk/workflow"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
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
	// Existing V1 histories may grow into the K2.4 approval envelope. Replay must
	// retain the original prefix and accept the first approval signal after 102.
	for version := uint64(3); version <= 103; version++ {
		kind := "supplier.case.evidence-added"
		if version == 102 {
			kind = "supplier.case.submitted"
		} else if version == 103 {
			kind = "supplier.case.approval-decided"
		}
		intentID := fmt.Sprintf("aaaaaaaa-aaaa-4aaa-8aaa-%012x", version)
		if err := sender.Deliver(ctx, tenant, EventSignal{CaseID: caseID, IntentID: intentID, Version: version, EventType: kind, EventHash: strings.Repeat("c", 64)}); err != nil {
			t.Fatalf("send version %d: %v", version, err)
		}
	}
	if got := waitWorkflowVersion(ctx, t, c, tenant, caseID, 103); got != 103 {
		t.Fatalf("approval signal after the original 102-event cap was not replayed: %d", got)
	}
}

func TestTemporalHistoryBudgetReplayAndSimulated72HourRecovery(t *testing.T) {
	if os.Getenv("KEEL_TEST_TEMPORAL_HISTORY_BUDGET") != "1" {
		t.Skip("set KEEL_TEST_TEMPORAL_HISTORY_BUDGET=1 to run the pinned Temporal history stress qualification")
	}
	address := os.Getenv("KEEL_TEST_TEMPORAL_ADDRESS")
	if address == "" {
		t.Skip("set KEEL_TEST_TEMPORAL_ADDRESS to a pinned local Temporal server")
	}
	if workpg.MaxAttempts != MaxSignalDeliveryAttempts {
		t.Fatalf("workflow history budget assumes %d dispatch attempts, repository allows %d", MaxSignalDeliveryAttempts, workpg.MaxAttempts)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
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
	workflowID, err := WorkflowID(tenant, caseID)
	if err != nil {
		t.Fatal(err)
	}
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
	defer func() {
		if w != nil {
			w.Stop()
		}
	}()

	checkpoints := map[uint64]bool{102: true, 135: true, MaxEvents: true}
	var finalHistory *historypb.History
	var finalBytes int
	// This is an upper-bound transport history, not a valid supplier-case state
	// sequence. PostgreSQL validates legal transitions; Temporal validates ordered
	// event identities and must remain bounded even under the declared envelope.
	for version := uint64(1); version <= MaxEvents; version++ {
		kind := "supplier.case.evidence-added"
		switch {
		case version == 1:
			kind = "supplier.case.created"
		case version == 102:
			kind = "supplier.case.submitted"
		case version > 102 && version <= 134:
			kind = "supplier.case.approval-decided"
		case version == 135:
			kind = "supplier.case.canceled"
		case version == 136:
			kind = "supplier.case.manual-review-requested"
		case version == 137:
			kind = "supplier.case.manual-review-resolved"
		case version == MaxEvents:
			kind = "supplier.case.expired"
		}
		intentID := fmt.Sprintf("aaaaaaaa-aaaa-4aaa-8aaa-%012x", version)
		signal := EventSignal{CaseID: caseID, IntentID: intentID, Version: version, EventType: kind, EventHash: strings.Repeat("c", 64)}
		// Model the maximum accepted-at-Temporal retry envelope: an acknowledgement
		// can be lost after each of the bounded database dispatch attempts.
		for attempt := 0; attempt < MaxSignalDeliveryAttempts; attempt++ {
			if err := sender.Deliver(ctx, tenant, signal); err != nil {
				t.Fatalf("deliver event %d attempt %d: %v", version, attempt+1, err)
			}
		}
		if !checkpoints[version] {
			continue
		}
		if got := waitWorkflowVersion(ctx, t, c, tenant, caseID, version); got != version {
			t.Fatalf("checkpoint %d has workflow version %d", version, got)
		}
		history, historyBytes := captureWorkflowHistory(ctx, t, c, workflowID)
		if len(history.Events) >= MaxTemporalHistoryEvents || historyBytes >= MaxTemporalHistoryBytes {
			t.Fatalf("history checkpoint %d exceeded Keel budget: events=%d bytes=%d limits=(%d,%d)", version, len(history.Events), historyBytes, MaxTemporalHistoryEvents, MaxTemporalHistoryBytes)
		}
		replay := worker.NewWorkflowReplayer()
		replay.RegisterWorkflowWithOptions(SupplierCaseWorkflow, workflow.RegisterOptions{Name: WorkflowName})
		if err := replay.ReplayWorkflowHistory(nil, history); err != nil {
			t.Fatalf("replay checkpoint %d failed: %v", version, err)
		}
		if version == MaxEvents {
			finalHistory, finalBytes = history, historyBytes
		}
	}

	// There is no Temporal timer in the V1 projection workflow. Moving an archived
	// history fixture forward by the full case lifetime verifies replay has no
	// wall-clock dependency; a real worker restart below verifies persisted state.
	aged := proto.Clone(finalHistory).(*historypb.History)
	for _, event := range aged.Events {
		if event.EventTime != nil {
			event.EventTime = timestamppb.New(event.EventTime.AsTime().Add(72 * time.Hour))
		}
	}
	replayer := worker.NewWorkflowReplayer()
	replayer.RegisterWorkflowWithOptions(SupplierCaseWorkflow, workflow.RegisterOptions{Name: WorkflowName})
	if err := replayer.ReplayWorkflowHistory(nil, aged); err != nil {
		t.Fatalf("72-hour-shifted history replay failed (events=%d bytes=%d): %v", len(aged.Events), finalBytes, err)
	}
	w.Stop()
	w = nil
	w = newWorker()
	if got := waitWorkflowVersion(ctx, t, c, tenant, caseID, MaxEvents); got != MaxEvents {
		t.Fatalf("workflow did not recover after worker restart: version=%d", got)
	}
	t.Logf("maximum bounded dispatch envelope: %d signal attempts, %d history events, %d event bytes; 72-hour-shifted replay and worker recovery passed", MaxEvents*MaxSignalDeliveryAttempts, len(finalHistory.Events), finalBytes)
}

func captureWorkflowHistory(ctx context.Context, t *testing.T, c client.Client, workflowID string) (*historypb.History, int) {
	t.Helper()
	iterator := c.GetWorkflowHistory(ctx, workflowID, "", false, enumspb.HISTORY_EVENT_FILTER_TYPE_ALL_EVENT)
	history := &historypb.History{}
	for iterator.HasNext() {
		event, err := iterator.Next()
		if err != nil {
			t.Fatalf("read Temporal history: %v", err)
		}
		history.Events = append(history.Events, event)
	}
	return history, proto.Size(history)
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
