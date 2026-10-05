package postgres

import (
	"context"
	"crypto/sha256"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
	"github.com/sanskarpan/keel/internal/retrieval/index"
)

func TestPostgreSQLErasureDestructiveReceiptRequiresHoldClearance(t *testing.T) {
	appDB, indexerDB := retrievalTestDBs(t)
	app, err := New(appDB)
	if err != nil {
		t.Fatal(err)
	}
	worker, err := New(indexerDB)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	tenant := tenancy.TenantID(uuid.NewString())
	visibility := "erasure-hold-order:" + uuid.NewString()
	hasher, err := index.NewHMACTermHasher(string(tenant), "erasure-hold-order-v1", []byte(strings.Repeat("h", 32)))
	if err != nil {
		t.Fatal(err)
	}
	chunk := preparedChunk(t, hasher, uuid.New(), "hold-order source")
	createReadyBuild(t, worker, tenant, visibility, buildSpec(uuid.New(), hasher.KeyID(), 1), chunk)
	job, err := app.WithdrawSource(ctx, tenant, visibility, uuid.New(), chunk.DocumentVersionID, uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	claim, claimed, err := worker.ClaimErasureJob(ctx, tenant, visibility, "eraser-hold-order", 5*time.Second)
	if err != nil || !claimed || claim.ID != job.ID {
		t.Fatalf("claim=%+v claimed=%t err=%v", claim, claimed, err)
	}
	actor := uuid.New()
	if _, err := worker.RecordErasureActionReceipt(ctx, tenant, visibility, "eraser-hold-order", claim.ID,
		claim.LeaseEpoch, ErasureActionSupplierSourceObject, ErasureReceiptComplete, actor, "",
		sha256.Sum256([]byte("premature object deletion"))); err == nil {
		t.Fatal("destructive source-object receipt was accepted before legal-hold clearance")
	}
	if _, err := worker.RecordErasureActionReceipt(ctx, tenant, visibility, "eraser-hold-order", claim.ID,
		claim.LeaseEpoch, ErasureActionLegalHoldCheck, ErasureReceiptComplete, actor, "",
		sha256.Sum256([]byte("synthetic hold-clearance evidence"))); err != nil {
		t.Fatalf("record hold-clearance decision: %v", err)
	}
	if _, err := worker.RecordErasureActionReceipt(ctx, tenant, visibility, "eraser-hold-order", claim.ID,
		claim.LeaseEpoch, ErasureActionSupplierSourceObject, ErasureReceiptComplete, actor, "",
		sha256.Sum256([]byte("source-action evidence"))); err != nil {
		t.Fatalf("record source action after hold clearance: %v", err)
	}
}
