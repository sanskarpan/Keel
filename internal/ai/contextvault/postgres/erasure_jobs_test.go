package postgres

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

func TestErasureWorkerStoreRejectsInvalidClaimsWithoutDatabaseAccess(t *testing.T) {
	if _, err := NewErasureWorkerStore(nil); err == nil {
		t.Fatal("nil erasure worker database was accepted")
	}
	store := &ErasureWorkerStore{db: &sql.DB{}}
	tenant := tenancy.TenantID("11111111-1111-4111-8111-111111111111")
	for _, test := range []struct {
		name     string
		workerID string
		lease    time.Duration
	}{
		{name: "empty worker"},
		{name: "invalid worker", workerID: "Worker A", lease: time.Minute},
		{name: "short lease", workerID: "worker-a", lease: time.Millisecond},
		{name: "long lease", workerID: "worker-a", lease: MaxErasureJobLease + time.Second},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, _, err := store.Claim(context.Background(), tenant, test.workerID, test.lease); !errors.Is(err, ErrInvalid) {
				t.Fatalf("claim error=%v, want invalid", err)
			}
		})
	}
}

func TestErasureWorkerStoreRejectsInvalidJobAndRetryBounds(t *testing.T) {
	store := &ErasureWorkerStore{db: &sql.DB{}}
	tenant := tenancy.TenantID("11111111-1111-4111-8111-111111111111")
	job := ErasureJob{TenantID: tenant, RecordID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", Version: 1,
		LeaseEpoch: 1, WorkerID: "worker-a"}
	if _, err := store.Process(context.Background(), tenant, ErasureJob{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("empty process job error=%v, want invalid", err)
	}
	if _, err := store.Retry(context.Background(), tenant, job, "Invalid raw error", time.Second); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unsafe retry code error=%v, want invalid", err)
	}
	if _, err := store.Retry(context.Background(), tenant, job, "delete_failed", MaxErasureJobBackoff+time.Second); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unbounded retry delay error=%v, want invalid", err)
	}
}
