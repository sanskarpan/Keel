package erasureworker

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sanskarpan/keel/internal/ai/contextvault/postgres"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

func TestProcessorCompletesOneClaim(t *testing.T) {
	repository := &fakeRepository{claimed: true}
	processor, err := NewProcessor(repository, "worker-a", time.Minute, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	job, claimed, err := processor.ProcessOne(context.Background(), tenancy.TenantID("11111111-1111-4111-8111-111111111111"))
	if err != nil || !claimed || job.State != "complete" || repository.processed != 1 || repository.retried != 0 {
		t.Fatalf("job=%+v claimed=%v err=%v repository=%+v", job, claimed, err, repository)
	}
}

func TestProcessorPersistsBoundedRetryWithSafeCode(t *testing.T) {
	repository := &fakeRepository{claimed: true, processErr: errors.New("raw storage details")}
	processor, err := NewProcessor(repository, "worker-a", time.Minute, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	job, claimed, err := processor.ProcessOne(context.Background(), tenancy.TenantID("11111111-1111-4111-8111-111111111111"))
	if !errors.Is(err, ErrJobRetryScheduled) || !claimed || job.State != "pending" || repository.retryCode != "delete_failed" ||
		repository.retryDelay != 4*time.Second || repository.retried != 1 {
		t.Fatalf("job=%+v claimed=%v err=%v repository=%+v", job, claimed, err, repository)
	}
}

func TestProcessorDoesNotRetryStaleLease(t *testing.T) {
	repository := &fakeRepository{claimed: true, processErr: postgres.ErrErasureJobLeaseLost}
	processor, err := NewProcessor(repository, "worker-a", time.Minute, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_, claimed, err := processor.ProcessOne(context.Background(), tenancy.TenantID("11111111-1111-4111-8111-111111111111"))
	if !errors.Is(err, postgres.ErrErasureJobLeaseLost) || !claimed || repository.retried != 0 {
		t.Fatalf("claimed=%v err=%v repository=%+v", claimed, err, repository)
	}
}

func TestProcessorReportsLegalHoldWithoutRetryingOrCompleting(t *testing.T) {
	repository := &fakeRepository{claimed: true, processResult: postgres.ErasureProcessHeld}
	processor, err := NewProcessor(repository, "worker-a", time.Minute, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	job, claimed, err := processor.ProcessOne(context.Background(), tenancy.TenantID("11111111-1111-4111-8111-111111111111"))
	if err != nil || !claimed || job.State != "held" || repository.retried != 0 {
		t.Fatalf("held job=%+v claimed=%v retries=%d err=%v", job, claimed, repository.retried, err)
	}
}

func TestRetryDelayCapsAtMaximum(t *testing.T) {
	if got := retryDelay(time.Second, 1); got != time.Second {
		t.Fatalf("first retry delay=%s", got)
	}
	if got := retryDelay(time.Second, 5); got != 16*time.Second {
		t.Fatalf("fifth retry delay=%s", got)
	}
	if got := retryDelay(12*time.Hour, 5); got != postgres.MaxErasureJobBackoff {
		t.Fatalf("capped retry delay=%s", got)
	}
}

type fakeRepository struct {
	claimed       bool
	processErr    error
	processResult postgres.ErasureProcessResult
	retried       int
	retryCode     string
	retryDelay    time.Duration
	retryState    string
	processed     int
}

func (r *fakeRepository) Claim(_ context.Context, tenant tenancy.TenantID, worker string, _ time.Duration) (postgres.ErasureJob, bool, error) {
	return postgres.ErasureJob{TenantID: tenant, RecordID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", Version: 1, LeaseEpoch: 1, Failures: 1}, r.claimed, nil
}

func (r *fakeRepository) Process(context.Context, tenancy.TenantID, postgres.ErasureJob) (postgres.ErasureProcessResult, error) {
	r.processed++
	if r.processResult == "" {
		r.processResult = postgres.ErasureProcessDeleted
	}
	return r.processResult, r.processErr
}

func (r *fakeRepository) Retry(_ context.Context, _ tenancy.TenantID, _ postgres.ErasureJob, code string, delay time.Duration) (string, error) {
	r.retried++
	r.retryCode = code
	r.retryDelay = delay
	if r.retryState == "" {
		r.retryState = "pending"
	}
	return r.retryState, nil
}
