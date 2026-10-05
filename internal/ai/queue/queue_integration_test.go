package queue

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

func TestPostgreSQLFairClaimsConcurrencyFencingAndCaps(t *testing.T) {
	appDSN := os.Getenv("KEEL_TEST_DATABASE_URL")
	workerDSN := os.Getenv("KEEL_TEST_AI_WORKER_DATABASE_URL")
	adminDSN := os.Getenv("KEEL_TEST_ADMIN_DATABASE_URL")
	if appDSN == "" || workerDSN == "" || adminDSN == "" {
		t.Skip("set app, AI worker and admin PostgreSQL URLs for durable queue integration coverage")
	}
	open := func(dsn string) *sql.DB {
		t.Helper()
		parsed, err := url.Parse(dsn)
		if err != nil {
			t.Fatal(err)
		}
		db, err := sql.Open("pgx", parsed.String())
		if err != nil {
			t.Fatal(err)
		}
		db.SetMaxOpenConns(6)
		if err := db.Ping(); err != nil {
			db.Close()
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		return db
	}
	appDB, workerDB, admin := open(appDSN), open(workerDSN), open(adminDSN)
	repo, err := NewRepository(appDB, workerDB)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	tenantID := uuid.NewString()
	tenant, err := tenancy.ParseTenantID(tenantID)
	if err != nil {
		t.Fatal(err)
	}
	periodID := uuid.NewString()
	provider, model := "offline-test", "model-v1"
	policyHash := make([]byte, 32)
	for i := range policyHash {
		policyHash[i] = byte(i + 1)
	}
	policyDigest := hex.EncodeToString(policyHash)
	now := time.Now().UTC()
	periodStart, periodEnd := now.Add(-time.Hour), now.Add(time.Hour)
	if _, err := admin.ExecContext(ctx, `INSERT INTO keel_meta.ai_budget_accounts
		(tenant_id,period_id,scope,period_start,period_end,currency,hard_limit_micro_usd)
		VALUES($1,$2,'inference',$3,$4,'USD',100000)`, tenantID, periodID, periodStart, periodEnd); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.ExecContext(ctx, `INSERT INTO keel_meta.ai_budget_period_heads(tenant_id,scope,period_id)
		VALUES($1,'inference',$2)`, tenantID, periodID); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.ExecContext(ctx, `INSERT INTO keel_meta.ai_execution_profiles
		(tenant_id,provider_id,model_id,policy_sha256,max_concurrency,max_queue_depth,max_output_tokens,max_attempt_duration_ms)
		VALUES($1,$2,$3,$4,2,8,128,10000)`, tenantID, provider, model, policyHash); err != nil {
		t.Fatal(err)
	}
	principalDigest := make([]byte, 32)
	requestDigest, rateDigest, quoteDigest := make([]byte, 32), make([]byte, 32), make([]byte, 32)
	for i := range principalDigest {
		principalDigest[i], requestDigest[i], rateDigest[i], quoteDigest[i] = 3, 4, 5, 6
	}
	createAdmission := func(principal string) JobSpec {
		t.Helper()
		inferenceID, attemptID, reservationID := uuid.NewString(), uuid.NewString(), uuid.NewString()
		if _, err := admin.ExecContext(ctx, `INSERT INTO keel_meta.ai_inference_admissions
			(tenant_id,inference_id,attempt_id,period_id,scope,principal_binding_sha256,request_sha256,policy_sha256,
			rate_card_id,rate_card_version,rate_card_sha256,quote_sha256,max_liability_micro_usd,currency,
			quoted_at,rate_effective_from,rate_effective_until)
			VALUES($1,$2,$3,$4,'inference',$5,$6,$7,'test','v1',$8,$9,1000,'USD',$10,$11,$12)`,
			tenantID, inferenceID, attemptID, periodID, principalDigest, requestDigest, policyHash,
			rateDigest, quoteDigest, now, now.Add(-time.Hour), now.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		if _, err := admin.ExecContext(ctx, `INSERT INTO keel_meta.ai_budget_reservations
			(tenant_id,reservation_id,inference_id,attempt_id,period_id,scope,amount_micro_usd,liability_state)
			VALUES($1,$2,$3,$4,$5,'inference',1000,'reserved')`, tenantID, reservationID, inferenceID, attemptID, periodID); err != nil {
			t.Fatal(err)
		}
		return JobSpec{Tenant: tenant, InferenceID: inferenceID, AttemptID: attemptID, PeriodID: periodID,
			ProviderID: provider, ModelID: model, PolicySHA256: policyDigest, Principal: principal, MaxOutputTokens: 64}
	}
	firstSpec := createAdmission("principal:member-a")
	secondSpec := createAdmission("principal:member-a")
	if result, err := repo.Enqueue(ctx, firstSpec); err != nil || result.Replayed {
		t.Fatalf("enqueue first job result=%+v err=%v", result, err)
	}
	if result, err := repo.Enqueue(ctx, firstSpec); err != nil || !result.Replayed {
		t.Fatalf("idempotent enqueue result=%+v err=%v", result, err)
	}
	leases := make([]Lease, 2)
	claimFlags := make([]bool, 2)
	errs := make([]error, 2)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range leases {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			leases[i], claimFlags[i], errs[i] = repo.ClaimNext(ctx, tenant, provider, model, []string{"worker-a", "worker-b"}[i], 5*time.Second)
		}(i)
	}
	close(start)
	wg.Wait()
	first := Lease{}
	claimCount := 0
	for i := range leases {
		if errs[i] != nil {
			t.Fatalf("concurrent claim %d: %v", i, errs[i])
		}
		if claimFlags[i] {
			first = leases[i]
			claimCount++
		}
	}
	if claimCount != 1 || first.MaxOutputTokens != 64 || first.Epoch != 1 || first.AttemptCount != 1 {
		t.Fatalf("same queued job was claimed %d times; lease=%+v", claimCount, first)
	}
	if result, err := repo.Enqueue(ctx, secondSpec); err != nil || result.Replayed {
		t.Fatalf("enqueue second job result=%+v err=%v", result, err)
	}
	other := createAdmission("principal:member-b")
	if _, err := repo.Enqueue(ctx, other); err != nil {
		t.Fatal(err)
	}
	second, claimedSecond, err := repo.ClaimNext(ctx, tenant, provider, model, "worker-b", 5*time.Second)
	if err != nil || !claimedSecond || second.InferenceID != other.InferenceID {
		t.Fatalf("new principal starved behind existing principal: claim=%+v claimed=%t err=%v", second, claimedSecond, err)
	}
	if _, claimed, err := repo.ClaimNext(ctx, tenant, provider, model, "worker-c", 5*time.Second); err != nil || claimed {
		t.Fatalf("provider concurrency cap was exceeded: claimed=%t err=%v", claimed, err)
	}
	if _, err := repo.Renew(ctx, Lease{Tenant: tenant, InferenceID: first.InferenceID, AttemptID: first.AttemptID,
		ProviderID: provider, ModelID: model, WorkerID: "worker-c", Epoch: first.Epoch}, 5*time.Second); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("different worker renewed lease: %v", err)
	}
	renewed, err := repo.Renew(ctx, first, 5*time.Second)
	if err != nil || !renewed.LeaseUntil.After(first.LeaseUntil) || renewed.LeaseUntil.After(renewed.AttemptDeadline) {
		t.Fatalf("bounded lease renewal=%+v err=%v", renewed, err)
	}
	if _, err := appDB.ExecContext(ctx, `UPDATE keel_meta.ai_jobs SET lease_epoch=lease_epoch+1 WHERE tenant_id=$1 AND inference_id=$2`, tenantID, first.InferenceID); err == nil {
		t.Fatal("application role directly changed fenced worker state")
	}
	if _, err := workerDB.ExecContext(ctx, `UPDATE keel_meta.ai_jobs SET lease_epoch=lease_epoch+1 WHERE tenant_id=$1 AND inference_id=$2`, tenantID, first.InferenceID); err == nil {
		t.Fatal("worker role bypassed the guarded claim/renew functions")
	}
	otherTenant, _ := tenancy.ParseTenantID(uuid.NewString())
	if _, claimed, err := repo.ClaimNext(ctx, otherTenant, provider, model, "worker-z", time.Second); err != nil || claimed {
		t.Fatalf("cross-tenant job became visible: claimed=%t err=%v", claimed, err)
	}
}
