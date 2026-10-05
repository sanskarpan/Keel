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
	"github.com/sanskarpan/keel/internal/ai/budget"
	"github.com/sanskarpan/keel/internal/ai/policy"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

type allowQueueReconciliation struct{}

func (allowQueueReconciliation) AuthorizeBudgetReconciliation(context.Context, tenancy.TenantID, string, string, string, string, string, int64) error {
	return nil
}

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
	budgetRepo, err := budget.NewRepository(appDB, allowQueueReconciliation{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	repo, err := NewRepository(budgetRepo, workerDB)
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
	provider, model := "offline-fake", "model-offline-v1"
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
	bundle := policy.Bundle{ID: "test", Version: "v1", Prompt: policy.PromptTemplate{ID: "summary", Version: "v1", Text: "Summarize {{document}}", Variables: []string{"document"}},
		Provider: policy.ProviderPolicy{ID: provider, Version: "v1", ModelID: model}, Generation: policy.GenerationLimits{MaxInputBytes: 1024, MaxOutputTokens: 128},
		Tools: policy.ToolPolicy{Version: "tools.none.v1"}, Scrubber: policy.ScrubberPolicy{Version: policy.ScrubberHighConfidenceV1}}
	registry, err := policy.NewRegistry([]policy.Bundle{bundle})
	if err != nil {
		t.Fatal(err)
	}
	call, err := registry.Prepare(policy.Request{BundleID: "test", BundleVersion: "v1", Variables: map[string]policy.InputSegment{"document": {Source: policy.SourceUser, Classification: policy.ClassificationGeneral, Text: "synthetic"}}})
	if err != nil {
		t.Fatal(err)
	}
	rateBook, err := budget.NewRateBook([]budget.RateCard{{ID: "offline", Version: "v1", ProviderID: provider, ProviderVersion: "v1", ModelID: model, Currency: "USD", InputMicroUSDPerMillionTokens: 1000, OutputMicroUSDPerMillionTokens: 1000, SafetyMarginBasisPoints: 1000, EffectiveFrom: now.Add(-time.Hour), EffectiveUntil: now.Add(time.Hour)}})
	if err != nil {
		t.Fatal(err)
	}
	quote, err := rateBook.QuoteWorstCase(call.Policy(), now)
	if err != nil {
		t.Fatal(err)
	}
	policyHash, _ := hex.DecodeString(quote.PolicyDigest())
	if _, err := admin.ExecContext(ctx, `INSERT INTO keel_meta.ai_execution_profiles
		(tenant_id,provider_id,model_id,policy_sha256,max_concurrency,max_queue_depth,max_output_tokens,max_attempt_duration_ms)
		VALUES($1,$2,$3,$4,2,8,128,10000)`, tenantID, provider, model, policyHash); err != nil {
		t.Fatal(err)
	}
	createAdmission := func(principal string) JobSpec {
		t.Helper()
		return JobSpec{Admission: budget.Admission{Tenant: tenant, PeriodID: periodID, InferenceID: uuid.NewString(), AttemptID: uuid.NewString(), ReservationID: uuid.NewString(),
			PeriodStart: periodStart, PeriodEnd: periodEnd, PrincipalBinding: "principal:" + principal, RequestDigest: hex.EncodeToString(make([]byte, 32)), Quote: quote},
			ProviderID: provider, ModelID: model, MaxOutputTokens: 64}
	}
	firstSpec := createAdmission("member-a")
	secondSpec := createAdmission("member-a")
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
	other := createAdmission("member-b")
	if _, err := repo.Enqueue(ctx, other); err != nil {
		t.Fatal(err)
	}
	second, claimedSecond, err := repo.ClaimNext(ctx, tenant, provider, model, "worker-b", 5*time.Second)
	if err != nil || !claimedSecond || second.InferenceID != other.Admission.InferenceID {
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
	// A failure after the budget lock/reservation begins must roll the entire
	// admission back when the execution profile is unavailable.
	missingProfile := createAdmission("member-missing-profile")
	if _, err := admin.ExecContext(ctx, `UPDATE keel_meta.ai_execution_profiles SET enabled=false WHERE tenant_id=$1 AND provider_id=$2 AND model_id=$3`, tenantID, provider, model); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Enqueue(ctx, missingProfile); !errors.Is(err, ErrQueueUnavailable) {
		t.Fatalf("enqueue without an installed profile: %v", err)
	}
	if _, err := admin.ExecContext(ctx, `UPDATE keel_meta.ai_execution_profiles SET enabled=true WHERE tenant_id=$1 AND provider_id=$2 AND model_id=$3`, tenantID, provider, model); err != nil {
		t.Fatal(err)
	}
	var admissions, reservations int
	if err := admin.QueryRowContext(ctx, `SELECT count(*) FROM keel_meta.ai_inference_admissions WHERE tenant_id=$1 AND inference_id=$2`, tenantID, missingProfile.Admission.InferenceID).Scan(&admissions); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRowContext(ctx, `SELECT count(*) FROM keel_meta.ai_budget_reservations WHERE tenant_id=$1 AND inference_id=$2`, tenantID, missingProfile.Admission.InferenceID).Scan(&reservations); err != nil {
		t.Fatal(err)
	}
	if admissions != 0 || reservations != 0 {
		t.Fatalf("failed enqueue left budget state behind: admissions=%d reservations=%d", admissions, reservations)
	}

	// A queued request whose pinned policy/token bounds are no longer active is
	// held safely and not delivered under newly changed execution limits.
	stale := createAdmission("member-stale-profile")
	if _, err := repo.Enqueue(ctx, stale); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.ExecContext(ctx, `UPDATE keel_meta.ai_execution_profiles SET max_concurrency=10,max_output_tokens=32 WHERE tenant_id=$1 AND provider_id=$2 AND model_id=$3`, tenantID, provider, model); err != nil {
		t.Fatal(err)
	}
	if _, claimed, err := repo.ClaimNext(ctx, tenant, provider, model, "worker-stale", 5*time.Second); err != nil || claimed {
		t.Fatalf("job exceeding updated token cap was claimed: claimed=%t err=%v", claimed, err)
	}
	if _, err := admin.ExecContext(ctx, `UPDATE keel_meta.ai_execution_profiles SET max_concurrency=10,max_output_tokens=128,max_attempt_duration_ms=1000 WHERE tenant_id=$1 AND provider_id=$2 AND model_id=$3`, tenantID, provider, model); err != nil {
		t.Fatal(err)
	}
	for _, worker := range []string{"worker-drain-a", "worker-drain-b"} {
		if _, claimed, err := repo.ClaimNext(ctx, tenant, provider, model, worker, 5*time.Second); err != nil || !claimed {
			t.Fatalf("could not drain compatible queued work before expiry test: claimed=%t err=%v", claimed, err)
		}
	}
	expired := createAdmission("member-expired")
	if _, err := repo.Enqueue(ctx, expired); err != nil {
		t.Fatal(err)
	}
	expiredLease, claimed, err := repo.ClaimNext(ctx, tenant, provider, model, "worker-expired", 5*time.Second)
	if err != nil || !claimed {
		t.Fatalf("claim attempt for expiry test: claimed=%t err=%v", claimed, err)
	}
	time.Sleep(time.Until(expiredLease.AttemptDeadline) + 20*time.Millisecond)
	var reaped [2]int
	var reapErrors [2]error
	reapStart := make(chan struct{})
	var reapWG sync.WaitGroup
	for i := range reaped {
		reapWG.Add(1)
		go func(i int) {
			defer reapWG.Done()
			<-reapStart
			reaped[i], reapErrors[i] = repo.ReapExpired(ctx, tenant, 10)
		}(i)
	}
	close(reapStart)
	reapWG.Wait()
	if reapErrors[0] != nil || reapErrors[1] != nil || reaped[0]+reaped[1] < 1 {
		t.Fatalf("concurrent expired attempt reaping counts=%v errors=%v", reaped, reapErrors)
	}
	if reaped, err := repo.ReapExpired(ctx, tenant, 10); err != nil || reaped != 0 {
		t.Fatalf("replaying the expiry scan changed an already reconciled candidate: count=%d err=%v", reaped, err)
	}
	var outcome, liability string
	if err := admin.QueryRowContext(ctx, `SELECT state FROM keel_meta.ai_jobs WHERE tenant_id=$1 AND inference_id=$2`, tenantID, expiredLease.InferenceID).Scan(&outcome); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRowContext(ctx, `SELECT liability_state FROM keel_meta.ai_budget_reservations WHERE tenant_id=$1 AND inference_id=$2`, tenantID, expiredLease.InferenceID).Scan(&liability); err != nil {
		t.Fatal(err)
	}
	if outcome != "unknown" || liability != "unknown" {
		t.Fatalf("expired call lost ambiguous protection: job=%s liability=%s", outcome, liability)
	}
	// A tenant-scoped app SQL session must not be able to manufacture settlement
	// evidence for a queue-owned reservation or call the worker-only transition.
	for name, statement := range map[string]string{
		"liability": `UPDATE keel_meta.ai_budget_reservations SET liability_state='settled' WHERE tenant_id=$1 AND inference_id=$2`,
		"ledger": `INSERT INTO keel_meta.ai_usage_ledger(tenant_id,entry_id,inference_id,attempt_id,entry_kind,amount_micro_usd,confidence,currency,source_ref,reconciled_by,reason_code)
			SELECT tenant_id,$3,inference_id,attempt_id,'reconciliation',0,'exact','USD','forged:no-charge','principal:attacker','provider_outcome_verified'
			FROM keel_meta.ai_inference_admissions WHERE tenant_id=$1 AND inference_id=$2`,
	} {
		err := tenancy.WithTenantTx(ctx, appDB, tenant, nil, func(tx *sql.Tx) error {
			if name == "ledger" {
				_, err := tx.ExecContext(ctx, statement, tenantID, expiredLease.InferenceID, uuid.NewString())
				return err
			}
			_, err := tx.ExecContext(ctx, statement, tenantID, expiredLease.InferenceID)
			return err
		})
		if err == nil {
			t.Fatalf("application role forged queued budget %s evidence", name)
		}
	}
	if _, err := appDB.ExecContext(ctx, `SELECT keel_meta.resolve_ai_job_outcome($1,$2,'no_charge','forged:no-charge')`, tenantID, expiredLease.InferenceID); err == nil {
		t.Fatal("application role called the worker-only outcome transition")
	}
	if _, err := repo.Renew(ctx, expiredLease, time.Second); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("unknown attempt renewed its stale lease: %v", err)
	}
	if err := repo.ReconcileUnknown(ctx, tenant, expiredLease.InferenceID, "principal:operator", "provider_outcome_verified", nil, "reconcile:provider-confirmed-no-charge"); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRowContext(ctx, `SELECT state FROM keel_meta.ai_jobs WHERE tenant_id=$1 AND inference_id=$2`, tenantID, expiredLease.InferenceID).Scan(&outcome); err != nil {
		t.Fatal(err)
	}
	if outcome != "no_charge" {
		t.Fatalf("authorized no-charge reconciliation left job in %s", outcome)
	}

	// An explicit transport ambiguity keeps both the reservation and concurrency
	// liability until an operator verifies the provider's actual result.
	ambiguous := createAdmission("member-ambiguous")
	if _, err := repo.Enqueue(ctx, ambiguous); err != nil {
		t.Fatal(err)
	}
	ambiguousLease, claimed, err := repo.ClaimNext(ctx, tenant, provider, model, "worker-ambiguous", 5*time.Second)
	if err != nil || !claimed {
		t.Fatalf("claim ambiguous attempt: claimed=%t err=%v", claimed, err)
	}
	if err := repo.RecordUnknown(ctx, ambiguousLease, "provider-response-lost"); err != nil {
		t.Fatal(err)
	}
	if err := repo.RecordUnknown(ctx, ambiguousLease, "provider-response-lost"); err != nil {
		t.Fatalf("replaying the identical unknown outcome: %v", err)
	}
	if _, err := repo.Renew(ctx, ambiguousLease, time.Second); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("ambiguous provider call renewed its lease: %v", err)
	}
	var ambiguousState, ambiguousLiability string
	if err := admin.QueryRowContext(ctx, `SELECT state FROM keel_meta.ai_jobs WHERE tenant_id=$1 AND inference_id=$2`, tenantID, ambiguousLease.InferenceID).Scan(&ambiguousState); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRowContext(ctx, `SELECT liability_state FROM keel_meta.ai_budget_reservations WHERE tenant_id=$1 AND inference_id=$2`, tenantID, ambiguousLease.InferenceID).Scan(&ambiguousLiability); err != nil {
		t.Fatal(err)
	}
	if ambiguousState != "unknown" || ambiguousLiability != "unknown" {
		t.Fatalf("ambiguous provider result lost its liability: job=%s budget=%s", ambiguousState, ambiguousLiability)
	}
	actual := ambiguous.Admission.Quote.MaximumLiabilityMicroUSD()
	if err := repo.ReconcileUnknown(ctx, tenant, ambiguousLease.InferenceID, "principal:operator", "provider_outcome_verified", &actual, "reconcile:provider-confirmed"); err != nil {
		t.Fatal(err)
	}
	if err := repo.ReconcileUnknown(ctx, tenant, ambiguousLease.InferenceID, "principal:operator", "provider_outcome_verified", &actual, "reconcile:provider-confirmed"); err != nil {
		t.Fatalf("replaying the identical reconciliation: %v", err)
	}
	if err := admin.QueryRowContext(ctx, `SELECT state FROM keel_meta.ai_jobs WHERE tenant_id=$1 AND inference_id=$2`, tenantID, ambiguousLease.InferenceID).Scan(&ambiguousState); err != nil {
		t.Fatal(err)
	}
	if ambiguousState != "succeeded" {
		t.Fatalf("confirmed reconciliation left job in %s", ambiguousState)
	}

	// A direct definite provider response settles its charge and queue state in
	// one transaction; delivery replay must be harmless.
	confirmed := createAdmission("member-confirmed")
	if _, err := repo.Enqueue(ctx, confirmed); err != nil {
		t.Fatal(err)
	}
	confirmedLease, claimed, err := repo.ClaimNext(ctx, tenant, provider, model, "worker-confirmed", 5*time.Second)
	if err != nil || !claimed {
		t.Fatalf("claim confirmed attempt: claimed=%t err=%v", claimed, err)
	}
	rollbackErr := errors.New("injected queue callback failure")
	err = repo.outcomeBudget.SettleConfirmedWith(ctx, tenant, confirmedLease.InferenceID,
		confirmed.Admission.Quote.MaximumLiabilityMicroUSD(), "provider-usage:rollback", func(*sql.Tx) error { return rollbackErr })
	if !errors.Is(err, rollbackErr) {
		t.Fatalf("injected settlement callback failure: %v", err)
	}
	var rollbackJob, rollbackLiability string
	if err := admin.QueryRowContext(ctx, `SELECT state FROM keel_meta.ai_jobs WHERE tenant_id=$1 AND inference_id=$2`, tenantID, confirmedLease.InferenceID).Scan(&rollbackJob); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRowContext(ctx, `SELECT liability_state FROM keel_meta.ai_budget_reservations WHERE tenant_id=$1 AND inference_id=$2`, tenantID, confirmedLease.InferenceID).Scan(&rollbackLiability); err != nil {
		t.Fatal(err)
	}
	var rollbackRows int
	if err := admin.QueryRowContext(ctx, `SELECT count(*) FROM keel_meta.ai_usage_ledger WHERE tenant_id=$1 AND inference_id=$2 AND entry_kind='confirmed'`, tenantID, confirmedLease.InferenceID).Scan(&rollbackRows); err != nil {
		t.Fatal(err)
	}
	if rollbackJob != "leased" || rollbackLiability != "reserved" || rollbackRows != 0 {
		t.Fatalf("callback error failed to roll back full outcome: job=%s liability=%s ledger=%d", rollbackJob, rollbackLiability, rollbackRows)
	}
	if err := repo.SettleConfirmed(ctx, confirmedLease, confirmed.Admission.Quote.MaximumLiabilityMicroUSD(), "provider-usage:confirmed"); err != nil {
		t.Fatal(err)
	}
	if err := repo.SettleConfirmed(ctx, confirmedLease, confirmed.Admission.Quote.MaximumLiabilityMicroUSD(), "provider-usage:confirmed"); err != nil {
		t.Fatalf("replaying the identical confirmed result: %v", err)
	}
	staleConfirmedLease := confirmedLease
	staleConfirmedLease.Epoch++
	if err := repo.SettleConfirmed(ctx, staleConfirmedLease, confirmed.Admission.Quote.MaximumLiabilityMicroUSD(), "provider-usage:confirmed"); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("stale lease epoch replay was accepted: %v", err)
	}
	if err := admin.QueryRowContext(ctx, `SELECT state FROM keel_meta.ai_jobs WHERE tenant_id=$1 AND inference_id=$2`, tenantID, confirmedLease.InferenceID).Scan(&outcome); err != nil {
		t.Fatal(err)
	}
	if outcome != "succeeded" {
		t.Fatalf("confirmed result left job in %s", outcome)
	}

	noCharge := createAdmission("member-no-charge")
	if _, err := repo.Enqueue(ctx, noCharge); err != nil {
		t.Fatal(err)
	}
	noChargeLease, claimed, err := repo.ClaimNext(ctx, tenant, provider, model, "worker-no-charge", 5*time.Second)
	if err != nil || !claimed {
		t.Fatalf("claim no-charge attempt: claimed=%t err=%v", claimed, err)
	}
	if err := repo.SettleNoCharge(ctx, noChargeLease, "provider-explicit-no-charge"); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRowContext(ctx, `SELECT state FROM keel_meta.ai_jobs WHERE tenant_id=$1 AND inference_id=$2`, tenantID, noChargeLease.InferenceID).Scan(&outcome); err != nil {
		t.Fatal(err)
	}
	if outcome != "no_charge" {
		t.Fatalf("definite no-charge result left job in %s", outcome)
	}
}
