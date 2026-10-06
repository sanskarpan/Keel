package ratelimit

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/redis/go-redis/v9"
	"github.com/sanskarpan/keel/internal/platform/buildinfo"
	"github.com/sanskarpan/keel/internal/platform/health"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

type allowRatePolicyChanges struct{}

func (allowRatePolicyChanges) AuthorizeFleetPolicy(context.Context, FleetPolicy) error   { return nil }
func (allowRatePolicyChanges) AuthorizeTenantPolicy(context.Context, TenantPolicy) error { return nil }

type stubPrimaryAdmission struct {
	decision Decision
	err      error
}

func (s stubPrimaryAdmission) Allow(context.Context, Request) (Decision, error) {
	return s.decision, s.err
}

type stubSafeReadFallback struct {
	decision DegradedDecision
	err      error
	calls    int
}

func TestDegradedMetricsAreLowCardinalityAndScrapedByHealthHandler(t *testing.T) {
	metrics := NewDegradedMetrics()
	metrics.record("allowed", 25*time.Millisecond)
	metrics.record("db_error", 5*time.Millisecond)
	metrics.record("tenant-private-123", time.Second)
	handler := health.NewHandlerWithMetrics(buildinfo.Info{}, metrics)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest("GET", "/metrics", nil))
	content := response.Body.String()
	if response.Code != 200 || !strings.Contains(content, `keel_rate_limit_degraded_admissions_total{result="allowed"} 1`) ||
		!strings.Contains(content, `keel_rate_limit_degraded_admissions_total{result="db_error"} 1`) ||
		!strings.Contains(content, `keel_rate_limit_degraded_admission_duration_seconds_sum{result="allowed"} 0.025000`) ||
		!strings.Contains(content, `result="invalid_request"`) || strings.Contains(content, "tenant-private-123") {
		t.Fatalf("health metrics missing fixed low-cardinality degraded series or exposed input: %s", content)
	}
}

func (s *stubSafeReadFallback) Allow(context.Context, DegradedRequest) (DegradedDecision, error) {
	s.calls++
	return s.decision, s.err
}

func TestAdmissionCoordinatorFallsBackOnlyOnRedisAvailability(t *testing.T) {
	fallback := &stubSafeReadFallback{decision: DegradedDecision{Allowed: true, Remaining: 3, Replayed: true}}
	coordinator, err := NewCoordinator(stubPrimaryAdmission{err: ErrUnavailable}, fallback)
	if err != nil {
		t.Fatal(err)
	}
	request := Request{TenantID: "00000000-0000-4000-8000-000000000001", RouteID: "safe.read",
		RequestID: "00000000-0000-4000-8000-000000000002", Policy: Policy{Digest: "policy-digest", CostUnits: 1}}
	decision, err := coordinator.Allow(context.Background(), request)
	if err != nil || !decision.Allowed || !decision.Replayed || decision.Remaining != 3 || fallback.calls != 1 {
		t.Fatalf("safe-read fallback decision=%+v err=%v calls=%d", decision, err, fallback.calls)
	}

	fallback.calls = 0
	coordinator, _ = NewCoordinator(stubPrimaryAdmission{err: ErrIdempotencyConflict}, fallback)
	if _, err := coordinator.Allow(context.Background(), request); !errors.Is(err, ErrIdempotencyConflict) || fallback.calls != 0 {
		t.Fatalf("non-availability failure incorrectly used degraded authority: err=%v calls=%d", err, fallback.calls)
	}

	fallback.calls = 0
	fallback.err = ErrDegradedPolicyRejected
	coordinator, _ = NewCoordinator(stubPrimaryAdmission{err: ErrUnavailable}, fallback)
	if _, err := coordinator.Allow(context.Background(), request); !errors.Is(err, ErrUnavailable) || fallback.calls != 1 {
		t.Fatalf("unapproved route did not fail closed: err=%v calls=%d", err, fallback.calls)
	}

	fallback.calls = 0
	request.Policy.CostUnits = 2
	coordinator, _ = NewCoordinator(stubPrimaryAdmission{err: ErrUnavailable}, fallback)
	if _, err := coordinator.Allow(context.Background(), request); !errors.Is(err, ErrUnavailable) || fallback.calls != 0 {
		t.Fatalf("higher-cost request was silently downgraded for fallback: err=%v calls=%d", err, fallback.calls)
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	fallback.calls = 0
	coordinator, _ = NewCoordinator(stubPrimaryAdmission{err: ErrUnavailable}, fallback)
	if _, err := coordinator.Allow(canceled, request); !errors.Is(err, ErrUnavailable) || fallback.calls != 0 {
		t.Fatalf("canceled primary request entered fallback: err=%v calls=%d", err, fallback.calls)
	}
}

func TestDegradedPostgresUnavailableFailsClosed(t *testing.T) {
	db, err := sql.Open("pgx", "postgres://keel_local_app:local-only@127.0.0.1:1/postgres?sslmode=disable&connect_timeout=1")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	limiter, err := NewDegradedLimiter(db, DegradedConfig{Region: "test-local", HomeRegion: "test-local", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err = limiter.Allow(ctx, DegradedRequest{TenantID: "00000000-0000-4000-8000-000000000001", RouteID: "safe.read",
		RequestID: "00000000-0000-4000-8000-000000000002", PolicyDigest: strings.Repeat("0", 64)})
	if !errors.Is(err, ErrDegradedUnavailable) {
		t.Fatalf("PostgreSQL outage did not fail closed: %v", err)
	}
	if !strings.Contains(limiter.Metrics().PrometheusMetrics(), `result="db_error"`) {
		t.Fatal("PostgreSQL outage was not recorded as a bounded metric outcome")
	}
}

func TestPostgresDegradedAdmissionIsFleetBoundRestartSafeAndTenantScoped(t *testing.T) {
	appDB, admin, rateControl := openDegradedTestDatabases(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	region := "test-" + uuid.NewString()[:8]
	route := "safe.read"
	fleet := FleetPolicy{Region: region, Capacity: 5, RefillPerSec: 1, Enabled: true}
	fleet.Digest = FleetPolicyDigest(fleet)
	control, err := NewPolicyRepository(rateControl, allowRatePolicyChanges{})
	if err != nil {
		t.Fatal(err)
	}
	if err := control.SetFleetPolicy(ctx, fleet); err != nil {
		t.Fatal(err)
	}
	// Begin with no refill credit. Any allowance beyond burst capacity must be
	// explained by the configured one-token-per-second refill over test runtime.
	if _, err := admin.ExecContext(ctx, `INSERT INTO keel_meta.rate_limit_degraded_fleet_buckets(home_region,tokens_micro,updated_at)
		VALUES($1,5000000,clock_timestamp()+interval '1 hour')`, region); err != nil {
		t.Fatal(err)
	}
	type admission struct {
		tenant  tenancy.TenantID
		request string
		digest  string
	}
	inputs := make([]admission, 20)
	for i := range inputs {
		tenant, err := tenancy.ParseTenantID(uuid.NewString())
		if err != nil {
			t.Fatal(err)
		}
		policy := TenantPolicy{TenantID: string(tenant), Region: region, RouteID: route, Capacity: 20, RefillPerSec: 1, Enabled: true}
		policy.Digest = TenantPolicyDigest(policy)
		if err := control.SetTenantPolicy(ctx, policy); err != nil {
			t.Fatalf("install tenant policy %d: %v", i, err)
		}
		inputs[i] = admission{tenant: tenant, request: uuid.NewString(), digest: policy.Digest}
	}
	// Application credentials cannot edit the policy that bounds fallback use.
	if err := tenancy.WithTenantTx(ctx, appDB, inputs[0].tenant, nil, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE keel_meta.rate_limit_degraded_tenant_policies SET capacity_units=999999
			WHERE tenant_id=$1 AND home_region=$2 AND route_id=$3`, string(inputs[0].tenant), region, route)
		return err
	}); err == nil {
		t.Fatal("app role changed a control-plane safe-read policy")
	}
	limiter, err := NewDegradedLimiter(appDB, DegradedConfig{Region: region, HomeRegion: region, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := limiter.Allow(ctx, DegradedRequest{TenantID: string(inputs[0].tenant), RouteID: route,
		RequestID: uuid.NewString(), PolicyDigest: hex.EncodeToString(make([]byte, 32))}); err != ErrDegradedPolicyRejected {
		t.Fatalf("stale policy digest was accepted: %v", err)
	}
	var windows int
	if err := admin.QueryRowContext(ctx, `SELECT count(*) FROM keel_meta.rate_limit_degraded_windows WHERE home_region=$1`, region).Scan(&windows); err != nil {
		t.Fatal(err)
	}
	if windows != 0 {
		t.Fatalf("rejected stale policy opened the outage window: windows=%d", windows)
	}

	// Each goroutine creates a fresh limiter, simulating process replacement and
	// replica scaling while sharing only the durable PostgreSQL authority.
	var wg sync.WaitGroup
	var mu sync.Mutex
	allowed := 0
	var first admission
	concurrencyStarted := time.Now()
	for i, input := range inputs {
		wg.Add(1)
		go func(i int, input admission) {
			defer wg.Done()
			decision, err := limiter.Allow(ctx, DegradedRequest{TenantID: string(input.tenant), RouteID: route, RequestID: input.request, PolicyDigest: input.digest})
			if err != nil {
				t.Errorf("admit %d: %v", i, err)
				return
			}
			if decision.Allowed {
				mu.Lock()
				allowed++
				first = input
				mu.Unlock()
			}
		}(i, input)
	}
	wg.Wait()
	maxRefill := int(time.Since(concurrencyStarted)/time.Second) + 1
	if allowed > 5+maxRefill {
		t.Fatalf("replica concurrency exceeded fleet burst plus elapsed refill: allowed=%d burst=5 max_elapsed_refill=%d", allowed, maxRefill)
	}

	var replayWG sync.WaitGroup
	var replayErrors sync.Mutex
	replayed := 0
	for i := 0; i < 16; i++ {
		replayWG.Add(1)
		go func() {
			defer replayWG.Done()
			limiter, err := NewDegradedLimiter(appDB, DegradedConfig{Region: region, HomeRegion: region, Enabled: true})
			if err == nil {
				var decision DegradedDecision
				decision, err = limiter.Allow(ctx, DegradedRequest{TenantID: string(first.tenant), RouteID: route, RequestID: first.request, PolicyDigest: first.digest})
				if err == nil && decision.Allowed && decision.Replayed {
					replayErrors.Lock()
					replayed++
					replayErrors.Unlock()
					return
				}
			}
			t.Errorf("concurrent exact replay returned err=%v", err)
		}()
	}
	replayWG.Wait()
	if replayed != 16 {
		t.Fatalf("concurrent exact replays changed decision or failed: replayed=%d want=16", replayed)
	}

	restartedLimiter, err := NewDegradedLimiter(appDB, DegradedConfig{Region: region, HomeRegion: region, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	replay, err := restartedLimiter.Allow(ctx, DegradedRequest{TenantID: string(first.tenant), RouteID: route, RequestID: first.request, PolicyDigest: first.digest})
	if err != nil || !replay.Allowed || !replay.Replayed || replay.OutageID == "" {
		t.Fatalf("restart lost durable exact replay: %+v err=%v", replay, err)
	}
	updatedPolicy := TenantPolicy{TenantID: string(first.tenant), Region: region, RouteID: route,
		Capacity: 19, RefillPerSec: 1, Enabled: true}
	updatedPolicy.Digest = TenantPolicyDigest(updatedPolicy)
	if err := control.SetTenantPolicy(ctx, updatedPolicy); err != nil {
		t.Fatal(err)
	}
	conflict := DegradedRequest{TenantID: string(first.tenant), RouteID: route, RequestID: first.request,
		PolicyDigest: updatedPolicy.Digest}
	if _, err := restartedLimiter.Allow(ctx, conflict); err != ErrIdempotencyConflict {
		t.Fatalf("request ID reused under another policy was accepted: %v", err)
	}
	if _, err := restartedLimiter.Allow(ctx, DegradedRequest{TenantID: string(first.tenant), RouteID: route,
		RequestID: uuid.NewString(), PolicyDigest: first.digest}); err != ErrDegradedPolicyRejected {
		t.Fatalf("stale tenant policy generation was accepted: %v", err)
	}

	// Expiry is latched: an extended Redis outage cannot start another 60s window.
	if _, err := admin.ExecContext(ctx, `UPDATE keel_meta.rate_limit_degraded_windows
		SET started_at=clock_timestamp()-interval '61 seconds',expires_at=clock_timestamp()-interval '2 seconds' WHERE home_region=$1`, region); err != nil {
		t.Fatal(err)
	}
	next := inputs[5]
	next.request = uuid.NewString()
	if _, err := restartedLimiter.Allow(ctx, DegradedRequest{TenantID: string(next.tenant), RouteID: route, RequestID: next.request, PolicyDigest: next.digest}); err != ErrDegradedWindowExpired {
		t.Fatalf("expired degraded window silently renewed while Redis remained unavailable: %v", err)
	}
}

func TestPostgresDegradedWindowDeadlineUsesPostLockDatabaseTime(t *testing.T) {
	appDB, admin, rateControl := openDegradedTestDatabases(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	region := "test-" + uuid.NewString()[:8]
	tenant, _ := tenancy.ParseTenantID(uuid.NewString())
	route := "safe.read"
	fleet := FleetPolicy{Region: region, Capacity: 2, RefillPerSec: 1, Enabled: true}
	fleet.Digest = FleetPolicyDigest(fleet)
	policy := TenantPolicy{TenantID: string(tenant), Region: region, RouteID: route, Capacity: 2, RefillPerSec: 1, Enabled: true}
	policy.Digest = TenantPolicyDigest(policy)
	control, err := NewPolicyRepository(rateControl, allowRatePolicyChanges{})
	if err != nil {
		t.Fatal(err)
	}
	if err := control.SetFleetPolicy(ctx, fleet); err != nil {
		t.Fatal(err)
	}
	if err := control.SetTenantPolicy(ctx, policy); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.ExecContext(ctx, `INSERT INTO keel_meta.rate_limit_degraded_windows(home_region,outage_id,started_at,expires_at,active)
		VALUES($1,gen_random_uuid(),clock_timestamp()-interval '59 seconds',clock_timestamp()+interval '250 milliseconds',true)`, region); err != nil {
		t.Fatal(err)
	}
	lockTx, err := admin.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer lockTx.Rollback()
	var locked string
	if err := lockTx.QueryRowContext(ctx, `SELECT home_region FROM keel_meta.rate_limit_degraded_windows WHERE home_region=$1 FOR UPDATE`, region).Scan(&locked); err != nil {
		t.Fatal(err)
	}
	limiter, err := NewDegradedLimiter(appDB, DegradedConfig{Region: region, HomeRegion: region, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		_, err := limiter.Allow(ctx, DegradedRequest{TenantID: string(tenant), RouteID: route, RequestID: uuid.NewString(), PolicyDigest: policy.Digest})
		result <- err
	}()
	time.Sleep(500 * time.Millisecond)
	if err := lockTx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err != ErrDegradedWindowExpired {
		t.Fatalf("lock wait crossed the outage deadline but request was admitted: %v", err)
	}
}

func TestPostgresDegradedExpiredReceiptKeyCanBeReusedAfterBoundedCleanup(t *testing.T) {
	appDB, admin, rateControl := openDegradedTestDatabases(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	region := "test-" + uuid.NewString()[:8]
	tenant, _ := tenancy.ParseTenantID(uuid.NewString())
	route := "safe.read"
	fleet := FleetPolicy{Region: region, Capacity: 2, RefillPerSec: 1, Enabled: true}
	fleet.Digest = FleetPolicyDigest(fleet)
	policy := TenantPolicy{TenantID: string(tenant), Region: region, RouteID: route, Capacity: 2, RefillPerSec: 1, Enabled: true}
	policy.Digest = TenantPolicyDigest(policy)
	control, err := NewPolicyRepository(rateControl, allowRatePolicyChanges{})
	if err != nil {
		t.Fatal(err)
	}
	if err := control.SetFleetPolicy(ctx, fleet); err != nil {
		t.Fatal(err)
	}
	if err := control.SetTenantPolicy(ctx, policy); err != nil {
		t.Fatal(err)
	}
	limiter, err := NewDegradedLimiter(appDB, DegradedConfig{Region: region, HomeRegion: region, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	requestID := uuid.NewString()
	first, err := limiter.Allow(ctx, DegradedRequest{TenantID: string(tenant), RouteID: route, RequestID: requestID, PolicyDigest: policy.Digest})
	if err != nil || !first.Allowed || first.Replayed {
		t.Fatalf("initial request was not admitted: %+v err=%v", first, err)
	}
	if _, err := admin.ExecContext(ctx, `UPDATE keel_meta.rate_limit_degraded_receipts
		SET created_at=clock_timestamp()-interval '2 seconds',expires_at=clock_timestamp()-interval '1 second'
		WHERE tenant_id=$1 AND home_region=$2 AND route_id=$3 AND request_id=$4`, string(tenant), region, route, requestID); err != nil {
		t.Fatal(err)
	}
	// More than 100 older stale receipts ensure the bounded global cleanup does
	// not happen to remove the target key; exact-key deletion must free it.
	if _, err := admin.ExecContext(ctx, `INSERT INTO keel_meta.rate_limit_degraded_receipts
		(tenant_id,home_region,route_id,request_id,policy_sha256,fleet_policy_sha256,outage_id,allowed,remaining_units,
		retry_after_ms,created_at,expires_at)
		SELECT $1,$2,$3,gen_random_uuid(),$4,$5,w.outage_id,false,0,0,
		clock_timestamp()-interval '31 minutes',clock_timestamp()-interval '30 minutes'
		FROM generate_series(1,101), keel_meta.rate_limit_degraded_windows w WHERE w.home_region=$2`,
		string(tenant), region, route, mustHex(t, policy.Digest), mustHex(t, fleet.Digest)); err != nil {
		t.Fatal(err)
	}
	replay, err := limiter.Allow(ctx, DegradedRequest{TenantID: string(tenant), RouteID: route, RequestID: requestID, PolicyDigest: policy.Digest})
	if err != nil || !replay.Allowed || replay.Replayed {
		t.Fatalf("expired request key was not safely re-admitted: %+v err=%v", replay, err)
	}
}

func mustHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func TestPostgresDegradedRecoveryRequiresRateControlRoleAndHealthyRedis(t *testing.T) {
	appDB, _, rateControl := openDegradedTestDatabases(t)
	redisURL := os.Getenv("KEEL_TEST_REDIS_URL")
	if redisURL == "" {
		t.Skip("set KEEL_TEST_REDIS_URL to qualify degraded-window recovery against home-region Redis")
	}
	options, err := redis.ParseURL(redisURL)
	if err != nil {
		t.Fatal(err)
	}
	options.MaxRetries = -1
	redisClient := redis.NewClient(options)
	t.Cleanup(func() { _ = redisClient.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	region := "test-" + uuid.NewString()[:8]
	primary, err := New(redisClient, Config{Region: region, HomeRegion: region, KeyID: "recovery-test",
		Secret: []byte("safe-read-recovery-secret-material-0123456"), ReplayTTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	tenant, _ := tenancy.ParseTenantID(uuid.NewString())
	route := "safe.read"
	fleet := FleetPolicy{Region: region, Capacity: 2, RefillPerSec: 1, Enabled: true}
	fleet.Digest = FleetPolicyDigest(fleet)
	control, err := NewPolicyRepository(rateControl, allowRatePolicyChanges{})
	if err != nil {
		t.Fatal(err)
	}
	if err := control.SetFleetPolicy(ctx, fleet); err != nil {
		t.Fatal(err)
	}
	policy := TenantPolicy{TenantID: string(tenant), Region: region, RouteID: route, Capacity: 2, RefillPerSec: 1, Enabled: true}
	policy.Digest = TenantPolicyDigest(policy)
	if err := control.SetTenantPolicy(ctx, policy); err != nil {
		t.Fatal(err)
	}
	limiter, err := NewDegradedLimiter(appDB, DegradedConfig{Region: region, HomeRegion: region, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	first, err := limiter.Allow(ctx, DegradedRequest{TenantID: string(tenant), RouteID: route, RequestID: uuid.NewString(), PolicyDigest: policy.Digest})
	if err != nil || !first.Allowed {
		t.Fatalf("first degraded admission: %+v err=%v", first, err)
	}
	if _, err := appDB.ExecContext(ctx, `SELECT keel_meta.mark_rate_limit_redis_healthy($1,'5 seconds')`, region); err == nil {
		t.Fatal("ordinary app credential closed the degraded window")
	}
	if err := ObserveRedisRecovery(ctx, primary, rateControl); err != nil {
		t.Fatal(err)
	}
	second, err := limiter.Allow(ctx, DegradedRequest{TenantID: string(tenant), RouteID: route, RequestID: uuid.NewString(), PolicyDigest: policy.Digest})
	if err != nil || !second.Allowed || second.OutageID == first.OutageID {
		t.Fatalf("verified recovery did not fence a subsequent outage: first=%+v second=%+v err=%v", first, second, err)
	}
}

func TestCoordinatorUsesPostgresFallbackOnlyForApprovedSafeRead(t *testing.T) {
	appDB, _, rateControl := openDegradedTestDatabases(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	region := "test-" + uuid.NewString()[:8]
	tenant, _ := tenancy.ParseTenantID(uuid.NewString())
	policy := TenantPolicy{TenantID: string(tenant), Region: region, RouteID: "safe.read", Capacity: 1, RefillPerSec: 1, Enabled: true}
	policy.Digest = TenantPolicyDigest(policy)
	fleet := FleetPolicy{Region: region, Capacity: 3, RefillPerSec: 1, Enabled: true}
	fleet.Digest = FleetPolicyDigest(fleet)
	control, err := NewPolicyRepository(rateControl, allowRatePolicyChanges{})
	if err != nil {
		t.Fatal(err)
	}
	if err := control.SetFleetPolicy(ctx, fleet); err != nil {
		t.Fatal(err)
	}
	if err := control.SetTenantPolicy(ctx, policy); err != nil {
		t.Fatal(err)
	}
	redisClient, err := NewRedisClient(ClientConfig{Addr: "127.0.0.1:1", Region: region, HomeRegion: region,
		AllowSyntheticLoopback: true, DialTimeout: 50 * time.Millisecond, ReadTimeout: 50 * time.Millisecond,
		WriteTimeout: 50 * time.Millisecond, PoolSize: 2})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = redisClient.Close() })
	primary, err := New(redisClient, Config{Region: region, HomeRegion: region, KeyID: "hmac-test",
		Secret: []byte("safe-read-test-secret-material-0123456789"), ReplayTTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	degraded, err := NewDegradedLimiter(appDB, DegradedConfig{Region: region, HomeRegion: region, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := NewCoordinator(primary, degraded)
	if err != nil {
		t.Fatal(err)
	}
	request := Request{TenantID: string(tenant), RouteID: policy.RouteID, RequestID: uuid.NewString(),
		Policy: Policy{Digest: policy.Digest, CapacityUnits: policy.Capacity, RefillUnitsPerSecond: policy.RefillPerSec, CostUnits: 1}}
	first, err := coordinator.Allow(ctx, request)
	if err != nil || !first.Allowed || first.Replayed {
		t.Fatalf("Redis outage safe-read admission: %+v err=%v", first, err)
	}
	replay, err := coordinator.Allow(ctx, request)
	if err != nil || !replay.Allowed || !replay.Replayed {
		t.Fatalf("same logical request did not replay after ambiguous Redis failure: %+v err=%v", replay, err)
	}
	request.RequestID = uuid.NewString()
	if decision, err := coordinator.Allow(ctx, request); err != nil || decision.Allowed {
		t.Fatalf("tenant fallback policy cap was exceeded: %+v err=%v", decision, err)
	}
	request.RouteID = "model.generate"
	request.RequestID = uuid.NewString()
	if _, err := coordinator.Allow(ctx, request); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("model route did not fail closed when Redis was unavailable: %v", err)
	}
}

func openDegradedTestDatabases(t *testing.T) (app, admin, control *sql.DB) {
	t.Helper()
	appDSN := os.Getenv("KEEL_TEST_DATABASE_URL")
	adminDSN := os.Getenv("KEEL_TEST_ADMIN_DATABASE_URL")
	controlDSN := os.Getenv("KEEL_TEST_RATE_CONTROL_DATABASE_URL")
	if appDSN == "" || adminDSN == "" || controlDSN == "" {
		t.Skip("set app, admin and rate-control PostgreSQL URLs for durable degraded-admission integration coverage")
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
		db.SetMaxOpenConns(24)
		if err := db.Ping(); err != nil {
			_ = db.Close()
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		return db
	}
	return open(appDSN), open(adminDSN), open(controlDSN)
}
