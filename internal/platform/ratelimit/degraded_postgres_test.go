package ratelimit

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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

type scriptedPingClient struct {
	redis.UniversalClient
	mu     sync.Mutex
	calls  int
	failAt int
}

func (c *scriptedPingClient) Ping(ctx context.Context) *redis.StatusCmd {
	c.mu.Lock()
	c.calls++
	fail := c.calls == c.failAt
	c.mu.Unlock()
	cmd := redis.NewStatusCmd(ctx)
	if fail {
		cmd.SetErr(errors.New("synthetic transient Redis probe failure"))
	} else {
		cmd.SetVal("PONG")
	}
	return cmd
}

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
	metrics  *DegradedMetrics
}

func (s *stubSafeReadFallback) Metrics() *DegradedMetrics {
	if s.metrics == nil {
		s.metrics = NewDegradedMetrics()
	}
	return s.metrics
}

type responseLosingFallback struct {
	fallback SafeReadFallback
	loseNext bool
}

type appliedThenLostRedisResponse struct {
	primary PrimaryAdmission
}

func (p appliedThenLostRedisResponse) Allow(ctx context.Context, request Request) (Decision, error) {
	decision, err := p.primary.Allow(ctx, request)
	if err != nil || !decision.Allowed {
		return decision, err
	}
	// The Redis operation has committed, but its response is lost before the
	// coordinator can observe the decision.
	return Decision{}, ErrUnavailable
}

func (f *responseLosingFallback) Allow(ctx context.Context, request DegradedRequest) (DegradedDecision, error) {
	decision, err := f.fallback.Allow(ctx, request)
	if err != nil {
		return DegradedDecision{}, err
	}
	if f.loseNext {
		f.loseNext = false
		return DegradedDecision{}, ErrDegradedUnavailable
	}
	return decision, nil
}

func TestDegradedMetricsAreLowCardinalityAndScrapedByHealthHandler(t *testing.T) {
	metrics := NewDegradedMetrics()
	metrics.record("allowed", 25*time.Millisecond)
	metrics.record("db_error", 5*time.Millisecond)
	metrics.record("tenant-private-123", time.Second)
	metrics.recordPrimary("unavailable", 8*time.Millisecond)
	metrics.recordPrimary("tenant-private-123", time.Second)
	recoveredAt := time.Unix(1_800_000_000, 0).UTC()
	metrics.setWindowStatus(DegradedWindowStatus{Present: true, Active: true, AdmissionOpen: true,
		SecondsUntilExpiry: 42.5, ObservedAt: time.Unix(1_800_000_010, 0).UTC(), LastRecoveredAt: &recoveredAt})
	handler := health.NewHandlerWithMetrics(buildinfo.Info{}, metrics)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest("GET", "/metrics", nil))
	content := response.Body.String()
	if response.Code != 200 || !strings.Contains(content, `keel_rate_limit_degraded_admissions_total{result="allowed"} 1`) ||
		!strings.Contains(content, `keel_rate_limit_degraded_admissions_total{result="db_error"} 1`) ||
		!strings.Contains(content, `keel_rate_limit_degraded_admission_duration_seconds_sum{result="allowed"} 0.025000`) ||
		!strings.Contains(content, `keel_rate_limit_primary_admissions_total{result="unavailable"} 1`) ||
		!strings.Contains(content, `keel_rate_limit_primary_admissions_total{result="error"} 1`) ||
		!strings.Contains(content, `result="invalid_request"`) ||
		!strings.Contains(content, "keel_rate_limit_degraded_window_status_observed 1") ||
		!strings.Contains(content, "keel_rate_limit_degraded_window_present 1") ||
		!strings.Contains(content, "keel_rate_limit_degraded_window_active 1") ||
		!strings.Contains(content, "keel_rate_limit_degraded_admission_window_open 1") ||
		!strings.Contains(content, "keel_rate_limit_degraded_window_seconds_until_expiry 42.500000") ||
		!strings.Contains(content, "keel_rate_limit_degraded_window_last_recovered_timestamp_seconds 1800000000.000000") ||
		strings.Contains(content, "tenant-private-123") {
		t.Fatalf("health metrics missing fixed low-cardinality degraded series or exposed input: %s", content)
	}
	unobserved := NewDegradedMetrics().PrometheusMetrics()
	if !strings.Contains(unobserved, "\nkeel_rate_limit_degraded_window_status_observed 0\n") ||
		strings.Contains(unobserved, "\nkeel_rate_limit_degraded_window_present ") {
		t.Fatalf("unobserved database status was presented as an empty healthy window: %s", unobserved)
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
	if got := fallback.Metrics().PrometheusMetrics(); !strings.Contains(got, `keel_rate_limit_primary_admissions_total{result="unavailable"} 1`) {
		t.Fatalf("Redis availability failure was not measured on the coordinator path: %s", got)
	}

	for _, routeID := range []string{"model.generate", "unclassified.route"} {
		fallback.calls = 0
		request.RouteID = routeID
		coordinator, _ = NewCoordinator(stubPrimaryAdmission{err: ErrUnavailable}, fallback)
		if _, err := coordinator.Allow(context.Background(), request); !errors.Is(err, ErrUnavailable) || fallback.calls != 0 {
			t.Fatalf("unclassified route %q entered safe-read fallback: err=%v calls=%d", routeID, err, fallback.calls)
		}
	}
	request.RouteID = "safe.read"

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

func TestAdmissionCoordinatorNeverBypassesHealthyRedisDecision(t *testing.T) {
	request := Request{TenantID: "00000000-0000-4000-8000-000000000001", RouteID: "safe.read",
		RequestID: "00000000-0000-4000-8000-000000000002", Policy: Policy{Digest: "policy-digest", CostUnits: 1}}
	for _, primaryDecision := range []Decision{
		{Allowed: true, Remaining: 4},
		{Allowed: false, Remaining: 0, RetryAfter: 250 * time.Millisecond},
	} {
		fallback := &stubSafeReadFallback{decision: DegradedDecision{Allowed: true, Remaining: 3}}
		coordinator, err := NewCoordinator(stubPrimaryAdmission{decision: primaryDecision}, fallback)
		if err != nil {
			t.Fatal(err)
		}
		decision, err := coordinator.Allow(context.Background(), request)
		if err != nil || decision != primaryDecision || fallback.calls != 0 {
			t.Fatalf("healthy Redis decision was changed or bypassed: primary=%+v got=%+v err=%v fallback_calls=%d",
				primaryDecision, decision, err, fallback.calls)
		}
		outcome := "allowed"
		if !primaryDecision.Allowed {
			outcome = "limited"
		}
		if got := fallback.Metrics().PrometheusMetrics(); !strings.Contains(got, `keel_rate_limit_primary_admissions_total{result="`+outcome+`"} 1`) {
			t.Fatalf("healthy Redis %s decision was not measured: %s", outcome, got)
		}
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

func TestDegradedKillSwitchStopsFallbackBeforePostgres(t *testing.T) {
	db, err := sql.Open("pgx", "postgres://keel_local_app:local-only@127.0.0.1:1/postgres?sslmode=disable&connect_timeout=1")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	metrics := NewDegradedMetrics()
	fallback, err := NewDegradedLimiterWithMetrics(db,
		DegradedConfig{Region: "test-local", HomeRegion: "test-local", Enabled: false}, metrics)
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := NewCoordinator(stubPrimaryAdmission{err: ErrUnavailable}, fallback)
	if err != nil {
		t.Fatal(err)
	}
	request := Request{TenantID: "00000000-0000-4000-8000-000000000001", RouteID: "safe.read",
		RequestID: "00000000-0000-4000-8000-000000000002",
		Policy:    Policy{Digest: strings.Repeat("0", 64), CostUnits: 1}}
	decision, err := coordinator.Allow(context.Background(), request)
	if !errors.Is(err, ErrUnavailable) || decision.Allowed || errors.Is(err, ErrDegradedUnavailable) {
		t.Fatalf("disabled fallback did not fail closed before PostgreSQL: decision=%+v err=%v", decision, err)
	}
	content := metrics.PrometheusMetrics()
	if !strings.Contains(content, `result="disabled"} 1`) || !strings.Contains(content, `result="db_error"} 0`) {
		t.Fatalf("kill switch outcome is not recorded without a PostgreSQL attempt: %s", content)
	}
}

func TestDegradedLimiterRejectsNilContextBeforeDatabase(t *testing.T) {
	db, err := sql.Open("pgx", "postgres://keel_local_app:local-only@127.0.0.1:1/postgres?sslmode=disable&connect_timeout=1")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	metrics := NewDegradedMetrics()
	limiter, err := NewDegradedLimiterWithMetrics(db, DegradedConfig{Region: "test-local", HomeRegion: "test-local", Enabled: true}, metrics)
	if err != nil {
		t.Fatal(err)
	}
	_, err = limiter.Allow(nil, DegradedRequest{TenantID: "00000000-0000-4000-8000-000000000001",
		RouteID: "safe.read", RequestID: "00000000-0000-4000-8000-000000000002", PolicyDigest: strings.Repeat("a", 64)})
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil context did not fail closed as invalid configuration: %v", err)
	}
	content := metrics.PrometheusMetrics()
	if !strings.Contains(content, `result="invalid_request"} 1`) || !strings.Contains(content, `result="db_error"} 0`) {
		t.Fatalf("nil context was not rejected before database access: %s", content)
	}
}

func TestDegradedLimiterRejectsUnclassifiedRouteBeforeDatabase(t *testing.T) {
	db, err := sql.Open("pgx", "postgres://keel_local_app:local-only@127.0.0.1:1/postgres?sslmode=disable&connect_timeout=1")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	metrics := NewDegradedMetrics()
	limiter, err := NewDegradedLimiterWithMetrics(db, DegradedConfig{Region: "test-local", HomeRegion: "test-local", Enabled: true}, metrics)
	if err != nil {
		t.Fatal(err)
	}
	_, err = limiter.Allow(context.Background(), DegradedRequest{TenantID: "00000000-0000-4000-8000-000000000001",
		RouteID: "unclassified.route", RequestID: "00000000-0000-4000-8000-000000000002", PolicyDigest: strings.Repeat("a", 64)})
	if !errors.Is(err, ErrDegradedPolicyRejected) || !strings.Contains(metrics.PrometheusMetrics(), `result="policy_rejected"} 1`) {
		t.Fatalf("unclassified direct fallback was not rejected before SQL: err=%v metrics=%s", err, metrics.PrometheusMetrics())
	}
}

func TestCoordinatorFailsClosedWhenRedisAndPostgresAreUnavailable(t *testing.T) {
	db, err := sql.Open("pgx", "postgres://keel_local_app:local-only@127.0.0.1:1/postgres?sslmode=disable&connect_timeout=1")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	metrics := NewDegradedMetrics()
	fallback, err := NewDegradedLimiterWithMetrics(db,
		DegradedConfig{Region: "test-local", HomeRegion: "test-local", Enabled: true}, metrics)
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := NewCoordinator(stubPrimaryAdmission{err: ErrUnavailable}, fallback)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	request := Request{TenantID: "00000000-0000-4000-8000-000000000001", RouteID: "safe.read",
		RequestID: "00000000-0000-4000-8000-000000000002",
		Policy:    Policy{Digest: strings.Repeat("0", 64), CostUnits: 1}}
	if decision, err := coordinator.Allow(ctx, request); !errors.Is(err, ErrDegradedUnavailable) || decision.Allowed {
		t.Fatalf("request was not rejected when both admission authorities were unavailable: decision=%+v err=%v", decision, err)
	}
	if !strings.Contains(metrics.PrometheusMetrics(), `result="db_error"`) {
		t.Fatal("combined authority failure was not recorded as a bounded db_error metric")
	}
}

func TestPostgresDegradedFleetPolicyKillSwitchTakesEffectImmediately(t *testing.T) {
	appDB, adminDB, rateControlDB := openDegradedTestDatabases(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	region := "test-" + uuid.NewString()[:8]
	tenant, err := tenancy.ParseTenantID(uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	const route = "safe.read"
	fleet := FleetPolicy{Region: region, Capacity: 4, RefillPerSec: 1, Enabled: true}
	fleet.Digest = FleetPolicyDigest(fleet)
	tenantPolicy := TenantPolicy{TenantID: string(tenant), Region: region, RouteID: route,
		Capacity: 4, RefillPerSec: 1, Enabled: true}
	tenantPolicy.Digest = TenantPolicyDigest(tenantPolicy)

	policies, err := NewPolicyRepository(rateControlDB, allowRatePolicyChanges{})
	if err != nil {
		t.Fatal(err)
	}
	if err := policies.SetFleetPolicy(ctx, fleet); err != nil {
		t.Fatal(err)
	}
	if err := policies.SetTenantPolicy(ctx, tenantPolicy); err != nil {
		t.Fatal(err)
	}
	metrics := NewDegradedMetrics()
	limiter, err := NewDegradedLimiterWithMetrics(appDB,
		DegradedConfig{Region: region, HomeRegion: region, Enabled: true}, metrics)
	if err != nil {
		t.Fatal(err)
	}
	firstRequestID := uuid.NewString()
	first, err := limiter.Allow(ctx, DegradedRequest{TenantID: string(tenant), RouteID: route,
		RequestID: firstRequestID, PolicyDigest: tenantPolicy.Digest})
	if err != nil || !first.Allowed {
		t.Fatalf("enabled fleet policy did not admit the initial request: decision=%+v err=%v", first, err)
	}

	fleet.Enabled = false
	fleet.Digest = FleetPolicyDigest(fleet)
	if err := policies.SetFleetPolicy(ctx, fleet); err != nil {
		t.Fatal(err)
	}
	disabledRequestID := uuid.NewString()
	decision, err := limiter.Allow(ctx, DegradedRequest{TenantID: string(tenant), RouteID: route,
		RequestID: disabledRequestID, PolicyDigest: tenantPolicy.Digest})
	if !errors.Is(err, ErrDegradedPolicyRejected) || decision.Allowed {
		t.Fatalf("disabled fleet policy did not immediately reject fallback: decision=%+v err=%v", decision, err)
	}
	replay, err := limiter.Allow(ctx, DegradedRequest{TenantID: string(tenant), RouteID: route,
		RequestID: firstRequestID, PolicyDigest: tenantPolicy.Digest})
	if !errors.Is(err, ErrDegradedPolicyRejected) || replay.Allowed {
		t.Fatalf("fleet kill switch allowed an exact receipt replay: decision=%+v err=%v", replay, err)
	}
	if !strings.Contains(metrics.PrometheusMetrics(), `result="policy_rejected"} 2`) {
		t.Fatal("dynamic kill-switch rejections were not recorded as bounded policy outcomes")
	}
	var receipts int
	if err := adminDB.QueryRowContext(ctx, `SELECT count(*) FROM keel_meta.rate_limit_degraded_receipts
		WHERE tenant_id=$1 AND home_region=$2 AND route_id=$3 AND request_id=$4`,
		string(tenant), region, route, disabledRequestID).Scan(&receipts); err != nil {
		t.Fatal(err)
	}
	if receipts != 0 {
		t.Fatalf("disabled fleet policy wrote an admission receipt: count=%d", receipts)
	}
}

func TestPostgresDegradedAdmissionRemainsFleetBoundAcrossProcesses(t *testing.T) {
	_, _, rateControl := openDegradedTestDatabases(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	region := "test-" + uuid.NewString()[:8]
	tenant, err := tenancy.ParseTenantID(uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	const route = "safe.read"
	const capacity int64 = 5
	fleet := FleetPolicy{Region: region, Capacity: capacity, RefillPerSec: 1, Enabled: true}
	fleet.Digest = FleetPolicyDigest(fleet)
	policy := TenantPolicy{TenantID: string(tenant), Region: region, RouteID: route,
		Capacity: capacity, RefillPerSec: 1, Enabled: true}
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

	type processResult struct {
		requestID string
		decision  DegradedDecision
		err       error
	}
	const processCount = 12
	started := time.Now()
	results := make(chan processResult, processCount)
	var workers sync.WaitGroup
	for range processCount {
		requestID := uuid.NewString()
		workers.Add(1)
		go func() {
			defer workers.Done()
			decision, err := runDegradedAdmissionProcess(ctx, region, string(tenant), route, requestID, policy.Digest)
			results <- processResult{requestID: requestID, decision: decision, err: err}
		}()
	}
	workers.Wait()
	close(results)

	allowed := 0
	var replayRequestID string
	var replayRemaining int64
	for result := range results {
		if result.err != nil {
			t.Fatalf("separate process admission failed: %v", result.err)
		}
		if result.decision.Allowed {
			allowed++
			if replayRequestID == "" {
				replayRequestID = result.requestID
				replayRemaining = result.decision.Remaining
			}
		}
	}
	elapsed := time.Since(started)
	allowedCeiling := capacity + int64(elapsed/time.Second) + 1
	if int64(allowed) > allowedCeiling {
		t.Fatalf("independent processes exceeded shared fleet allowance: allowed=%d ceiling=%d elapsed=%s", allowed, allowedCeiling, elapsed)
	}
	if replayRequestID == "" {
		t.Fatal("all independent processes were denied despite unused initial capacity")
	}

	replay, err := runDegradedAdmissionProcess(ctx, region, string(tenant), route, replayRequestID, policy.Digest)
	if err != nil || !replay.Allowed || !replay.Replayed || replay.Remaining != replayRemaining {
		t.Fatalf("fresh process did not replay the durable receipt: decision=%+v err=%v", replay, err)
	}
	newRequest, err := runDegradedAdmissionProcess(ctx, region, string(tenant), route, uuid.NewString(), policy.Digest)
	if err != nil {
		t.Fatal(err)
	}
	totalAllowed := allowed
	if newRequest.Allowed {
		totalAllowed++
	}
	allowedCeiling = capacity + int64(time.Since(started)/time.Second) + 1
	if int64(totalAllowed) > allowedCeiling {
		t.Fatalf("fresh processes exceeded shared burst plus refill envelope: allowed=%d ceiling=%d elapsed=%s", totalAllowed, allowedCeiling, time.Since(started))
	}
}

func TestDegradedAdmissionProcessChild(t *testing.T) {
	if os.Getenv("KEEL_DEGRADED_PROCESS_CHILD") != "1" {
		return
	}
	db, err := sql.Open("pgx", os.Getenv("KEEL_TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)

	region := os.Getenv("KEEL_DEGRADED_REGION")
	limiter, err := NewDegradedLimiter(db, DegradedConfig{Region: region, HomeRegion: region, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	decision, err := limiter.Allow(ctx, DegradedRequest{
		TenantID: os.Getenv("KEEL_DEGRADED_TENANT"), RouteID: os.Getenv("KEEL_DEGRADED_ROUTE"),
		RequestID: os.Getenv("KEEL_DEGRADED_REQUEST_ID"), PolicyDigest: os.Getenv("KEEL_DEGRADED_POLICY_DIGEST"),
	})
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("DECISION %t %t %d\n", decision.Allowed, decision.Replayed, decision.Remaining)
}

func runDegradedAdmissionProcess(ctx context.Context, region, tenant, route, requestID, digest string) (DegradedDecision, error) {
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestDegradedAdmissionProcessChild$")
	command.Env = append(os.Environ(),
		"KEEL_DEGRADED_PROCESS_CHILD=1",
		"KEEL_DEGRADED_REGION="+region,
		"KEEL_DEGRADED_TENANT="+tenant,
		"KEEL_DEGRADED_ROUTE="+route,
		"KEEL_DEGRADED_REQUEST_ID="+requestID,
		"KEEL_DEGRADED_POLICY_DIGEST="+digest,
	)
	output, err := command.CombinedOutput()
	if err != nil {
		return DegradedDecision{}, fmt.Errorf("run separate admission process: %w: %s", err, strings.TrimSpace(string(output)))
	}
	for _, line := range strings.Split(string(output), "\n") {
		if !strings.HasPrefix(line, "DECISION ") {
			continue
		}
		var decision DegradedDecision
		var allowed, replayed bool
		if _, err := fmt.Sscanf(strings.TrimPrefix(line, "DECISION "), "%t %t %d", &allowed, &replayed, &decision.Remaining); err != nil {
			return DegradedDecision{}, fmt.Errorf("parse separate admission process result: %w", err)
		}
		decision.Allowed = allowed
		decision.Replayed = replayed
		return decision, nil
	}
	return DegradedDecision{}, fmt.Errorf("separate admission process returned no decision: %s", strconv.Quote(strings.TrimSpace(string(output))))
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
	// Keep this expiry check on a tenant whose policy was not changed above;
	// otherwise the stale-policy rejection can mask the expired-window result
	// when that tenant happened to win the concurrent admission race.
	next := inputs[0]
	for _, candidate := range inputs {
		if candidate.tenant != first.tenant {
			next = candidate
			break
		}
	}
	next.request = uuid.NewString()
	if _, err := restartedLimiter.Allow(ctx, DegradedRequest{TenantID: string(next.tenant), RouteID: route, RequestID: next.request, PolicyDigest: next.digest}); err != ErrDegradedWindowExpired {
		t.Fatalf("expired degraded window silently renewed while Redis remained unavailable: %v", err)
	}
}

func TestPostgresDegradedReceiptReplaysAfterWindowExpiryWithoutSpendingAgain(t *testing.T) {
	appDB, admin, rateControl := openDegradedTestDatabases(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	region := "test-" + uuid.NewString()[:8]
	tenant, err := tenancy.ParseTenantID(uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	route := "safe.read"
	fleet := FleetPolicy{Region: region, Capacity: 1, RefillPerSec: 1, Enabled: true}
	fleet.Digest = FleetPolicyDigest(fleet)
	policy := TenantPolicy{TenantID: string(tenant), Region: region, RouteID: route, Capacity: 1, RefillPerSec: 1, Enabled: true}
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
	request := DegradedRequest{TenantID: string(tenant), RouteID: route, RequestID: requestID, PolicyDigest: policy.Digest}
	first, err := limiter.Allow(ctx, request)
	if err != nil || !first.Allowed || first.Replayed || first.Remaining != 0 || first.OutageID == "" {
		t.Fatalf("initial request did not consume the single token: %+v err=%v", first, err)
	}
	if _, err := admin.ExecContext(ctx, `UPDATE keel_meta.rate_limit_degraded_windows
		SET started_at=clock_timestamp()-interval '61 seconds',expires_at=clock_timestamp()-interval '2 seconds'
		WHERE home_region=$1`, region); err != nil {
		t.Fatal(err)
	}

	// A recorded admission is idempotent for its receipt lifetime, even after
	// the outage admission window expires. Replaying returns the original result
	// without granting a second token or extending the window.
	replay, err := limiter.Allow(ctx, request)
	if err != nil || !replay.Allowed || !replay.Replayed || replay.Remaining != first.Remaining || replay.OutageID != first.OutageID {
		t.Fatalf("exact receipt changed after window expiry: first=%+v replay=%+v err=%v", first, replay, err)
	}
	newRequest := request
	newRequest.RequestID = uuid.NewString()
	if decision, err := limiter.Allow(ctx, newRequest); err != ErrDegradedWindowExpired || decision.Allowed {
		t.Fatalf("new request was admitted after the window expired: decision=%+v err=%v", decision, err)
	}
	var receipts int
	if err := admin.QueryRowContext(ctx, `SELECT count(*) FROM keel_meta.rate_limit_degraded_receipts WHERE home_region=$1`, region).Scan(&receipts); err != nil {
		t.Fatal(err)
	}
	if receipts != 1 {
		t.Fatalf("replay or expired-window denial wrote a second receipt: count=%d want=1", receipts)
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

func TestPostgresDegradedRecoveryProbeFlapRestartsHealthInterval(t *testing.T) {
	_, admin, rateControl := openDegradedTestDatabases(t)
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	region := "test-" + uuid.NewString()[:8]
	if _, err := admin.ExecContext(ctx, `INSERT INTO keel_meta.rate_limit_degraded_windows(home_region,outage_id,started_at,expires_at,active)
		VALUES($1,gen_random_uuid(),clock_timestamp(),clock_timestamp()+interval '30 seconds',true)`, region); err != nil {
		t.Fatal(err)
	}
	client := &scriptedPingClient{failAt: 3}
	primary, err := New(client, Config{Region: region, HomeRegion: region, KeyID: "flap-test",
		Secret: []byte("safe-read-flapping-test-secret-material-01"), ReplayTTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if err := ObserveRedisRecovery(ctx, primary, rateControl); err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(started)
	client.mu.Lock()
	calls := client.calls
	client.mu.Unlock()
	if calls < 8 || elapsed < 7*time.Second {
		t.Fatalf("a failed probe did not restart the five-second health interval: calls=%d elapsed=%s", calls, elapsed)
	}
	var active bool
	if err := admin.QueryRowContext(ctx, `SELECT active FROM keel_meta.rate_limit_degraded_windows WHERE home_region=$1`, region).Scan(&active); err != nil {
		t.Fatal(err)
	}
	if active {
		t.Fatal("verified recovery did not close the degraded window after consecutive healthy probes")
	}
}

func TestPostgresDegradedWindowStatusIsRateControlOnlyAndReflectsRecovery(t *testing.T) {
	appDB, admin, rateControl := openDegradedTestDatabases(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	region := "test-" + uuid.NewString()[:8]
	t.Cleanup(func() {
		_, _ = admin.ExecContext(context.Background(), `DELETE FROM keel_meta.rate_limit_degraded_windows WHERE home_region=$1`, region)
	})
	metrics := NewDegradedMetrics()

	if err := ObserveDegradedWindowStatus(ctx, rateControl, region, metrics); err != nil {
		t.Fatalf("read absent region window: %v", err)
	}
	if got := metrics.PrometheusMetrics(); !strings.Contains(got, "keel_rate_limit_degraded_window_status_observed 1") ||
		!strings.Contains(got, "keel_rate_limit_degraded_window_present 0") {
		t.Fatalf("absent window status was not represented explicitly: %s", got)
	}
	if err := ObserveDegradedWindowStatus(ctx, appDB, region, NewDegradedMetrics()); err == nil {
		t.Fatal("ordinary application role read the rate-control-only window status function")
	}
	if _, err := appDB.ExecContext(ctx, `SELECT count(*) FROM keel_meta.rate_limit_degraded_windows`); err == nil {
		t.Fatal("ordinary application role read the degraded-window table directly")
	}

	if _, err := admin.ExecContext(ctx, `INSERT INTO keel_meta.rate_limit_degraded_windows(home_region,outage_id,started_at,expires_at,active)
		VALUES($1,gen_random_uuid(),clock_timestamp(),clock_timestamp()+interval '60 seconds',true)`, region); err != nil {
		t.Fatal(err)
	}
	if err := ObserveDegradedWindowStatus(ctx, rateControl, region, metrics); err != nil {
		t.Fatalf("read active region window: %v", err)
	}
	activeMetrics := metrics.PrometheusMetrics()
	if !strings.Contains(activeMetrics, "keel_rate_limit_degraded_window_present 1") ||
		!strings.Contains(activeMetrics, "keel_rate_limit_degraded_window_active 1") ||
		!strings.Contains(activeMetrics, "keel_rate_limit_degraded_admission_window_open 1") ||
		strings.Contains(activeMetrics, "{region=") || strings.Contains(activeMetrics, region) {
		t.Fatalf("active window status is missing or leaks regional identity: %s", activeMetrics)
	}

	if _, err := admin.ExecContext(ctx, `UPDATE keel_meta.rate_limit_degraded_windows
		SET started_at=clock_timestamp()-interval '60 seconds', expires_at=clock_timestamp()-interval '1 second'
		WHERE home_region=$1`, region); err != nil {
		t.Fatal(err)
	}
	if err := ObserveDegradedWindowStatus(ctx, rateControl, region, metrics); err != nil {
		t.Fatalf("read expired region window: %v", err)
	}
	expiredMetrics := metrics.PrometheusMetrics()
	if !strings.Contains(expiredMetrics, "keel_rate_limit_degraded_window_active 1") ||
		!strings.Contains(expiredMetrics, "keel_rate_limit_degraded_admission_window_open 0") ||
		!strings.Contains(expiredMetrics, "keel_rate_limit_degraded_window_seconds_until_expiry 0.000000") {
		t.Fatalf("expired window did not remain fenced: %s", expiredMetrics)
	}

	if _, err := admin.ExecContext(ctx, `UPDATE keel_meta.rate_limit_degraded_windows
		SET active=false,recovered_at=clock_timestamp() WHERE home_region=$1`, region); err != nil {
		t.Fatal(err)
	}
	if err := ObserveDegradedWindowStatus(ctx, rateControl, region, metrics); err != nil {
		t.Fatalf("read recovered region window: %v", err)
	}
	recoveredMetrics := metrics.PrometheusMetrics()
	if !strings.Contains(recoveredMetrics, "keel_rate_limit_degraded_window_active 0") ||
		!strings.Contains(recoveredMetrics, "keel_rate_limit_degraded_admission_window_open 0") ||
		!strings.Contains(recoveredMetrics, "keel_rate_limit_degraded_window_last_recovered_timestamp_seconds 1") {
		t.Fatalf("recovered window state or timestamp is missing: %s", recoveredMetrics)
	}
}

func TestPostgresDegradedAppPoolExhaustionFailsBeforeAdmission(t *testing.T) {
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
	appDB.SetMaxOpenConns(1)
	heldTx, err := appDB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer heldTx.Rollback()
	limiter, err := NewDegradedLimiter(appDB, DegradedConfig{Region: region, HomeRegion: region, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	shortCtx, stop := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer stop()
	_, err = limiter.Allow(shortCtx, DegradedRequest{TenantID: string(tenant), RouteID: route, RequestID: uuid.NewString(), PolicyDigest: policy.Digest})
	if !errors.Is(err, ErrDegradedUnavailable) {
		t.Fatalf("connection-pool exhaustion did not fail closed: %v", err)
	}
	var windows int
	if err := admin.QueryRowContext(ctx, `SELECT count(*) FROM keel_meta.rate_limit_degraded_windows WHERE home_region=$1`, region).Scan(&windows); err != nil {
		t.Fatal(err)
	}
	if windows != 0 {
		t.Fatalf("pool exhaustion opened an outage window without an admission attempt reaching SQL: %d", windows)
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
	modelPolicy := TenantPolicy{TenantID: string(tenant), Region: region, RouteID: "model.generate",
		Capacity: 1, RefillPerSec: 1, Enabled: true}
	modelPolicy.Digest = TenantPolicyDigest(modelPolicy)
	if err := control.SetTenantPolicy(ctx, modelPolicy); err != nil {
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
	request.Policy.Digest = modelPolicy.Digest
	request.RequestID = uuid.NewString()
	if _, err := coordinator.Allow(ctx, request); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("model route did not fail closed when Redis was unavailable: %v", err)
	}
}

func TestPostgresFallbackBoundsAfterExecutedRedisAdmissionReplyIsLost(t *testing.T) {
	appDB, _, rateControl := openDegradedTestDatabases(t)
	redisURL := os.Getenv("KEEL_TEST_REDIS_URL")
	if redisURL == "" {
		t.Skip("set KEEL_TEST_REDIS_URL to qualify ambiguous home-region Redis responses")
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
	tenant, _ := tenancy.ParseTenantID(uuid.NewString())
	route := "safe.read"
	fleet := FleetPolicy{Region: region, Capacity: 1, RefillPerSec: 1, Enabled: true}
	fleet.Digest = FleetPolicyDigest(fleet)
	policy := TenantPolicy{TenantID: string(tenant), Region: region, RouteID: route,
		Capacity: 1, RefillPerSec: 1, Enabled: true}
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

	redisLimiter, err := New(redisClient, Config{Region: region, HomeRegion: region, KeyID: "lost-reply-test",
		Secret: []byte("lost-redis-reply-test-secret-material-012345"), ReplayTTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	degraded, err := NewDegradedLimiter(appDB, DegradedConfig{Region: region, HomeRegion: region, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	fallback := &responseLosingFallback{fallback: degraded, loseNext: true}
	coordinator, err := NewCoordinator(appliedThenLostRedisResponse{primary: redisLimiter}, fallback)
	if err != nil {
		t.Fatal(err)
	}
	request := Request{TenantID: string(tenant), RouteID: route, RequestID: uuid.NewString(),
		Policy: Policy{Digest: policy.Digest, CapacityUnits: policy.Capacity,
			RefillUnitsPerSecond: policy.RefillPerSec, CostUnits: 1}}
	if _, err := coordinator.Allow(ctx, request); !errors.Is(err, ErrDegradedUnavailable) {
		t.Fatalf("lost PostgreSQL response was not surfaced after Redis execution: %v", err)
	}

	// The Redis call really consumed its only token even though the coordinator
	// observed an availability error and then lost the fallback response.
	redisSecond, err := redisLimiter.Allow(ctx, Request{TenantID: string(tenant), RouteID: route,
		RequestID: uuid.NewString(), Policy: request.Policy})
	if err != nil || redisSecond.Allowed {
		t.Fatalf("lost Redis reply did not leave the original bucket charged: %+v err=%v", redisSecond, err)
	}

	// Model the continuing Redis outage with a newly constructed coordinator.
	// PostgreSQL must return the exact receipt without charging its cap again.
	restartedLimiter, err := NewDegradedLimiter(appDB, DegradedConfig{Region: region, HomeRegion: region, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	restartedCoordinator, err := NewCoordinator(stubPrimaryAdmission{err: ErrUnavailable}, restartedLimiter)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := restartedCoordinator.Allow(ctx, request)
	if err != nil || !replay.Allowed || !replay.Replayed || replay.Remaining != 0 {
		t.Fatalf("fallback receipt was not replayed exactly after both responses were lost: %+v err=%v", replay, err)
	}
	postgresSecond, err := restartedCoordinator.Allow(ctx, Request{TenantID: string(tenant), RouteID: route,
		RequestID: uuid.NewString(), Policy: request.Policy})
	if err != nil || postgresSecond.Allowed {
		t.Fatalf("ambiguous Redis and PostgreSQL responses exceeded the independent fallback cap: %+v err=%v", postgresSecond, err)
	}
}

func TestCoordinatorFailsClosedWhenAmbiguousRedisAdmissionCannotReachPostgres(t *testing.T) {
	_, _, rateControl := openDegradedTestDatabases(t)
	redisURL := os.Getenv("KEEL_TEST_REDIS_URL")
	if redisURL == "" {
		t.Skip("set KEEL_TEST_REDIS_URL to qualify ambiguous home-region Redis responses")
	}
	options, err := redis.ParseURL(redisURL)
	if err != nil {
		t.Fatal(err)
	}
	options.MaxRetries = -1
	redisClient := redis.NewClient(options)
	t.Cleanup(func() { _ = redisClient.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	region := "test-" + uuid.NewString()[:8]
	tenant, err := tenancy.ParseTenantID(uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	policy := TenantPolicy{TenantID: string(tenant), Region: region, RouteID: "safe.read",
		Capacity: 1, RefillPerSec: 1, Enabled: true}
	policy.Digest = TenantPolicyDigest(policy)
	control, err := NewPolicyRepository(rateControl, allowRatePolicyChanges{})
	if err != nil {
		t.Fatal(err)
	}
	if err := control.SetTenantPolicy(ctx, policy); err != nil {
		t.Fatal(err)
	}
	primary, err := New(redisClient, Config{Region: region, HomeRegion: region, KeyID: "pg-unavailable-test",
		Secret: []byte("postgres-unavailable-test-secret-material-0123"), ReplayTTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	failedDB, err := sql.Open("pgx", "postgres://keel_local_app:local-only@127.0.0.1:1/postgres?sslmode=disable&connect_timeout=1")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = failedDB.Close() })
	fallback, err := NewDegradedLimiter(failedDB,
		DegradedConfig{Region: region, HomeRegion: region, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := NewCoordinator(appliedThenLostRedisResponse{primary: primary}, fallback)
	if err != nil {
		t.Fatal(err)
	}
	request := Request{TenantID: string(tenant), RouteID: policy.RouteID, RequestID: uuid.NewString(),
		Policy: Policy{Digest: policy.Digest, CapacityUnits: policy.Capacity,
			RefillUnitsPerSecond: policy.RefillPerSec, CostUnits: 1}}
	if decision, err := coordinator.Allow(ctx, request); !errors.Is(err, ErrDegradedUnavailable) || decision.Allowed {
		t.Fatalf("ambiguous Redis success with unavailable PostgreSQL did not fail closed: decision=%+v err=%v", decision, err)
	}

	// The Redis script committed before the response was hidden. An independent
	// request must therefore observe the spent Redis token despite fallback DB
	// failure; the outage cannot multiply the primary allowance.
	second, err := primary.Allow(ctx, Request{TenantID: string(tenant), RouteID: policy.RouteID,
		RequestID: uuid.NewString(), Policy: request.Policy})
	if err != nil || second.Allowed {
		t.Fatalf("PostgreSQL outage multiplied an ambiguous Redis admission: decision=%+v err=%v", second, err)
	}
}

func TestCoordinatorBoundsFallbackAfterAmbiguousRedisSuccess(t *testing.T) {
	appDB, _, rateControl := openDegradedTestDatabases(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	region := "test-" + uuid.NewString()[:8]
	tenant, _ := tenancy.ParseTenantID(uuid.NewString())
	route := "safe.read"
	policy := TenantPolicy{TenantID: string(tenant), Region: region, RouteID: route, Capacity: 1, RefillPerSec: 1, Enabled: true}
	policy.Digest = TenantPolicyDigest(policy)
	fleet := FleetPolicy{Region: region, Capacity: 1, RefillPerSec: 1, Enabled: true}
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
	degraded, err := NewDegradedLimiter(appDB, DegradedConfig{Region: region, HomeRegion: region, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	// Model a Redis script that may have consumed an allowance before its
	// response was lost. The fallback must apply its independent shared cap.
	primary := stubPrimaryAdmission{decision: Decision{Allowed: true}, err: ErrUnavailable}
	coordinator, err := NewCoordinator(primary, degraded)
	if err != nil {
		t.Fatal(err)
	}
	request := Request{TenantID: string(tenant), RouteID: route, RequestID: uuid.NewString(),
		Policy: Policy{Digest: policy.Digest, CapacityUnits: policy.Capacity, RefillUnitsPerSecond: policy.RefillPerSec, CostUnits: 1}}
	first, err := coordinator.Allow(ctx, request)
	if err != nil || !first.Allowed || first.Replayed {
		t.Fatalf("first ambiguous Redis response was not bounded by fallback policy: %+v err=%v", first, err)
	}
	replay, err := coordinator.Allow(ctx, request)
	if err != nil || !replay.Allowed || !replay.Replayed || replay.Remaining != first.Remaining {
		t.Fatalf("same logical request did not replay its durable fallback receipt: first=%+v replay=%+v err=%v", first, replay, err)
	}
	request.RequestID = uuid.NewString()
	second, err := coordinator.Allow(ctx, request)
	if err != nil || second.Allowed {
		t.Fatalf("a second ambiguous response exceeded the shared fallback burst: %+v err=%v", second, err)
	}
}

func TestCoordinatorReplaysAdmissionAfterLostPostgresResponse(t *testing.T) {
	appDB, _, rateControl := openDegradedTestDatabases(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	region := "test-" + uuid.NewString()[:8]
	tenant, _ := tenancy.ParseTenantID(uuid.NewString())
	route := "safe.read"
	policy := TenantPolicy{TenantID: string(tenant), Region: region, RouteID: route, Capacity: 1, RefillPerSec: 1, Enabled: true}
	policy.Digest = TenantPolicyDigest(policy)
	fleet := FleetPolicy{Region: region, Capacity: 1, RefillPerSec: 1, Enabled: true}
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
	limiter, err := NewDegradedLimiter(appDB, DegradedConfig{Region: region, HomeRegion: region, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	fallback := &responseLosingFallback{fallback: limiter, loseNext: true}
	coordinator, err := NewCoordinator(stubPrimaryAdmission{err: ErrUnavailable}, fallback)
	if err != nil {
		t.Fatal(err)
	}
	request := Request{TenantID: string(tenant), RouteID: route, RequestID: uuid.NewString(),
		Policy: Policy{Digest: policy.Digest, CapacityUnits: policy.Capacity, RefillUnitsPerSecond: policy.RefillPerSec, CostUnits: 1}}
	if _, err := coordinator.Allow(ctx, request); !errors.Is(err, ErrDegradedUnavailable) {
		t.Fatalf("simulated lost PostgreSQL response unexpectedly returned success: %v", err)
	}

	// A new limiter models a restarted process. The database receipt must be
	// sufficient to return the exact admitted decision without another token.
	restartedLimiter, err := NewDegradedLimiter(appDB, DegradedConfig{Region: region, HomeRegion: region, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	restartedCoordinator, err := NewCoordinator(stubPrimaryAdmission{err: ErrUnavailable}, restartedLimiter)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := restartedCoordinator.Allow(ctx, request)
	if err != nil || !replay.Allowed || !replay.Replayed || replay.Remaining != 0 {
		t.Fatalf("new process did not recover committed admission receipt: %+v err=%v", replay, err)
	}
	request.RequestID = uuid.NewString()
	second, err := restartedCoordinator.Allow(ctx, request)
	if err != nil || second.Allowed {
		t.Fatalf("lost response caused fallback capacity to be spent more than once: %+v err=%v", second, err)
	}
}

// Run with a fixed count such as -benchtime=1024x. Adaptive Go calibration can
// issue large bursts of durable database writes while estimating this benchmark.
func BenchmarkPostgresDegradedAdmissionContention(b *testing.B) {
	appDB, adminDB, rateControl := openDegradedTestDatabases(b)
	for _, workers := range []int{1, 8, 32} {
		b.Run(fmt.Sprintf("workers-%d", workers), func(b *testing.B) {
			b.StopTimer()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			region := "bench-" + uuid.NewString()[:8]
			defer cleanupDegradedBenchmarkRegion(b, adminDB, region)

			tenant, err := tenancy.ParseTenantID(uuid.NewString())
			if err != nil {
				b.Fatal(err)
			}
			fleet := FleetPolicy{Region: region, Capacity: 1_000_000_000, RefillPerSec: 100_000_000, Enabled: true}
			fleet.Digest = FleetPolicyDigest(fleet)
			policy := TenantPolicy{TenantID: string(tenant), Region: region, RouteID: "safe.read",
				Capacity: fleet.Capacity, RefillPerSec: fleet.RefillPerSec, Enabled: true}
			policy.Digest = TenantPolicyDigest(policy)
			control, err := NewPolicyRepository(rateControl, allowRatePolicyChanges{})
			if err != nil {
				b.Fatal(err)
			}
			if err := control.SetFleetPolicy(ctx, fleet); err != nil {
				b.Fatal(err)
			}
			if err := control.SetTenantPolicy(ctx, policy); err != nil {
				b.Fatal(err)
			}
			limiter, err := NewDegradedLimiter(appDB, DegradedConfig{Region: region, HomeRegion: region, Enabled: true})
			if err != nil {
				b.Fatal(err)
			}

			var next atomic.Uint64
			var samplesMu sync.Mutex
			samples := make([]time.Duration, 0, b.N/16+1)
			var firstErr error
			var errOnce sync.Once
			var wg sync.WaitGroup
			b.ResetTimer()
			started := time.Now()
			for worker := 0; worker < workers; worker++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for {
						index := next.Add(1) - 1
						if index >= uint64(b.N) {
							return
						}
						started := time.Now()
						decision, err := limiter.Allow(ctx, DegradedRequest{TenantID: string(tenant), RouteID: policy.RouteID,
							RequestID: uuid.NewString(), PolicyDigest: policy.Digest})
						elapsed := time.Since(started)
						if err != nil {
							errOnce.Do(func() { firstErr = err })
							return
						}
						if !decision.Allowed {
							errOnce.Do(func() { firstErr = fmt.Errorf("benchmark admission unexpectedly limited") })
							return
						}
						if index%16 == 0 {
							samplesMu.Lock()
							samples = append(samples, elapsed)
							samplesMu.Unlock()
						}
					}
				}()
			}
			wg.Wait()
			elapsed := time.Since(started)
			b.StopTimer()
			if firstErr != nil {
				b.Fatal(firstErr)
			}
			if len(samples) == 0 {
				b.Fatal("benchmark collected no latency samples")
			}
			sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
			quantile := func(percent int) float64 {
				index := (len(samples) - 1) * percent / 100
				return float64(samples[index].Nanoseconds()) / 1000
			}
			b.ReportMetric(float64(workers), "workers")
			b.ReportMetric(float64(b.N)/elapsed.Seconds(), "ops/s")
			b.ReportMetric(quantile(50), "p50-us")
			b.ReportMetric(quantile(95), "p95-us")
			b.ReportMetric(quantile(99), "p99-us")
		})
	}
}

func cleanupDegradedBenchmarkRegion(t testing.TB, admin *sql.DB, region string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tx, err := admin.BeginTx(ctx, nil)
	if err != nil {
		t.Errorf("begin benchmark fixture cleanup: %v", err)
		return
	}
	defer tx.Rollback()
	for _, statement := range []string{
		`DELETE FROM keel_meta.rate_limit_degraded_receipts WHERE home_region=$1`,
		`DELETE FROM keel_meta.rate_limit_degraded_tenant_buckets WHERE home_region=$1`,
		`DELETE FROM keel_meta.rate_limit_degraded_windows WHERE home_region=$1`,
		`DELETE FROM keel_meta.rate_limit_degraded_fleet_buckets WHERE home_region=$1`,
		`DELETE FROM keel_meta.rate_limit_degraded_tenant_policies WHERE home_region=$1`,
		`DELETE FROM keel_meta.rate_limit_degraded_fleet_policies WHERE home_region=$1`,
	} {
		if _, err := tx.ExecContext(ctx, statement, region); err != nil {
			t.Errorf("clean benchmark fixture region %s: %v", region, err)
			return
		}
	}
	if err := tx.Commit(); err != nil {
		t.Errorf("commit benchmark fixture cleanup: %v", err)
	}
}

func openDegradedTestDatabases(t testing.TB) (app, admin, control *sql.DB) {
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
