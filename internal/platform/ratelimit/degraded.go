package ratelimit

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

var (
	ErrDegradedDisabled        = errors.New("safe-read degraded admission is disabled")
	ErrDegradedUnavailable     = errors.New("safe-read degraded admission is unavailable")
	ErrDegradedWindowExpired   = errors.New("safe-read degraded window expired")
	ErrDegradedPolicyRejected  = errors.New("safe-read degraded policy is absent or disabled")
	ErrDegradedRecoveryDenied  = errors.New("Redis recovery fence was not authorized")
	degradedDigestPattern      = regexp.MustCompile(`^[0-9a-f]{64}$`)
	degradedRequestUUIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
)

const (
	degradedMaxWindow     = 60 * time.Second
	degradedReceiptTTL    = 10 * time.Minute
	degradedHealthyPeriod = 5 * time.Second
	degradedHealthyProbe  = time.Second
)

type DegradedConfig struct {
	Region     string
	HomeRegion string
	Enabled    bool
}

type DegradedRequest struct {
	TenantID     string
	RouteID      string
	RequestID    string
	PolicyDigest string
}

type DegradedDecision struct {
	Allowed       bool
	Remaining     int64
	RetryAfter    time.Duration
	Replayed      bool
	OutageID      string
	WindowExpires time.Time
}

// DegradedLimiter uses PostgreSQL as a shared, durable fallback authority. It
// does not keep counters in process memory, so restarting or scaling API pods
// cannot create additional allowance. SQL policy rows are control-plane owned.
type DegradedLimiter struct {
	db      *sql.DB
	region  string
	enabled bool
	metrics *DegradedMetrics
}

// DegradedMetrics is a low-cardinality Prometheus extension. Its only label
// is a fixed outcome enum; tenant, route, request, region and outage IDs are
// intentionally excluded.
type DegradedMetrics struct {
	mu      sync.Mutex
	samples map[string]degradedMetricSample
}

type degradedMetricSample struct {
	count    uint64
	duration time.Duration
}

var degradedMetricOutcomes = []string{
	"allowed", "limited", "disabled", "policy_rejected", "window_expired",
	"idempotency_conflict", "invalid_request", "db_error",
}

func NewDegradedMetrics() *DegradedMetrics {
	samples := make(map[string]degradedMetricSample, len(degradedMetricOutcomes))
	for _, outcome := range degradedMetricOutcomes {
		samples[outcome] = degradedMetricSample{}
	}
	return &DegradedMetrics{samples: samples}
}

func (m *DegradedMetrics) record(outcome string, duration time.Duration) {
	if m == nil {
		return
	}
	m.mu.Lock()
	if _, ok := m.samples[outcome]; !ok {
		outcome = "invalid_request"
	}
	sample := m.samples[outcome]
	sample.count++
	sample.duration += duration
	m.samples[outcome] = sample
	m.mu.Unlock()
}

// PrometheusMetrics implements the health endpoint's structural
// MetricsExtension contract with a fixed set of outcome labels.
func (m *DegradedMetrics) PrometheusMetrics() string {
	if m == nil {
		return ""
	}
	m.mu.Lock()
	samples := make(map[string]degradedMetricSample, len(m.samples))
	for outcome, sample := range m.samples {
		samples[outcome] = sample
	}
	m.mu.Unlock()
	outcomes := make([]string, 0, len(samples))
	for outcome := range samples {
		outcomes = append(outcomes, outcome)
	}
	sort.Strings(outcomes)
	var b strings.Builder
	b.WriteString("# HELP keel_rate_limit_degraded_admissions_total PostgreSQL safe-read fallback outcomes.\n")
	b.WriteString("# TYPE keel_rate_limit_degraded_admissions_total counter\n")
	b.WriteString("# HELP keel_rate_limit_degraded_admission_duration_seconds_sum Cumulative fallback admission duration.\n")
	b.WriteString("# TYPE keel_rate_limit_degraded_admission_duration_seconds_sum counter\n")
	b.WriteString("# HELP keel_rate_limit_degraded_admission_duration_seconds_count Fallback admission observations.\n")
	b.WriteString("# TYPE keel_rate_limit_degraded_admission_duration_seconds_count counter\n")
	for _, outcome := range outcomes {
		sample := samples[outcome]
		fmt.Fprintf(&b, "keel_rate_limit_degraded_admissions_total{result=%q} %d\n", outcome, sample.count)
		fmt.Fprintf(&b, "keel_rate_limit_degraded_admission_duration_seconds_sum{result=%q} %.6f\n", outcome, sample.duration.Seconds())
		fmt.Fprintf(&b, "keel_rate_limit_degraded_admission_duration_seconds_count{result=%q} %d\n", outcome, sample.count)
	}
	return b.String()
}

type PrimaryAdmission interface {
	Allow(context.Context, Request) (Decision, error)
}

type SafeReadFallback interface {
	Allow(context.Context, DegradedRequest) (DegradedDecision, error)
}

// Coordinator tries Redis first. It offers a durable fallback only after an
// availability failure; the database's control-plane policy table is the
// authoritative safe-read allowlist, so callers cannot classify model/write
// work as safe by setting a request flag.
type Coordinator struct {
	primary  PrimaryAdmission
	fallback SafeReadFallback
}

func NewCoordinator(primary PrimaryAdmission, fallback SafeReadFallback) (*Coordinator, error) {
	if primary == nil || fallback == nil {
		return nil, ErrInvalidConfig
	}
	return &Coordinator{primary: primary, fallback: fallback}, nil
}

func (c *Coordinator) Allow(ctx context.Context, request Request) (Decision, error) {
	if c == nil || c.primary == nil || c.fallback == nil || ctx == nil {
		return Decision{}, ErrInvalidConfig
	}
	decision, err := c.primary.Allow(ctx, request)
	if err == nil || !errors.Is(err, ErrUnavailable) || ctx == nil || ctx.Err() != nil {
		return decision, err
	}
	// Degraded SQL admission currently has a fixed one-unit request cost. Do not
	// silently change a caller's more expensive Redis policy into a one-unit
	// fallback admission.
	if request.Policy.CostUnits != 1 {
		return Decision{}, fmt.Errorf("%w: degraded route cost is not one unit", ErrUnavailable)
	}
	fallback, fallbackErr := c.fallback.Allow(ctx, DegradedRequest{TenantID: request.TenantID,
		RouteID: request.RouteID, RequestID: request.RequestID, PolicyDigest: request.Policy.Digest})
	if fallbackErr != nil {
		if errors.Is(fallbackErr, ErrDegradedPolicyRejected) || errors.Is(fallbackErr, ErrDegradedDisabled) {
			return Decision{}, fmt.Errorf("%w: no approved safe-read degradation policy", ErrUnavailable)
		}
		return Decision{}, fallbackErr
	}
	return Decision{Allowed: fallback.Allowed, Remaining: fallback.Remaining,
		RetryAfter: fallback.RetryAfter, Replayed: fallback.Replayed}, nil
}

func NewDegradedLimiter(db *sql.DB, cfg DegradedConfig) (*DegradedLimiter, error) {
	return NewDegradedLimiterWithMetrics(db, cfg, NewDegradedMetrics())
}

// NewDegradedLimiterWithMetrics creates a limiter whose metrics can also be
// attached to health.NewHandlerWithMetrics / RunWithMetrics.
func NewDegradedLimiterWithMetrics(db *sql.DB, cfg DegradedConfig, metrics *DegradedMetrics) (*DegradedLimiter, error) {
	if db == nil || !validIdentifier(cfg.Region, maxRegionLength) || cfg.Region != cfg.HomeRegion {
		return nil, ErrInvalidConfig
	}
	if metrics == nil {
		metrics = NewDegradedMetrics()
	}
	return &DegradedLimiter{db: db, region: cfg.Region, enabled: cfg.Enabled, metrics: metrics}, nil
}

func (l *DegradedLimiter) Metrics() *DegradedMetrics {
	if l == nil {
		return nil
	}
	return l.metrics
}

func (l *DegradedLimiter) Allow(ctx context.Context, request DegradedRequest) (DegradedDecision, error) {
	started := time.Now()
	outcome := "db_error"
	var metrics *DegradedMetrics
	if l != nil {
		metrics = l.metrics
	}
	defer func() { metrics.record(outcome, time.Since(started)) }()
	if l == nil || l.db == nil {
		return DegradedDecision{}, ErrDegradedUnavailable
	}
	if !l.enabled {
		outcome = "disabled"
		return DegradedDecision{}, ErrDegradedDisabled
	}
	tenant, err := tenancy.ParseTenantID(request.TenantID)
	if err != nil || !degradedRequestUUIDPattern.MatchString(request.RequestID) ||
		!validIdentifier(request.RouteID, maxRouteLength) || !degradedDigestPattern.MatchString(request.PolicyDigest) {
		outcome = "invalid_request"
		return DegradedDecision{}, ErrInvalidConfig
	}
	digest, _ := hex.DecodeString(request.PolicyDigest)
	var result DegradedDecision
	var code int
	var retryMS int64
	var outageID sql.NullString
	var expires sql.NullTime
	err = tenancy.WithTenantTx(ctx, l.db, tenant, nil, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT decision_code,allowed,remaining_units,retry_after_ms,replayed,outage_id::text,window_expires_at
			FROM keel_meta.admit_safe_read_degraded($1,$2,$3,$4,$5)`, request.TenantID, l.region, request.RouteID, request.RequestID, digest).
			Scan(&code, &result.Allowed, &result.Remaining, &retryMS, &result.Replayed, &outageID, &expires)
	})
	if err != nil {
		return DegradedDecision{}, fmt.Errorf("%w: %v", ErrDegradedUnavailable, err)
	}
	result.RetryAfter = time.Duration(retryMS) * time.Millisecond
	if outageID.Valid {
		result.OutageID = outageID.String
	}
	if expires.Valid {
		result.WindowExpires = expires.Time
	}
	switch code {
	case -1:
		outcome = "idempotency_conflict"
		return DegradedDecision{}, ErrIdempotencyConflict
	case 0, 1:
		if result.Allowed {
			outcome = "allowed"
		} else {
			outcome = "limited"
		}
		return result, nil
	case 2:
		outcome = "policy_rejected"
		return DegradedDecision{}, ErrDegradedPolicyRejected
	case 3:
		outcome = "window_expired"
		return result, ErrDegradedWindowExpired
	default:
		return DegradedDecision{}, ErrDegradedUnavailable
	}
}

// ObserveRedisRecovery closes an expired-or-active degraded window only after
// five consecutive seconds of successful PINGs through the configured primary
// home-region limiter. Taking the Limiter avoids separately choosing a Redis
// client and recovery region at the call site. The caller supplies the
// separately credentialed rate-control DB connection; app credentials cannot
// reset the outage fence.
func ObserveRedisRecovery(ctx context.Context, primary *Limiter, rateControlDB *sql.DB) error {
	if ctx == nil || primary == nil || primary.client == nil || rateControlDB == nil ||
		!validIdentifier(primary.region, maxRegionLength) {
		return ErrDegradedRecoveryDenied
	}
	region := primary.region
	start := time.Now()
	ticker := time.NewTicker(degradedHealthyProbe)
	defer ticker.Stop()
	for {
		if err := primary.client.Ping(ctx).Err(); err != nil {
			start = time.Now()
		} else if time.Since(start) >= degradedHealthyPeriod {
			if _, err := rateControlDB.ExecContext(ctx, `SELECT keel_meta.mark_rate_limit_redis_healthy($1,$2::interval)`, region, degradedHealthyPeriod.String()); err != nil {
				return fmt.Errorf("%w: %v", ErrDegradedRecoveryDenied, err)
			}
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

type FleetPolicy struct {
	Region       string
	Digest       string
	Capacity     int64
	RefillPerSec int64
	Enabled      bool
}

type TenantPolicy struct {
	TenantID     string
	Region       string
	RouteID      string
	Digest       string
	Capacity     int64
	RefillPerSec int64
	Enabled      bool
}

type PolicyAuthorizer interface {
	AuthorizeFleetPolicy(context.Context, FleetPolicy) error
	AuthorizeTenantPolicy(context.Context, TenantPolicy) error
}

type PolicyRepository struct {
	db         *sql.DB
	authorizer PolicyAuthorizer
}

func NewPolicyRepository(db *sql.DB, authorizer PolicyAuthorizer) (*PolicyRepository, error) {
	if db == nil || authorizer == nil {
		return nil, ErrInvalidConfig
	}
	return &PolicyRepository{db: db, authorizer: authorizer}, nil
}

// SetFleetPolicy requires a rate-control identity and explicit authorization.
// Fleet capacity is shared by all tenants and all replicas in the region.
func (r *PolicyRepository) SetFleetPolicy(ctx context.Context, policy FleetPolicy) error {
	if !validIdentifier(policy.Region, maxRegionLength) || !degradedDigestPattern.MatchString(policy.Digest) ||
		policy.Capacity <= 0 || policy.Capacity > maxCapacityUnits || policy.RefillPerSec <= 0 || policy.RefillPerSec > maxRefillUnitsPS {
		return ErrInvalidConfig
	}
	if policy.Digest != FleetPolicyDigest(policy) {
		return ErrInvalidConfig
	}
	if err := r.authorizer.AuthorizeFleetPolicy(ctx, policy); err != nil {
		return fmt.Errorf("%w: %v", ErrDegradedRecoveryDenied, err)
	}
	digest, _ := hex.DecodeString(policy.Digest)
	_, err := r.db.ExecContext(ctx, `INSERT INTO keel_meta.rate_limit_degraded_fleet_policies
		(home_region,policy_sha256,capacity_units,refill_units_per_second,enabled)
		VALUES($1,$2,$3,$4,$5) ON CONFLICT(home_region) DO UPDATE SET policy_sha256=EXCLUDED.policy_sha256,
		capacity_units=EXCLUDED.capacity_units,refill_units_per_second=EXCLUDED.refill_units_per_second,
		enabled=EXCLUDED.enabled,updated_at=clock_timestamp()`, policy.Region, digest, policy.Capacity, policy.RefillPerSec, policy.Enabled)
	if err != nil {
		return fmt.Errorf("configure degraded fleet policy: %w", err)
	}
	return nil
}

// SetTenantPolicy changes a tenant route's separate degraded cap. The database
// control role applies RLS using the transaction-scoped tenant identity.
func (r *PolicyRepository) SetTenantPolicy(ctx context.Context, policy TenantPolicy) error {
	tenant, err := tenancy.ParseTenantID(policy.TenantID)
	if err != nil || !validIdentifier(policy.Region, maxRegionLength) || !validIdentifier(policy.RouteID, maxRouteLength) ||
		!degradedDigestPattern.MatchString(policy.Digest) || policy.Capacity <= 0 || policy.Capacity > maxCapacityUnits ||
		policy.RefillPerSec <= 0 || policy.RefillPerSec > maxRefillUnitsPS {
		return ErrInvalidConfig
	}
	if policy.Digest != TenantPolicyDigest(policy) {
		return ErrInvalidConfig
	}
	if err := r.authorizer.AuthorizeTenantPolicy(ctx, policy); err != nil {
		return fmt.Errorf("%w: %v", ErrDegradedRecoveryDenied, err)
	}
	digest, _ := hex.DecodeString(policy.Digest)
	return tenancy.WithTenantTx(ctx, r.db, tenant, nil, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO keel_meta.rate_limit_degraded_tenant_policies
			(tenant_id,home_region,route_id,policy_sha256,capacity_units,refill_units_per_second,enabled)
			VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(tenant_id,home_region,route_id) DO UPDATE SET
			policy_sha256=EXCLUDED.policy_sha256,capacity_units=EXCLUDED.capacity_units,
			refill_units_per_second=EXCLUDED.refill_units_per_second,enabled=EXCLUDED.enabled,updated_at=clock_timestamp()`,
			policy.TenantID, policy.Region, policy.RouteID, digest, policy.Capacity, policy.RefillPerSec, policy.Enabled)
		return err
	})
}

func FleetPolicyDigest(policy FleetPolicy) string {
	b, _ := json.Marshal(struct {
		Region           string
		Capacity, Refill int64
		Enabled          bool
	}{policy.Region, policy.Capacity, policy.RefillPerSec, policy.Enabled})
	digest := sha256.Sum256(b)
	return hex.EncodeToString(digest[:])
}

func TenantPolicyDigest(policy TenantPolicy) string {
	b, _ := json.Marshal(struct {
		Tenant, Region, Route string
		Capacity, Refill      int64
		Enabled               bool
	}{policy.TenantID, policy.Region, policy.RouteID, policy.Capacity, policy.RefillPerSec, policy.Enabled})
	digest := sha256.Sum256(b)
	return hex.EncodeToString(digest[:])
}
