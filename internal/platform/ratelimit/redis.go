// Package ratelimit implements home-region Redis token-bucket admission.
// Redis errors are returned to callers; budgeted and sensitive routes must
// fail closed rather than inventing local capacity.
package ratelimit

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

var (
	ErrInvalidConfig       = errors.New("Redis rate limiter configuration is invalid")
	ErrUnavailable         = errors.New("Redis rate limiter is unavailable")
	ErrRedisFailure        = errors.New("Redis rate limiter returned a permanent command or protocol failure")
	ErrIdempotencyConflict = errors.New("rate limit request ID was reused with different policy or cost")
	idPattern              = regexp.MustCompile(`^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$`)
	uuidPattern            = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	digestPattern          = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

const (
	maxCapacityUnits = int64(1_000_000_000_000)
	maxRefillUnitsPS = int64(100_000_000)
	maxBucketTTL     = 30 * 24 * time.Hour
	maxReplayTTL     = 10 * time.Minute
	maxRegionLength  = 64
	maxKeyIDLength   = 64
	maxRouteLength   = 128
)

// ClientConfig makes remote TLS mandatory. Plaintext is available only for
// explicitly synthetic loopback Redis in local tests/development.
type ClientConfig struct {
	Addr                   string
	Username               string
	Password               string
	Region                 string
	HomeRegion             string
	TLSConfig              *tls.Config
	AllowSyntheticLoopback bool
	DialTimeout            time.Duration
	ReadTimeout            time.Duration
	WriteTimeout           time.Duration
	PoolSize               int
	// CredentialsProvider supplies dynamic remote credentials, including IAM-signed MemoryDB tokens.
	CredentialsProvider func(context.Context) (username string, password string, err error)
}

func NewRedisClient(cfg ClientConfig) (*redis.Client, error) {
	if err := validateRedisClientConfig(cfg); err != nil {
		return nil, ErrInvalidConfig
	}
	options := &redis.Options{Addr: cfg.Addr, Username: cfg.Username, Password: cfg.Password,
		DialTimeout: cfg.DialTimeout, ReadTimeout: cfg.ReadTimeout, WriteTimeout: cfg.WriteTimeout,
		PoolSize: cfg.PoolSize, MaxRetries: -1, CredentialsProviderContext: cfg.CredentialsProvider}
	tlsConfig, err := validatedRedisTLSConfig(cfg.TLSConfig)
	if err != nil {
		return nil, ErrInvalidConfig
	}
	options.TLSConfig = tlsConfig
	if cfg.CredentialsProvider != nil {
		// MemoryDB closes IAM-authenticated connections after 12 hours. Recycle
		// pooled connections earlier so new connections receive fresh tokens.
		options.ConnMaxLifetime = 10 * time.Hour
	}
	return redis.NewClient(options), nil
}

// NewRedisClusterClient creates the cluster-aware client required by managed
// Redis-compatible endpoints that expose Redis Cluster topology discovery.
func NewRedisClusterClient(cfg ClientConfig) (*redis.ClusterClient, error) {
	if err := validateRedisClientConfig(cfg); err != nil {
		return nil, ErrInvalidConfig
	}
	options := &redis.ClusterOptions{Addrs: []string{cfg.Addr}, Username: cfg.Username, Password: cfg.Password,
		DialTimeout: cfg.DialTimeout, ReadTimeout: cfg.ReadTimeout, WriteTimeout: cfg.WriteTimeout,
		PoolSize: cfg.PoolSize, MaxRetries: -1, CredentialsProviderContext: cfg.CredentialsProvider}
	tlsConfig, err := validatedRedisTLSConfig(cfg.TLSConfig)
	if err != nil {
		return nil, ErrInvalidConfig
	}
	options.TLSConfig = tlsConfig
	if cfg.CredentialsProvider != nil {
		// Keep pooled IAM-authenticated connections below MemoryDB's 12-hour limit.
		options.ConnMaxLifetime = 10 * time.Hour
	}
	return redis.NewClusterClient(options), nil
}

func validateRedisClientConfig(cfg ClientConfig) error {
	host, _, err := net.SplitHostPort(cfg.Addr)
	if err != nil || !validIdentifier(cfg.Region, maxRegionLength) || cfg.Region != cfg.HomeRegion ||
		cfg.DialTimeout < 50*time.Millisecond || cfg.DialTimeout > 5*time.Second ||
		cfg.ReadTimeout < 50*time.Millisecond || cfg.ReadTimeout > 5*time.Second ||
		cfg.WriteTimeout < 50*time.Millisecond || cfg.WriteTimeout > 5*time.Second ||
		cfg.PoolSize < 1 || cfg.PoolSize > 1000 ||
		cfg.CredentialsProvider != nil && (cfg.Username == "" || cfg.Password != "") {
		return ErrInvalidConfig
	}
	if cfg.TLSConfig != nil {
		if _, err := validatedRedisTLSConfig(cfg.TLSConfig); err != nil {
			return ErrInvalidConfig
		}
		if cfg.Password == "" && cfg.CredentialsProvider == nil &&
			!(cfg.AllowSyntheticLoopback && (host == "localhost" || net.ParseIP(host) != nil && net.ParseIP(host).IsLoopback())) {
			return ErrInvalidConfig
		}
		return nil
	}
	ip := net.ParseIP(host)
	if !cfg.AllowSyntheticLoopback || (host != "localhost" && (ip == nil || !ip.IsLoopback())) ||
		cfg.Password != "" || cfg.CredentialsProvider != nil {
		return ErrInvalidConfig
	}
	return nil
}

func validatedRedisTLSConfig(config *tls.Config) (*tls.Config, error) {
	if config == nil {
		return nil, nil
	}
	validated := config.Clone()
	if validated.InsecureSkipVerify || validated.MaxVersion != 0 && validated.MaxVersion < tls.VersionTLS12 {
		return nil, ErrInvalidConfig
	}
	if validated.MinVersion < tls.VersionTLS12 {
		validated.MinVersion = tls.VersionTLS12
	}
	return validated, nil
}

type Config struct {
	Region     string
	HomeRegion string
	KeyID      string
	Secret     []byte
	ReplayTTL  time.Duration
}

type Policy struct {
	Digest               string
	CapacityUnits        int64
	RefillUnitsPerSecond int64
	CostUnits            int64
}

type Request struct {
	TenantID  string
	RouteID   string
	RequestID string
	Policy    Policy
}

type Decision struct {
	Allowed    bool
	Remaining  int64
	RetryAfter time.Duration
	Replayed   bool
}

type Limiter struct {
	client    redis.UniversalClient
	region    string
	keyID     string
	secret    []byte
	replayTTL time.Duration
}

func New(client redis.UniversalClient, cfg Config) (*Limiter, error) {
	if client == nil || !validIdentifier(cfg.Region, maxRegionLength) || cfg.Region != cfg.HomeRegion ||
		!validIdentifier(cfg.KeyID, maxKeyIDLength) || len(cfg.Secret) < 32 ||
		cfg.ReplayTTL < time.Second || cfg.ReplayTTL > maxReplayTTL {
		return nil, ErrInvalidConfig
	}
	return &Limiter{client: client, region: cfg.Region, keyID: cfg.KeyID,
		secret: append([]byte(nil), cfg.Secret...), replayTTL: cfg.ReplayTTL}, nil
}

func (l *Limiter) Allow(ctx context.Context, request Request) (Decision, error) {
	if ctx == nil || l == nil || l.client == nil || !uuidPattern.MatchString(request.TenantID) ||
		!uuidPattern.MatchString(request.RequestID) || !validIdentifier(request.RouteID, maxRouteLength) ||
		!digestPattern.MatchString(request.Policy.Digest) || request.Policy.CapacityUnits <= 0 ||
		request.Policy.CapacityUnits > maxCapacityUnits || request.Policy.RefillUnitsPerSecond <= 0 ||
		request.Policy.RefillUnitsPerSecond > maxRefillUnitsPS || request.Policy.CostUnits <= 0 ||
		request.Policy.CostUnits > request.Policy.CapacityUnits {
		return Decision{}, ErrInvalidConfig
	}
	bucketTTL := time.Duration((request.Policy.CapacityUnits*1000+request.Policy.RefillUnitsPerSecond-1)/request.Policy.RefillUnitsPerSecond)*time.Millisecond + time.Second
	if bucketTTL <= 0 || bucketTTL > maxBucketTTL {
		return Decision{}, ErrInvalidConfig
	}
	bucketKey, requestKey := l.keys(request.TenantID, request.RouteID, request.RequestID)
	fingerprint, err := l.fingerprint(request)
	if err != nil {
		return Decision{}, ErrInvalidConfig
	}
	values, err := consumeScript.Run(ctx, l.client, []string{bucketKey, requestKey},
		request.Policy.CapacityUnits, request.Policy.RefillUnitsPerSecond, request.Policy.CostUnits,
		bucketTTL.Milliseconds(), l.replayTTL.Milliseconds(), fingerprint).Slice()
	if err != nil {
		return Decision{}, classifyRedisError(err)
	}
	if len(values) != 4 {
		return Decision{}, ErrRedisFailure
	}
	code, ok1 := redisInt(values[0])
	remaining, ok2 := redisInt(values[1])
	retryMS, ok3 := redisInt(values[2])
	replayed, ok4 := redisInt(values[3])
	if !ok1 || !ok2 || !ok3 || !ok4 || code < -1 || code > 1 || remaining < 0 || retryMS < 0 || replayed < 0 || replayed > 1 {
		return Decision{}, ErrRedisFailure
	}
	if code == -1 {
		return Decision{}, ErrIdempotencyConflict
	}
	return Decision{Allowed: code == 1, Remaining: remaining, RetryAfter: time.Duration(retryMS) * time.Millisecond, Replayed: replayed == 1}, nil
}

func classifyRedisError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	var networkError net.Error
	if errors.As(err, &networkError) {
		return fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	var serverError redis.Error
	if errors.As(err, &serverError) {
		switch {
		case redis.HasErrorPrefix(err, "CLUSTERDOWN "),
			redis.HasErrorPrefix(err, "LOADING "),
			redis.HasErrorPrefix(err, "MASTERDOWN "),
			redis.HasErrorPrefix(err, "READONLY "),
			redis.HasErrorPrefix(err, "TRYAGAIN "),
			strings.HasPrefix(err.Error(), "ERR max number of clients reached"):
			return fmt.Errorf("%w: %w", ErrUnavailable, err)
		default:
			return fmt.Errorf("%w: %w", ErrRedisFailure, err)
		}
	}
	return fmt.Errorf("%w: %w", ErrRedisFailure, err)
}

func validIdentifier(value string, maxLength int) bool {
	return len(value) > 0 && len(value) <= maxLength && idPattern.MatchString(value)
}

func (l *Limiter) keys(tenant, route, request string) (string, string) {
	scope := strings.Join([]string{l.region, tenant, route}, "\x00")
	// Redis Cluster requires every key touched by one Lua script to share a
	// hash slot. The opaque HMAC scope is used as the hash tag for both keys.
	scopeTag := l.mac("keel.ratelimit.scope.v1\x00", scope)
	dedup := l.mac("keel.ratelimit.request.v1\x00", scope+"\x00"+request)
	prefix := "keel:rl:v1:" + l.region + ":" + l.keyID + ":"
	return prefix + "{" + scopeTag + "}:b", prefix + "{" + scopeTag + "}:r:" + dedup
}

func (l *Limiter) fingerprint(request Request) (string, error) {
	b, err := json.Marshal(struct {
		Tenant, Route, RequestID, PolicyDigest string
		Capacity, Refill, Cost                 int64
	}{request.TenantID, request.RouteID, request.RequestID, request.Policy.Digest,
		request.Policy.CapacityUnits, request.Policy.RefillUnitsPerSecond, request.Policy.CostUnits})
	if err != nil {
		return "", err
	}
	return l.mac("keel.ratelimit.fingerprint.v1\x00", string(b)), nil
}

func (l *Limiter) mac(domain, value string) string {
	m := hmac.New(sha256.New, l.secret)
	_, _ = m.Write([]byte(domain))
	_, _ = m.Write([]byte(value))
	return hex.EncodeToString(m.Sum(nil))
}

func redisInt(value any) (int64, bool) {
	switch n := value.(type) {
	case int64:
		return n, true
	case string:
		v, err := strconv.ParseInt(n, 10, 64)
		return v, err == nil
	case []byte:
		v, err := strconv.ParseInt(string(n), 10, 64)
		return v, err == nil
	default:
		return 0, false
	}
}

var consumeScript = redis.NewScript(`
local old = redis.call('HMGET', KEYS[2], 'fingerprint', 'allowed', 'remaining', 'retry_ms')
if old[1] then
    if old[1] ~= ARGV[6] then return {-1, 0, 0, 1} end
    return {tonumber(old[2]), tonumber(old[3]), tonumber(old[4]), 1}
end
local capacity = tonumber(ARGV[1])
local refill = tonumber(ARGV[2])
local cost = tonumber(ARGV[3])
-- Store milli-tokens so requests during a partial refill interval do not
-- discard fractional credit when the bucket's update timestamp advances.
capacity = capacity * 1000
cost = cost * 1000
local ttl = tonumber(ARGV[4])
local request_ttl = tonumber(ARGV[5])
local time = redis.call('TIME')
local now = tonumber(time[1]) * 1000 + math.floor(tonumber(time[2]) / 1000)
local state = redis.call('HMGET', KEYS[1], 'tokens_milli', 'updated_ms')
local tokens = capacity
if state[1] then
    tokens = tonumber(state[1])
    local updated = tonumber(state[2])
    if now < updated then now = updated end
    local elapsed = now - updated
    -- Refill is expressed as milli-tokens per millisecond, so fractional
    -- units remain exact for the full bounded capacity/refill range.
    local replenished = elapsed * refill
    if replenished >= capacity - tokens then tokens = capacity else tokens = tokens + replenished end
end
local allowed = 0
local retry_ms = 0
if tokens >= cost then
    allowed = 1
    tokens = tokens - cost
else
    retry_ms = math.ceil((cost - tokens) / refill)
end
redis.call('HSET', KEYS[1], 'tokens_milli', tokens, 'updated_ms', now)
redis.call('PEXPIRE', KEYS[1], ttl)
redis.call('HSET', KEYS[2], 'fingerprint', ARGV[6], 'allowed', allowed, 'remaining', math.floor(tokens / 1000), 'retry_ms', retry_ms)
redis.call('PEXPIRE', KEYS[2], request_ttl)
return {allowed, math.floor(tokens / 1000), retry_ms, 0}
`)
