package ratelimit

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

func TestLimiterValidationAndRegionFence(t *testing.T) {
	client := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"})
	t.Cleanup(func() { _ = client.Close() })
	if _, err := New(client, Config{Region: "us-east-1", HomeRegion: "eu-west-1", KeyID: "k1", Secret: []byte(strings.Repeat("s", 32)), ReplayTTL: time.Minute}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("non-home region was accepted: %v", err)
	}
	if _, err := New(client, Config{Region: "us-east-1", HomeRegion: "us-east-1", KeyID: strings.Repeat("k", maxKeyIDLength+1), Secret: []byte(strings.Repeat("s", 32)), ReplayTTL: time.Minute}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("oversized key identifier was accepted: %v", err)
	}
	if _, err := NewRedisClient(ClientConfig{Addr: "cache.example:6379", Region: "us-east-1", HomeRegion: "us-east-1",
		Password: "secret", AllowSyntheticLoopback: true, DialTimeout: time.Second, ReadTimeout: time.Second,
		WriteTimeout: time.Second, PoolSize: 4}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("remote plaintext Redis was accepted: %v", err)
	}
	if _, err := NewRedisClient(ClientConfig{Addr: "127.0.0.1:6379", Region: "local", HomeRegion: "local",
		AllowSyntheticLoopback: true, TLSConfig: &tls.Config{InsecureSkipVerify: true}, DialTimeout: time.Second,
		ReadTimeout: time.Second, WriteTimeout: time.Second, PoolSize: 4}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("TLS certificate verification bypass was accepted: %v", err)
	}
	if _, err := NewRedisClient(ClientConfig{Addr: "127.0.0.1:6379", Region: "local", HomeRegion: "local",
		AllowSyntheticLoopback: true, DialTimeout: time.Second, ReadTimeout: time.Second,
		WriteTimeout: time.Second, PoolSize: 4}); err != nil {
		t.Fatalf("explicit local loopback profile was rejected: %v", err)
	}
}

func TestRedisScriptKeysShareOpaqueClusterHashTag(t *testing.T) {
	client := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"})
	t.Cleanup(func() { _ = client.Close() })
	limiter, err := New(client, Config{
		Region: "us-east-1", HomeRegion: "us-east-1", KeyID: "hmac-v1",
		Secret: []byte(strings.Repeat("s", 32)), ReplayTTL: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	bucket, request := limiter.keys("00000000-0000-4000-8000-000000000001", "ai.generate", "00000000-0000-4000-8000-000000000002")
	if left, right := redisHashTag(bucket), redisHashTag(request); left == "" || left != right {
		t.Fatalf("Lua keys do not share one nonempty Redis Cluster hash tag: %q %q", left, right)
	}
}

func redisHashTag(key string) string {
	start := strings.IndexByte(key, '{')
	if start < 0 {
		return ""
	}
	end := strings.IndexByte(key[start+1:], '}')
	if end <= 0 {
		return ""
	}
	return key[start+1 : start+1+end]
}

func TestRedisUnavailableFailsClosed(t *testing.T) {
	client := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", DialTimeout: 50 * time.Millisecond,
		ReadTimeout: 50 * time.Millisecond, WriteTimeout: 50 * time.Millisecond, MaxRetries: -1})
	t.Cleanup(func() { _ = client.Close() })
	limiter, err := New(client, Config{Region: "us-east-1", HomeRegion: "us-east-1", KeyID: "hmac-v1",
		Secret: []byte(strings.Repeat("s", 32)), ReplayTTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	request := Request{TenantID: "00000000-0000-4000-8000-000000000001", RouteID: "ai.generate",
		RequestID: "00000000-0000-4000-8000-000000000002",
		Policy:    Policy{Digest: strings.Repeat("a", 64), CapacityUnits: 1000, RefillUnitsPerSecond: 1, CostUnits: 1}}
	request.RouteID = strings.Repeat("r", maxRouteLength+1)
	if _, err := limiter.Allow(context.Background(), request); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("oversized route identifier was accepted: %v", err)
	}
	request.RouteID = "ai.generate"
	if _, err := limiter.Allow(context.Background(), request); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("unavailable Redis did not fail closed: %v", err)
	}
}

func TestRedisGlobalBucketIdempotencyAndIsolation(t *testing.T) {
	url := os.Getenv("KEEL_TEST_REDIS_URL")
	if url == "" {
		t.Skip("set KEEL_TEST_REDIS_URL for shared Redis limiter integration coverage")
	}
	options, err := redis.ParseURL(url)
	if err != nil {
		t.Fatal(err)
	}
	options.MaxRetries = 0
	clientA, clientB := redis.NewClient(options), redis.NewClient(options)
	t.Cleanup(func() { _ = clientA.Close(); _ = clientB.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := clientA.Ping(ctx).Err(); err != nil {
		t.Fatal(err)
	}
	secret := []byte(strings.Repeat("s", 32))
	cfg := Config{Region: "us-east-1", HomeRegion: "us-east-1", KeyID: "hmac-v1", Secret: secret, ReplayTTL: time.Minute}
	a, err := New(clientA, cfg)
	if err != nil {
		t.Fatal(err)
	}
	b, err := New(clientB, cfg)
	if err != nil {
		t.Fatal(err)
	}
	// Use a fresh tenant scope on every run because this test intentionally
	// shares Redis between independent clients and must not flush its database.
	tenantScope := time.Now().UnixNano() & 0xffffffffffff
	tenant := fmt.Sprintf("00000000-0000-4000-8000-%012x", tenantScope)
	policy := Policy{Digest: strings.Repeat("a", 64), CapacityUnits: 5000, RefillUnitsPerSecond: 1, CostUnits: 1000}
	var mu sync.Mutex
	allowed := 0
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			limiter := a
			if i%2 != 0 {
				limiter = b
			}
			request := Request{TenantID: tenant, RouteID: "ai.generate", RequestID: fmt.Sprintf("00000000-0000-4000-8000-%012x", i+100), Policy: policy}
			decision, err := limiter.Allow(ctx, request)
			if err != nil {
				t.Errorf("allow %d: %v", i, err)
				return
			}
			if decision.Allowed {
				mu.Lock()
				allowed++
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()
	if allowed != 5 {
		t.Fatalf("two limiters overspent global bucket: allowed=%d, want 5", allowed)
	}

	// A new logical admission is charged once, and replaying the same request
	// through the other client returns the original decision without consuming
	// another token. Reusing its ID with a changed cost is a conflict.
	policy = Policy{Digest: strings.Repeat("b", 64), CapacityUnits: 2000, RefillUnitsPerSecond: 1, CostUnits: 1000}
	req := Request{TenantID: fmt.Sprintf("00000000-0000-4000-8000-%012x", (tenantScope+1)&0xffffffffffff), RouteID: "safe.read",
		RequestID: "00000000-0000-4000-8000-000000000011", Policy: policy}
	first, err := a.Allow(ctx, req)
	if err != nil || !first.Allowed {
		t.Fatalf("first idempotent admission: %+v %v", first, err)
	}
	replay, err := b.Allow(ctx, req)
	if err != nil || !replay.Allowed || !replay.Replayed || replay.Remaining != first.Remaining {
		t.Fatalf("request replay changed token state: first=%+v replay=%+v err=%v", first, replay, err)
	}
	conflict := req
	conflict.Policy.CostUnits = 1500
	if _, err := b.Allow(ctx, conflict); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("conflicting request ID reuse was accepted: %v", err)
	}
	// A denied admission must retain sub-unit refill credit when it advances
	// the bucket timestamp; rounding it away would incorrectly return ~1s.
	fractional := Request{TenantID: fmt.Sprintf("00000000-0000-4000-8000-%012x", (tenantScope+3)&0xffffffffffff), RouteID: "safe.read",
		RequestID: "00000000-0000-4000-8000-000000000021",
		Policy:    Policy{Digest: strings.Repeat("c", 64), CapacityUnits: 1, RefillUnitsPerSecond: 1, CostUnits: 1}}
	if decision, err := a.Allow(ctx, fractional); err != nil || !decision.Allowed {
		t.Fatalf("fractional refill setup: %+v err=%v", decision, err)
	}
	time.Sleep(550 * time.Millisecond)
	fractional.RequestID = "00000000-0000-4000-8000-000000000022"
	denied, err := b.Allow(ctx, fractional)
	if err != nil || denied.Allowed || denied.RetryAfter <= 0 || denied.RetryAfter >= 750*time.Millisecond {
		t.Fatalf("partial refill credit was not retained: %+v err=%v", denied, err)
	}
	time.Sleep(denied.RetryAfter + 50*time.Millisecond)
	fractional.RequestID = "00000000-0000-4000-8000-000000000023"
	refilled, err := a.Allow(ctx, fractional)
	if err != nil || !refilled.Allowed {
		t.Fatalf("bucket did not refill after remaining interval: %+v err=%v", refilled, err)
	}
	otherTenant := req
	otherTenant.TenantID = fmt.Sprintf("00000000-0000-4000-8000-%012x", (tenantScope+2)&0xffffffffffff)
	otherTenant.RequestID = "00000000-0000-4000-8000-000000000013"
	isolated, err := b.Allow(ctx, otherTenant)
	if err != nil || !isolated.Allowed || isolated.Remaining != 1000 {
		t.Fatalf("one tenant's usage leaked into another bucket: %+v err=%v", isolated, err)
	}
}
