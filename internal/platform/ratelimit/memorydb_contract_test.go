package ratelimit

import (
	"context"
	"crypto/tls"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/google/uuid"
)

// TestMemoryDBManagedClusterContract is an opt-in, non-destructive contract
// check for a dedicated MemoryDB test cluster. It uses the caller's normal AWS
// workload identity, writes only uniquely scoped limiter keys, and relies on
// their short TTLs instead of flushing or deleting shared cluster data.
func TestMemoryDBManagedClusterContract(t *testing.T) {
	addr := strings.TrimSpace(os.Getenv("KEEL_TEST_MEMORYDB_ADDR"))
	region := strings.TrimSpace(os.Getenv("KEEL_TEST_MEMORYDB_REGION"))
	username := strings.TrimSpace(os.Getenv("KEEL_TEST_MEMORYDB_USERNAME"))
	confirmation := strings.TrimSpace(os.Getenv("KEEL_TEST_MEMORYDB_CONFIRM_WRITES"))
	if addr == "" || region == "" || username == "" || confirmation != "I_UNDERSTAND_TEST_KEYS_ARE_WRITTEN" {
		t.Skip("set MemoryDB endpoint/region/username and KEEL_TEST_MEMORYDB_CONFIRM_WRITES=I_UNDERSTAND_TEST_KEYS_ARE_WRITTEN for managed contract coverage")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	awsConfig, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		t.Fatal("load AWS workload identity configuration")
	}
	var credentials aws.CredentialsProvider = awsConfig.Credentials
	provider, err := NewMemoryDBIAMCredentialsProvider(addr, username, region, credentials)
	if err != nil {
		t.Fatalf("configure MemoryDB IAM authentication: %v", err)
	}
	clientConfig := ClientConfig{
		Addr: addr, Username: username, Region: region, HomeRegion: region,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12}, CredentialsProvider: provider,
		DialTimeout: time.Second, ReadTimeout: time.Second, WriteTimeout: time.Second, PoolSize: 8,
	}
	clientA, err := NewRedisClusterClient(clientConfig)
	if err != nil {
		t.Fatalf("configure cluster-aware MemoryDB client: %v", err)
	}
	t.Cleanup(func() { _ = clientA.Close() })
	clientB, err := NewRedisClusterClient(clientConfig)
	if err != nil {
		t.Fatalf("configure second MemoryDB client: %v", err)
	}
	t.Cleanup(func() { _ = clientB.Close() })
	if err := clientA.Ping(ctx).Err(); err != nil {
		t.Fatalf("connect to MemoryDB with verified TLS and IAM: %v", err)
	}

	secret := []byte(strings.Repeat("m", 32))
	limiterA, err := New(clientA, Config{Region: region, HomeRegion: region, KeyID: "managed-test", Secret: secret, ReplayTTL: time.Minute})
	if err != nil {
		t.Fatal("create MemoryDB limiter")
	}
	limiterB, err := New(clientB, Config{Region: region, HomeRegion: region, KeyID: "managed-test", Secret: secret, ReplayTTL: time.Minute})
	if err != nil {
		t.Fatal("create second MemoryDB limiter")
	}

	// A low refill rate keeps the five-token concurrency assertion stable. The
	// test creates only TTL-bounded, HMAC-obscured keys under a random tenant.
	tenant := uuid.NewString()
	policy := Policy{Digest: strings.Repeat("c", 64), CapacityUnits: 5, RefillUnitsPerSecond: 1, CostUnits: 1}
	var mu sync.Mutex
	allowed := 0
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			limiter := limiterA
			if i%2 != 0 {
				limiter = limiterB
			}
			request := Request{TenantID: tenant, RouteID: "safe.read", RequestID: uuid.NewString(), Policy: policy}
			decision, err := limiter.Allow(ctx, request)
			if err != nil {
				t.Errorf("concurrent admission %d: %v", i, err)
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
		t.Fatalf("cluster-wide token bucket admitted %d requests; want exactly 5", allowed)
	}

	// A distinct tenant isolates receipt replay from the concurrent burst.
	replayRequest := Request{TenantID: uuid.NewString(), RouteID: "safe.read", RequestID: uuid.NewString(), Policy: policy}
	first, err := limiterA.Allow(ctx, replayRequest)
	if err != nil || !first.Allowed {
		t.Fatalf("initial MemoryDB admission = %+v, err=%v", first, err)
	}
	replay, err := limiterB.Allow(ctx, replayRequest)
	if err != nil || !replay.Allowed || !replay.Replayed || replay.Remaining != first.Remaining {
		t.Fatalf("cross-client receipt replay = %+v, err=%v; original=%+v", replay, err, first)
	}
	changed := replayRequest
	changed.Policy.CostUnits = 2
	if _, err := limiterB.Allow(ctx, changed); err != ErrIdempotencyConflict {
		t.Fatalf("changed replay fingerprint returned %v, want %v", err, ErrIdempotencyConflict)
	}
	t.Logf("MemoryDB cluster contract passed for region %s with two clients", region)
}
