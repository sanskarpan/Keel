package ratelimit

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
)

func TestMemoryDBIAMCredentialsProviderSignsFreshClusterCredentials(t *testing.T) {
	var calls int
	credentials := aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		calls++
		return aws.Credentials{AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: "secret-example", SessionToken: "session-example"}, nil
	})
	provider, err := NewMemoryDBIAMCredentialsProvider("cache.example.memorydb.us-east-1.amazonaws.com:6379", "keel-limiter", "us-east-1", credentials)
	if err != nil {
		t.Fatalf("create IAM credentials provider: %v", err)
	}
	for i := 0; i < 2; i++ {
		username, token, err := provider(context.Background())
		if err != nil {
			t.Fatalf("create IAM auth token: %v", err)
		}
		if username != "keel-limiter" {
			t.Fatalf("provider username = %q", username)
		}
		parsed, err := url.Parse(token)
		if err != nil {
			t.Fatalf("parse IAM token: %v", err)
		}
		query := parsed.Query()
		if parsed.Scheme != "http" || parsed.Host != "cache.example.memorydb.us-east-1.amazonaws.com" || parsed.Path != "/" ||
			query.Get("Action") != "connect" || query.Get("User") != username || query.Get("X-Amz-Expires") != "900" ||
			query.Get("X-Amz-Signature") == "" || query.Get("X-Amz-Security-Token") != "session-example" {
			t.Fatalf("IAM token does not contain the expected signed MemoryDB request: %s", token)
		}
		if !strings.Contains(query.Get("X-Amz-Credential"), "/us-east-1/memorydb/aws4_request") {
			t.Fatalf("IAM token has the wrong service or region signing scope: %q", query.Get("X-Amz-Credential"))
		}
	}
	if calls != 2 {
		t.Fatalf("credentials were retrieved %d times; want a fresh retrieval per connection", calls)
	}
}

func TestMemoryDBIAMCredentialsProviderRejectsInvalidInputs(t *testing.T) {
	validCredentials := aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return aws.Credentials{AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: "secret-example"}, nil
	})
	for name, tc := range map[string]struct {
		addr        string
		username    string
		region      string
		credentials aws.CredentialsProvider
	}{
		"missing address":  {username: "keel-limiter", region: "us-east-1", credentials: validCredentials},
		"IP endpoint":      {addr: "127.0.0.1:6379", username: "keel-limiter", region: "us-east-1", credentials: validCredentials},
		"invalid user":     {addr: "cache.example:6379", username: "Bad User", region: "us-east-1", credentials: validCredentials},
		"invalid region":   {addr: "cache.example:6379", username: "keel-limiter", region: "US-EAST-1", credentials: validCredentials},
		"missing provider": {addr: "cache.example:6379", username: "keel-limiter", region: "us-east-1"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewMemoryDBIAMCredentialsProvider(tc.addr, tc.username, tc.region, tc.credentials); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("invalid IAM configuration returned %v", err)
			}
		})
	}
	if _, _, err := newMemoryDBIAMCredentialsProvider("cache.example", "keel-limiter", "us-east-1", validCredentials, time.Now)(nil); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil request context returned %v", err)
	}
}

func TestMemoryDBIAMCredentialsProviderFailsClosedWithoutAWSCredentials(t *testing.T) {
	provider, err := NewMemoryDBIAMCredentialsProvider("cache.example:6379", "keel-limiter", "us-east-1",
		aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			return aws.Credentials{}, errors.New("no workload identity")
		}))
	if err != nil {
		t.Fatalf("create IAM credentials provider: %v", err)
	}
	if _, _, err := provider(context.Background()); err == nil {
		t.Fatal("provider accepted missing AWS workload credentials")
	}
}
