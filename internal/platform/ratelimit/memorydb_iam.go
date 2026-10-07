package ratelimit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

const memoryDBIAMTokenTTL = 15 * time.Minute

// NewMemoryDBIAMCredentialsProvider returns a go-redis credentials callback
// that signs a short-lived MemoryDB IAM token for each new connection. The
// supplied AWS credentials provider should use the workload's normal IAM
// identity chain, such as EKS Pod Identity or IRSA.
func NewMemoryDBIAMCredentialsProvider(addr, username, region string, credentials aws.CredentialsProvider) (func(context.Context) (string, string, error), error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil || host == "" || net.ParseIP(host) != nil || !validIdentifier(username, 40) ||
		!validIdentifier(region, maxRegionLength) || credentials == nil {
		return nil, ErrInvalidConfig
	}
	return newMemoryDBIAMCredentialsProvider(host, username, region, credentials, time.Now), nil
}

func newMemoryDBIAMCredentialsProvider(host, username, region string, credentials aws.CredentialsProvider, now func() time.Time) func(context.Context) (string, string, error) {
	return func(ctx context.Context) (string, string, error) {
		if ctx == nil || credentials == nil || now == nil {
			return "", "", ErrInvalidConfig
		}
		awsCredentials, err := credentials.Retrieve(ctx)
		if err != nil {
			return "", "", fmt.Errorf("retrieve MemoryDB IAM signing credentials: %w", err)
		}
		token, err := signMemoryDBIAMToken(ctx, host, username, region, awsCredentials, now())
		if err != nil {
			return "", "", fmt.Errorf("sign MemoryDB IAM authentication token: %w", err)
		}
		return username, token, nil
	}
}

func signMemoryDBIAMToken(ctx context.Context, host, username, region string, credentials aws.Credentials, now time.Time) (string, error) {
	if ctx == nil || host == "" || username == "" || region == "" || !credentials.HasKeys() {
		return "", ErrInvalidConfig
	}
	endpoint := &url.URL{Scheme: "http", Host: host, Path: "/"}
	query := endpoint.Query()
	query.Set("Action", "connect")
	query.Set("User", username)
	query.Set("X-Amz-Expires", strconv.FormatInt(int64(memoryDBIAMTokenTTL/time.Second), 10))
	endpoint.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return "", ErrInvalidConfig
	}
	emptyPayloadHash := sha256.Sum256(nil)
	signedURL, _, err := v4.NewSigner().PresignHTTP(ctx, credentials, request, hex.EncodeToString(emptyPayloadHash[:]), "memorydb", region, now.UTC())
	if err != nil {
		return "", err
	}
	if signedURL == "" {
		return "", errors.New("AWS signer returned an empty MemoryDB token")
	}
	return signedURL, nil
}
