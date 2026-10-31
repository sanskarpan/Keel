package httpapi

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

const (
	testBearerTenant = "11111111-1111-4111-8111-111111111111"
	testBearerToken  = "abcdefghijklmnopqrstuvwxyz012345"
)

func testGrants(t *testing.T) []TokenGrant {
	t.Helper()
	grants, err := ParseTokenGrants(testBearerTenant + ":ops-one:" + testBearerToken + "," +
		"22222222-2222-4222-8222-222222222222:ops-replay:" + strings.Repeat("r", 32) + ":replay")
	if err != nil {
		t.Fatal(err)
	}
	return grants
}

func TestParseTokenGrantsDefaultsToBothScopes(t *testing.T) {
	grants, err := ParseTokenGrants(testBearerTenant + ":ops-one:" + testBearerToken)
	if err != nil {
		t.Fatal(err)
	}
	if len(grants) != 1 || !grants[0].Replay || !grants[0].Policies {
		t.Fatalf("grants = %+v", grants)
	}
}

func TestParseTokenGrantsRejectsBadInput(t *testing.T) {
	other := strings.Repeat("o", 32)
	for _, test := range []struct {
		name string
		raw  string
	}{
		{"empty", ""},
		{"two parts", "tenant:name"},
		{"five parts", "a:b:c:d:e"},
		{"bad tenant", "not-a-tenant:ops:" + testBearerToken},
		{"zero tenant", "00000000-0000-0000-0000-000000000000:ops:" + testBearerToken},
		{"bad name", testBearerTenant + ":not a name:" + testBearerToken},
		{"short token", testBearerTenant + ":ops:short"},
		{"spaced token", testBearerTenant + ":ops:" + strings.Repeat("s ", 16)},
		{"empty scopes", testBearerTenant + ":ops:" + testBearerToken + ":"},
		{"bad scope", testBearerTenant + ":ops:" + testBearerToken + ":admin"},
		{"duplicate name", testBearerTenant + ":ops:" + testBearerToken + "," +
			testBearerTenant + ":ops:" + other},
		{"duplicate token", testBearerTenant + ":ops-a:" + testBearerToken + "," +
			testBearerTenant + ":ops-b:" + testBearerToken},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := ParseTokenGrants(test.raw); err == nil {
				t.Fatalf("grants %q were accepted", test.raw)
			}
		})
	}
	if _, err := NewBearerAuth(nil); err == nil {
		t.Fatal("empty bearer auth was accepted")
	}
}

func TestBearerResolveAuthenticatesKnownToken(t *testing.T) {
	auth, err := NewBearerAuth(testGrants(t))
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest("GET", "/v1/webhooks/reconciliation-runs", nil)
	request.Header.Set("Authorization", "Bearer "+testBearerToken)
	principal, ok := auth.Resolve(context.Background(), request)
	if !ok {
		t.Fatal("known token was rejected")
	}
	if string(principal.TenantID) != testBearerTenant || principal.ActorRef != "bearer:ops-one" {
		t.Fatalf("principal = %+v", principal)
	}
	if !auth.CanReplayWebhooks(context.Background(), principal) ||
		!auth.CanManageWebhookPolicies(context.Background(), principal) {
		t.Fatal("full-scope grant was denied")
	}
}

func TestBearerResolveRejectsUnknownPresentations(t *testing.T) {
	auth, err := NewBearerAuth(testGrants(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, header := range []string{
		"",
		"Basic dXNlcjpwYXNz",
		"Bearer " + strings.Repeat("z", 32),
		"Bearer short",
		"bearer " + testBearerToken,
		"Bearer  " + testBearerToken + " ",
		strings.Repeat("B", 300),
	} {
		request := httptest.NewRequest("GET", "/v1/webhooks/reconciliation-runs", nil)
		if header != "" {
			request.Header.Set("Authorization", header)
		}
		if _, ok := auth.Resolve(context.Background(), request); ok {
			t.Fatalf("header %q was accepted", header)
		}
	}
	var nilAuth *BearerAuth
	if _, ok := nilAuth.Resolve(context.Background(), httptest.NewRequest("GET", "/", nil)); ok {
		t.Fatal("nil bearer auth resolved")
	}
}

func TestBearerScopesAreEnforcedPerGrant(t *testing.T) {
	auth, err := NewBearerAuth(testGrants(t))
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest("GET", "/v1/webhooks/reconciliation-runs", nil)
	request.Header.Set("Authorization", "Bearer "+strings.Repeat("r", 32))
	principal, ok := auth.Resolve(context.Background(), request)
	if !ok {
		t.Fatal("replay-scope token was rejected")
	}
	if !auth.CanReplayWebhooks(context.Background(), principal) {
		t.Fatal("replay scope was denied")
	}
	if auth.CanManageWebhookPolicies(context.Background(), principal) {
		t.Fatal("policy scope was granted to a replay-only token")
	}
	strangerTenant, err := tenancy.ParseTenantID("33333333-3333-4333-8333-333333333333")
	if err != nil {
		t.Fatal(err)
	}
	stranger := Principal{TenantID: strangerTenant, ActorRef: "bearer:ops-one"}
	if auth.CanReplayWebhooks(context.Background(), stranger) {
		t.Fatal("cross-tenant principal was authorized")
	}
	if auth.CanReplayWebhooks(context.Background(), Principal{ActorRef: "operator@example.com"}) {
		t.Fatal("non-bearer principal was authorized")
	}
}
