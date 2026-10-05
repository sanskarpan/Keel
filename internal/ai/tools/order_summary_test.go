package tools

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

const (
	testTenant    = "11111111-1111-4111-8111-111111111111"
	testOther     = "22222222-2222-4222-8222-222222222222"
	testOrder     = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	testPrincipal = "principal:test-user"
)

type fakeOrderAuthorizer struct {
	allowed bool
	err     error
	calls   int
}

func (a *fakeOrderAuthorizer) CanReadOrder(_ context.Context, principal, tenant string, orderID uuid.UUID) (bool, error) {
	a.calls++
	if principal != testPrincipal || tenant != testTenant || orderID.String() != testOrder {
		return false, errors.New("unexpected authorization scope")
	}
	return a.allowed, a.err
}

type fakeOrderReader struct {
	tenant string
	result OrderSummary
	err    error
	calls  int
}

func (r *fakeOrderReader) TenantID() string { return r.tenant }
func (r *fakeOrderReader) ReadOrderSummary(_ context.Context, _ uuid.UUID) (OrderSummary, error) {
	r.calls++
	return r.result, r.err
}

func newBroker(t *testing.T, allowed bool) (*OrderSummaryBroker, *fakeOrderAuthorizer, *fakeOrderReader, Principal) {
	t.Helper()
	principal, err := NewPrincipalFromVerifiedAuth(testPrincipal, testTenant)
	if err != nil {
		t.Fatal(err)
	}
	authorizer := &fakeOrderAuthorizer{allowed: allowed}
	reader := &fakeOrderReader{tenant: testTenant, result: OrderSummary{Status: "submitted", Version: 3, UpdatedAt: time.Unix(1_700_000_000, 0).UTC()}}
	broker, err := NewOrderSummaryBroker(testTenant, authorizer, reader)
	if err != nil {
		t.Fatal(err)
	}
	return broker, authorizer, reader, principal
}

func TestOrderSummaryInvokesOnlyAfterAuthorization(t *testing.T) {
	broker, authorizer, reader, principal := newBroker(t, true)
	got, err := broker.Invoke(context.Background(), principal, GetOrderSummaryName, []byte(`{"order_id":"`+testOrder+`"}`))
	if err != nil || got.Status != "submitted" || got.Version != 3 || authorizer.calls != 1 || reader.calls != 1 {
		t.Fatalf("Invoke() summary=%+v auth calls=%d reader calls=%d err=%v", got, authorizer.calls, reader.calls, err)
	}
}

func TestOrderSummaryRejectsUntrustedScopeAndMalformedInputBeforeLookup(t *testing.T) {
	broker, authorizer, reader, principal := newBroker(t, true)
	otherTenant, err := NewPrincipalFromVerifiedAuth(testPrincipal, testOther)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		tool   string
		input  string
		caller Principal
	}{
		{name: "unknown tool", tool: "query_sql", input: `{"order_id":"` + testOrder + `"}`, caller: principal},
		{name: "unknown field", tool: GetOrderSummaryName, input: `{"order_id":"` + testOrder + `","tenant_id":"` + testOther + `"}`, caller: principal},
		{name: "duplicate field", tool: GetOrderSummaryName, input: `{"order_id":"` + testOrder + `","order_id":"` + testOrder + `"}`, caller: principal},
		{name: "uppercase UUID", tool: GetOrderSummaryName, input: `{"order_id":"AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"}`, caller: principal},
		{name: "extra value", tool: GetOrderSummaryName, input: `{"order_id":"` + testOrder + `"}{}`, caller: principal},
		{name: "oversized", tool: GetOrderSummaryName, input: `{"order_id":"` + testOrder + `","padding":"` + string(make([]byte, maxToolInputBytes)) + `"}`, caller: principal},
		{name: "tenant mismatch", tool: GetOrderSummaryName, input: `{"order_id":"` + testOrder + `"}`, caller: otherTenant},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := broker.Invoke(context.Background(), tc.caller, tc.tool, []byte(tc.input)); !errors.Is(err, ErrToolRejected) {
				t.Fatalf("Invoke() err=%v, want rejected", err)
			}
		})
	}
	if authorizer.calls != 0 || reader.calls != 0 {
		t.Fatalf("rejected requests reached auth/data boundary: auth=%d read=%d", authorizer.calls, reader.calls)
	}
}

func TestOrderSummaryDenialAndAuthorizationFailureDoNotRead(t *testing.T) {
	for _, tc := range []struct {
		name       string
		authorizer fakeOrderAuthorizer
		want       error
	}{
		{name: "denied", authorizer: fakeOrderAuthorizer{allowed: false}, want: ErrToolNotFound},
		{name: "authorizer failure", authorizer: fakeOrderAuthorizer{err: errors.New("private detail")}, want: ErrToolUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewPrincipalFromVerifiedAuth(testPrincipal, testTenant)
			if err != nil {
				t.Fatal(err)
			}
			principal := Principal{ref: testPrincipal, tenantID: testTenant}
			reader := &fakeOrderReader{tenant: testTenant}
			authorizer := tc.authorizer
			broker, err := NewOrderSummaryBroker(testTenant, &authorizer, reader)
			if err != nil {
				t.Fatal(err)
			}
			_, err = broker.Invoke(context.Background(), principal, GetOrderSummaryName, []byte(`{"order_id":"`+testOrder+`"}`))
			if !errors.Is(err, tc.want) || reader.calls != 0 {
				t.Fatalf("Invoke() err=%v reads=%d, want %v and no read", err, reader.calls, tc.want)
			}
		})
	}
}

func TestOrderSummaryBrokerRequiresBoundTenantMatch(t *testing.T) {
	authorizer := &fakeOrderAuthorizer{allowed: true}
	reader := &fakeOrderReader{tenant: testOther}
	if _, err := NewOrderSummaryBroker(testTenant, authorizer, reader); !errors.Is(err, ErrToolUnavailable) {
		t.Fatalf("broker accepted cross-tenant reader binding: %v", err)
	}
}
