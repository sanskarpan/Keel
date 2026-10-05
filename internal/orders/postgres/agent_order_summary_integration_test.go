package postgres

import (
	"context"
	"errors"
	"net/url"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/sanskarpan/keel/internal/ai/tools"
)

const (
	tenantAlpha = "11111111-1111-4111-8111-111111111111"
	tenantBeta  = "22222222-2222-4222-8222-222222222222"
)

type fixedOrderAuthorizer struct {
	allowed bool
	calls   int
}

type countingOrderReader struct {
	tools.BoundOrderReader
	calls int
}

func (r *countingOrderReader) ReadOrderSummary(ctx context.Context, orderID uuid.UUID) (tools.OrderSummary, error) {
	r.calls++
	return r.BoundOrderReader.ReadOrderSummary(ctx, orderID)
}

func (a *fixedOrderAuthorizer) CanReadOrder(_ context.Context, principal, tenant string, _ uuid.UUID) (bool, error) {
	a.calls++
	if principal == "" || tenant != tenantAlpha && tenant != tenantBeta {
		return false, errors.New("invalid trusted principal scope")
	}
	return a.allowed, nil
}

func TestPostgreSQLAgentOrderSummaryTenantBoundProjection(t *testing.T) {
	appDSN := os.Getenv("KEEL_TEST_DATABASE_URL")
	agentPassword := os.Getenv("KEEL_TEST_AGENT_PASSWORD")
	if appDSN == "" || agentPassword == "" {
		t.Skip("set KEEL_TEST_DATABASE_URL and KEEL_TEST_AGENT_PASSWORD for agent query integration coverage")
	}
	ctx := context.Background()
	appDB := integrationDB(t, appDSN, 4)
	repo, err := NewRepository(appDB)
	if err != nil {
		t.Fatal(err)
	}
	alpha, beta := mustTenant(t, tenantAlpha), mustTenant(t, tenantBeta)
	alphaMetadata := testMetadata(string(alpha), nextUUID())
	alphaMetadata.ActorRef = "principal:fixture"
	alphaOrder, err := repo.Create(ctx, alpha, testCreate("agent-alpha-"+nextUUID()), alphaMetadata, "agent-alpha-"+nextUUID(), "principal:fixture")
	if err != nil {
		t.Fatal(err)
	}
	betaMetadata := testMetadata(string(beta), nextUUID())
	betaMetadata.ActorRef = "principal:fixture"
	betaOrder, err := repo.Create(ctx, beta, testCreate("agent-beta-"+nextUUID()), betaMetadata, "agent-beta-"+nextUUID(), "principal:fixture")
	if err != nil {
		t.Fatal(err)
	}

	alphaDB := integrationDB(t, agentDSN(t, appDSN, "keel_local_agent_alpha", agentPassword), 1)
	betaDB := integrationDB(t, agentDSN(t, appDSN, "keel_local_agent_beta", agentPassword), 1)
	alphaReader, err := tools.NewPostgresOrderSummaryReader(tenantAlpha, alphaDB)
	if err != nil {
		t.Fatal(err)
	}
	betaReader, err := tools.NewPostgresOrderSummaryReader(tenantBeta, betaDB)
	if err != nil {
		t.Fatal(err)
	}
	authorizer := &fixedOrderAuthorizer{allowed: true}
	alphaBroker, err := tools.NewOrderSummaryBroker(tenantAlpha, authorizer, alphaReader)
	if err != nil {
		t.Fatal(err)
	}
	alphaPrincipal, err := tools.NewPrincipalFromVerifiedAuth("principal:alpha-reader", tenantAlpha)
	if err != nil {
		t.Fatal(err)
	}
	got, err := alphaBroker.Invoke(ctx, alphaPrincipal, tools.GetOrderSummaryName, []byte(`{"order_id":"`+alphaOrder.Snapshot.OrderID+`"}`))
	if err != nil || got.Status != "draft" || got.Version != 1 {
		t.Fatalf("same-tenant summary=%+v err=%v", got, err)
	}
	deniedReader := &countingOrderReader{BoundOrderReader: alphaReader}
	deniedBroker, err := tools.NewOrderSummaryBroker(tenantAlpha, &fixedOrderAuthorizer{allowed: false}, deniedReader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := deniedBroker.Invoke(ctx, alphaPrincipal, tools.GetOrderSummaryName, []byte(`{"order_id":"`+alphaOrder.Snapshot.OrderID+`"}`)); !errors.Is(err, tools.ErrToolNotFound) || deniedReader.calls != 0 {
		t.Fatalf("denied principal reached PostgreSQL reader: calls=%d err=%v", deniedReader.calls, err)
	}

	// A forged tenant GUC does not override the protected session_user mapping.
	if _, err := alphaDB.ExecContext(ctx, `SELECT pg_catalog.set_config('keel.tenant_id',$1,false)`, tenantBeta); err != nil {
		t.Fatal(err)
	}
	_, err = alphaReader.ReadOrderSummary(ctx, uuid.MustParse(betaOrder.Snapshot.OrderID))
	if err == nil {
		t.Fatal("alpha-bound session read a beta order after forged tenant GUC")
	}
	if _, err := betaReader.ReadOrderSummary(ctx, uuid.MustParse(betaOrder.Snapshot.OrderID)); err != nil {
		t.Fatalf("beta-bound session could not read beta summary: %v", err)
	}
	if _, err := betaReader.ReadOrderSummary(ctx, uuid.MustParse(alphaOrder.Snapshot.OrderID)); err == nil {
		t.Fatal("beta-bound session read an alpha order")
	}

	var private string
	if err := alphaDB.QueryRowContext(ctx, `SELECT command_snapshot::text FROM keel_meta.order_heads WHERE order_id=$1`, alphaOrder.Snapshot.OrderID).Scan(&private); err == nil {
		t.Fatal("agent role read the private command snapshot from the base table")
	}
	if _, err := alphaDB.ExecContext(ctx, `UPDATE keel_meta.order_heads SET status='approved' WHERE order_id=$1`, alphaOrder.Snapshot.OrderID); err == nil {
		t.Fatal("agent role mutated the base order table")
	}
	if _, err := alphaDB.ExecContext(ctx, `UPDATE keel_meta.agent_order_summary SET status='approved' WHERE order_id=$1`, alphaOrder.Snapshot.OrderID); err == nil {
		t.Fatal("agent role mutated the summary projection")
	}
	if authorizer.calls != 1 {
		t.Fatalf("broker authorization calls=%d, want 1", authorizer.calls)
	}
}

func agentDSN(t *testing.T, raw, username, password string) string {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	parsed.User = url.UserPassword(username, password)
	return parsed.String()
}
