package postgres

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sanskarpan/keel/internal/orders/historycursor"
	"github.com/sanskarpan/keel/internal/orders/httpapi"
	"github.com/sanskarpan/keel/internal/platform/tenancy"
)

// This exercises the API's trusted-identity boundary and PostgreSQL tenant RLS together.
// The identity is injected as if by verified authentication middleware; this test does not
// claim an identity-provider integration, which remains a production wiring gate.
func TestPostgreSQLTwoTenantOrderAPIIsolation(t *testing.T) {
	_, tenantAlpha, repo := repositoryTestDB(t)
	tenantBeta := mustTenant(t, nextUUID())
	alphaOrderID, betaOrderID := nextUUID(), nextUUID()
	ctx := context.Background()
	for _, item := range []struct {
		tenant tenancy.TenantID
		order  string
		ref    string
		key    string
	}{
		{tenant: tenantAlpha, order: alphaOrderID, ref: "tenant-alpha-api-" + nextUUID(), key: "tenant-alpha-api-create-" + nextUUID()},
		{tenant: tenantBeta, order: betaOrderID, ref: "tenant-beta-api-" + nextUUID(), key: "tenant-beta-api-create-" + nextUUID()},
	} {
		metadata := testMetadata(string(item.tenant), item.order)
		if _, err := repo.Create(ctx, item.tenant, testCreate(item.ref), metadata, item.key, "principal:api-reader"); err != nil {
			t.Fatalf("create synthetic order for %s: %v", item.tenant, err)
		}
	}

	codec, err := historycursor.New("api-test", map[string][]byte{"api-test": []byte("0123456789abcdef0123456789abcdef")})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := httpapi.NewHandler(repo, allowTenantReadAuthorizer{}, codec)
	if err != nil {
		t.Fatal(err)
	}

	var sessionUser, currentUser string
	var appRoleMember bool
	if err := repo.db.QueryRowContext(ctx, `SELECT session_user::text,current_user::text,pg_catalog.pg_has_role(session_user,'keel_app','MEMBER')`).Scan(&sessionUser, &currentUser, &appRoleMember); err != nil {
		t.Fatal(err)
	}
	if sessionUser != "keel_local_app" || !appRoleMember {
		t.Fatalf("API integration did not use the least-privilege app login: session_user=%q current_user=%q app_role_member=%v", sessionUser, currentUser, appRoleMember)
	}

	serve := func(tenant tenancy.TenantID, orderID, forgedTenant string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/v1/orders/"+orderID, nil)
		if forgedTenant != "" {
			req.Header.Set("X-Tenant-ID", forgedTenant)
		}
		identity := httpapi.Identity{TenantID: tenant, PrincipalRef: "principal:api-reader"}
		req = req.WithContext(httpapi.WithIdentity(req.Context(), identity))
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		return response
	}

	alphaResponse := serve(tenantAlpha, alphaOrderID, string(tenantBeta))
	if alphaResponse.Code != http.StatusOK || !strings.Contains(alphaResponse.Body.String(), "tenant-alpha-api-") || strings.Contains(alphaResponse.Body.String(), "tenant-beta-api-") {
		t.Fatalf("alpha identity was influenced by forged tenant header: status=%d body=%s", alphaResponse.Code, alphaResponse.Body.String())
	}
	betaThroughAlpha := serve(tenantAlpha, betaOrderID, "")
	if betaThroughAlpha.Code != http.StatusNotFound || strings.Contains(betaThroughAlpha.Body.String(), "tenant-beta-api-") {
		t.Fatalf("alpha identity read another tenant's order: status=%d body=%s", betaThroughAlpha.Code, betaThroughAlpha.Body.String())
	}
	betaResponse := serve(tenantBeta, betaOrderID, string(tenantAlpha))
	if betaResponse.Code != http.StatusOK || !strings.Contains(betaResponse.Body.String(), "tenant-beta-api-") || strings.Contains(betaResponse.Body.String(), "tenant-alpha-api-") {
		t.Fatalf("beta identity was influenced by forged tenant header: status=%d body=%s", betaResponse.Code, betaResponse.Body.String())
	}
	alphaThroughBeta := serve(tenantBeta, alphaOrderID, "")
	if alphaThroughBeta.Code != http.StatusNotFound || strings.Contains(alphaThroughBeta.Body.String(), "tenant-alpha-api-") {
		t.Fatalf("beta identity read another tenant's order: status=%d body=%s", alphaThroughBeta.Code, alphaThroughBeta.Body.String())
	}
}

type allowTenantReadAuthorizer struct{}

func (allowTenantReadAuthorizer) CanReadOrder(_ context.Context, identity httpapi.Identity, _ string) (bool, error) {
	_, err := tenancy.ParseTenantID(string(identity.TenantID))
	return err == nil && strings.HasPrefix(identity.PrincipalRef, "principal:"), nil
}

var _ httpapi.Reader = (*Repository)(nil)
var _ httpapi.Authorizer = allowTenantReadAuthorizer{}
