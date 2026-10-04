package tenancy

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"reflect"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"
)

const (
	tenantAlpha = "11111111-1111-4111-8111-111111111111"
	tenantBeta  = "22222222-2222-4222-8222-222222222222"
)

type queryContext interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func databaseForUser(t *testing.T, baseDSN, username, password string) *sql.DB {
	t.Helper()
	parsed, err := url.Parse(baseDSN)
	if err != nil {
		t.Fatal(err)
	}
	parsed.User = url.UserPassword(username, password)
	db, err := sql.Open("pgx", parsed.String())
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if err := db.PingContext(context.Background()); err != nil {
		db.Close()
		t.Fatalf("connect as %s: %v", username, err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func markers(ctx context.Context, db queryContext) ([]string, error) {
	rows, err := db.QueryContext(ctx, "SELECT marker FROM tenant_data.rls_probe ORDER BY marker")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var values []string
	for rows.Next() {
		var marker string
		if err := rows.Scan(&marker); err != nil {
			return nil, err
		}
		values = append(values, marker)
	}
	return values, rows.Err()
}

func requireMarkers(t *testing.T, ctx context.Context, db queryContext, want ...string) {
	t.Helper()
	got, err := markers(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("visible markers = %v, want %v", got, want)
	}
}

func TestPostgreSQLTenantIsolation(t *testing.T) {
	appDSN := os.Getenv("KEEL_TEST_DATABASE_URL")
	if appDSN == "" {
		t.Skip("set KEEL_TEST_DATABASE_URL to a least-privilege Keel app database role")
	}
	agentPassword := os.Getenv("KEEL_TEST_AGENT_PASSWORD")
	if agentPassword == "" {
		t.Fatal("KEEL_TEST_AGENT_PASSWORD is required when PostgreSQL integration tests are enabled")
	}
	appDB := databaseForUser(t, appDSN, "keel_local_app", "keel-app-local-only")
	agentDB := databaseForUser(t, appDSN, "keel_local_agent_alpha", agentPassword)
	ctx := context.Background()
	alpha, err := ParseTenantID(tenantAlpha)
	if err != nil {
		t.Fatal(err)
	}
	beta, err := ParseTenantID(tenantBeta)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("app role sees only transaction-bound tenant and context does not leak", func(t *testing.T) {
		err := WithTenantTx(ctx, appDB, alpha, nil, func(tx *sql.Tx) error {
			requireMarkers(t, ctx, tx, "synthetic-alpha")
			var forced bool
			if err := tx.QueryRowContext(ctx, `SELECT relforcerowsecurity FROM pg_class AS c JOIN pg_namespace AS n ON n.oid = c.relnamespace WHERE n.nspname = 'tenant_data' AND c.relname = 'rls_probe'`).Scan(&forced); err != nil {
				return err
			}
			if !forced {
				t.Fatal("tenant table does not FORCE ROW LEVEL SECURITY")
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		requireMarkers(t, ctx, appDB)
		var contextAfterCommit string
		if err := appDB.QueryRowContext(ctx, `SELECT coalesce(nullif(current_setting('keel.tenant_id', true), ''), 'unset')`).Scan(&contextAfterCommit); err != nil {
			t.Fatal(err)
		}
		if contextAfterCommit != "unset" {
			t.Fatalf("transaction-local tenant context leaked across pooled connection: %q", contextAfterCommit)
		}
	})

	t.Run("bound agent identity overrides forged GUC and supplied tenant", func(t *testing.T) {
		// session_user mapping works even outside the wrapper; callers cannot select another tenant.
		requireMarkers(t, ctx, agentDB, "synthetic-alpha")
		err := WithTenantTx(ctx, agentDB, beta, nil, func(tx *sql.Tx) error {
			if _, err := tx.ExecContext(ctx, "SELECT set_config('keel.tenant_id', $1, true)", tenantBeta); err != nil {
				return err
			}
			requireMarkers(t, ctx, tx, "synthetic-alpha")
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		requireMarkers(t, ctx, agentDB, "synthetic-alpha")
	})

	t.Run("agent role cannot write", func(t *testing.T) {
		_, err := agentDB.ExecContext(ctx, `INSERT INTO tenant_data.rls_probe (tenant_id, probe_id, marker) VALUES ($1, 'cccccccc-cccc-4ccc-8ccc-cccccccccccc', 'forbidden')`, tenantAlpha)
		if err == nil {
			t.Fatal("read-only agent role unexpectedly inserted a row")
		}
		var state interface{ SQLState() string }
		if errors.As(err, &state) && state.SQLState() != "42501" {
			t.Fatalf("agent write failed with SQLSTATE %s, expected privilege denial 42501: %v", state.SQLState(), err)
		}
	})

	t.Run("agent cannot inherit the cross-tenant app role", func(t *testing.T) {
		var member bool
		if err := agentDB.QueryRowContext(ctx, `SELECT pg_catalog.pg_has_role(session_user, 'keel_app', 'MEMBER')`).Scan(&member); err != nil {
			t.Fatal(err)
		}
		if member {
			t.Fatal("tenant-bound agent login is a member of the cross-tenant app role")
		}
	})
}
