-- Base role/bootstrap DDL for the local synthetic profile. Production role credentials
-- are provisioned and rotated separately; these local passwords are not deployable.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'keel_schema_owner') THEN
        CREATE ROLE keel_schema_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'keel_context_owner') THEN
        CREATE ROLE keel_context_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'keel_app') THEN
        CREATE ROLE keel_app NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'keel_worker') THEN
        CREATE ROLE keel_worker NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'keel_agent') THEN
        CREATE ROLE keel_agent NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'keel_local_app') THEN
        CREATE ROLE keel_local_app LOGIN PASSWORD 'keel-app-local-only' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'keel_local_worker') THEN
        CREATE ROLE keel_local_worker LOGIN PASSWORD 'keel-worker-local-only' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'keel_local_agent_alpha') THEN
        CREATE ROLE keel_local_agent_alpha LOGIN PASSWORD 'keel-agent-local-only' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'keel_local_agent_beta') THEN
        CREATE ROLE keel_local_agent_beta LOGIN PASSWORD 'keel-agent-local-only' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'keel_local_migrator') THEN
        CREATE ROLE keel_local_migrator LOGIN PASSWORD 'keel-migrate-local-only' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
    END IF;
END
$$;

ALTER ROLE keel_schema_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
ALTER ROLE keel_context_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
ALTER ROLE keel_app NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
ALTER ROLE keel_worker NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
ALTER ROLE keel_agent NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
ALTER ROLE keel_local_app LOGIN PASSWORD 'keel-app-local-only' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
ALTER ROLE keel_local_worker LOGIN PASSWORD 'keel-worker-local-only' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
ALTER ROLE keel_local_agent_alpha LOGIN PASSWORD 'keel-agent-local-only' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
ALTER ROLE keel_local_agent_beta LOGIN PASSWORD 'keel-agent-local-only' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
ALTER ROLE keel_local_migrator LOGIN PASSWORD 'keel-migrate-local-only' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;

GRANT keel_app TO keel_local_app;
GRANT keel_worker TO keel_local_worker;
GRANT keel_agent TO keel_local_agent_alpha;
GRANT keel_agent TO keel_local_agent_beta;
GRANT keel_schema_owner TO keel_local_migrator;

REVOKE CREATE ON SCHEMA public FROM PUBLIC;
CREATE SCHEMA IF NOT EXISTS keel_private AUTHORIZATION keel_context_owner;
CREATE SCHEMA IF NOT EXISTS tenant_data AUTHORIZATION keel_schema_owner;
CREATE SCHEMA IF NOT EXISTS keel_meta AUTHORIZATION keel_schema_owner;
ALTER SCHEMA keel_private OWNER TO keel_context_owner;
ALTER SCHEMA tenant_data OWNER TO keel_schema_owner;
ALTER SCHEMA keel_meta OWNER TO keel_schema_owner;
REVOKE ALL ON SCHEMA keel_meta FROM PUBLIC;
GRANT USAGE ON SCHEMA keel_private TO keel_app, keel_worker, keel_agent;
GRANT USAGE ON SCHEMA tenant_data TO keel_app, keel_worker, keel_agent;

SET ROLE keel_context_owner;
CREATE TABLE IF NOT EXISTS keel_private.agent_role_tenant (
    role_name name PRIMARY KEY,
    tenant_id uuid NOT NULL,
    provisioned_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
REVOKE ALL ON keel_private.agent_role_tenant FROM PUBLIC, keel_app, keel_worker, keel_agent;
CREATE OR REPLACE FUNCTION keel_private.current_tenant_id()
RETURNS uuid
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, keel_private, pg_temp
AS $$
    SELECT CASE
        WHEN pg_catalog.pg_has_role(session_user, 'keel_agent', 'MEMBER') THEN (
            SELECT mapping.tenant_id
            FROM keel_private.agent_role_tenant AS mapping
            WHERE mapping.role_name = session_user::name
        )
        ELSE nullif(pg_catalog.current_setting('keel.tenant_id', true), '')::uuid
    END
$$;
REVOKE ALL ON FUNCTION keel_private.current_tenant_id() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION keel_private.current_tenant_id() TO keel_app, keel_worker, keel_agent;
RESET ROLE;
GRANT USAGE ON SCHEMA keel_private TO keel_schema_owner;
GRANT EXECUTE ON FUNCTION keel_private.current_tenant_id() TO keel_schema_owner;

SET ROLE keel_schema_owner;
CREATE TABLE IF NOT EXISTS tenant_data.rls_probe (
    tenant_id uuid NOT NULL,
    probe_id uuid NOT NULL,
    marker text NOT NULL CHECK (length(marker) BETWEEN 1 AND 80),
    PRIMARY KEY (tenant_id, probe_id)
);
ALTER TABLE tenant_data.rls_probe ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_data.rls_probe FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON tenant_data.rls_probe;
CREATE POLICY tenant_isolation ON tenant_data.rls_probe
    TO keel_app, keel_worker, keel_agent
    USING (tenant_id = (SELECT keel_private.current_tenant_id()))
    WITH CHECK (tenant_id = (SELECT keel_private.current_tenant_id()));
RESET ROLE;

GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_data.rls_probe TO keel_app;
GRANT SELECT, INSERT, UPDATE ON tenant_data.rls_probe TO keel_worker;
GRANT SELECT ON tenant_data.rls_probe TO keel_agent;

INSERT INTO keel_private.agent_role_tenant (role_name, tenant_id)
VALUES
    ('keel_local_agent_alpha', '11111111-1111-4111-8111-111111111111'),
    ('keel_local_agent_beta', '22222222-2222-4222-8222-222222222222')
ON CONFLICT (role_name) DO UPDATE SET tenant_id = EXCLUDED.tenant_id;

INSERT INTO tenant_data.rls_probe (tenant_id, probe_id, marker)
VALUES
    ('11111111-1111-4111-8111-111111111111', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'synthetic-alpha'),
    ('22222222-2222-4222-8222-222222222222', 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', 'synthetic-beta')
ON CONFLICT (tenant_id, probe_id) DO UPDATE SET marker = EXCLUDED.marker;
