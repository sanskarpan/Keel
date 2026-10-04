-- Deterministic synthetic fixture identities only; this is not Keel's production schema.
CREATE EXTENSION IF NOT EXISTS vector;
CREATE SCHEMA IF NOT EXISTS local_fixtures;
CREATE TABLE IF NOT EXISTS local_fixtures.tenants (
    tenant_id uuid PRIMARY KEY,
    tenant_key text NOT NULL UNIQUE,
    display_name text NOT NULL,
    created_at timestamptz NOT NULL
);
INSERT INTO local_fixtures.tenants (tenant_id, tenant_key, display_name, created_at)
VALUES
    ('11111111-1111-4111-8111-111111111111', 'synthetic-alpha', 'Synthetic Alpha', '2026-01-01T00:00:00Z'),
    ('22222222-2222-4222-8222-222222222222', 'synthetic-beta', 'Synthetic Beta', '2026-01-01T00:00:00Z')
ON CONFLICT (tenant_id) DO UPDATE
SET tenant_key = EXCLUDED.tenant_key,
    display_name = EXCLUDED.display_name,
    created_at = EXCLUDED.created_at;
