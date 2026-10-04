CREATE TABLE keel_meta.order_heads (
    tenant_id uuid NOT NULL,
    order_id uuid NOT NULL,
    external_reference text COLLATE "C" NOT NULL CHECK (length(external_reference) BETWEEN 1 AND 128),
    supplier_id uuid NOT NULL,
    status text NOT NULL CHECK (status IN ('draft', 'submitted', 'verifying', 'approved', 'rejected', 'canceled')),
    version bigint NOT NULL CHECK (version > 0),
    command_snapshot jsonb NOT NULL CHECK (jsonb_typeof(command_snapshot) = 'object'),
    snapshot_hash bytea NOT NULL CHECK (octet_length(snapshot_hash) = 32),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, order_id),
    UNIQUE (tenant_id, external_reference)
);

CREATE TABLE keel_meta.order_events (
    tenant_id uuid NOT NULL,
    order_id uuid NOT NULL,
    aggregate_version bigint NOT NULL CHECK (aggregate_version > 0),
    event_id uuid NOT NULL,
    event_type text NOT NULL CHECK (event_type IN ('order.created', 'order.submitted', 'order.verification_started', 'order.approved', 'order.rejected', 'order.canceled')),
    event_data jsonb NOT NULL CHECK (jsonb_typeof(event_data) = 'object'),
    event_hash bytea NOT NULL CHECK (octet_length(event_hash) = 32),
    occurred_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, order_id, aggregate_version),
    UNIQUE (tenant_id, event_id),
    FOREIGN KEY (tenant_id, order_id) REFERENCES keel_meta.order_heads (tenant_id, order_id)
);

CREATE TABLE keel_meta.idempotency_dedup (
    tenant_id uuid NOT NULL,
    route text NOT NULL CHECK (route IN ('POST /v1/orders', 'POST /v1/orders/{order_id}/submit')),
    key_digest bytea NOT NULL CHECK (octet_length(key_digest) = 32),
    principal_binding_hash bytea NOT NULL CHECK (octet_length(principal_binding_hash) = 32),
    request_hash bytea NOT NULL CHECK (octet_length(request_hash) = 32),
    operation_ref uuid,
    outcome_state text NOT NULL CHECK (outcome_state IN ('in_progress', 'completed', 'rejected')),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    completed_at timestamptz,
    PRIMARY KEY (tenant_id, route, key_digest),
    CHECK ((outcome_state = 'in_progress') = (completed_at IS NULL)),
    CHECK ((outcome_state = 'completed') = (operation_ref IS NOT NULL)),
    FOREIGN KEY (tenant_id, operation_ref) REFERENCES keel_meta.order_heads (tenant_id, order_id) DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE keel_meta.idempotency_requests (
    tenant_id uuid NOT NULL,
    route text NOT NULL,
    key_digest bytea NOT NULL CHECK (octet_length(key_digest) = 32),
    request_hash bytea NOT NULL CHECK (octet_length(request_hash) = 32),
    response_body jsonb NOT NULL CHECK (jsonb_typeof(response_body) = 'object'),
    error_code text,
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, route, key_digest),
    FOREIGN KEY (tenant_id, route, key_digest) REFERENCES keel_meta.idempotency_dedup (tenant_id, route, key_digest)
);
CREATE INDEX idempotency_requests_expiry_idx ON keel_meta.idempotency_requests (tenant_id, expires_at);

ALTER TABLE keel_meta.order_heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.order_heads FORCE ROW LEVEL SECURITY;
CREATE POLICY order_heads_tenant_isolation ON keel_meta.order_heads
    TO keel_app USING (tenant_id = (SELECT keel_private.current_tenant_id()))
    WITH CHECK (tenant_id = (SELECT keel_private.current_tenant_id()));

ALTER TABLE keel_meta.order_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.order_events FORCE ROW LEVEL SECURITY;
CREATE POLICY order_events_tenant_isolation ON keel_meta.order_events
    TO keel_app USING (tenant_id = (SELECT keel_private.current_tenant_id()))
    WITH CHECK (tenant_id = (SELECT keel_private.current_tenant_id()));

ALTER TABLE keel_meta.idempotency_dedup ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.idempotency_dedup FORCE ROW LEVEL SECURITY;
CREATE POLICY idempotency_dedup_tenant_isolation ON keel_meta.idempotency_dedup
    TO keel_app USING (tenant_id = (SELECT keel_private.current_tenant_id()))
    WITH CHECK (tenant_id = (SELECT keel_private.current_tenant_id()));

ALTER TABLE keel_meta.idempotency_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.idempotency_requests FORCE ROW LEVEL SECURITY;
CREATE POLICY idempotency_requests_tenant_isolation ON keel_meta.idempotency_requests
    TO keel_app, keel_worker USING (tenant_id = (SELECT keel_private.current_tenant_id()))
    WITH CHECK (tenant_id = (SELECT keel_private.current_tenant_id()));

REVOKE ALL ON keel_meta.order_heads, keel_meta.order_events, keel_meta.idempotency_dedup, keel_meta.idempotency_requests FROM PUBLIC;
GRANT USAGE ON SCHEMA keel_meta TO keel_app, keel_worker;
GRANT SELECT, INSERT ON keel_meta.order_heads TO keel_app;
GRANT UPDATE (version, command_snapshot, snapshot_hash, status, updated_at) ON keel_meta.order_heads TO keel_app;
GRANT SELECT, INSERT ON keel_meta.order_events TO keel_app;
GRANT SELECT, INSERT ON keel_meta.idempotency_dedup TO keel_app;
GRANT UPDATE (operation_ref, outcome_state, completed_at) ON keel_meta.idempotency_dedup TO keel_app;
GRANT SELECT, INSERT ON keel_meta.idempotency_requests TO keel_app;
GRANT SELECT, DELETE ON keel_meta.idempotency_requests TO keel_worker;
