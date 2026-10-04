CREATE TABLE keel_meta.event_outbox (
    tenant_id uuid NOT NULL,
    event_id uuid NOT NULL,
    aggregate_id uuid NOT NULL,
    aggregate_version bigint NOT NULL CHECK (aggregate_version > 0),
    event_type text NOT NULL CHECK (event_type IN ('order.created', 'order.submitted', 'order.verification_started', 'order.approved', 'order.rejected', 'order.canceled')),
    schema_version integer NOT NULL CHECK (schema_version > 0),
    safe_envelope jsonb NOT NULL CHECK (jsonb_typeof(safe_envelope) = 'object'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, event_id),
    UNIQUE (tenant_id, aggregate_id, aggregate_version),
    FOREIGN KEY (tenant_id, event_id) REFERENCES keel_meta.order_events (tenant_id, event_id)
);
CREATE INDEX event_outbox_aggregate_order_idx ON keel_meta.event_outbox (tenant_id, aggregate_id, aggregate_version);

CREATE TABLE keel_meta.state_feed_counters (
    tenant_id uuid PRIMARY KEY,
    last_sequence bigint NOT NULL DEFAULT 0 CHECK (last_sequence >= 0),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE keel_meta.state_updates (
    tenant_id uuid NOT NULL,
    sequence bigint NOT NULL CHECK (sequence > 0),
    event_id uuid NOT NULL,
    aggregate_id uuid NOT NULL,
    aggregate_version bigint NOT NULL CHECK (aggregate_version > 0),
    update_kind text NOT NULL CHECK (update_kind = 'order.changed'),
    safe_payload jsonb NOT NULL CHECK (jsonb_typeof(safe_payload) = 'object'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, sequence),
    UNIQUE (tenant_id, event_id),
    FOREIGN KEY (tenant_id, event_id) REFERENCES keel_meta.order_events (tenant_id, event_id)
);
CREATE INDEX state_updates_aggregate_order_idx ON keel_meta.state_updates (tenant_id, aggregate_id, aggregate_version);

ALTER TABLE keel_meta.event_outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.event_outbox FORCE ROW LEVEL SECURITY;
CREATE POLICY event_outbox_tenant_isolation ON keel_meta.event_outbox
    TO keel_app, keel_worker USING (tenant_id = (SELECT keel_private.current_tenant_id()))
    WITH CHECK (tenant_id = (SELECT keel_private.current_tenant_id()));

ALTER TABLE keel_meta.state_feed_counters ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.state_feed_counters FORCE ROW LEVEL SECURITY;
CREATE POLICY state_feed_counters_tenant_isolation ON keel_meta.state_feed_counters
    TO keel_app USING (tenant_id = (SELECT keel_private.current_tenant_id()))
    WITH CHECK (tenant_id = (SELECT keel_private.current_tenant_id()));

ALTER TABLE keel_meta.state_updates ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.state_updates FORCE ROW LEVEL SECURITY;
CREATE POLICY state_updates_tenant_isolation ON keel_meta.state_updates
    TO keel_app, keel_worker USING (tenant_id = (SELECT keel_private.current_tenant_id()))
    WITH CHECK (tenant_id = (SELECT keel_private.current_tenant_id()));

REVOKE ALL ON keel_meta.event_outbox, keel_meta.state_feed_counters, keel_meta.state_updates FROM PUBLIC;
GRANT SELECT, INSERT ON keel_meta.event_outbox TO keel_app;
GRANT SELECT ON keel_meta.event_outbox TO keel_worker;
GRANT SELECT, INSERT, UPDATE (last_sequence, updated_at) ON keel_meta.state_feed_counters TO keel_app;
GRANT SELECT, INSERT ON keel_meta.state_updates TO keel_app;
GRANT SELECT ON keel_meta.state_updates TO keel_worker;
REVOKE UPDATE, DELETE, TRUNCATE ON keel_meta.order_events, keel_meta.event_outbox, keel_meta.state_updates FROM keel_app, keel_worker, PUBLIC;
