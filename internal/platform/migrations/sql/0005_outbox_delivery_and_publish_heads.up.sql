-- Claims/delivery state is mutable metadata separate from immutable event and outbox content.
ALTER TABLE keel_meta.event_outbox
    ADD CONSTRAINT event_outbox_delivery_identity_unique
    UNIQUE (tenant_id, event_id, aggregate_id, aggregate_version);

CREATE TABLE keel_meta.outbox_delivery (
    tenant_id uuid NOT NULL,
    event_id uuid NOT NULL,
    aggregate_id uuid NOT NULL,
    aggregate_version bigint NOT NULL CHECK (aggregate_version > 0),
    delivery_state text NOT NULL DEFAULT 'pending' CHECK (delivery_state IN ('pending', 'published', 'blocked')),
    attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    next_attempt_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    last_error_code text CHECK (last_error_code IN ('broker_timeout', 'broker_unavailable', 'broker_rejected', 'broker_error', 'outbox_corrupt')),
    published_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, event_id),
    UNIQUE (tenant_id, aggregate_id, aggregate_version),
    CHECK ((delivery_state = 'published') = (published_at IS NOT NULL)),
    FOREIGN KEY (tenant_id, event_id, aggregate_id, aggregate_version)
        REFERENCES keel_meta.event_outbox (tenant_id, event_id, aggregate_id, aggregate_version)
);
CREATE INDEX outbox_delivery_pending_idx
    ON keel_meta.outbox_delivery (tenant_id, next_attempt_at, aggregate_id, aggregate_version)
    WHERE delivery_state = 'pending';

CREATE TABLE keel_meta.outbox_publish_heads (
    tenant_id uuid NOT NULL,
    aggregate_id uuid NOT NULL,
    next_version bigint NOT NULL CHECK (next_version > 0),
    claim_owner text,
    lease_epoch bigint NOT NULL DEFAULT 0 CHECK (lease_epoch >= 0),
    lease_expires_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, aggregate_id),
    CHECK ((claim_owner IS NULL) = (lease_expires_at IS NULL)),
    FOREIGN KEY (tenant_id, aggregate_id) REFERENCES keel_meta.order_heads (tenant_id, order_id)
);
CREATE INDEX outbox_publish_heads_lease_idx
    ON keel_meta.outbox_publish_heads (tenant_id, lease_expires_at, aggregate_id);

-- The forward migration may run after outbox rows already exist. Read them as the schema owner
-- just for this transaction, initialize every message as pending, then remove the broad policy.
CREATE POLICY event_outbox_migration_read ON keel_meta.event_outbox
    TO keel_schema_owner USING (true);
INSERT INTO keel_meta.outbox_delivery (tenant_id, event_id, aggregate_id, aggregate_version)
SELECT tenant_id, event_id, aggregate_id, aggregate_version
FROM keel_meta.event_outbox;
INSERT INTO keel_meta.outbox_publish_heads (tenant_id, aggregate_id, next_version)
SELECT tenant_id, aggregate_id, min(aggregate_version)
FROM keel_meta.event_outbox
GROUP BY tenant_id, aggregate_id;
DROP POLICY event_outbox_migration_read ON keel_meta.event_outbox;

ALTER TABLE keel_meta.outbox_delivery ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.outbox_delivery FORCE ROW LEVEL SECURITY;
CREATE POLICY outbox_delivery_app_tenant ON keel_meta.outbox_delivery
    TO keel_app USING (tenant_id = (SELECT keel_private.current_tenant_id()))
    WITH CHECK (tenant_id = (SELECT keel_private.current_tenant_id()));
CREATE POLICY outbox_delivery_worker_tenant ON keel_meta.outbox_delivery
    TO keel_worker USING (tenant_id = (SELECT keel_private.current_tenant_id()))
    WITH CHECK (tenant_id = (SELECT keel_private.current_tenant_id()));

ALTER TABLE keel_meta.outbox_publish_heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.outbox_publish_heads FORCE ROW LEVEL SECURITY;
CREATE POLICY outbox_publish_heads_app_tenant ON keel_meta.outbox_publish_heads
    TO keel_app USING (tenant_id = (SELECT keel_private.current_tenant_id()))
    WITH CHECK (tenant_id = (SELECT keel_private.current_tenant_id()));
CREATE POLICY outbox_publish_heads_worker_tenant ON keel_meta.outbox_publish_heads
    TO keel_worker USING (tenant_id = (SELECT keel_private.current_tenant_id()))
    WITH CHECK (tenant_id = (SELECT keel_private.current_tenant_id()));

REVOKE ALL ON keel_meta.outbox_delivery, keel_meta.outbox_publish_heads FROM PUBLIC;
GRANT SELECT, INSERT ON keel_meta.outbox_delivery TO keel_app;
GRANT SELECT ON keel_meta.outbox_delivery TO keel_worker;
GRANT UPDATE (delivery_state, attempt_count, next_attempt_at, last_error_code, published_at, updated_at)
    ON keel_meta.outbox_delivery TO keel_worker;
GRANT SELECT, INSERT ON keel_meta.outbox_publish_heads TO keel_app;
GRANT SELECT ON keel_meta.outbox_publish_heads TO keel_worker;
GRANT UPDATE (next_version, claim_owner, lease_epoch, lease_expires_at, updated_at)
    ON keel_meta.outbox_publish_heads TO keel_worker;
