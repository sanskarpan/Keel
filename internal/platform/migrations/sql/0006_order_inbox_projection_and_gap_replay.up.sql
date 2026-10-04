-- Projection state is deliberately smaller than protected command snapshots. The broker only
-- carries the allowlisted identity envelope; source-of-truth replay reads that same envelope.
CREATE TABLE keel_meta.order_projections (
    tenant_id uuid NOT NULL,
    aggregate_id uuid NOT NULL,
    applied_version bigint NOT NULL DEFAULT 0 CHECK (applied_version >= 0),
    status text CHECK (status IN ('draft', 'submitted', 'verifying', 'approved', 'rejected', 'canceled')),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, aggregate_id),
    CHECK ((applied_version = 0) = (status IS NULL)),
    FOREIGN KEY (tenant_id, aggregate_id) REFERENCES keel_meta.order_heads (tenant_id, order_id)
);

CREATE TABLE keel_meta.event_inbox (
    tenant_id uuid NOT NULL,
    consumer_id text NOT NULL CHECK (consumer_id = 'order-projection-v1'),
    event_id uuid NOT NULL,
    aggregate_id uuid NOT NULL,
    aggregate_version bigint NOT NULL CHECK (aggregate_version > 0),
    event_type text NOT NULL CHECK (event_type IN ('order.created', 'order.submitted', 'order.verification_started', 'order.approved', 'order.rejected', 'order.canceled')),
    envelope_hash bytea NOT NULL CHECK (octet_length(envelope_hash) = 32),
    delivery_source text NOT NULL CHECK (delivery_source IN ('broker', 'replay')),
    apply_state text NOT NULL CHECK (apply_state IN ('applied', 'deferred', 'quarantined')),
    received_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    applied_at timestamptz,
    PRIMARY KEY (tenant_id, consumer_id, event_id),
    UNIQUE (tenant_id, consumer_id, aggregate_id, aggregate_version),
    CHECK ((apply_state = 'applied') = (applied_at IS NOT NULL)),
    FOREIGN KEY (tenant_id, event_id, aggregate_id, aggregate_version)
        REFERENCES keel_meta.event_outbox (tenant_id, event_id, aggregate_id, aggregate_version)
);
CREATE INDEX event_inbox_aggregate_apply_idx
    ON keel_meta.event_inbox (tenant_id, consumer_id, aggregate_id, aggregate_version, apply_state);

CREATE TABLE keel_meta.deferred_events (
    tenant_id uuid NOT NULL,
    consumer_id text NOT NULL CHECK (consumer_id = 'order-projection-v1'),
    aggregate_id uuid NOT NULL,
    aggregate_version bigint NOT NULL CHECK (aggregate_version > 0),
    event_id uuid NOT NULL,
    expected_version bigint NOT NULL CHECK (expected_version > 0),
    retry_count integer NOT NULL DEFAULT 0 CHECK (retry_count >= 0),
    next_attempt_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'blocked')),
    last_error_code text CHECK (last_error_code IN ('source_event_missing', 'source_event_invalid')),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, consumer_id, aggregate_id, aggregate_version),
    UNIQUE (tenant_id, consumer_id, event_id),
    FOREIGN KEY (tenant_id, consumer_id, event_id)
        REFERENCES keel_meta.event_inbox (tenant_id, consumer_id, event_id)
);
CREATE INDEX deferred_events_due_idx
    ON keel_meta.deferred_events (tenant_id, next_attempt_at, aggregate_id, aggregate_version)
    WHERE state = 'pending';

-- Store hashes and bounded classifications only. Never persist an untrusted raw broker payload.
CREATE TABLE keel_meta.event_quarantine (
    tenant_id uuid NOT NULL,
    consumer_id text NOT NULL CHECK (consumer_id = 'order-projection-v1'),
    event_id uuid NOT NULL,
    aggregate_id uuid NOT NULL,
    aggregate_version bigint NOT NULL CHECK (aggregate_version > 0),
    envelope_hash bytea NOT NULL CHECK (octet_length(envelope_hash) = 32),
    reason_code text NOT NULL CHECK (reason_code IN ('source_mismatch', 'event_id_conflict', 'version_conflict', 'invalid_transition', 'source_event_missing', 'source_event_invalid')),
    quarantined_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, consumer_id, event_id, envelope_hash, reason_code)
);
CREATE INDEX event_quarantine_recent_idx
    ON keel_meta.event_quarantine (tenant_id, quarantined_at DESC);

-- Malformed messages may have no valid tenant/event identity. Store only trusted Kafka
-- coordinates, a digest, and an allowlisted reason; never retain raw bytes or payload fields.
CREATE TABLE keel_meta.transport_quarantine (
    source_topic text NOT NULL CHECK (source_topic ~ '^keel[.][a-z0-9-]+[.]orders[.]v1$'),
    partition_id integer NOT NULL CHECK (partition_id >= 0),
    message_offset bigint NOT NULL CHECK (message_offset >= 0),
    payload_hash bytea NOT NULL CHECK (octet_length(payload_hash) = 32),
    reason_code text NOT NULL CHECK (reason_code IN ('invalid_record', 'unsupported_schema', 'source_mismatch')),
    quarantined_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (source_topic, partition_id, message_offset)
);

ALTER TABLE keel_meta.order_projections ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.order_projections FORCE ROW LEVEL SECURITY;
CREATE POLICY order_projections_tenant_isolation ON keel_meta.order_projections
    TO keel_app, keel_projector USING (tenant_id = (SELECT keel_private.current_tenant_id()))
    WITH CHECK (tenant_id = (SELECT keel_private.current_tenant_id()));

ALTER TABLE keel_meta.event_inbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.event_inbox FORCE ROW LEVEL SECURITY;
CREATE POLICY event_inbox_projector_tenant ON keel_meta.event_inbox
    TO keel_projector USING (tenant_id = (SELECT keel_private.current_tenant_id()))
    WITH CHECK (tenant_id = (SELECT keel_private.current_tenant_id()));

ALTER TABLE keel_meta.deferred_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.deferred_events FORCE ROW LEVEL SECURITY;
CREATE POLICY deferred_events_projector_tenant ON keel_meta.deferred_events
    TO keel_projector USING (tenant_id = (SELECT keel_private.current_tenant_id()))
    WITH CHECK (tenant_id = (SELECT keel_private.current_tenant_id()));

ALTER TABLE keel_meta.event_quarantine ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.event_quarantine FORCE ROW LEVEL SECURITY;
CREATE POLICY event_quarantine_projector_tenant ON keel_meta.event_quarantine
    TO keel_projector USING (tenant_id = (SELECT keel_private.current_tenant_id()))
    WITH CHECK (tenant_id = (SELECT keel_private.current_tenant_id()));

ALTER TABLE keel_meta.transport_quarantine ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.transport_quarantine FORCE ROW LEVEL SECURITY;
CREATE POLICY transport_quarantine_projector_insert ON keel_meta.transport_quarantine
    FOR INSERT TO keel_projector WITH CHECK (true);
-- Kafka coordinates and hashes are global transport metadata, not tenant payload. The projector
-- can inspect only those fields so duplicate offsets can be verified without exposing raw bytes.
CREATE POLICY transport_quarantine_projector_read ON keel_meta.transport_quarantine
    FOR SELECT TO keel_projector USING (true);

REVOKE ALL ON keel_meta.order_projections, keel_meta.event_inbox, keel_meta.deferred_events, keel_meta.event_quarantine, keel_meta.transport_quarantine FROM PUBLIC;
GRANT USAGE ON SCHEMA keel_meta TO keel_projector;
GRANT SELECT ON keel_meta.order_projections TO keel_app;
GRANT SELECT, INSERT, UPDATE (applied_version, status, updated_at) ON keel_meta.order_projections TO keel_projector;
GRANT SELECT, INSERT, UPDATE (apply_state, applied_at) ON keel_meta.event_inbox TO keel_projector;
GRANT SELECT, INSERT, UPDATE (expected_version, retry_count, next_attempt_at, state, last_error_code, updated_at), DELETE
    ON keel_meta.deferred_events TO keel_projector;
GRANT SELECT, INSERT ON keel_meta.event_quarantine TO keel_projector;
GRANT SELECT ON keel_meta.event_outbox TO keel_projector;
GRANT SELECT (source_topic, partition_id, message_offset, payload_hash, reason_code), INSERT
    ON keel_meta.transport_quarantine TO keel_projector;

CREATE POLICY event_outbox_projector_tenant ON keel_meta.event_outbox
    TO keel_projector USING (tenant_id = (SELECT keel_private.current_tenant_id()));
