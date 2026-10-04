-- The repair role can inspect one tenant's blocked stream and change only retry eligibility.
CREATE TABLE keel_meta.outbox_repair_audit (
    request_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    aggregate_id uuid NOT NULL,
    event_id uuid NOT NULL,
    aggregate_version bigint NOT NULL CHECK (aggregate_version > 0),
    actor_ref text NOT NULL CHECK (actor_ref ~ '^(principal|service-principal):[A-Za-z0-9._~-]{1,120}$'),
    reason_code text NOT NULL CHECK (reason_code IN ('serializer_compatibility_fix', 'verified_storage_recovery', 'other_approved_change')),
    evidence_ref text NOT NULL CHECK (evidence_ref ~ '^(INC|CHG|OPS)-[A-Z0-9]{4,20}$'),
    prior_error_code text NOT NULL CHECK (prior_error_code = 'outbox_corrupt'),
    prior_attempt_count integer NOT NULL CHECK (prior_attempt_count >= 0),
    repaired_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (tenant_id, event_id, aggregate_id, aggregate_version)
        REFERENCES keel_meta.event_outbox (tenant_id, event_id, aggregate_id, aggregate_version)
);
CREATE INDEX outbox_repair_audit_stream_idx
    ON keel_meta.outbox_repair_audit (tenant_id, aggregate_id, event_id, aggregate_version, repaired_at DESC);

ALTER TABLE keel_meta.outbox_repair_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.outbox_repair_audit FORCE ROW LEVEL SECURITY;
CREATE POLICY outbox_repair_audit_operator_tenant ON keel_meta.outbox_repair_audit
    TO keel_operator USING (tenant_id = (SELECT keel_private.current_tenant_id()))
    WITH CHECK (tenant_id = (SELECT keel_private.current_tenant_id()));

CREATE POLICY order_events_operator_tenant ON keel_meta.order_events
    TO keel_operator USING (tenant_id = (SELECT keel_private.current_tenant_id()));
CREATE POLICY event_outbox_operator_tenant ON keel_meta.event_outbox
    TO keel_operator USING (tenant_id = (SELECT keel_private.current_tenant_id()));
CREATE POLICY outbox_delivery_operator_tenant ON keel_meta.outbox_delivery
    TO keel_operator USING (tenant_id = (SELECT keel_private.current_tenant_id()))
    WITH CHECK (tenant_id = (SELECT keel_private.current_tenant_id()));
CREATE POLICY outbox_publish_heads_operator_tenant ON keel_meta.outbox_publish_heads
    TO keel_operator USING (tenant_id = (SELECT keel_private.current_tenant_id()));

-- Even direct SQL through the restricted operator role cannot make a blocked event pending
-- unless the same tenant/event/version has a just-written audit record in this transaction.
CREATE FUNCTION keel_meta.require_outbox_repair_audit()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, keel_meta, pg_temp
AS $$
BEGIN
	IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname=session_user AND NOT rolsuper)
		AND pg_catalog.pg_has_role(session_user, 'keel_operator', 'MEMBER') AND NOT (
		OLD.delivery_state='blocked' AND NEW.delivery_state='pending'
		AND NEW.tenant_id=OLD.tenant_id AND NEW.aggregate_id=OLD.aggregate_id
		AND NEW.event_id=OLD.event_id AND NEW.aggregate_version=OLD.aggregate_version
		AND NEW.attempt_count=OLD.attempt_count AND NEW.last_error_code IS NOT DISTINCT FROM OLD.last_error_code
		AND NEW.published_at IS NOT DISTINCT FROM OLD.published_at AND NEW.created_at=OLD.created_at
		AND NEW.next_attempt_at >= OLD.updated_at AND NEW.updated_at >= OLD.updated_at
	) THEN
		RAISE EXCEPTION 'operator role may only requeue an audited blocked outbox delivery';
	END IF;
	IF OLD.delivery_state = 'blocked' AND NEW.delivery_state = 'pending' AND NOT EXISTS (
        SELECT 1 FROM keel_meta.outbox_repair_audit a
        WHERE a.tenant_id=NEW.tenant_id AND a.aggregate_id=NEW.aggregate_id
          AND a.event_id=NEW.event_id AND a.aggregate_version=NEW.aggregate_version
          AND a.repaired_at >= OLD.updated_at
    ) THEN
        RAISE EXCEPTION 'blocked outbox delivery requires a contemporaneous repair audit';
    END IF;
    RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION keel_meta.require_outbox_repair_audit() FROM PUBLIC;
CREATE TRIGGER outbox_delivery_repair_audit_guard
    BEFORE UPDATE ON keel_meta.outbox_delivery
    FOR EACH ROW EXECUTE FUNCTION keel_meta.require_outbox_repair_audit();

REVOKE ALL ON keel_meta.outbox_repair_audit FROM PUBLIC, keel_app, keel_worker, keel_projector, keel_agent;
GRANT USAGE ON SCHEMA keel_meta, keel_private TO keel_operator;
GRANT EXECUTE ON FUNCTION keel_private.current_tenant_id() TO keel_operator;
GRANT SELECT ON keel_meta.order_events, keel_meta.event_outbox,
    keel_meta.outbox_publish_heads TO keel_operator;
GRANT SELECT ON keel_meta.outbox_delivery TO keel_operator;
GRANT UPDATE (delivery_state, next_attempt_at, updated_at) ON keel_meta.outbox_delivery TO keel_operator;
GRANT SELECT, INSERT ON keel_meta.outbox_repair_audit TO keel_operator;
