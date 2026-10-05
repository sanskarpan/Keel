-- Mutable delivery leases are deliberately separate from immutable case intents.
CREATE TABLE keel_meta.supplier_workflow_dispatch (
    tenant_id uuid NOT NULL,
    intent_id uuid NOT NULL,
    case_id uuid NOT NULL,
    aggregate_version bigint NOT NULL CHECK (aggregate_version BETWEEN 1 AND 102),
    intent_type text NOT NULL CHECK (intent_type IN (
        'supplier.case.created', 'supplier.case.evidence-added', 'supplier.case.submitted'
    )),
    event_hash bytea NOT NULL CHECK (octet_length(event_hash) = 32),
    dispatch_state text NOT NULL DEFAULT 'pending' CHECK (dispatch_state IN ('pending', 'leased', 'delivered', 'dead')),
    attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count BETWEEN 0 AND 12),
    available_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    lease_owner uuid,
    lease_epoch bigint NOT NULL DEFAULT 0 CHECK (lease_epoch >= 0),
    lease_expires_at timestamptz,
    delivered_at timestamptz,
    last_error_code text CHECK (last_error_code IS NULL OR last_error_code IN (
        'temporal_unavailable', 'temporal_timeout', 'invalid_intent', 'workflow_conflict', 'unknown'
    )),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, intent_id),
    UNIQUE (tenant_id, case_id, aggregate_version),
    FOREIGN KEY (tenant_id, intent_id)
        REFERENCES keel_meta.supplier_workflow_intents (tenant_id, intent_id),
    FOREIGN KEY (tenant_id, case_id, aggregate_version)
        REFERENCES keel_meta.supplier_case_events (tenant_id, case_id, aggregate_version),
    CHECK (
        (dispatch_state = 'leased' AND lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL)
        OR (dispatch_state <> 'leased' AND lease_owner IS NULL AND lease_expires_at IS NULL)
    ),
    CHECK ((dispatch_state = 'delivered') = (delivered_at IS NOT NULL)),
    CHECK (dispatch_state <> 'dead' OR (last_error_code IS NOT NULL AND attempt_count > 0))
);

CREATE INDEX supplier_workflow_dispatch_pending_idx
    ON keel_meta.supplier_workflow_dispatch (tenant_id, available_at, case_id, aggregate_version)
    WHERE dispatch_state IN ('pending', 'leased');

CREATE FUNCTION keel_meta.enqueue_supplier_workflow_dispatch()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, keel_meta, pg_temp
AS $$
DECLARE
    event_digest bytea;
BEGIN
    SELECT event_hash INTO event_digest
    FROM keel_meta.supplier_case_events
    WHERE tenant_id = NEW.tenant_id AND case_id = NEW.case_id
      AND aggregate_version = NEW.aggregate_version AND event_type = NEW.intent_type;
    IF event_digest IS NULL THEN
        RAISE EXCEPTION 'workflow intent does not match a canonical supplier case event';
    END IF;
    INSERT INTO keel_meta.supplier_workflow_dispatch
        (tenant_id, intent_id, case_id, aggregate_version, intent_type, event_hash)
    VALUES (NEW.tenant_id, NEW.intent_id, NEW.case_id, NEW.aggregate_version, NEW.intent_type, event_digest);
    RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION keel_meta.enqueue_supplier_workflow_dispatch() FROM PUBLIC;
CREATE POLICY supplier_case_event_dispatch_owner_read
    ON keel_meta.supplier_case_events FOR SELECT TO keel_schema_owner
    USING (true);
CREATE TRIGGER supplier_workflow_dispatch_enqueue
    AFTER INSERT ON keel_meta.supplier_workflow_intents
    FOR EACH ROW EXECUTE FUNCTION keel_meta.enqueue_supplier_workflow_dispatch();

INSERT INTO keel_meta.supplier_workflow_dispatch
    (tenant_id, intent_id, case_id, aggregate_version, intent_type, event_hash)
SELECT wi.tenant_id, wi.intent_id, wi.case_id, wi.aggregate_version, wi.intent_type, e.event_hash
FROM keel_meta.supplier_workflow_intents AS wi
JOIN keel_meta.supplier_case_events AS e
  ON e.tenant_id = wi.tenant_id AND e.case_id = wi.case_id
 AND e.aggregate_version = wi.aggregate_version AND e.event_type = wi.intent_type;

ALTER TABLE keel_meta.supplier_workflow_dispatch ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.supplier_workflow_dispatch FORCE ROW LEVEL SECURITY;
CREATE POLICY supplier_workflow_dispatch_worker_isolation
    ON keel_meta.supplier_workflow_dispatch FOR ALL TO keel_worker
    USING (tenant_id = (SELECT keel_private.current_tenant_id()))
    WITH CHECK (tenant_id = (SELECT keel_private.current_tenant_id()));
CREATE POLICY supplier_workflow_dispatch_owner_access
    ON keel_meta.supplier_workflow_dispatch FOR ALL TO keel_schema_owner
    USING (true) WITH CHECK (true);

REVOKE ALL ON keel_meta.supplier_workflow_dispatch FROM PUBLIC, keel_agent, keel_app,
    keel_file_processor, keel_operator, keel_projector;
GRANT SELECT, UPDATE ON keel_meta.supplier_workflow_dispatch TO keel_worker;
