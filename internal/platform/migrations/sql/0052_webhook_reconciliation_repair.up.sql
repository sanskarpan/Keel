CREATE TABLE keel_meta.webhook_reconciliation_repair_runs (
    tenant_id uuid NOT NULL CHECK (tenant_id<>'00000000-0000-0000-0000-000000000000'::uuid),
    repair_id text NOT NULL CHECK (repair_id ~ '^[A-Za-z0-9_-]{8,64}$'),
    run_id text NOT NULL,
    requested_by text NOT NULL CHECK (requested_by ~ '^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}$'),
    gap_events integer NOT NULL CHECK (gap_events BETWEEN 0 AND 500),
    inserted_deliveries integer NOT NULL CHECK (inserted_deliveries BETWEEN 0 AND 10000),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id,repair_id),
    CONSTRAINT webhook_reconciliation_repair_runs_run_fk FOREIGN KEY (tenant_id,run_id)
        REFERENCES keel_meta.webhook_reconciliation_runs (tenant_id,run_id)
);
ALTER TABLE keel_meta.webhook_reconciliation_repair_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.webhook_reconciliation_repair_runs FORCE ROW LEVEL SECURITY;
CREATE POLICY webhook_reconciliation_repair_runs_schema_owner
    ON keel_meta.webhook_reconciliation_repair_runs TO keel_schema_owner USING (true) WITH CHECK (true);
REVOKE ALL ON keel_meta.webhook_reconciliation_repair_runs FROM PUBLIC,keel_app,keel_worker,keel_operator,
    keel_budget_control,keel_rate_control,keel_ai_worker,keel_projector,keel_file_processor,
    keel_retrieval_indexer,keel_context_vault,keel_context_policy,keel_context_erasure,
    keel_context_erasure_worker,keel_context_legal_hold,keel_context_replay,keel_agent,
    keel_callback,keel_webhook;

CREATE TABLE keel_meta.webhook_reconciliation_repair_items (
    tenant_id uuid NOT NULL,
    repair_id text NOT NULL,
    event_id uuid NOT NULL,
    endpoint_id text NOT NULL CHECK (endpoint_id ~ '^[A-Za-z0-9_-]{8,64}$'),
    subscription_version integer NOT NULL CHECK (subscription_version BETWEEN 1 AND 1000000),
    delivery_id text NOT NULL CHECK (delivery_id ~ '^[A-Za-z0-9_-]{8,64}$'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id,repair_id,event_id,endpoint_id),
    CONSTRAINT webhook_reconciliation_repair_items_run_fk FOREIGN KEY (tenant_id,repair_id)
        REFERENCES keel_meta.webhook_reconciliation_repair_runs (tenant_id,repair_id),
    CONSTRAINT webhook_reconciliation_repair_items_delivery_fk FOREIGN KEY (tenant_id,delivery_id)
        REFERENCES keel_meta.webhook_deliveries (tenant_id,delivery_id)
);
ALTER TABLE keel_meta.webhook_reconciliation_repair_items ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.webhook_reconciliation_repair_items FORCE ROW LEVEL SECURITY;
CREATE POLICY webhook_reconciliation_repair_items_schema_owner
    ON keel_meta.webhook_reconciliation_repair_items TO keel_schema_owner USING (true) WITH CHECK (true);
REVOKE ALL ON keel_meta.webhook_reconciliation_repair_items FROM PUBLIC,keel_app,keel_worker,keel_operator,
    keel_budget_control,keel_rate_control,keel_ai_worker,keel_projector,keel_file_processor,
    keel_retrieval_indexer,keel_context_vault,keel_context_policy,keel_context_erasure,
    keel_context_erasure_worker,keel_context_legal_hold,keel_context_replay,keel_agent,
    keel_callback,keel_webhook;

CREATE TRIGGER webhook_reconciliation_repair_run_immutable BEFORE UPDATE OR DELETE
    ON keel_meta.webhook_reconciliation_repair_runs FOR EACH ROW
    EXECUTE FUNCTION keel_meta.reject_webhook_reconciliation_mutation();
CREATE TRIGGER webhook_reconciliation_repair_item_immutable BEFORE UPDATE OR DELETE
    ON keel_meta.webhook_reconciliation_repair_items FOR EACH ROW
    EXECUTE FUNCTION keel_meta.reject_webhook_reconciliation_mutation();

CREATE FUNCTION keel_meta.repair_webhook_reconciliation_run(
    p_repair_id text,p_run_id text,p_requested_by text,p_limit integer)
RETURNS TABLE(r_repair_id text,r_gap_events integer,r_inserted_deliveries integer)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,keel_meta,keel_private,pg_temp AS $$
DECLARE authorized_tenant uuid;
        selected_count integer;
        inserted_count integer;
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'keel_operator','MEMBER') THEN
        RAISE EXCEPTION 'webhook reconciliation capability is required';
    END IF;
    authorized_tenant:=keel_private.current_tenant_id();
    IF authorized_tenant IS NULL OR
       p_repair_id IS NULL OR p_repair_id !~ '^[A-Za-z0-9_-]{8,64}$' OR
       p_run_id IS NULL OR p_run_id !~ '^[A-Za-z0-9_-]{8,64}$' OR
       p_requested_by IS NULL OR p_requested_by !~ '^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}$' OR
       p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 500 THEN
        RAISE EXCEPTION 'webhook reconciliation repair request is invalid';
    END IF;

    PERFORM pg_catalog.pg_advisory_xact_lock(
        pg_catalog.hashtextextended('keel.webhook.reconciliation.repair:'||authorized_tenant::text,0));

    IF NOT EXISTS (SELECT 1 FROM keel_meta.webhook_reconciliation_runs
                    WHERE tenant_id=authorized_tenant AND run_id=p_run_id) THEN
        RAISE EXCEPTION 'webhook reconciliation run was not found';
    END IF;
    IF EXISTS (SELECT 1 FROM keel_meta.webhook_reconciliation_repair_runs
                WHERE tenant_id=authorized_tenant AND repair_id=p_repair_id) THEN
        RAISE EXCEPTION 'webhook reconciliation repair already exists';
    END IF;

    DROP TABLE IF EXISTS pg_temp.webhook_reconciliation_selected;
    DROP TABLE IF EXISTS pg_temp.webhook_reconciliation_candidates;
    DROP TABLE IF EXISTS pg_temp.webhook_reconciliation_repair_items;
    CREATE TEMP TABLE pg_temp.webhook_reconciliation_selected
        ON COMMIT DROP AS
        SELECT g.event_id
          FROM keel_meta.webhook_reconciliation_gaps g
         WHERE g.tenant_id=authorized_tenant AND g.run_id=p_run_id
         ORDER BY g.event_id
         LIMIT p_limit;
    CREATE TEMP TABLE pg_temp.webhook_reconciliation_candidates
        ON COMMIT DROP AS
        SELECT s.event_id,e.endpoint_id,e.subscription_version,
               'whd_'||replace(gen_random_uuid()::text,'-','') AS delivery_id
          FROM pg_temp.webhook_reconciliation_selected s
          JOIN keel_meta.webhook_endpoints e
            ON e.tenant_id=authorized_tenant AND e.status='active'
          LEFT JOIN keel_meta.webhook_deliveries d
            ON d.tenant_id=authorized_tenant AND d.event_id=s.event_id::text
           AND d.endpoint_id=e.endpoint_id AND d.subscription_version=e.subscription_version
         WHERE d.delivery_id IS NULL;
    IF (SELECT count(*) FROM pg_temp.webhook_reconciliation_candidates)>10000 THEN
        RAISE EXCEPTION 'webhook reconciliation repair exceeds the delivery bound';
    END IF;
    CREATE TEMP TABLE pg_temp.webhook_reconciliation_repair_items
        (event_id uuid,endpoint_id text,subscription_version integer,delivery_id text)
        ON COMMIT DROP;

    WITH inserted AS (
        INSERT INTO keel_meta.webhook_deliveries
            (tenant_id,event_id,endpoint_id,subscription_version,delivery_id)
        SELECT authorized_tenant,c.event_id::text,c.endpoint_id,c.subscription_version,c.delivery_id
          FROM pg_temp.webhook_reconciliation_candidates c
        ON CONFLICT (tenant_id,event_id,endpoint_id,subscription_version) DO NOTHING
        RETURNING event_id::uuid AS event_id,endpoint_id,subscription_version,delivery_id)
    INSERT INTO pg_temp.webhook_reconciliation_repair_items
    SELECT event_id,endpoint_id,subscription_version,delivery_id FROM inserted;

    selected_count:=(SELECT count(*) FROM pg_temp.webhook_reconciliation_selected);
    inserted_count:=(SELECT count(*) FROM pg_temp.webhook_reconciliation_repair_items);

    INSERT INTO keel_meta.webhook_reconciliation_repair_runs
        (tenant_id,repair_id,run_id,requested_by,gap_events,inserted_deliveries)
    VALUES (authorized_tenant,p_repair_id,p_run_id,p_requested_by,selected_count,inserted_count);

    INSERT INTO keel_meta.webhook_reconciliation_repair_items
        (tenant_id,repair_id,event_id,endpoint_id,subscription_version,delivery_id)
    SELECT authorized_tenant,p_repair_id,event_id,endpoint_id,subscription_version,delivery_id
      FROM pg_temp.webhook_reconciliation_repair_items;

    RETURN QUERY SELECT p_repair_id,selected_count,inserted_count;
END $$;
REVOKE ALL ON FUNCTION keel_meta.repair_webhook_reconciliation_run(text,text,text,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION keel_meta.repair_webhook_reconciliation_run(text,text,text,integer)
    TO keel_operator;
