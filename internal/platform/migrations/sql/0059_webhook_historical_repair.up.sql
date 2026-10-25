ALTER TABLE keel_meta.webhook_reconciliation_repair_runs
    ADD COLUMN skipped_identities integer NOT NULL DEFAULT 0
    CHECK (skipped_identities BETWEEN 0 AND 10000);

CREATE INDEX webhook_endpoint_status_history_lookup
    ON keel_meta.webhook_endpoint_status_history (tenant_id,endpoint_id,recorded_at DESC,version DESC);

DROP FUNCTION keel_meta.repair_webhook_reconciliation_run(text,text,text,integer);

CREATE FUNCTION keel_meta.repair_webhook_reconciliation_run(
    p_repair_id text,p_run_id text,p_requested_by text,p_limit integer)
RETURNS TABLE(r_repair_id text,r_gap_events integer,r_inserted_deliveries integer,r_skipped_identities integer)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,keel_meta,keel_private,pg_temp AS $$
DECLARE authorized_tenant uuid;
        selected_count integer;
        inserted_count integer;
        skipped_count integer;
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
    DROP TABLE IF EXISTS pg_temp.webhook_reconciliation_historical;
    DROP TABLE IF EXISTS pg_temp.webhook_reconciliation_candidates;
    DROP TABLE IF EXISTS pg_temp.webhook_reconciliation_repair_items;
    CREATE TEMP TABLE pg_temp.webhook_reconciliation_selected
        ON COMMIT DROP AS
        SELECT g.event_id,g.event_created_at
          FROM keel_meta.webhook_reconciliation_gaps g
         WHERE g.tenant_id=authorized_tenant AND g.run_id=p_run_id
         ORDER BY g.event_id
         LIMIT p_limit;
    CREATE TEMP TABLE pg_temp.webhook_reconciliation_historical
        ON COMMIT DROP AS
        SELECT s.event_id,s.event_created_at,e.endpoint_id,
               (SELECT h.status
                  FROM keel_meta.webhook_endpoint_status_history h
                 WHERE h.tenant_id=authorized_tenant AND h.endpoint_id=e.endpoint_id
                   AND h.recorded_at<=s.event_created_at
                 ORDER BY h.recorded_at DESC,h.version DESC
                 LIMIT 1) AS status_at,
               (SELECT h.subscription_version
                  FROM keel_meta.webhook_endpoint_status_history h
                 WHERE h.tenant_id=authorized_tenant AND h.endpoint_id=e.endpoint_id
                   AND h.recorded_at<=s.event_created_at
                 ORDER BY h.recorded_at DESC,h.version DESC
                 LIMIT 1) AS subscription_at
          FROM pg_temp.webhook_reconciliation_selected s
          JOIN keel_meta.webhook_endpoints e
            ON e.tenant_id=authorized_tenant AND e.status='active';
    skipped_count:=(SELECT count(*)::integer FROM pg_temp.webhook_reconciliation_historical h
                    WHERE h.status_at IS NULL OR h.status_at<>'active');
    CREATE TEMP TABLE pg_temp.webhook_reconciliation_candidates
        ON COMMIT DROP AS
        SELECT h.event_id,h.endpoint_id,h.subscription_at AS subscription_version,
               'whd_'||replace(gen_random_uuid()::text,'-','') AS delivery_id
          FROM pg_temp.webhook_reconciliation_historical h
          LEFT JOIN keel_meta.webhook_deliveries d
            ON d.tenant_id=authorized_tenant AND d.event_id=h.event_id::text
           AND d.endpoint_id=h.endpoint_id AND d.subscription_version=h.subscription_at
         WHERE h.status_at='active' AND d.delivery_id IS NULL;
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
        (tenant_id,repair_id,run_id,requested_by,gap_events,inserted_deliveries,skipped_identities)
    VALUES (authorized_tenant,p_repair_id,p_run_id,p_requested_by,selected_count,inserted_count,skipped_count);

    INSERT INTO keel_meta.webhook_reconciliation_repair_items
        (tenant_id,repair_id,event_id,endpoint_id,subscription_version,delivery_id)
    SELECT authorized_tenant,p_repair_id,event_id,endpoint_id,subscription_version,delivery_id
      FROM pg_temp.webhook_reconciliation_repair_items;

    RETURN QUERY SELECT p_repair_id,selected_count,inserted_count,skipped_count;
END $$;
REVOKE ALL ON FUNCTION keel_meta.repair_webhook_reconciliation_run(text,text,text,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION keel_meta.repair_webhook_reconciliation_run(text,text,text,integer)
    TO keel_operator;
