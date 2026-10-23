CREATE INDEX event_outbox_reconciliation_cursor
    ON keel_meta.event_outbox (tenant_id,created_at,event_id);

CREATE TABLE keel_meta.webhook_reconciliation_cursors (
    tenant_id uuid PRIMARY KEY CHECK (tenant_id<>'00000000-0000-0000-0000-000000000000'::uuid),
    last_event_created_at timestamptz NOT NULL,
    last_event_id uuid NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
ALTER TABLE keel_meta.webhook_reconciliation_cursors ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.webhook_reconciliation_cursors FORCE ROW LEVEL SECURITY;
CREATE POLICY webhook_reconciliation_cursors_schema_owner
    ON keel_meta.webhook_reconciliation_cursors TO keel_schema_owner USING (true) WITH CHECK (true);
REVOKE ALL ON keel_meta.webhook_reconciliation_cursors FROM PUBLIC,keel_app,keel_worker,keel_operator,
    keel_budget_control,keel_rate_control,keel_ai_worker,keel_projector,keel_file_processor,
    keel_retrieval_indexer,keel_context_vault,keel_context_policy,keel_context_erasure,
    keel_context_erasure_worker,keel_context_legal_hold,keel_context_replay,keel_agent,
    keel_callback,keel_webhook;

CREATE TABLE keel_meta.webhook_reconciliation_runs (
    tenant_id uuid NOT NULL CHECK (tenant_id<>'00000000-0000-0000-0000-000000000000'::uuid),
    run_id text NOT NULL CHECK (run_id ~ '^[A-Za-z0-9_-]{8,64}$'),
    requested_by text NOT NULL CHECK (requested_by ~ '^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}$'),
    from_created_at timestamptz NOT NULL,
    cursor_from_created_at timestamptz,
    cursor_from_event_id uuid,
    cursor_to_created_at timestamptz,
    cursor_to_event_id uuid,
    events_scanned integer NOT NULL CHECK (events_scanned BETWEEN 0 AND 500),
    gap_events integer NOT NULL CHECK (gap_events BETWEEN 0 AND 500),
    missing_deliveries bigint NOT NULL CHECK (missing_deliveries>=0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id,run_id),
    CONSTRAINT webhook_reconciliation_runs_cursor_shape CHECK (
        (cursor_from_created_at IS NULL)=(cursor_from_event_id IS NULL) AND
        (cursor_to_created_at IS NULL)=(cursor_to_event_id IS NULL)),
    CONSTRAINT webhook_reconciliation_runs_gaps CHECK (gap_events<=events_scanned)
);
ALTER TABLE keel_meta.webhook_reconciliation_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.webhook_reconciliation_runs FORCE ROW LEVEL SECURITY;
CREATE POLICY webhook_reconciliation_runs_schema_owner
    ON keel_meta.webhook_reconciliation_runs TO keel_schema_owner USING (true) WITH CHECK (true);
REVOKE ALL ON keel_meta.webhook_reconciliation_runs FROM PUBLIC,keel_app,keel_worker,keel_operator,
    keel_budget_control,keel_rate_control,keel_ai_worker,keel_projector,keel_file_processor,
    keel_retrieval_indexer,keel_context_vault,keel_context_policy,keel_context_erasure,
    keel_context_erasure_worker,keel_context_legal_hold,keel_context_replay,keel_agent,
    keel_callback,keel_webhook;

CREATE TABLE keel_meta.webhook_reconciliation_gaps (
    tenant_id uuid NOT NULL,
    run_id text NOT NULL,
    event_id uuid NOT NULL,
    event_created_at timestamptz NOT NULL,
    missing_count integer NOT NULL CHECK (missing_count BETWEEN 1 AND 1000000),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id,run_id,event_id),
    CONSTRAINT webhook_reconciliation_gaps_run_fk FOREIGN KEY (tenant_id,run_id)
        REFERENCES keel_meta.webhook_reconciliation_runs (tenant_id,run_id)
);
ALTER TABLE keel_meta.webhook_reconciliation_gaps ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.webhook_reconciliation_gaps FORCE ROW LEVEL SECURITY;
CREATE POLICY webhook_reconciliation_gaps_schema_owner
    ON keel_meta.webhook_reconciliation_gaps TO keel_schema_owner USING (true) WITH CHECK (true);
REVOKE ALL ON keel_meta.webhook_reconciliation_gaps FROM PUBLIC,keel_app,keel_worker,keel_operator,
    keel_budget_control,keel_rate_control,keel_ai_worker,keel_projector,keel_file_processor,
    keel_retrieval_indexer,keel_context_vault,keel_context_policy,keel_context_erasure,
    keel_context_erasure_worker,keel_context_legal_hold,keel_context_replay,keel_agent,
    keel_callback,keel_webhook;

CREATE FUNCTION keel_meta.reject_webhook_reconciliation_mutation()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    RAISE EXCEPTION 'webhook reconciliation history is immutable';
END $$;
CREATE TRIGGER webhook_reconciliation_run_immutable BEFORE UPDATE OR DELETE
    ON keel_meta.webhook_reconciliation_runs FOR EACH ROW
    EXECUTE FUNCTION keel_meta.reject_webhook_reconciliation_mutation();
CREATE TRIGGER webhook_reconciliation_gap_immutable BEFORE UPDATE OR DELETE
    ON keel_meta.webhook_reconciliation_gaps FOR EACH ROW
    EXECUTE FUNCTION keel_meta.reject_webhook_reconciliation_mutation();
REVOKE ALL ON FUNCTION keel_meta.reject_webhook_reconciliation_mutation() FROM PUBLIC;

CREATE FUNCTION keel_meta.guard_webhook_reconciliation_cursor()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    IF TG_OP='DELETE' THEN
        RAISE EXCEPTION 'webhook reconciliation cursor cannot be deleted';
    END IF;
    IF NEW.tenant_id<>OLD.tenant_id OR
       (NEW.last_event_created_at,NEW.last_event_id)<=(OLD.last_event_created_at,OLD.last_event_id) THEN
        RAISE EXCEPTION 'webhook reconciliation cursor is invalid';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER webhook_reconciliation_cursor_guarded BEFORE UPDATE OR DELETE
    ON keel_meta.webhook_reconciliation_cursors FOR EACH ROW
    EXECUTE FUNCTION keel_meta.guard_webhook_reconciliation_cursor();
REVOKE ALL ON FUNCTION keel_meta.guard_webhook_reconciliation_cursor() FROM PUBLIC;

CREATE FUNCTION keel_meta.plan_webhook_reconciliation(
    p_run_id text,p_requested_by text,p_from timestamptz,p_limit integer)
RETURNS TABLE(r_event_id text,r_event_created_at timestamptz,r_missing_count integer)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,keel_meta,keel_private,pg_temp AS $$
DECLARE authorized_tenant uuid;
        start_time timestamptz;
        start_id uuid;
        has_cursor boolean;
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'keel_operator','MEMBER') THEN
        RAISE EXCEPTION 'webhook reconciliation capability is required';
    END IF;
    authorized_tenant:=keel_private.current_tenant_id();
    IF authorized_tenant IS NULL OR
       p_run_id IS NULL OR p_run_id !~ '^[A-Za-z0-9_-]{8,64}$' OR
       p_requested_by IS NULL OR p_requested_by !~ '^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}$' OR
       p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 500 THEN
        RAISE EXCEPTION 'webhook reconciliation request is invalid';
    END IF;

    PERFORM pg_catalog.pg_advisory_xact_lock(
        pg_catalog.hashtextextended('keel.webhook.reconciliation:'||authorized_tenant::text,0));

    IF EXISTS (SELECT 1 FROM keel_meta.webhook_reconciliation_runs
                WHERE tenant_id=authorized_tenant AND run_id=p_run_id) THEN
        RAISE EXCEPTION 'webhook reconciliation run already exists';
    END IF;

    SELECT c.last_event_created_at,c.last_event_id INTO start_time,start_id
      FROM keel_meta.webhook_reconciliation_cursors c
     WHERE c.tenant_id=authorized_tenant;
    has_cursor:=FOUND;
    IF NOT has_cursor THEN
        IF p_from IS NULL OR p_from>clock_timestamp() THEN
            RAISE EXCEPTION 'webhook reconciliation start time is required';
        END IF;
        start_time:=p_from;
        start_id:='00000000-0000-0000-0000-000000000000'::uuid;
    END IF;

    DROP TABLE IF EXISTS pg_temp.webhook_reconciliation_page;
    CREATE TEMP TABLE pg_temp.webhook_reconciliation_page ON COMMIT DROP AS
    WITH page AS (
        SELECT o.event_id,o.created_at
          FROM keel_meta.event_outbox o
         WHERE o.tenant_id=authorized_tenant AND o.created_at>=start_time
           AND (o.created_at,o.event_id)>(start_time,start_id)
         ORDER BY o.created_at,o.event_id
         LIMIT p_limit
    )
    SELECT p.event_id,p.created_at AS event_created_at,
           count(e.endpoint_id) FILTER (WHERE d.delivery_id IS NULL)::integer AS missing
      FROM page p
      LEFT JOIN keel_meta.webhook_endpoints e
        ON e.tenant_id=authorized_tenant AND e.status='active'
      LEFT JOIN keel_meta.webhook_deliveries d
        ON d.tenant_id=authorized_tenant AND d.event_id=p.event_id::text
       AND d.endpoint_id=e.endpoint_id AND d.subscription_version=e.subscription_version
     GROUP BY p.event_id,p.created_at;

    INSERT INTO keel_meta.webhook_reconciliation_runs
        (tenant_id,run_id,requested_by,from_created_at,cursor_from_created_at,cursor_from_event_id,
         cursor_to_created_at,cursor_to_event_id,events_scanned,gap_events,missing_deliveries)
    VALUES (authorized_tenant,p_run_id,p_requested_by,start_time,
            CASE WHEN has_cursor THEN start_time END,
            CASE WHEN has_cursor THEN start_id END,
            (SELECT event_created_at FROM pg_temp.webhook_reconciliation_page
              ORDER BY event_created_at DESC,event_id DESC LIMIT 1),
            (SELECT event_id FROM pg_temp.webhook_reconciliation_page
              ORDER BY event_created_at DESC,event_id DESC LIMIT 1),
            (SELECT count(*) FROM pg_temp.webhook_reconciliation_page),
            (SELECT count(*) FROM pg_temp.webhook_reconciliation_page WHERE missing>0),
            (SELECT coalesce(sum(missing),0) FROM pg_temp.webhook_reconciliation_page WHERE missing>0));

    INSERT INTO keel_meta.webhook_reconciliation_gaps
        (tenant_id,run_id,event_id,event_created_at,missing_count)
    SELECT authorized_tenant,p_run_id,event_id,event_created_at,missing
      FROM pg_temp.webhook_reconciliation_page
     WHERE missing>0;

    INSERT INTO keel_meta.webhook_reconciliation_cursors
        (tenant_id,last_event_created_at,last_event_id)
    SELECT authorized_tenant,event_created_at,event_id
      FROM pg_temp.webhook_reconciliation_page
     ORDER BY event_created_at DESC,event_id DESC LIMIT 1
    ON CONFLICT (tenant_id) DO UPDATE
       SET last_event_created_at=EXCLUDED.last_event_created_at,
           last_event_id=EXCLUDED.last_event_id,
           updated_at=clock_timestamp();

    RETURN QUERY
    SELECT p.event_id::text,p.event_created_at,p.missing
      FROM pg_temp.webhook_reconciliation_page p
     ORDER BY p.event_created_at,p.event_id;
END $$;
REVOKE ALL ON FUNCTION keel_meta.plan_webhook_reconciliation(text,text,timestamptz,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION keel_meta.plan_webhook_reconciliation(text,text,timestamptz,integer)
    TO keel_operator;
