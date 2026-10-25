CREATE FUNCTION keel_meta.list_webhook_reconciliation_runs(p_limit integer)
RETURNS TABLE(r_run_id text,r_requested_by text,r_from_created_at timestamptz,
    r_cursor_to_created_at timestamptz,r_cursor_to_event_id uuid,
    r_events_scanned integer,r_gap_events integer,r_missing_deliveries bigint,
    r_repaired_deliveries integer,r_skipped_identities integer,r_created_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,keel_meta,keel_private,pg_temp AS $$
DECLARE authorized_tenant uuid;
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'keel_operator','MEMBER') THEN
        RAISE EXCEPTION 'webhook reconciliation capability is required';
    END IF;
    authorized_tenant:=keel_private.current_tenant_id();
    IF authorized_tenant IS NULL OR
       p_limit IS NULL OR p_limit<1 OR p_limit>100 THEN
        RAISE EXCEPTION 'webhook reconciliation runs request is invalid';
    END IF;

    RETURN QUERY
    SELECT r.run_id,r.requested_by,r.from_created_at,
        r.cursor_to_created_at,r.cursor_to_event_id,
        r.events_scanned,r.gap_events,r.missing_deliveries,
        COALESCE(sum(p.inserted_deliveries),0)::integer,
        COALESCE(sum(p.skipped_identities),0)::integer,
        r.created_at
      FROM keel_meta.webhook_reconciliation_runs r
      LEFT JOIN keel_meta.webhook_reconciliation_repair_runs p
        ON p.tenant_id=r.tenant_id AND p.run_id=r.run_id
     WHERE r.tenant_id=authorized_tenant
     GROUP BY r.run_id,r.requested_by,r.from_created_at,
        r.cursor_to_created_at,r.cursor_to_event_id,
        r.events_scanned,r.gap_events,r.missing_deliveries,r.created_at
     ORDER BY r.created_at DESC,r.run_id
     LIMIT p_limit;
END $$;
REVOKE ALL ON FUNCTION keel_meta.list_webhook_reconciliation_runs(integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION keel_meta.list_webhook_reconciliation_runs(integer) TO keel_operator;
