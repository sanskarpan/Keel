CREATE FUNCTION keel_meta.fanout_webhook_deliveries(p_event_id text)
RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,keel_meta,keel_private,pg_temp AS $$
DECLARE authorized_tenant uuid;
        canonical_event text;
        inserted integer;
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'keel_app','MEMBER') THEN
        RAISE EXCEPTION 'webhook fanout capability is required';
    END IF;
    authorized_tenant:=keel_private.current_tenant_id();
    IF authorized_tenant IS NULL OR p_event_id IS NULL OR
       p_event_id !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN
        RAISE EXCEPTION 'webhook fanout event is invalid';
    END IF;
    canonical_event:=p_event_id::uuid::text;
    IF NOT EXISTS (
        SELECT 1 FROM keel_meta.event_outbox o
         WHERE o.tenant_id=authorized_tenant AND o.event_id=canonical_event::uuid) THEN
        RAISE EXCEPTION 'webhook fanout event was not found';
    END IF;

    INSERT INTO keel_meta.webhook_deliveries
        (tenant_id,event_id,endpoint_id,subscription_version,delivery_id)
    SELECT authorized_tenant,canonical_event,e.endpoint_id,e.subscription_version,
           'whd_'||replace(gen_random_uuid()::text,'-','')
      FROM keel_meta.webhook_endpoints e
     WHERE e.tenant_id=authorized_tenant AND e.status='active'
     ORDER BY e.endpoint_id
    ON CONFLICT (tenant_id,event_id,endpoint_id,subscription_version) DO NOTHING;
    GET DIAGNOSTICS inserted=ROW_COUNT;
    RETURN inserted;
END $$;
REVOKE ALL ON FUNCTION keel_meta.fanout_webhook_deliveries(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION keel_meta.fanout_webhook_deliveries(text) TO keel_app;
