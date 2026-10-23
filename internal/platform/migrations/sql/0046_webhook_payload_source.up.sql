CREATE POLICY event_outbox_schema_owner ON keel_meta.event_outbox
    TO keel_schema_owner USING (true) WITH CHECK (true);

CREATE FUNCTION keel_meta.read_webhook_delivery_body(p_delivery_id text)
RETURNS TABLE(r_event_id text,r_content_type text,r_body bytea)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,keel_meta,keel_private,pg_temp AS $$
DECLARE authorized_tenant uuid;
        delivery_event text;
        body text;
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'keel_webhook','MEMBER') THEN
        RAISE EXCEPTION 'webhook delivery capability is required';
    END IF;
    authorized_tenant:=keel_private.current_tenant_id();
    IF authorized_tenant IS NULL THEN
        RAISE EXCEPTION 'webhook delivery tenant context is required';
    END IF;
    IF p_delivery_id IS NULL OR p_delivery_id !~ '^[A-Za-z0-9_-]{8,64}$' THEN
        RAISE EXCEPTION 'webhook delivery lookup is invalid';
    END IF;

    SELECT d.event_id INTO delivery_event
      FROM keel_meta.webhook_deliveries d
     WHERE d.tenant_id=authorized_tenant AND d.delivery_id=p_delivery_id;
    IF NOT FOUND OR delivery_event !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN
        RETURN;
    END IF;

    SELECT o.safe_envelope::text INTO body
      FROM keel_meta.event_outbox o
     WHERE o.tenant_id=authorized_tenant AND o.event_id=delivery_event::uuid;
    IF NOT FOUND THEN
        RETURN;
    END IF;
    IF octet_length(body)<1 OR octet_length(body)>1048576 THEN
        RAISE EXCEPTION 'webhook delivery body is invalid';
    END IF;
    RETURN QUERY SELECT delivery_event,'application/json',pg_catalog.convert_to(body,'UTF8');
END $$;
REVOKE ALL ON FUNCTION keel_meta.read_webhook_delivery_body(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION keel_meta.read_webhook_delivery_body(text) TO keel_webhook;
