CREATE INDEX webhook_delivery_state_replay_candidates
    ON keel_meta.webhook_delivery_state (tenant_id,delivery_id)
    WHERE state IN ('failed','exhausted');

CREATE FUNCTION keel_meta.list_webhook_replay_candidates(p_limit integer)
RETURNS TABLE(r_delivery_id text,r_event_id text,r_endpoint_id text,r_subscription_version integer,
    r_state text,r_attempts integer,r_replayed boolean,r_endpoint_status text,r_key_id text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,keel_meta,keel_private,pg_temp AS $$
DECLARE authorized_tenant uuid;
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'keel_operator','MEMBER') THEN
        RAISE EXCEPTION 'webhook replay capability is required';
    END IF;
    authorized_tenant:=keel_private.current_tenant_id();
    IF authorized_tenant IS NULL OR p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 5000 THEN
        RAISE EXCEPTION 'webhook replay candidate request is invalid';
    END IF;

    RETURN QUERY
    SELECT d.delivery_id,d.event_id,d.endpoint_id,d.subscription_version,
           s.state,s.attempts,
           EXISTS (SELECT 1 FROM keel_meta.webhook_replays r
                    WHERE r.tenant_id=d.tenant_id AND r.delivery_id=d.delivery_id),
           COALESCE(e.status,'unknown'),COALESCE(e.key_id,'')
      FROM keel_meta.webhook_deliveries d
      JOIN keel_meta.webhook_delivery_state s
        ON s.tenant_id=d.tenant_id AND s.delivery_id=d.delivery_id
      LEFT JOIN keel_meta.webhook_endpoints e
        ON e.tenant_id=d.tenant_id AND e.endpoint_id=d.endpoint_id
       AND e.subscription_version=d.subscription_version
     WHERE d.tenant_id=authorized_tenant
       AND s.state IN ('failed','exhausted') AND s.attempts>=1
     ORDER BY d.delivery_id
     LIMIT p_limit;
END $$;
REVOKE ALL ON FUNCTION keel_meta.list_webhook_replay_candidates(integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION keel_meta.list_webhook_replay_candidates(integer) TO keel_operator;
