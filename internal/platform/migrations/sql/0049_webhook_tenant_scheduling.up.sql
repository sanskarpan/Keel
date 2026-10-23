CREATE INDEX webhook_delivery_state_pending_due_global
    ON keel_meta.webhook_delivery_state (next_attempt_at)
    WHERE state='pending';
CREATE INDEX webhook_delivery_state_in_flight_expiry_global
    ON keel_meta.webhook_delivery_state (lease_expires_at)
    WHERE state='in_flight';

CREATE FUNCTION keel_meta.list_webhook_delivery_tenants(p_limit integer)
RETURNS TABLE(r_tenant_id uuid)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,keel_meta,keel_private,pg_temp AS $$
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'keel_webhook','MEMBER') THEN
        RAISE EXCEPTION 'webhook delivery capability is required';
    END IF;
    IF p_limit IS NULL OR p_limit<1 OR p_limit>1000 THEN
        RAISE EXCEPTION 'webhook tenant limit is invalid';
    END IF;

    RETURN QUERY
    SELECT due.tenant_id
      FROM (
            SELECT s.tenant_id,s.next_attempt_at AS due_at
              FROM keel_meta.webhook_delivery_state s
             WHERE s.state='pending' AND s.next_attempt_at<=clock_timestamp()
            UNION ALL
            SELECT s.tenant_id,s.lease_expires_at
              FROM keel_meta.webhook_delivery_state s
             WHERE s.state='in_flight' AND s.lease_expires_at<=clock_timestamp()
           ) due
     GROUP BY due.tenant_id
     ORDER BY min(due.due_at),due.tenant_id
     LIMIT p_limit;
END $$;
REVOKE ALL ON FUNCTION keel_meta.list_webhook_delivery_tenants(integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION keel_meta.list_webhook_delivery_tenants(integer) TO keel_webhook;
