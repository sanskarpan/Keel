DROP FUNCTION keel_meta.lease_webhook_deliveries(integer,integer);

CREATE FUNCTION keel_meta.lease_webhook_deliveries(p_limit integer,p_lease_seconds integer)
RETURNS TABLE(event_id text,endpoint_id text,subscription_version integer,delivery_id text,
    attempt_number integer,attempt_id text,lease_epoch bigint,lease_expires_at timestamptz,
    first_attempt_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,keel_meta,keel_private,pg_temp AS $$
DECLARE authorized_tenant uuid;
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'keel_webhook','MEMBER') THEN
        RAISE EXCEPTION 'webhook delivery capability is required';
    END IF;
    authorized_tenant:=keel_private.current_tenant_id();
    IF authorized_tenant IS NULL THEN
        RAISE EXCEPTION 'webhook delivery tenant context is required';
    END IF;
    IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 100 OR
       p_lease_seconds IS NULL OR p_lease_seconds NOT BETWEEN 5 AND 300 THEN
        RAISE EXCEPTION 'webhook delivery lease is invalid';
    END IF;

    RETURN QUERY
    WITH due AS (
        SELECT s.tenant_id,s.delivery_id
          FROM keel_meta.webhook_delivery_state s
         WHERE s.tenant_id=authorized_tenant
           AND ((s.state='pending' AND s.next_attempt_at<=clock_timestamp())
             OR (s.state='in_flight' AND s.lease_expires_at<=clock_timestamp()))
         ORDER BY coalesce(s.next_attempt_at,s.lease_expires_at)
         LIMIT p_limit
         FOR UPDATE SKIP LOCKED
    ), leased AS (
        UPDATE keel_meta.webhook_delivery_state s
           SET state='in_flight',
               attempts=s.attempts+1,
               first_attempt_at=coalesce(s.first_attempt_at,clock_timestamp()),
               next_attempt_at=NULL,
               lease_epoch=s.lease_epoch+1,
               lease_expires_at=clock_timestamp()+(p_lease_seconds*interval '1 second'),
               updated_at=clock_timestamp()
          FROM due
         WHERE s.tenant_id=due.tenant_id AND s.delivery_id=due.delivery_id
        RETURNING s.tenant_id,s.delivery_id,s.attempts,s.first_attempt_at,s.lease_epoch,
            s.lease_expires_at
    )
    SELECT d.event_id,d.endpoint_id,d.subscription_version,l.delivery_id,l.attempts,
           gen_random_uuid()::text,l.lease_epoch,l.lease_expires_at,l.first_attempt_at
      FROM leased l
      JOIN keel_meta.webhook_deliveries d
        ON d.tenant_id=l.tenant_id AND d.delivery_id=l.delivery_id
     ORDER BY l.lease_expires_at,l.delivery_id;
END $$;
REVOKE ALL ON FUNCTION keel_meta.lease_webhook_deliveries(integer,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION keel_meta.lease_webhook_deliveries(integer,integer) TO keel_webhook;
