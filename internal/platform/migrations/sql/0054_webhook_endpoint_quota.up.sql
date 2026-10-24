CREATE OR REPLACE FUNCTION keel_meta.register_webhook_endpoint(
    p_endpoint_id text,p_url text,p_key_id text,p_subscription_version integer,
    p_expected_version bigint)
RETURNS TABLE(r_endpoint_id text,r_endpoint_version bigint,r_status text,r_url text,r_key_id text,
    r_subscription_version integer,r_created_at timestamptz,r_updated_at timestamptz,r_created boolean)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,keel_meta,keel_private,pg_temp AS $$
DECLARE authorized_tenant uuid;
        recorded_id text;
        recorded_version bigint;
        recorded_status text;
        recorded_url text;
        recorded_key text;
        recorded_subscription integer;
        recorded_created timestamptz;
        recorded_updated timestamptz;
        created_now boolean:=false;
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'keel_app','MEMBER') THEN
        RAISE EXCEPTION 'webhook endpoint registration capability is required';
    END IF;
    authorized_tenant:=keel_private.current_tenant_id();
    IF authorized_tenant IS NULL OR
       p_endpoint_id IS NULL OR p_endpoint_id !~ '^[A-Za-z0-9_-]{8,64}$' OR
       p_url IS NULL OR length(p_url) NOT BETWEEN 8 AND 2048 OR p_url !~ '^https://'
           OR p_url ~ '[[:cntrl:][:space:]]' OR
       p_key_id IS NULL OR p_key_id !~ '^[A-Za-z0-9_-]{4,64}$' OR
       p_subscription_version IS NULL OR p_subscription_version NOT BETWEEN 1 AND 1000000 OR
       p_expected_version IS NULL OR p_expected_version NOT BETWEEN 0 AND 9007199254740991 THEN
        RAISE EXCEPTION 'webhook endpoint registration is invalid';
    END IF;

    PERFORM pg_catalog.pg_advisory_xact_lock(
        pg_catalog.hashtextextended('keel.webhook.endpoints:'||authorized_tenant::text,0));

    IF p_expected_version=0 THEN
        IF (SELECT count(*) FROM keel_meta.webhook_endpoints e
             WHERE e.tenant_id=authorized_tenant AND e.status='active')>=100 THEN
            RAISE EXCEPTION 'webhook active endpoint quota exceeded';
        END IF;
        INSERT INTO keel_meta.webhook_endpoints
            (tenant_id,endpoint_id,url,key_id,subscription_version,status)
        VALUES (authorized_tenant,p_endpoint_id,p_url,p_key_id,p_subscription_version,'active')
        ON CONFLICT (tenant_id,endpoint_id) DO NOTHING
        RETURNING webhook_endpoints.endpoint_id,webhook_endpoints.version,
            webhook_endpoints.status,webhook_endpoints.url,webhook_endpoints.key_id,
            webhook_endpoints.subscription_version,webhook_endpoints.created_at,
            webhook_endpoints.updated_at
          INTO recorded_id,recorded_version,recorded_status,recorded_url,recorded_key,
              recorded_subscription,recorded_created,recorded_updated;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'webhook endpoint already exists';
        END IF;
        created_now:=true;
    ELSE
        UPDATE keel_meta.webhook_endpoints e
           SET url=p_url,key_id=p_key_id,subscription_version=p_subscription_version,
               version=e.version+1,updated_at=clock_timestamp()
         WHERE e.tenant_id=authorized_tenant AND e.endpoint_id=p_endpoint_id
           AND e.version=p_expected_version
        RETURNING e.endpoint_id,e.version,e.status,e.url,e.key_id,e.subscription_version,
            e.created_at,e.updated_at
          INTO recorded_id,recorded_version,recorded_status,recorded_url,recorded_key,
              recorded_subscription,recorded_created,recorded_updated;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'webhook endpoint version conflict or unknown endpoint';
        END IF;
    END IF;

    RETURN QUERY SELECT recorded_id,recorded_version,recorded_status,recorded_url,recorded_key,
        recorded_subscription,recorded_created,recorded_updated,created_now;
END $$;

CREATE OR REPLACE FUNCTION keel_meta.set_webhook_endpoint_status(
    p_endpoint_id text,p_status text,p_expected_version bigint)
RETURNS TABLE(r_endpoint_id text,r_endpoint_version bigint,r_status text,r_url text,r_key_id text,
    r_subscription_version integer,r_created_at timestamptz,r_updated_at timestamptz,r_created boolean)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,keel_meta,keel_private,pg_temp AS $$
DECLARE authorized_tenant uuid;
        current_status text;
        recorded_id text;
        recorded_version bigint;
        recorded_status text;
        recorded_url text;
        recorded_key text;
        recorded_subscription integer;
        recorded_created timestamptz;
        recorded_updated timestamptz;
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'keel_app','MEMBER') THEN
        RAISE EXCEPTION 'webhook endpoint registration capability is required';
    END IF;
    authorized_tenant:=keel_private.current_tenant_id();
    IF authorized_tenant IS NULL OR
       p_endpoint_id IS NULL OR p_endpoint_id !~ '^[A-Za-z0-9_-]{8,64}$' OR
       p_status IS NULL OR p_status NOT IN ('active','inactive') OR
       p_expected_version IS NULL OR p_expected_version NOT BETWEEN 1 AND 9007199254740991 THEN
        RAISE EXCEPTION 'webhook endpoint status change is invalid';
    END IF;

    PERFORM pg_catalog.pg_advisory_xact_lock(
        pg_catalog.hashtextextended('keel.webhook.endpoints:'||authorized_tenant::text,0));

    SELECT e.status INTO current_status
      FROM keel_meta.webhook_endpoints e
     WHERE e.tenant_id=authorized_tenant AND e.endpoint_id=p_endpoint_id;
    IF FOUND AND p_status='active' AND current_status='inactive' AND
       (SELECT count(*) FROM keel_meta.webhook_endpoints e
         WHERE e.tenant_id=authorized_tenant AND e.status='active')>=100 THEN
        RAISE EXCEPTION 'webhook active endpoint quota exceeded';
    END IF;

    UPDATE keel_meta.webhook_endpoints e
       SET status=p_status,version=e.version+1,updated_at=clock_timestamp()
     WHERE e.tenant_id=authorized_tenant AND e.endpoint_id=p_endpoint_id
       AND e.version=p_expected_version
    RETURNING e.endpoint_id,e.version,e.status,e.url,e.key_id,e.subscription_version,
        e.created_at,e.updated_at
      INTO recorded_id,recorded_version,recorded_status,recorded_url,recorded_key,
          recorded_subscription,recorded_created,recorded_updated;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'webhook endpoint version conflict or unknown endpoint';
    END IF;

    RETURN QUERY SELECT recorded_id,recorded_version,recorded_status,recorded_url,recorded_key,
        recorded_subscription,recorded_created,recorded_updated,false;
END $$;
