CREATE TABLE keel_meta.webhook_tenant_policies (
    tenant_id uuid PRIMARY KEY CHECK (tenant_id<>'00000000-0000-0000-0000-000000000000'::uuid),
    active_endpoint_limit integer NOT NULL CHECK (active_endpoint_limit BETWEEN 1 AND 10000),
    version bigint NOT NULL DEFAULT 1 CHECK (version BETWEEN 1 AND 9007199254740991),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
ALTER TABLE keel_meta.webhook_tenant_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.webhook_tenant_policies FORCE ROW LEVEL SECURITY;
CREATE POLICY webhook_tenant_policies_schema_owner
    ON keel_meta.webhook_tenant_policies TO keel_schema_owner USING (true) WITH CHECK (true);
REVOKE ALL ON keel_meta.webhook_tenant_policies FROM PUBLIC,keel_app,keel_worker,keel_operator,
    keel_budget_control,keel_rate_control,keel_ai_worker,keel_projector,keel_file_processor,
    keel_retrieval_indexer,keel_context_vault,keel_context_policy,keel_context_erasure,
    keel_context_erasure_worker,keel_context_legal_hold,keel_context_replay,keel_agent,
    keel_callback,keel_webhook;

CREATE TABLE keel_meta.webhook_tenant_policy_history (
    tenant_id uuid NOT NULL,
    change_id text NOT NULL CHECK (change_id ~ '^[A-Za-z0-9_-]{8,64}$'),
    version bigint NOT NULL CHECK (version BETWEEN 1 AND 9007199254740991),
    prior_limit integer CHECK (prior_limit BETWEEN 1 AND 10000),
    new_limit integer NOT NULL CHECK (new_limit BETWEEN 1 AND 10000),
    requested_by text NOT NULL CHECK (requested_by ~ '^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}$'),
    reason text NOT NULL CHECK (length(reason) BETWEEN 1 AND 512 AND reason !~ '[[:cntrl:]]'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id,change_id)
);
ALTER TABLE keel_meta.webhook_tenant_policy_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.webhook_tenant_policy_history FORCE ROW LEVEL SECURITY;
CREATE POLICY webhook_tenant_policy_history_schema_owner
    ON keel_meta.webhook_tenant_policy_history TO keel_schema_owner USING (true) WITH CHECK (true);
REVOKE ALL ON keel_meta.webhook_tenant_policy_history FROM PUBLIC,keel_app,keel_worker,keel_operator,
    keel_budget_control,keel_rate_control,keel_ai_worker,keel_projector,keel_file_processor,
    keel_retrieval_indexer,keel_context_vault,keel_context_policy,keel_context_erasure,
    keel_context_erasure_worker,keel_context_legal_hold,keel_context_replay,keel_agent,
    keel_callback,keel_webhook;

CREATE FUNCTION keel_meta.reject_webhook_tenant_policy_mutation()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    RAISE EXCEPTION 'webhook tenant policy history is immutable';
END $$;
CREATE TRIGGER webhook_tenant_policy_history_immutable BEFORE UPDATE OR DELETE
    ON keel_meta.webhook_tenant_policy_history FOR EACH ROW
    EXECUTE FUNCTION keel_meta.reject_webhook_tenant_policy_mutation();
REVOKE ALL ON FUNCTION keel_meta.reject_webhook_tenant_policy_mutation() FROM PUBLIC;

CREATE FUNCTION keel_meta.webhook_active_endpoint_limit(p_tenant uuid)
RETURNS integer LANGUAGE sql STABLE SET search_path=pg_catalog,keel_meta AS $$
    SELECT COALESCE((SELECT p.active_endpoint_limit FROM keel_meta.webhook_tenant_policies p
                      WHERE p.tenant_id=p_tenant),100)
$$;
REVOKE ALL ON FUNCTION keel_meta.webhook_active_endpoint_limit(uuid) FROM PUBLIC;

CREATE FUNCTION keel_meta.set_webhook_endpoint_limit(
    p_change_id text,p_requested_by text,p_limit integer,p_reason text,p_expected_version bigint)
RETURNS TABLE(r_change_id text,r_version bigint,r_active_endpoint_limit integer,r_updated_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,keel_meta,keel_private,pg_temp AS $$
DECLARE authorized_tenant uuid;
        prior_limit integer;
        new_version bigint;
        recorded_at timestamptz;
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'keel_operator','MEMBER') THEN
        RAISE EXCEPTION 'webhook policy capability is required';
    END IF;
    authorized_tenant:=keel_private.current_tenant_id();
    IF authorized_tenant IS NULL OR
       p_change_id IS NULL OR p_change_id !~ '^[A-Za-z0-9_-]{8,64}$' OR
       p_requested_by IS NULL OR p_requested_by !~ '^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}$' OR
       p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 10000 OR
       p_reason IS NULL OR length(p_reason) NOT BETWEEN 1 AND 512 OR p_reason ~ '[[:cntrl:]]' OR
       p_expected_version IS NULL OR p_expected_version NOT BETWEEN 0 AND 9007199254740991 THEN
        RAISE EXCEPTION 'webhook policy request is invalid';
    END IF;

    PERFORM pg_catalog.pg_advisory_xact_lock(
        pg_catalog.hashtextextended('keel.webhook.quota.policy:'||authorized_tenant::text,0));
    IF EXISTS (SELECT 1 FROM keel_meta.webhook_tenant_policy_history h
                WHERE h.tenant_id=authorized_tenant AND h.change_id=p_change_id) THEN
        RAISE EXCEPTION 'webhook policy change already exists';
    END IF;

    IF p_expected_version=0 THEN
        IF EXISTS (SELECT 1 FROM keel_meta.webhook_tenant_policies p
                    WHERE p.tenant_id=authorized_tenant) THEN
            RAISE EXCEPTION 'webhook policy already exists';
        END IF;
        INSERT INTO keel_meta.webhook_tenant_policies (tenant_id,active_endpoint_limit)
        VALUES (authorized_tenant,p_limit)
        RETURNING version,updated_at INTO new_version,recorded_at;
        prior_limit:=NULL;
    ELSE
        SELECT p.active_endpoint_limit INTO prior_limit
          FROM keel_meta.webhook_tenant_policies p
         WHERE p.tenant_id=authorized_tenant AND p.version=p_expected_version
           FOR UPDATE;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'webhook policy version conflict';
        END IF;
        UPDATE keel_meta.webhook_tenant_policies p
           SET active_endpoint_limit=p_limit,version=p.version+1,updated_at=clock_timestamp()
         WHERE p.tenant_id=authorized_tenant AND p.version=p_expected_version
        RETURNING p.version,p.updated_at INTO new_version,recorded_at;
    END IF;

    INSERT INTO keel_meta.webhook_tenant_policy_history
        (tenant_id,change_id,version,prior_limit,new_limit,requested_by,reason)
    VALUES (authorized_tenant,p_change_id,new_version,prior_limit,p_limit,p_requested_by,p_reason);

    RETURN QUERY SELECT p_change_id,new_version,p_limit,recorded_at;
END $$;
REVOKE ALL ON FUNCTION keel_meta.set_webhook_endpoint_limit(text,text,integer,text,bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION keel_meta.set_webhook_endpoint_limit(text,text,integer,text,bigint)
    TO keel_operator;
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
             WHERE e.tenant_id=authorized_tenant AND e.status='active')>=keel_meta.webhook_active_endpoint_limit(authorized_tenant) THEN
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
         WHERE e.tenant_id=authorized_tenant AND e.status='active')>=keel_meta.webhook_active_endpoint_limit(authorized_tenant) THEN
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
