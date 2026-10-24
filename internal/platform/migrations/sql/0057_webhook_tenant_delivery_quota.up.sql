CREATE TABLE keel_meta.webhook_tenant_delivery_policies (
    tenant_id uuid PRIMARY KEY CHECK (tenant_id<>'00000000-0000-0000-0000-000000000000'::uuid),
    delivery_batch_limit integer NOT NULL CHECK (delivery_batch_limit BETWEEN 1 AND 100),
    version bigint NOT NULL DEFAULT 1 CHECK (version BETWEEN 1 AND 9007199254740991),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
ALTER TABLE keel_meta.webhook_tenant_delivery_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.webhook_tenant_delivery_policies FORCE ROW LEVEL SECURITY;
CREATE POLICY webhook_tenant_delivery_policies_schema_owner
    ON keel_meta.webhook_tenant_delivery_policies TO keel_schema_owner USING (true) WITH CHECK (true);
REVOKE ALL ON keel_meta.webhook_tenant_delivery_policies FROM PUBLIC,keel_app,keel_worker,keel_operator,
    keel_budget_control,keel_rate_control,keel_ai_worker,keel_projector,keel_file_processor,
    keel_retrieval_indexer,keel_context_vault,keel_context_policy,keel_context_erasure,
    keel_context_erasure_worker,keel_context_legal_hold,keel_context_replay,keel_agent,
    keel_callback,keel_webhook;

CREATE TABLE keel_meta.webhook_tenant_delivery_policy_history (
    tenant_id uuid NOT NULL,
    change_id text NOT NULL CHECK (change_id ~ '^[A-Za-z0-9_-]{8,64}$'),
    version bigint NOT NULL CHECK (version BETWEEN 1 AND 9007199254740991),
    prior_limit integer CHECK (prior_limit BETWEEN 1 AND 100),
    new_limit integer NOT NULL CHECK (new_limit BETWEEN 1 AND 100),
    requested_by text NOT NULL CHECK (requested_by ~ '^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}$'),
    reason text NOT NULL CHECK (length(reason) BETWEEN 1 AND 512 AND reason !~ '[[:cntrl:]]'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id,change_id)
);
ALTER TABLE keel_meta.webhook_tenant_delivery_policy_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.webhook_tenant_delivery_policy_history FORCE ROW LEVEL SECURITY;
CREATE POLICY webhook_tenant_delivery_policy_history_schema_owner
    ON keel_meta.webhook_tenant_delivery_policy_history TO keel_schema_owner USING (true) WITH CHECK (true);
REVOKE ALL ON keel_meta.webhook_tenant_delivery_policy_history FROM PUBLIC,keel_app,keel_worker,keel_operator,
    keel_budget_control,keel_rate_control,keel_ai_worker,keel_projector,keel_file_processor,
    keel_retrieval_indexer,keel_context_vault,keel_context_policy,keel_context_erasure,
    keel_context_erasure_worker,keel_context_legal_hold,keel_context_replay,keel_agent,
    keel_callback,keel_webhook;

CREATE FUNCTION keel_meta.reject_webhook_tenant_delivery_policy_mutation()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    RAISE EXCEPTION 'webhook tenant delivery policy history is immutable';
END $$;
CREATE TRIGGER webhook_tenant_delivery_policy_history_immutable BEFORE UPDATE OR DELETE
    ON keel_meta.webhook_tenant_delivery_policy_history FOR EACH ROW
    EXECUTE FUNCTION keel_meta.reject_webhook_tenant_delivery_policy_mutation();
REVOKE ALL ON FUNCTION keel_meta.reject_webhook_tenant_delivery_policy_mutation() FROM PUBLIC;

CREATE FUNCTION keel_meta.webhook_delivery_batch_limit(p_tenant uuid)
RETURNS integer LANGUAGE sql STABLE SET search_path=pg_catalog,keel_meta AS $$
    SELECT COALESCE((SELECT p.delivery_batch_limit FROM keel_meta.webhook_tenant_delivery_policies p
                      WHERE p.tenant_id=p_tenant),5)
$$;
REVOKE ALL ON FUNCTION keel_meta.webhook_delivery_batch_limit(uuid) FROM PUBLIC;

CREATE FUNCTION keel_meta.set_webhook_delivery_batch_limit(
    p_change_id text,p_requested_by text,p_limit integer,p_reason text,p_expected_version bigint)
RETURNS TABLE(r_change_id text,r_version bigint,r_delivery_batch_limit integer,r_updated_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,keel_meta,keel_private,pg_temp AS $$
DECLARE authorized_tenant uuid;
        prior_limit integer;
        new_version bigint;
        recorded_at timestamptz;
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'keel_operator','MEMBER') THEN
        RAISE EXCEPTION 'webhook delivery policy capability is required';
    END IF;
    authorized_tenant:=keel_private.current_tenant_id();
    IF authorized_tenant IS NULL OR
       p_change_id IS NULL OR p_change_id !~ '^[A-Za-z0-9_-]{8,64}$' OR
       p_requested_by IS NULL OR p_requested_by !~ '^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}$' OR
       p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 100 OR
       p_reason IS NULL OR length(p_reason) NOT BETWEEN 1 AND 512 OR p_reason ~ '[[:cntrl:]]' OR
       p_expected_version IS NULL OR p_expected_version NOT BETWEEN 0 AND 9007199254740991 THEN
        RAISE EXCEPTION 'webhook delivery policy request is invalid';
    END IF;

    PERFORM pg_catalog.pg_advisory_xact_lock(
        pg_catalog.hashtextextended('keel.webhook.delivery.policy:'||authorized_tenant::text,0));
    IF EXISTS (SELECT 1 FROM keel_meta.webhook_tenant_delivery_policy_history h
                WHERE h.tenant_id=authorized_tenant AND h.change_id=p_change_id) THEN
        RAISE EXCEPTION 'webhook delivery policy change already exists';
    END IF;

    IF p_expected_version=0 THEN
        IF EXISTS (SELECT 1 FROM keel_meta.webhook_tenant_delivery_policies p
                    WHERE p.tenant_id=authorized_tenant) THEN
            RAISE EXCEPTION 'webhook delivery policy already exists';
        END IF;
        INSERT INTO keel_meta.webhook_tenant_delivery_policies (tenant_id,delivery_batch_limit)
        VALUES (authorized_tenant,p_limit)
        RETURNING version,updated_at INTO new_version,recorded_at;
        prior_limit:=NULL;
    ELSE
        SELECT p.delivery_batch_limit INTO prior_limit
          FROM keel_meta.webhook_tenant_delivery_policies p
         WHERE p.tenant_id=authorized_tenant AND p.version=p_expected_version
           FOR UPDATE;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'webhook delivery policy version conflict';
        END IF;
        UPDATE keel_meta.webhook_tenant_delivery_policies p
           SET delivery_batch_limit=p_limit,version=p.version+1,updated_at=clock_timestamp()
         WHERE p.tenant_id=authorized_tenant AND p.version=p_expected_version
        RETURNING p.version,p.updated_at INTO new_version,recorded_at;
    END IF;

    INSERT INTO keel_meta.webhook_tenant_delivery_policy_history
        (tenant_id,change_id,version,prior_limit,new_limit,requested_by,reason)
    VALUES (authorized_tenant,p_change_id,new_version,prior_limit,p_limit,p_requested_by,p_reason);

    RETURN QUERY SELECT p_change_id,new_version,p_limit,recorded_at;
END $$;
REVOKE ALL ON FUNCTION keel_meta.set_webhook_delivery_batch_limit(text,text,integer,text,bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION keel_meta.set_webhook_delivery_batch_limit(text,text,integer,text,bigint)
    TO keel_operator;

DROP FUNCTION keel_meta.list_webhook_delivery_tenants(integer);

CREATE FUNCTION keel_meta.list_webhook_delivery_tenants(p_limit integer)
RETURNS TABLE(r_tenant_id uuid,r_due_at timestamptz,r_due_count bigint,r_batch_limit integer)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,keel_meta,keel_private,pg_temp AS $$
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'keel_webhook','MEMBER') THEN
        RAISE EXCEPTION 'webhook delivery capability is required';
    END IF;
    IF p_limit IS NULL OR p_limit<1 OR p_limit>1000 THEN
        RAISE EXCEPTION 'webhook tenant limit is invalid';
    END IF;

    RETURN QUERY
    SELECT due.tenant_id,min(due.due_at),count(*),
        keel_meta.webhook_delivery_batch_limit(due.tenant_id)
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
