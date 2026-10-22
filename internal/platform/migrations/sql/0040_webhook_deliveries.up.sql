CREATE TABLE keel_meta.webhook_deliveries (
    tenant_id uuid NOT NULL CHECK (tenant_id<>'00000000-0000-0000-0000-000000000000'::uuid),
    event_id text NOT NULL CHECK (event_id ~ '^[A-Za-z0-9_.:-]{8,128}$'),
    endpoint_id text NOT NULL CHECK (endpoint_id ~ '^[A-Za-z0-9_-]{8,64}$'),
    subscription_version integer NOT NULL CHECK (subscription_version BETWEEN 1 AND 1000000),
    delivery_id text NOT NULL CHECK (delivery_id ~ '^[A-Za-z0-9_-]{8,64}$'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id,delivery_id),
    CONSTRAINT webhook_deliveries_delivery_unique UNIQUE (delivery_id),
    CONSTRAINT webhook_deliveries_identity_unique
        UNIQUE (tenant_id,event_id,endpoint_id,subscription_version)
);
ALTER TABLE keel_meta.webhook_deliveries ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.webhook_deliveries FORCE ROW LEVEL SECURITY;
CREATE POLICY webhook_deliveries_schema_owner ON keel_meta.webhook_deliveries
    TO keel_schema_owner USING (true) WITH CHECK (true);
REVOKE ALL ON keel_meta.webhook_deliveries FROM PUBLIC,keel_app,keel_worker,keel_operator,
    keel_budget_control,keel_rate_control,keel_ai_worker,keel_projector,keel_file_processor,
    keel_retrieval_indexer,keel_context_vault,keel_context_policy,keel_context_erasure,
    keel_context_erasure_worker,keel_context_legal_hold,keel_context_replay,keel_agent,
    keel_callback,keel_webhook;

CREATE FUNCTION keel_meta.reject_webhook_delivery_mutation()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    RAISE EXCEPTION 'webhook delivery rows are immutable';
END $$;
CREATE TRIGGER webhook_delivery_immutable BEFORE UPDATE OR DELETE
    ON keel_meta.webhook_deliveries FOR EACH ROW
    EXECUTE FUNCTION keel_meta.reject_webhook_delivery_mutation();
REVOKE ALL ON FUNCTION keel_meta.reject_webhook_delivery_mutation() FROM PUBLIC;

CREATE FUNCTION keel_meta.claim_webhook_delivery(
    p_event_id text,p_endpoint_id text,p_subscription_version integer,p_delivery_id text)
RETURNS TABLE(delivery_id text,created boolean,created_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,keel_meta,keel_private,pg_temp AS $$
DECLARE authorized_tenant uuid;
        claimed_id text;
        claimed_at timestamptz;
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'keel_webhook','MEMBER') THEN
        RAISE EXCEPTION 'webhook delivery capability is required';
    END IF;
    authorized_tenant:=keel_private.current_tenant_id();
    IF authorized_tenant IS NULL OR
       p_event_id IS NULL OR p_event_id !~ '^[A-Za-z0-9_.:-]{8,128}$' OR
       p_endpoint_id IS NULL OR p_endpoint_id !~ '^[A-Za-z0-9_-]{8,64}$' OR
       p_subscription_version IS NULL OR p_subscription_version NOT BETWEEN 1 AND 1000000 OR
       p_delivery_id IS NULL OR p_delivery_id !~ '^[A-Za-z0-9_-]{8,64}$' THEN
        RAISE EXCEPTION 'webhook delivery claim is invalid';
    END IF;

    INSERT INTO keel_meta.webhook_deliveries
        (tenant_id,event_id,endpoint_id,subscription_version,delivery_id)
    VALUES (authorized_tenant,p_event_id,p_endpoint_id,p_subscription_version,p_delivery_id)
    ON CONFLICT (tenant_id,event_id,endpoint_id,subscription_version) DO NOTHING
    RETURNING webhook_deliveries.delivery_id,webhook_deliveries.created_at
      INTO claimed_id,claimed_at;
    IF claimed_id IS NOT NULL THEN
        RETURN QUERY SELECT claimed_id,true,claimed_at;
        RETURN;
    END IF;

    SELECT d.delivery_id,d.created_at INTO claimed_id,claimed_at
      FROM keel_meta.webhook_deliveries d
     WHERE d.tenant_id=authorized_tenant AND d.event_id=p_event_id
       AND d.endpoint_id=p_endpoint_id AND d.subscription_version=p_subscription_version;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'webhook delivery claim lost its recorded delivery';
    END IF;
    RETURN QUERY SELECT claimed_id,false,claimed_at;
END $$;
REVOKE ALL ON FUNCTION keel_meta.claim_webhook_delivery(text,text,integer,text) FROM PUBLIC;

GRANT USAGE ON SCHEMA keel_meta,keel_private TO keel_webhook;
GRANT EXECUTE ON FUNCTION keel_private.current_tenant_id() TO keel_webhook;
GRANT EXECUTE ON FUNCTION keel_meta.claim_webhook_delivery(text,text,integer,text) TO keel_webhook;
