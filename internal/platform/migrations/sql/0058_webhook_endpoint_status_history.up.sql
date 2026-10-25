CREATE TABLE keel_meta.webhook_endpoint_status_history (
    tenant_id uuid NOT NULL CHECK (tenant_id<>'00000000-0000-0000-0000-000000000000'::uuid),
    endpoint_id text NOT NULL CHECK (endpoint_id ~ '^[A-Za-z0-9_-]{8,64}$'),
    version bigint NOT NULL CHECK (version BETWEEN 1 AND 9007199254740991),
    status text NOT NULL CHECK (status IN ('active','inactive')),
    subscription_version integer NOT NULL CHECK (subscription_version BETWEEN 1 AND 1000000),
    recorded_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id,endpoint_id,version),
    FOREIGN KEY (tenant_id,endpoint_id) REFERENCES keel_meta.webhook_endpoints (tenant_id,endpoint_id)
);
ALTER TABLE keel_meta.webhook_endpoint_status_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.webhook_endpoint_status_history FORCE ROW LEVEL SECURITY;
CREATE POLICY webhook_endpoint_status_history_schema_owner
    ON keel_meta.webhook_endpoint_status_history TO keel_schema_owner USING (true) WITH CHECK (true);
REVOKE ALL ON keel_meta.webhook_endpoint_status_history FROM PUBLIC,keel_app,keel_worker,keel_operator,
    keel_budget_control,keel_rate_control,keel_ai_worker,keel_projector,keel_file_processor,
    keel_retrieval_indexer,keel_context_vault,keel_context_policy,keel_context_erasure,
    keel_context_erasure_worker,keel_context_legal_hold,keel_context_replay,keel_agent,
    keel_callback,keel_webhook;

CREATE FUNCTION keel_meta.reject_webhook_endpoint_status_history_mutation()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    RAISE EXCEPTION 'webhook endpoint status history is immutable';
END $$;
CREATE TRIGGER webhook_endpoint_status_history_immutable BEFORE UPDATE OR DELETE
    ON keel_meta.webhook_endpoint_status_history FOR EACH ROW
    EXECUTE FUNCTION keel_meta.reject_webhook_endpoint_status_history_mutation();
REVOKE ALL ON FUNCTION keel_meta.reject_webhook_endpoint_status_history_mutation() FROM PUBLIC;

CREATE FUNCTION keel_meta.record_webhook_endpoint_status_history()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,keel_meta AS $$
BEGIN
    INSERT INTO keel_meta.webhook_endpoint_status_history
        (tenant_id,endpoint_id,version,status,subscription_version,recorded_at)
    VALUES (NEW.tenant_id,NEW.endpoint_id,NEW.version,NEW.status,
        NEW.subscription_version,NEW.updated_at);
    RETURN NEW;
END $$;
CREATE TRIGGER webhook_endpoint_status_history_record AFTER INSERT OR UPDATE
    ON keel_meta.webhook_endpoints FOR EACH ROW
    EXECUTE FUNCTION keel_meta.record_webhook_endpoint_status_history();
REVOKE ALL ON FUNCTION keel_meta.record_webhook_endpoint_status_history() FROM PUBLIC;

INSERT INTO keel_meta.webhook_endpoint_status_history
    (tenant_id,endpoint_id,version,status,subscription_version,recorded_at)
SELECT e.tenant_id,e.endpoint_id,e.version,e.status,e.subscription_version,e.updated_at
  FROM keel_meta.webhook_endpoints e
  ON CONFLICT DO NOTHING;

CREATE FUNCTION keel_meta.webhook_endpoint_status_at(p_endpoint_id text,p_at timestamptz)
RETURNS TABLE(r_status text,r_subscription_version integer,r_version bigint,r_recorded_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,keel_meta,keel_private,pg_temp AS $$
DECLARE authorized_tenant uuid;
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'keel_operator','MEMBER') THEN
        RAISE EXCEPTION 'webhook status history capability is required';
    END IF;
    authorized_tenant:=keel_private.current_tenant_id();
    IF authorized_tenant IS NULL OR
       p_endpoint_id IS NULL OR p_endpoint_id !~ '^[A-Za-z0-9_-]{8,64}$' OR
       p_at IS NULL THEN
        RAISE EXCEPTION 'webhook status history request is invalid';
    END IF;

    RETURN QUERY
    SELECT h.status,h.subscription_version,h.version,h.recorded_at
      FROM keel_meta.webhook_endpoint_status_history h
     WHERE h.tenant_id=authorized_tenant AND h.endpoint_id=p_endpoint_id
       AND h.recorded_at<=p_at
     ORDER BY h.recorded_at DESC,h.version DESC
     LIMIT 1;
END $$;
REVOKE ALL ON FUNCTION keel_meta.webhook_endpoint_status_at(text,timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION keel_meta.webhook_endpoint_status_at(text,timestamptz) TO keel_operator;
