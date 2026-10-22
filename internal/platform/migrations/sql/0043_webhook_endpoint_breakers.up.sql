CREATE TABLE keel_meta.webhook_endpoint_breakers (
    tenant_id uuid NOT NULL,
    endpoint_id text NOT NULL,
    status text NOT NULL CHECK (status IN ('closed','open','half_open')),
    failures integer NOT NULL DEFAULT 0 CHECK (failures BETWEEN 0 AND 1000000),
    opened_at timestamptz,
    open_for_seconds integer CHECK (open_for_seconds BETWEEN 1 AND 86400),
    probes integer NOT NULL DEFAULT 0 CHECK (probes BETWEEN 0 AND 10),
    version bigint NOT NULL DEFAULT 1 CHECK (version BETWEEN 1 AND 9007199254740991),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id,endpoint_id),
    FOREIGN KEY (tenant_id,endpoint_id)
        REFERENCES keel_meta.webhook_endpoints (tenant_id,endpoint_id),
    CHECK (
        (status='closed' AND opened_at IS NULL AND open_for_seconds IS NULL)
        OR (status='open' AND failures=0 AND probes=0
            AND opened_at IS NOT NULL AND open_for_seconds IS NOT NULL)
        OR (status='half_open' AND failures=0
            AND opened_at IS NOT NULL AND open_for_seconds IS NOT NULL)
    )
);
ALTER TABLE keel_meta.webhook_endpoint_breakers ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.webhook_endpoint_breakers FORCE ROW LEVEL SECURITY;
CREATE POLICY webhook_endpoint_breakers_schema_owner ON keel_meta.webhook_endpoint_breakers
    TO keel_schema_owner USING (true) WITH CHECK (true);
REVOKE ALL ON keel_meta.webhook_endpoint_breakers FROM PUBLIC,keel_app,keel_worker,keel_operator,
    keel_budget_control,keel_rate_control,keel_ai_worker,keel_projector,keel_file_processor,
    keel_retrieval_indexer,keel_context_vault,keel_context_policy,keel_context_erasure,
    keel_context_erasure_worker,keel_context_legal_hold,keel_context_replay,keel_agent,
    keel_callback,keel_webhook;

CREATE FUNCTION keel_meta.guard_webhook_endpoint_breaker()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    IF TG_OP='DELETE' THEN
        RAISE EXCEPTION 'webhook breaker rows cannot be deleted';
    END IF;
    IF NEW.tenant_id<>OLD.tenant_id OR NEW.endpoint_id<>OLD.endpoint_id THEN
        RAISE EXCEPTION 'webhook breaker identity is immutable';
    END IF;
    IF NEW.version<>OLD.version+1 THEN
        RAISE EXCEPTION 'webhook breaker version must increase by one';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER webhook_endpoint_breaker_guarded BEFORE UPDATE OR DELETE
    ON keel_meta.webhook_endpoint_breakers FOR EACH ROW
    EXECUTE FUNCTION keel_meta.guard_webhook_endpoint_breaker();
REVOKE ALL ON FUNCTION keel_meta.guard_webhook_endpoint_breaker() FROM PUBLIC;

CREATE FUNCTION keel_meta.load_webhook_breaker(p_endpoint_id text)
RETURNS TABLE(r_status text,r_failures integer,r_opened_at timestamptz,
    r_open_for_seconds integer,r_probes integer,r_version bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,keel_meta,keel_private,pg_temp AS $$
DECLARE authorized_tenant uuid;
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'keel_webhook','MEMBER') THEN
        RAISE EXCEPTION 'webhook delivery capability is required';
    END IF;
    authorized_tenant:=keel_private.current_tenant_id();
    IF authorized_tenant IS NULL OR
       p_endpoint_id IS NULL OR p_endpoint_id !~ '^[A-Za-z0-9_-]{8,64}$' THEN
        RAISE EXCEPTION 'webhook breaker lookup is invalid';
    END IF;

    RETURN QUERY SELECT b.status,b.failures,b.opened_at,b.open_for_seconds,b.probes,b.version
      FROM keel_meta.webhook_endpoint_breakers b
     WHERE b.tenant_id=authorized_tenant AND b.endpoint_id=p_endpoint_id;
END $$;
REVOKE ALL ON FUNCTION keel_meta.load_webhook_breaker(text) FROM PUBLIC;

CREATE FUNCTION keel_meta.save_webhook_breaker(
    p_endpoint_id text,p_expected_version bigint,p_status text,p_failures integer,
    p_opened_at timestamptz,p_open_for_seconds integer,p_probes integer)
RETURNS TABLE(r_status text,r_failures integer,r_opened_at timestamptz,
    r_open_for_seconds integer,r_probes integer,r_version bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,keel_meta,keel_private,pg_temp AS $$
DECLARE authorized_tenant uuid;
        recorded_status text;
        recorded_failures integer;
        recorded_opened_at timestamptz;
        recorded_open_for integer;
        recorded_probes integer;
        recorded_version bigint;
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'keel_webhook','MEMBER') THEN
        RAISE EXCEPTION 'webhook delivery capability is required';
    END IF;
    authorized_tenant:=keel_private.current_tenant_id();
    IF authorized_tenant IS NULL OR
       p_endpoint_id IS NULL OR p_endpoint_id !~ '^[A-Za-z0-9_-]{8,64}$' OR
       p_expected_version IS NULL OR p_expected_version NOT BETWEEN 0 AND 9007199254740991 OR
       p_status IS NULL OR p_status NOT IN ('closed','open','half_open') OR
       p_failures IS NULL OR p_failures NOT BETWEEN 0 AND 1000000 OR
       p_probes IS NULL OR p_probes NOT BETWEEN 0 AND 10 OR
       ((p_status='closed') <> (p_opened_at IS NULL)) OR
       ((p_status='closed') <> (p_open_for_seconds IS NULL)) OR
       (p_open_for_seconds IS NOT NULL AND p_open_for_seconds NOT BETWEEN 1 AND 86400) OR
       (p_status='open' AND (p_failures<>0 OR p_probes<>0)) OR
       (p_status='half_open' AND p_failures<>0) THEN
        RAISE EXCEPTION 'webhook breaker state is invalid';
    END IF;

    IF p_expected_version=0 THEN
        INSERT INTO keel_meta.webhook_endpoint_breakers
            (tenant_id,endpoint_id,status,failures,opened_at,open_for_seconds,probes)
        VALUES (authorized_tenant,p_endpoint_id,p_status,p_failures,p_opened_at,
                p_open_for_seconds,p_probes)
        ON CONFLICT (tenant_id,endpoint_id) DO NOTHING
        RETURNING webhook_endpoint_breakers.status,webhook_endpoint_breakers.failures,
            webhook_endpoint_breakers.opened_at,webhook_endpoint_breakers.open_for_seconds,
            webhook_endpoint_breakers.probes,webhook_endpoint_breakers.version
          INTO recorded_status,recorded_failures,recorded_opened_at,
              recorded_open_for,recorded_probes,recorded_version;
    ELSE
        UPDATE keel_meta.webhook_endpoint_breakers b
           SET status=p_status,failures=p_failures,opened_at=p_opened_at,
               open_for_seconds=p_open_for_seconds,probes=p_probes,
               version=b.version+1,updated_at=clock_timestamp()
         WHERE b.tenant_id=authorized_tenant AND b.endpoint_id=p_endpoint_id
           AND b.version=p_expected_version
        RETURNING b.status,b.failures,b.opened_at,b.open_for_seconds,b.probes,b.version
          INTO recorded_status,recorded_failures,recorded_opened_at,
              recorded_open_for,recorded_probes,recorded_version;
    END IF;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'webhook breaker version conflict';
    END IF;

    RETURN QUERY SELECT recorded_status,recorded_failures,recorded_opened_at,
        recorded_open_for,recorded_probes,recorded_version;
END $$;
REVOKE ALL ON FUNCTION keel_meta.save_webhook_breaker(text,bigint,text,integer,timestamptz,integer,integer) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION keel_meta.load_webhook_breaker(text) TO keel_webhook;
GRANT EXECUTE ON FUNCTION keel_meta.save_webhook_breaker(text,bigint,text,integer,timestamptz,integer,integer)
    TO keel_webhook;
