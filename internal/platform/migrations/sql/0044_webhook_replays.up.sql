CREATE TABLE keel_meta.webhook_replays (
    tenant_id uuid NOT NULL CHECK (tenant_id<>'00000000-0000-0000-0000-000000000000'::uuid),
    replay_id text NOT NULL CHECK (replay_id ~ '^[A-Za-z0-9_-]{8,64}$'),
    delivery_id text NOT NULL CHECK (delivery_id ~ '^[A-Za-z0-9_-]{8,64}$'),
    requested_by text NOT NULL CHECK (requested_by ~ '^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}$'),
    reason text NOT NULL CHECK (reason=btrim(reason) AND length(reason) BETWEEN 1 AND 512
        AND reason !~ '[[:cntrl:]]'),
    requested_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id,replay_id),
    CONSTRAINT webhook_replays_delivery_unique UNIQUE (tenant_id,delivery_id),
    CONSTRAINT webhook_replays_delivery_fk FOREIGN KEY (tenant_id,delivery_id)
        REFERENCES keel_meta.webhook_deliveries (tenant_id,delivery_id)
);
ALTER TABLE keel_meta.webhook_replays ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.webhook_replays FORCE ROW LEVEL SECURITY;
CREATE POLICY webhook_replays_schema_owner ON keel_meta.webhook_replays
    TO keel_schema_owner USING (true) WITH CHECK (true);
REVOKE ALL ON keel_meta.webhook_replays FROM PUBLIC,keel_app,keel_worker,keel_operator,
    keel_budget_control,keel_rate_control,keel_ai_worker,keel_projector,keel_file_processor,
    keel_retrieval_indexer,keel_context_vault,keel_context_policy,keel_context_erasure,
    keel_context_erasure_worker,keel_context_legal_hold,keel_context_replay,keel_agent,
    keel_callback,keel_webhook;

CREATE FUNCTION keel_meta.reject_webhook_replay_mutation()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    RAISE EXCEPTION 'webhook replay rows are immutable';
END $$;
CREATE TRIGGER webhook_replay_immutable BEFORE UPDATE OR DELETE
    ON keel_meta.webhook_replays FOR EACH ROW
    EXECUTE FUNCTION keel_meta.reject_webhook_replay_mutation();
REVOKE ALL ON FUNCTION keel_meta.reject_webhook_replay_mutation() FROM PUBLIC;

CREATE FUNCTION keel_meta.record_webhook_replay(
    p_replay_id text,p_delivery_id text,p_requested_by text,p_reason text)
RETURNS TABLE(r_replay_id text,r_delivery_id text,r_requested_by text,r_reason text,
    r_requested_at timestamptz,r_created boolean)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,keel_meta,keel_private,pg_temp AS $$
DECLARE authorized_tenant uuid;
        recorded_replay_id text;
        recorded_delivery_id text;
        recorded_requested_by text;
        recorded_reason text;
        recorded_requested_at timestamptz;
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'keel_operator','MEMBER') THEN
        RAISE EXCEPTION 'webhook replay capability is required';
    END IF;
    authorized_tenant:=keel_private.current_tenant_id();
    IF authorized_tenant IS NULL OR
       p_replay_id IS NULL OR p_replay_id !~ '^[A-Za-z0-9_-]{8,64}$' OR
       p_delivery_id IS NULL OR p_delivery_id !~ '^[A-Za-z0-9_-]{8,64}$' OR
       p_requested_by IS NULL OR p_requested_by !~ '^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}$' OR
       p_reason IS NULL OR p_reason<>btrim(p_reason) OR
           length(p_reason) NOT BETWEEN 1 AND 512 OR p_reason ~ '[[:cntrl:]]' THEN
        RAISE EXCEPTION 'webhook replay request is invalid';
    END IF;

    SELECT r.replay_id,r.delivery_id,r.requested_by,r.reason,r.requested_at
      INTO recorded_replay_id,recorded_delivery_id,recorded_requested_by,recorded_reason,
          recorded_requested_at
      FROM keel_meta.webhook_replays r
     WHERE r.tenant_id=authorized_tenant AND r.replay_id=p_replay_id;
    IF FOUND THEN
        IF recorded_delivery_id<>p_delivery_id OR recorded_requested_by<>p_requested_by OR
           recorded_reason<>p_reason THEN
            RAISE EXCEPTION 'webhook replay request conflicts with an existing replay';
        END IF;
        RETURN QUERY SELECT recorded_replay_id,recorded_delivery_id,recorded_requested_by,
            recorded_reason,recorded_requested_at,false;
        RETURN;
    END IF;

    IF EXISTS (
        SELECT 1 FROM keel_meta.webhook_replays r
         WHERE r.tenant_id=authorized_tenant AND r.delivery_id=p_delivery_id) THEN
        RAISE EXCEPTION 'webhook delivery was already replayed';
    END IF;

    INSERT INTO keel_meta.webhook_replays
        (tenant_id,replay_id,delivery_id,requested_by,reason)
    VALUES (authorized_tenant,p_replay_id,p_delivery_id,p_requested_by,p_reason)
    RETURNING webhook_replays.replay_id,webhook_replays.delivery_id,webhook_replays.requested_by,
        webhook_replays.reason,webhook_replays.requested_at
      INTO recorded_replay_id,recorded_delivery_id,recorded_requested_by,recorded_reason,
          recorded_requested_at;
    RETURN QUERY SELECT recorded_replay_id,recorded_delivery_id,recorded_requested_by,
        recorded_reason,recorded_requested_at,true;
END $$;
REVOKE ALL ON FUNCTION keel_meta.record_webhook_replay(text,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION keel_meta.record_webhook_replay(text,text,text,text) TO keel_operator;

CREATE FUNCTION keel_meta.webhook_replay_recorded(p_delivery_id text)
RETURNS TABLE(r_recorded boolean)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,keel_meta,keel_private,pg_temp AS $$
DECLARE authorized_tenant uuid;
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'keel_operator','MEMBER') THEN
        RAISE EXCEPTION 'webhook replay capability is required';
    END IF;
    authorized_tenant:=keel_private.current_tenant_id();
    IF authorized_tenant IS NULL THEN
        RAISE EXCEPTION 'webhook replay tenant context is required';
    END IF;
    IF p_delivery_id IS NULL OR p_delivery_id !~ '^[A-Za-z0-9_-]{8,64}$' THEN
        RAISE EXCEPTION 'webhook replay lookup is invalid';
    END IF;
    RETURN QUERY SELECT EXISTS(
        SELECT 1 FROM keel_meta.webhook_replays r
         WHERE r.tenant_id=authorized_tenant AND r.delivery_id=p_delivery_id);
END $$;
REVOKE ALL ON FUNCTION keel_meta.webhook_replay_recorded(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION keel_meta.webhook_replay_recorded(text) TO keel_operator;
