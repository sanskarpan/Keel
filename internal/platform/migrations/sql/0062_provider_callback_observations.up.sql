CREATE TABLE keel_meta.provider_callback_observations (
    observation_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id uuid NOT NULL CHECK (tenant_id<>'00000000-0000-0000-0000-000000000000'::uuid),
    provider text NOT NULL CHECK (provider ~ '^[a-z][a-z0-9_-]{1,31}$'),
    provider_event_id text NOT NULL CHECK (provider_event_id ~ '^[A-Za-z0-9_.:-]{1,128}$'),
    outcome text NOT NULL CHECK (outcome IN ('applied','duplicate','conflict')),
    redelivery_delay_ms bigint CHECK (redelivery_delay_ms IS NULL OR redelivery_delay_ms BETWEEN 0 AND 9007199254740991),
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
ALTER TABLE keel_meta.provider_callback_observations ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.provider_callback_observations FORCE ROW LEVEL SECURITY;
CREATE POLICY provider_callback_observations_schema_owner
    ON keel_meta.provider_callback_observations TO keel_schema_owner USING (true) WITH CHECK (true);
REVOKE ALL ON keel_meta.provider_callback_observations FROM PUBLIC,keel_app,keel_worker,keel_operator,
    keel_budget_control,keel_rate_control,keel_ai_worker,keel_projector,keel_file_processor,
    keel_retrieval_indexer,keel_context_vault,keel_context_policy,keel_context_erasure,
    keel_context_erasure_worker,keel_context_legal_hold,keel_context_replay,keel_agent,
    keel_callback,keel_webhook;

CREATE FUNCTION keel_meta.reject_provider_callback_observation_mutation()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    RAISE EXCEPTION 'provider callback observations are immutable';
END $$;
CREATE TRIGGER provider_callback_observation_immutable BEFORE UPDATE OR DELETE
    ON keel_meta.provider_callback_observations FOR EACH ROW
    EXECUTE FUNCTION keel_meta.reject_provider_callback_observation_mutation();
REVOKE ALL ON FUNCTION keel_meta.reject_provider_callback_observation_mutation() FROM PUBLIC;

CREATE FUNCTION keel_meta.record_provider_callback_observation(
    p_provider text,p_event_id text,p_outcome text,p_redelivery_delay_ms bigint)
RETURNS TABLE(r_observation_id bigint,r_recorded_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,keel_meta,keel_private,pg_temp AS $$
DECLARE authorized_tenant uuid;
        recorded_id bigint;
        recorded_at timestamptz;
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'keel_callback','MEMBER') THEN
        RAISE EXCEPTION 'provider observation capability is required';
    END IF;
    authorized_tenant:=keel_private.current_tenant_id();
    IF authorized_tenant IS NULL OR
       p_provider IS NULL OR p_provider !~ '^[a-z][a-z0-9_-]{1,31}$' OR
       p_event_id IS NULL OR p_event_id !~ '^[A-Za-z0-9_.:-]{1,128}$' OR
       p_outcome IS NULL OR p_outcome NOT IN ('applied','duplicate','conflict') OR
       (p_redelivery_delay_ms IS NOT NULL AND
        (p_redelivery_delay_ms < 0 OR p_redelivery_delay_ms > 9007199254740991)) THEN
        RAISE EXCEPTION 'provider observation request is invalid';
    END IF;
    IF p_outcome IN ('applied','conflict') AND p_redelivery_delay_ms IS NOT NULL THEN
        RAISE EXCEPTION 'provider observation delay applies to redeliveries only';
    END IF;

    INSERT INTO keel_meta.provider_callback_observations
        (tenant_id,provider,provider_event_id,outcome,redelivery_delay_ms)
    VALUES (authorized_tenant,p_provider,p_event_id,p_outcome,p_redelivery_delay_ms)
    RETURNING provider_callback_observations.observation_id,
        provider_callback_observations.recorded_at INTO recorded_id,recorded_at;

    RETURN QUERY SELECT recorded_id,recorded_at;
END $$;
REVOKE ALL ON FUNCTION keel_meta.record_provider_callback_observation(text,text,text,bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION keel_meta.record_provider_callback_observation(text,text,text,bigint)
    TO keel_callback;
