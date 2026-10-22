CREATE TABLE keel_meta.callback_inbox (
    tenant_id uuid NOT NULL CHECK (tenant_id<>'00000000-0000-0000-0000-000000000000'::uuid),
    provider text NOT NULL CHECK (provider ~ '^[a-z][a-z0-9_-]{1,31}$'),
    provider_event_id text NOT NULL CHECK (provider_event_id ~ '^[A-Za-z0-9_.:-]{1,128}$'),
    payload_digest text NOT NULL CHECK (payload_digest ~ '^[0-9a-f]{64}$'),
    event_type text NOT NULL CHECK (event_type ~ '^[a-z][a-z0-9._-]{0,63}$'),
    key_id text NOT NULL CHECK (key_id ~ '^[A-Za-z0-9_.:-]{1,64}$'),
    occurred_at timestamptz NOT NULL,
    received_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    applied_at timestamptz,
    state text NOT NULL DEFAULT 'received' CHECK (state IN ('received','applied')),
    PRIMARY KEY (tenant_id,provider,provider_event_id),
    CONSTRAINT callback_inbox_provider_event_unique UNIQUE (provider,provider_event_id),
    CHECK ((state='received' AND applied_at IS NULL) OR (state='applied' AND applied_at IS NOT NULL))
);
ALTER TABLE keel_meta.callback_inbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.callback_inbox FORCE ROW LEVEL SECURITY;
CREATE POLICY callback_inbox_schema_owner ON keel_meta.callback_inbox
    TO keel_schema_owner USING (true) WITH CHECK (true);
REVOKE ALL ON keel_meta.callback_inbox FROM PUBLIC,keel_app,keel_worker,keel_operator,
    keel_budget_control,keel_rate_control,keel_ai_worker,keel_projector,keel_file_processor,
    keel_retrieval_indexer,keel_context_vault,keel_context_policy,keel_context_erasure,
    keel_context_erasure_worker,keel_context_legal_hold,keel_context_replay,keel_agent,keel_callback;

CREATE TABLE keel_meta.callback_conflicts (
    conflict_id bigint GENERATED ALWAYS AS IDENTITY,
    tenant_id uuid NOT NULL CHECK (tenant_id<>'00000000-0000-0000-0000-000000000000'::uuid),
    provider text NOT NULL CHECK (provider ~ '^[a-z][a-z0-9_-]{1,31}$'),
    provider_event_id text NOT NULL CHECK (provider_event_id ~ '^[A-Za-z0-9_.:-]{1,128}$'),
    presented_digest text NOT NULL CHECK (presented_digest ~ '^[0-9a-f]{64}$'),
    conflict_reason text NOT NULL CHECK (conflict_reason IN ('payload_mismatch','tenant_mismatch')),
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (conflict_id)
);
CREATE INDEX callback_conflicts_tenant_recorded ON keel_meta.callback_conflicts(tenant_id,recorded_at DESC);
ALTER TABLE keel_meta.callback_conflicts ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.callback_conflicts FORCE ROW LEVEL SECURITY;
CREATE POLICY callback_conflicts_schema_owner ON keel_meta.callback_conflicts
    TO keel_schema_owner USING (true) WITH CHECK (true);
REVOKE ALL ON keel_meta.callback_conflicts FROM PUBLIC,keel_app,keel_worker,keel_operator,
    keel_budget_control,keel_rate_control,keel_ai_worker,keel_projector,keel_file_processor,
    keel_retrieval_indexer,keel_context_vault,keel_context_policy,keel_context_erasure,
    keel_context_erasure_worker,keel_context_legal_hold,keel_context_replay,keel_agent,keel_callback;

CREATE FUNCTION keel_meta.guard_callback_inbox_row()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    IF TG_OP='DELETE' THEN
        RAISE EXCEPTION 'callback inbox rows are immutable';
    END IF;
    IF current_user<>'keel_schema_owner' OR
       NOT pg_catalog.pg_has_role(session_user,'keel_callback','MEMBER') THEN
        RAISE EXCEPTION 'callback inbox rows are immutable';
    END IF;
    IF NEW.tenant_id<>OLD.tenant_id OR NEW.provider<>OLD.provider OR
       NEW.provider_event_id<>OLD.provider_event_id OR NEW.payload_digest<>OLD.payload_digest OR
       NEW.event_type<>OLD.event_type OR NEW.key_id<>OLD.key_id OR
       NEW.occurred_at<>OLD.occurred_at OR NEW.received_at<>OLD.received_at OR
       OLD.state<>'received' OR NEW.state<>'applied' OR NEW.applied_at IS NULL THEN
        RAISE EXCEPTION 'callback inbox row transition is invalid';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER callback_inbox_guard BEFORE UPDATE OR DELETE
    ON keel_meta.callback_inbox FOR EACH ROW
    EXECUTE FUNCTION keel_meta.guard_callback_inbox_row();
REVOKE ALL ON FUNCTION keel_meta.guard_callback_inbox_row() FROM PUBLIC;

CREATE FUNCTION keel_meta.reject_callback_conflict_mutation()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    RAISE EXCEPTION 'callback conflicts are append-only';
END $$;
CREATE TRIGGER callback_conflict_immutable BEFORE UPDATE OR DELETE
    ON keel_meta.callback_conflicts FOR EACH ROW
    EXECUTE FUNCTION keel_meta.reject_callback_conflict_mutation();
REVOKE ALL ON FUNCTION keel_meta.reject_callback_conflict_mutation() FROM PUBLIC;

CREATE FUNCTION keel_meta.claim_provider_callback(
    p_provider text,p_provider_event_id text,p_payload_digest text,p_event_type text,
    p_key_id text,p_occurred_at timestamptz)
RETURNS TABLE(outcome text,applied_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,keel_meta,keel_private,pg_temp AS $$
DECLARE authorized_tenant uuid;
        existing_tenant uuid;
        existing_digest text;
        existing_state text;
        existing_applied_at timestamptz;
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'keel_callback','MEMBER') THEN
        RAISE EXCEPTION 'callback inbox capability is required';
    END IF;
    authorized_tenant:=keel_private.current_tenant_id();
    IF authorized_tenant IS NULL OR
       p_provider IS NULL OR p_provider !~ '^[a-z][a-z0-9_-]{1,31}$' OR
       p_provider_event_id IS NULL OR p_provider_event_id !~ '^[A-Za-z0-9_.:-]{1,128}$' OR
       p_payload_digest IS NULL OR p_payload_digest !~ '^[0-9a-f]{64}$' OR
       p_event_type IS NULL OR p_event_type !~ '^[a-z][a-z0-9._-]{0,63}$' OR
       p_key_id IS NULL OR p_key_id !~ '^[A-Za-z0-9_.:-]{1,64}$' OR
       p_occurred_at IS NULL THEN
        RAISE EXCEPTION 'callback inbox claim is invalid';
    END IF;

    INSERT INTO keel_meta.callback_inbox
        (tenant_id,provider,provider_event_id,payload_digest,event_type,key_id,occurred_at)
    VALUES (authorized_tenant,p_provider,p_provider_event_id,p_payload_digest,p_event_type,
        p_key_id,p_occurred_at)
    ON CONFLICT (provider,provider_event_id) DO NOTHING;
    IF FOUND THEN
        RETURN QUERY SELECT 'inserted'::text,NULL::timestamptz;
        RETURN;
    END IF;

    SELECT i.tenant_id,i.payload_digest,i.state,i.applied_at
      INTO existing_tenant,existing_digest,existing_state,existing_applied_at
      FROM keel_meta.callback_inbox i
     WHERE i.provider=p_provider AND i.provider_event_id=p_provider_event_id
     FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'callback inbox claim lost its recorded event';
    END IF;

    IF existing_tenant<>authorized_tenant THEN
        INSERT INTO keel_meta.callback_conflicts
            (tenant_id,provider,provider_event_id,presented_digest,conflict_reason)
        VALUES (authorized_tenant,p_provider,p_provider_event_id,p_payload_digest,'tenant_mismatch');
        RETURN QUERY SELECT 'tenant_mismatch'::text,NULL::timestamptz;
        RETURN;
    END IF;
    IF existing_digest<>p_payload_digest THEN
        INSERT INTO keel_meta.callback_conflicts
            (tenant_id,provider,provider_event_id,presented_digest,conflict_reason)
        VALUES (authorized_tenant,p_provider,p_provider_event_id,p_payload_digest,'payload_mismatch');
        RETURN QUERY SELECT 'conflict'::text,NULL::timestamptz;
        RETURN;
    END IF;
    IF existing_state<>'applied' OR existing_applied_at IS NULL THEN
        RAISE EXCEPTION 'callback inbox event is not durably applied';
    END IF;
    RETURN QUERY SELECT 'duplicate'::text,existing_applied_at;
END $$;
REVOKE ALL ON FUNCTION keel_meta.claim_provider_callback(text,text,text,text,text,timestamptz) FROM PUBLIC;

CREATE FUNCTION keel_meta.confirm_provider_callback(p_provider text,p_provider_event_id text)
RETURNS timestamptz
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,keel_meta,keel_private,pg_temp AS $$
DECLARE authorized_tenant uuid; applied timestamptz;
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'keel_callback','MEMBER') THEN
        RAISE EXCEPTION 'callback inbox capability is required';
    END IF;
    authorized_tenant:=keel_private.current_tenant_id();
    IF authorized_tenant IS NULL OR p_provider IS NULL OR p_provider_event_id IS NULL THEN
        RAISE EXCEPTION 'callback inbox confirmation is invalid';
    END IF;
    UPDATE keel_meta.callback_inbox i
       SET state='applied',applied_at=clock_timestamp()
     WHERE i.tenant_id=authorized_tenant AND i.provider=p_provider
       AND i.provider_event_id=p_provider_event_id AND i.state='received'
     RETURNING i.applied_at INTO applied;
    IF applied IS NULL THEN
        RAISE EXCEPTION 'callback inbox confirmation has no recorded event';
    END IF;
    RETURN applied;
END $$;
REVOKE ALL ON FUNCTION keel_meta.confirm_provider_callback(text,text) FROM PUBLIC;

GRANT USAGE ON SCHEMA keel_meta,keel_private TO keel_callback;
GRANT EXECUTE ON FUNCTION keel_private.current_tenant_id() TO keel_callback;
GRANT EXECUTE ON FUNCTION keel_meta.claim_provider_callback(text,text,text,text,text,timestamptz) TO keel_callback;
GRANT EXECUTE ON FUNCTION keel_meta.confirm_provider_callback(text,text) TO keel_callback;
