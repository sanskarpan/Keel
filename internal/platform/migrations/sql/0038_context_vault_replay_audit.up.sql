CREATE TABLE keel_meta.context_vault_replay_attempts (
    tenant_id uuid NOT NULL CHECK (tenant_id<>'00000000-0000-0000-0000-000000000000'::uuid),
    request_id text NOT NULL CHECK (request_id ~ '^[A-Za-z0-9_-]{16,96}$'),
    actor_id uuid NOT NULL CHECK (actor_id<>'00000000-0000-0000-0000-000000000000'::uuid),
    record_id uuid NOT NULL CHECK (record_id<>'00000000-0000-0000-0000-000000000000'::uuid),
    version bigint NOT NULL CHECK (version>0),
    purpose text NOT NULL CHECK (purpose IN ('read_only_replay','incident_review')),
    reason_code text NOT NULL CHECK (reason_code IN ('support_diagnostic','security_investigation','customer_requested')),
    state text NOT NULL CHECK (state IN ('started','complete','integrity_failed','delivery_failed','cancelled','unavailable')),
    started_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    finished_at timestamptz,
    PRIMARY KEY (tenant_id,request_id),
    CHECK ((state='started' AND finished_at IS NULL) OR (state<>'started' AND finished_at IS NOT NULL))
);
ALTER TABLE keel_meta.context_vault_replay_attempts ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.context_vault_replay_attempts FORCE ROW LEVEL SECURITY;
CREATE POLICY context_vault_replay_attempts_authority ON keel_meta.context_vault_replay_attempts
    TO keel_context_replay USING (tenant_id=(SELECT keel_private.current_tenant_id()))
    WITH CHECK (tenant_id=(SELECT keel_private.current_tenant_id()));
CREATE POLICY context_vault_replay_attempts_schema_owner ON keel_meta.context_vault_replay_attempts
    TO keel_schema_owner USING (true) WITH CHECK (true);
REVOKE ALL ON keel_meta.context_vault_replay_attempts FROM PUBLIC,keel_app,keel_worker,keel_operator,
    keel_context_vault,keel_context_policy,keel_context_erasure,keel_context_erasure_worker,
    keel_context_legal_hold,keel_context_replay,keel_agent;

CREATE TABLE keel_meta.context_vault_replay_events (
    tenant_id uuid NOT NULL,
    request_id text NOT NULL,
    event_no smallint NOT NULL CHECK (event_no IN (1,2)),
    actor_id uuid NOT NULL CHECK (actor_id<>'00000000-0000-0000-0000-000000000000'::uuid),
    record_id uuid NOT NULL CHECK (record_id<>'00000000-0000-0000-0000-000000000000'::uuid),
    version bigint NOT NULL CHECK (version>0),
    event_type text NOT NULL CHECK (event_type IN ('started','finished')),
    outcome text NOT NULL CHECK (outcome IN ('authorized','unauthorized','complete','integrity_failed','key_unavailable','delivery_failed','cancelled','unavailable')),
    event_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id,request_id,event_no),
    FOREIGN KEY (tenant_id,request_id) REFERENCES keel_meta.context_vault_replay_attempts(tenant_id,request_id)
);
ALTER TABLE keel_meta.context_vault_replay_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.context_vault_replay_events FORCE ROW LEVEL SECURITY;
CREATE POLICY context_vault_replay_events_authority ON keel_meta.context_vault_replay_events
    TO keel_context_replay USING (tenant_id=(SELECT keel_private.current_tenant_id()))
    WITH CHECK (tenant_id=(SELECT keel_private.current_tenant_id()));
CREATE POLICY context_vault_replay_events_schema_owner ON keel_meta.context_vault_replay_events
    TO keel_schema_owner USING (true) WITH CHECK (true);
REVOKE ALL ON keel_meta.context_vault_replay_events FROM PUBLIC,keel_app,keel_worker,keel_operator,
    keel_context_vault,keel_context_policy,keel_context_erasure,keel_context_erasure_worker,
    keel_context_legal_hold,keel_context_replay,keel_agent;

CREATE FUNCTION keel_meta.reject_context_vault_replay_event_mutation()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    RAISE EXCEPTION 'context vault replay events are append-only';
END $$;
CREATE TRIGGER context_vault_replay_event_immutable BEFORE UPDATE OR DELETE
    ON keel_meta.context_vault_replay_events FOR EACH ROW
    EXECUTE FUNCTION keel_meta.reject_context_vault_replay_event_mutation();
REVOKE ALL ON FUNCTION keel_meta.reject_context_vault_replay_event_mutation() FROM PUBLIC;

CREATE FUNCTION keel_meta.guard_context_vault_replay_attempt()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    IF TG_OP='INSERT' THEN
        IF NEW.state NOT IN ('started','unavailable') OR
           (NEW.state='started' AND NEW.finished_at IS NOT NULL) OR
           (NEW.state='unavailable' AND NEW.finished_at IS NULL) OR
           NOT pg_catalog.pg_has_role(session_user,'keel_context_replay','MEMBER') OR current_user<>'keel_schema_owner' THEN
            RAISE EXCEPTION 'context replay capability is required';
        END IF;
        RETURN NEW;
    END IF;
    IF TG_OP='DELETE' OR NEW.tenant_id<>OLD.tenant_id OR NEW.request_id<>OLD.request_id OR
       NEW.actor_id<>OLD.actor_id OR NEW.record_id<>OLD.record_id OR NEW.version<>OLD.version OR
       NEW.purpose<>OLD.purpose OR NEW.reason_code<>OLD.reason_code OR OLD.state<>'started' OR
       NEW.state='started' OR NEW.finished_at<=OLD.started_at OR current_user<>'keel_schema_owner' OR
       NOT pg_catalog.pg_has_role(session_user,'keel_context_replay','MEMBER') THEN
        RAISE EXCEPTION 'invalid context replay attempt transition';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER context_vault_replay_attempt_guard BEFORE INSERT OR UPDATE OR DELETE
    ON keel_meta.context_vault_replay_attempts FOR EACH ROW
    EXECUTE FUNCTION keel_meta.guard_context_vault_replay_attempt();
REVOKE ALL ON FUNCTION keel_meta.guard_context_vault_replay_attempt() FROM PUBLIC;

CREATE FUNCTION keel_meta.begin_context_vault_replay(
    p_request_id text,p_actor_id uuid,p_record_id uuid,p_version bigint,p_purpose text,p_reason_code text)
RETURNS TABLE(status text,record_id uuid,version bigint,policy_digest text,algorithm text,key_id text,
    wrapped_dek bytea,nonce bytea,ciphertext bytea)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,keel_meta,keel_private,pg_temp AS $$
DECLARE authorized_tenant uuid; record_row keel_meta.context_vault_records%ROWTYPE;
        initial_state text; initial_outcome text;
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'keel_context_replay','MEMBER') THEN
        RAISE EXCEPTION 'context replay capability is required';
    END IF;
    authorized_tenant:=keel_private.current_tenant_id();
    IF authorized_tenant IS NULL OR p_request_id IS NULL OR p_request_id !~ '^[A-Za-z0-9_-]{16,96}$' OR
       p_actor_id IS NULL OR p_actor_id='00000000-0000-0000-0000-000000000000'::uuid OR
       p_record_id IS NULL OR p_record_id='00000000-0000-0000-0000-000000000000'::uuid OR
       p_version IS NULL OR p_version<1 OR p_purpose IS NULL OR p_purpose NOT IN ('read_only_replay','incident_review') OR
       p_reason_code IS NULL OR p_reason_code NOT IN ('support_diagnostic','security_investigation','customer_requested') THEN
        RAISE EXCEPTION 'context replay request is invalid';
    END IF;
    IF EXISTS (SELECT 1 FROM keel_meta.context_vault_replay_attempts a
        WHERE a.tenant_id=authorized_tenant AND a.request_id=p_request_id) THEN
        RAISE EXCEPTION 'context replay request identity was already used';
    END IF;

    SELECT * INTO record_row FROM keel_meta.context_vault_records r
     WHERE r.tenant_id=authorized_tenant AND r.record_id=p_record_id AND r.version=p_version
       AND r.purpose=p_purpose AND r.expires_at>statement_timestamp()
     FOR SHARE;
    initial_state:='started'; initial_outcome:='authorized';
    IF NOT FOUND THEN initial_state:='unavailable'; initial_outcome:='unavailable';
    ELSIF keel_meta.context_vault_has_active_legal_hold(authorized_tenant,p_record_id,p_version) THEN
        initial_state:='unavailable'; initial_outcome:='unavailable';
    END IF;
    INSERT INTO keel_meta.context_vault_replay_attempts
        (tenant_id,request_id,actor_id,record_id,version,purpose,reason_code,state,finished_at)
    VALUES (authorized_tenant,p_request_id,p_actor_id,p_record_id,p_version,p_purpose,p_reason_code,
        initial_state,CASE WHEN initial_state='started' THEN NULL ELSE clock_timestamp() END);
    INSERT INTO keel_meta.context_vault_replay_events
        (tenant_id,request_id,event_no,actor_id,record_id,version,event_type,outcome)
    VALUES (authorized_tenant,p_request_id,1,p_actor_id,p_record_id,p_version,
        CASE WHEN initial_state='started' THEN 'started' ELSE 'finished' END,initial_outcome);
    IF initial_state<>'started' THEN
        RETURN QUERY SELECT initial_state,NULL::uuid,NULL::bigint,NULL::text,NULL::text,NULL::text,
            NULL::bytea,NULL::bytea,NULL::bytea;
        RETURN;
    END IF;
    RETURN QUERY SELECT initial_state,record_row.record_id,record_row.version,record_row.policy_digest,
        record_row.algorithm,record_row.key_id,record_row.wrapped_dek,record_row.nonce,record_row.ciphertext;
END $$;
REVOKE ALL ON FUNCTION keel_meta.begin_context_vault_replay(text,uuid,uuid,bigint,text,text) FROM PUBLIC;

CREATE FUNCTION keel_meta.record_denied_context_vault_replay(
    p_request_id text,p_actor_id uuid,p_record_id uuid,p_version bigint,p_purpose text,p_reason_code text)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,keel_meta,keel_private,pg_temp AS $$
DECLARE authorized_tenant uuid;
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'keel_context_replay','MEMBER') THEN
        RAISE EXCEPTION 'context replay capability is required';
    END IF;
    authorized_tenant:=keel_private.current_tenant_id();
    IF authorized_tenant IS NULL OR p_request_id IS NULL OR p_request_id !~ '^[A-Za-z0-9_-]{16,96}$' OR
       p_actor_id IS NULL OR p_actor_id='00000000-0000-0000-0000-000000000000'::uuid OR
       p_record_id IS NULL OR p_record_id='00000000-0000-0000-0000-000000000000'::uuid OR
       p_version IS NULL OR p_version<1 OR p_purpose IS NULL OR p_purpose NOT IN ('read_only_replay','incident_review') OR
       p_reason_code IS NULL OR p_reason_code NOT IN ('support_diagnostic','security_investigation','customer_requested') THEN
        RAISE EXCEPTION 'context replay request is invalid';
    END IF;
    INSERT INTO keel_meta.context_vault_replay_attempts
        (tenant_id,request_id,actor_id,record_id,version,purpose,reason_code,state,finished_at)
    VALUES (authorized_tenant,p_request_id,p_actor_id,p_record_id,p_version,p_purpose,p_reason_code,
        'unavailable',clock_timestamp());
    INSERT INTO keel_meta.context_vault_replay_events
        (tenant_id,request_id,event_no,actor_id,record_id,version,event_type,outcome)
    VALUES (authorized_tenant,p_request_id,1,p_actor_id,p_record_id,p_version,'finished','unauthorized');
END $$;
REVOKE ALL ON FUNCTION keel_meta.record_denied_context_vault_replay(text,uuid,uuid,bigint,text,text) FROM PUBLIC;

CREATE FUNCTION keel_meta.prepare_context_vault_replay_release(p_request_id text,p_actor_id uuid)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,keel_meta,keel_private,pg_temp AS $$
DECLARE authorized_tenant uuid; attempt keel_meta.context_vault_replay_attempts%ROWTYPE;
        record_found boolean;
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'keel_context_replay','MEMBER') THEN
        RAISE EXCEPTION 'context replay capability is required';
    END IF;
    authorized_tenant:=keel_private.current_tenant_id();
    SELECT * INTO attempt FROM keel_meta.context_vault_replay_attempts a
     WHERE a.tenant_id=authorized_tenant AND a.request_id=p_request_id AND a.actor_id=p_actor_id FOR UPDATE;
    IF NOT FOUND OR attempt.state<>'started' THEN RAISE EXCEPTION 'context replay request is unavailable'; END IF;
    PERFORM 1 FROM keel_meta.context_vault_records r
     WHERE r.tenant_id=authorized_tenant AND r.record_id=attempt.record_id AND r.version=attempt.version
       AND r.purpose=attempt.purpose AND r.expires_at>statement_timestamp() FOR SHARE;
    record_found:=FOUND;
    IF NOT record_found OR keel_meta.context_vault_has_active_legal_hold(
        authorized_tenant,attempt.record_id,attempt.version) THEN
        UPDATE keel_meta.context_vault_replay_attempts SET state='unavailable',finished_at=clock_timestamp()
         WHERE tenant_id=authorized_tenant AND request_id=p_request_id;
        INSERT INTO keel_meta.context_vault_replay_events
            (tenant_id,request_id,event_no,actor_id,record_id,version,event_type,outcome)
        VALUES (authorized_tenant,p_request_id,2,p_actor_id,attempt.record_id,attempt.version,'finished','unavailable');
        RETURN false;
    END IF;
    RETURN true;
END $$;
REVOKE ALL ON FUNCTION keel_meta.prepare_context_vault_replay_release(text,uuid) FROM PUBLIC;

CREATE FUNCTION keel_meta.finish_context_vault_replay(p_request_id text,p_actor_id uuid,p_outcome text)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,keel_meta,keel_private,pg_temp AS $$
DECLARE authorized_tenant uuid; attempt keel_meta.context_vault_replay_attempts%ROWTYPE;
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'keel_context_replay','MEMBER') THEN
        RAISE EXCEPTION 'context replay capability is required';
    END IF;
    authorized_tenant:=keel_private.current_tenant_id();
    IF authorized_tenant IS NULL OR p_request_id IS NULL OR p_actor_id IS NULL OR
       p_outcome NOT IN ('complete','integrity_failed','key_unavailable','delivery_failed','cancelled') THEN
        RAISE EXCEPTION 'context replay outcome is invalid';
    END IF;
    SELECT * INTO attempt FROM keel_meta.context_vault_replay_attempts a
     WHERE a.tenant_id=authorized_tenant AND a.request_id=p_request_id AND a.actor_id=p_actor_id FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'context replay request is unavailable'; END IF;
    IF attempt.state=p_outcome THEN RETURN; END IF;
    IF attempt.state<>'started' THEN RAISE EXCEPTION 'context replay request is already terminal'; END IF;
    UPDATE keel_meta.context_vault_replay_attempts SET state=p_outcome,finished_at=clock_timestamp()
     WHERE tenant_id=authorized_tenant AND request_id=p_request_id;
    INSERT INTO keel_meta.context_vault_replay_events
        (tenant_id,request_id,event_no,actor_id,record_id,version,event_type,outcome)
    VALUES (authorized_tenant,p_request_id,2,p_actor_id,attempt.record_id,attempt.version,'finished',p_outcome);
END $$;
REVOKE ALL ON FUNCTION keel_meta.finish_context_vault_replay(text,uuid,text) FROM PUBLIC;

GRANT USAGE ON SCHEMA keel_meta,keel_private TO keel_context_replay;
GRANT EXECUTE ON FUNCTION keel_private.current_tenant_id() TO keel_context_replay;
GRANT EXECUTE ON FUNCTION keel_meta.begin_context_vault_replay(text,uuid,uuid,bigint,text,text) TO keel_context_replay;
GRANT EXECUTE ON FUNCTION keel_meta.record_denied_context_vault_replay(text,uuid,uuid,bigint,text,text) TO keel_context_replay;
GRANT EXECUTE ON FUNCTION keel_meta.prepare_context_vault_replay_release(text,uuid) TO keel_context_replay;
GRANT EXECUTE ON FUNCTION keel_meta.finish_context_vault_replay(text,uuid,text) TO keel_context_replay;
