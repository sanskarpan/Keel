CREATE TABLE keel_meta.identity_principals (
    principal_id uuid NOT NULL CHECK (principal_id<>'00000000-0000-0000-0000-000000000000'::uuid),
    email_digest bytea NOT NULL CHECK (octet_length(email_digest)=32),
    state text NOT NULL DEFAULT 'pending_verification'
        CHECK (state IN ('pending_verification','active','disabled')),
    tenant_id uuid CHECK (tenant_id IS NULL OR tenant_id<>'00000000-0000-0000-0000-000000000000'::uuid),
    verified_at timestamptz,
    disabled_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (principal_id),
    CONSTRAINT identity_principal_email_unique UNIQUE (email_digest),
    CONSTRAINT identity_principal_state_shape CHECK (
        (state='pending_verification' AND verified_at IS NULL AND disabled_at IS NULL) OR
        (state='active' AND verified_at IS NOT NULL AND disabled_at IS NULL) OR
        (state='disabled' AND disabled_at IS NOT NULL))
);
ALTER TABLE keel_meta.identity_principals ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.identity_principals FORCE ROW LEVEL SECURITY;
CREATE POLICY identity_principals_schema_owner ON keel_meta.identity_principals
    TO keel_schema_owner USING (true) WITH CHECK (true);
REVOKE ALL ON keel_meta.identity_principals FROM PUBLIC,keel_app,keel_worker,keel_operator,
    keel_budget_control,keel_rate_control,keel_rate_status,keel_ai_worker,keel_projector,
    keel_file_processor,keel_retrieval_indexer,keel_context_vault,keel_context_policy,
    keel_context_erasure,keel_context_erasure_worker,keel_context_legal_hold,
    keel_context_replay,keel_agent,keel_callback,keel_webhook,keel_identity;

CREATE TABLE keel_meta.identity_credentials (
    principal_id uuid NOT NULL REFERENCES keel_meta.identity_principals(principal_id),
    password_hash text NOT NULL CHECK (length(password_hash) BETWEEN 1 AND 256),
    version integer NOT NULL DEFAULT 1 CHECK (version>=1),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (principal_id)
);
ALTER TABLE keel_meta.identity_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.identity_credentials FORCE ROW LEVEL SECURITY;
CREATE POLICY identity_credentials_schema_owner ON keel_meta.identity_credentials
    TO keel_schema_owner USING (true) WITH CHECK (true);
REVOKE ALL ON keel_meta.identity_credentials FROM PUBLIC,keel_app,keel_worker,keel_operator,
    keel_budget_control,keel_rate_control,keel_rate_status,keel_ai_worker,keel_projector,
    keel_file_processor,keel_retrieval_indexer,keel_context_vault,keel_context_policy,
    keel_context_erasure,keel_context_erasure_worker,keel_context_legal_hold,
    keel_context_replay,keel_agent,keel_callback,keel_webhook,keel_identity;

CREATE TABLE keel_meta.identity_email_verifications (
    principal_id uuid NOT NULL REFERENCES keel_meta.identity_principals(principal_id),
    token_digest bytea NOT NULL CHECK (octet_length(token_digest)=32),
    requested_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    CONSTRAINT identity_email_verification_token_unique UNIQUE (token_digest),
    CONSTRAINT identity_email_verification_window CHECK (expires_at>requested_at),
    CONSTRAINT identity_email_verification_shape CHECK (consumed_at IS NULL OR consumed_at>=requested_at)
);
ALTER TABLE keel_meta.identity_email_verifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.identity_email_verifications FORCE ROW LEVEL SECURITY;
CREATE POLICY identity_email_verifications_schema_owner ON keel_meta.identity_email_verifications
    TO keel_schema_owner USING (true) WITH CHECK (true);
REVOKE ALL ON keel_meta.identity_email_verifications FROM PUBLIC,keel_app,keel_worker,keel_operator,
    keel_budget_control,keel_rate_control,keel_rate_status,keel_ai_worker,keel_projector,
    keel_file_processor,keel_retrieval_indexer,keel_context_vault,keel_context_policy,
    keel_context_erasure,keel_context_erasure_worker,keel_context_legal_hold,
    keel_context_replay,keel_agent,keel_callback,keel_webhook,keel_identity;

CREATE TABLE keel_meta.identity_sessions (
    session_id uuid NOT NULL CHECK (session_id<>'00000000-0000-0000-0000-000000000000'::uuid),
    principal_id uuid NOT NULL REFERENCES keel_meta.identity_principals(principal_id),
    token_digest bytea NOT NULL CHECK (octet_length(token_digest)=32),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    PRIMARY KEY (session_id),
    CONSTRAINT identity_session_token_unique UNIQUE (token_digest),
    CONSTRAINT identity_session_window CHECK (
        expires_at>created_at AND expires_at-created_at<=INTERVAL '30 days'),
    CONSTRAINT identity_session_shape CHECK (revoked_at IS NULL OR revoked_at>=created_at)
);
ALTER TABLE keel_meta.identity_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.identity_sessions FORCE ROW LEVEL SECURITY;
CREATE POLICY identity_sessions_schema_owner ON keel_meta.identity_sessions
    TO keel_schema_owner USING (true) WITH CHECK (true);
REVOKE ALL ON keel_meta.identity_sessions FROM PUBLIC,keel_app,keel_worker,keel_operator,
    keel_budget_control,keel_rate_control,keel_rate_status,keel_ai_worker,keel_projector,
    keel_file_processor,keel_retrieval_indexer,keel_context_vault,keel_context_policy,
    keel_context_erasure,keel_context_erasure_worker,keel_context_legal_hold,
    keel_context_replay,keel_agent,keel_callback,keel_webhook,keel_identity;

CREATE FUNCTION keel_meta.guard_identity_principals_row()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    IF TG_OP='DELETE' THEN
        RAISE EXCEPTION 'identity principals have no delete path';
    END IF;
    IF current_user<>'keel_schema_owner' OR
       NOT pg_catalog.pg_has_role(session_user,'keel_identity','MEMBER') THEN
        RAISE EXCEPTION 'identity principals are capability-managed';
    END IF;
    IF NEW.principal_id<>OLD.principal_id OR NEW.email_digest<>OLD.email_digest OR
       NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR NEW.created_at<>OLD.created_at THEN
        RAISE EXCEPTION 'identity principal identity is immutable';
    END IF;
    IF NOT (OLD.state='pending_verification' AND NEW.state='active' AND
            NEW.verified_at IS NOT NULL AND NEW.disabled_at IS NULL) THEN
        RAISE EXCEPTION 'direct principal mutations are refused';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER identity_principals_guard BEFORE UPDATE OR DELETE
    ON keel_meta.identity_principals FOR EACH ROW
    EXECUTE FUNCTION keel_meta.guard_identity_principals_row();
REVOKE ALL ON FUNCTION keel_meta.guard_identity_principals_row() FROM PUBLIC;

CREATE FUNCTION keel_meta.guard_identity_credentials_row()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    RAISE EXCEPTION 'identity credentials are immutable; rotation arrives in a later audit slice';
END $$;
CREATE TRIGGER identity_credentials_guard BEFORE UPDATE OR DELETE
    ON keel_meta.identity_credentials FOR EACH ROW
    EXECUTE FUNCTION keel_meta.guard_identity_credentials_row();
REVOKE ALL ON FUNCTION keel_meta.guard_identity_credentials_row() FROM PUBLIC;

CREATE FUNCTION keel_meta.guard_identity_email_verifications_row()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    IF TG_OP='DELETE' THEN
        -- a resend replaces only an unconsumed pending request.
        IF OLD.consumed_at IS NOT NULL OR
           current_user<>'keel_schema_owner' OR
           NOT pg_catalog.pg_has_role(session_user,'keel_identity','MEMBER') THEN
            RAISE EXCEPTION 'consumed verifications are immutable';
        END IF;
        RETURN OLD;
    END IF;
    IF current_user<>'keel_schema_owner' OR
       NOT pg_catalog.pg_has_role(session_user,'keel_identity','MEMBER') THEN
        RAISE EXCEPTION 'identity verifications are capability-managed';
    END IF;
    IF NEW.principal_id<>OLD.principal_id OR NEW.token_digest<>OLD.token_digest OR
       NEW.requested_at<>OLD.requested_at OR NEW.expires_at<>OLD.expires_at OR
       OLD.consumed_at IS NOT NULL OR NEW.consumed_at IS NULL THEN
        RAISE EXCEPTION 'verification rows may only move pending to consumed';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER identity_email_verifications_guard BEFORE UPDATE OR DELETE
    ON keel_meta.identity_email_verifications FOR EACH ROW
    EXECUTE FUNCTION keel_meta.guard_identity_email_verifications_row();
REVOKE ALL ON FUNCTION keel_meta.guard_identity_email_verifications_row() FROM PUBLIC;

CREATE FUNCTION keel_meta.guard_identity_sessions_row()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    IF TG_OP='DELETE' OR NEW.session_id<>OLD.session_id OR NEW.principal_id<>OLD.principal_id OR
       NEW.token_digest<>OLD.token_digest OR NEW.created_at<>OLD.created_at OR
       NEW.expires_at<>OLD.expires_at OR (OLD.revoked_at IS NOT NULL AND NEW.revoked_at<>OLD.revoked_at) THEN
        RAISE EXCEPTION 'identity sessions are capability-managed history';
    END IF;
    IF current_user<>'keel_schema_owner' OR
       NOT pg_catalog.pg_has_role(session_user,'keel_identity','MEMBER') THEN
        RAISE EXCEPTION 'identity sessions are capability-managed';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER identity_sessions_guard BEFORE UPDATE OR DELETE
    ON keel_meta.identity_sessions FOR EACH ROW
    EXECUTE FUNCTION keel_meta.guard_identity_sessions_row();
REVOKE ALL ON FUNCTION keel_meta.guard_identity_sessions_row() FROM PUBLIC;

CREATE FUNCTION keel_meta.create_identity_principal(
    p_principal_id uuid,p_email_digest bytea,p_password_hash text,p_tenant uuid)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,keel_meta,pg_temp AS $$
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'keel_identity','MEMBER') THEN
        RAISE EXCEPTION 'identity capability is required';
    END IF;
    IF p_principal_id IS NULL OR p_principal_id='00000000-0000-0000-0000-000000000000'::uuid OR
       p_email_digest IS NULL OR octet_length(p_email_digest)<>32 OR
       p_password_hash IS NULL OR length(p_password_hash) NOT BETWEEN 1 AND 256 THEN
        RAISE EXCEPTION 'identity bootstrap is invalid';
    END IF;
    INSERT INTO keel_meta.identity_principals (principal_id,email_digest,tenant_id)
        VALUES (p_principal_id,p_email_digest,p_tenant);
    INSERT INTO keel_meta.identity_credentials (principal_id,password_hash)
        VALUES (p_principal_id,p_password_hash);
    RETURN 'created';
END $$;
REVOKE ALL ON FUNCTION keel_meta.create_identity_principal(uuid,bytea,text,uuid) FROM PUBLIC;

CREATE FUNCTION keel_meta.identity_password_credential(p_email_digest bytea)
RETURNS TABLE(out_principal_id uuid,out_state text,out_password_hash text)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,keel_meta,pg_temp AS $$
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'keel_identity','MEMBER') THEN
        RAISE EXCEPTION 'identity capability is required';
    END IF;
    IF p_email_digest IS NULL OR octet_length(p_email_digest)<>32 THEN
        RAISE EXCEPTION 'identity credential lookup is invalid';
    END IF;
    RETURN QUERY
        SELECT p.principal_id,p.state,c.password_hash
          FROM keel_meta.identity_principals p
          JOIN keel_meta.identity_credentials c ON c.principal_id=p.principal_id
         WHERE p.email_digest=p_email_digest;
END $$;
REVOKE ALL ON FUNCTION keel_meta.identity_password_credential(bytea) FROM PUBLIC;

CREATE FUNCTION keel_meta.record_identity_verification(
    p_principal_id uuid,p_token_digest bytea,p_expires_at timestamptz)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,keel_meta,pg_temp AS $$
DECLARE state text;
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'keel_identity','MEMBER') THEN
        RAISE EXCEPTION 'identity capability is required';
    END IF;
    IF p_principal_id IS NULL OR octet_length(p_token_digest)<>32 OR p_expires_at IS NULL THEN
        RAISE EXCEPTION 'identity verification request is invalid';
    END IF;
    SELECT principal_state INTO state FROM keel_meta.identity_principals
      WHERE principal_id=p_principal_id FOR UPDATE;
    IF state IS NULL OR state<>'pending_verification' THEN
        RETURN 'not_pending';
    END IF;
    IF p_expires_at<=clock_timestamp() OR
       p_expires_at>clock_timestamp()+INTERVAL '24 hours' THEN
        RAISE EXCEPTION 'identity verification window is out of bounds';
    END IF;
    IF EXISTS (SELECT 1 FROM keel_meta.identity_email_verifications v
                 WHERE v.token_digest=p_token_digest) THEN
        RETURN 'token_reuse';
    END IF;
    DELETE FROM keel_meta.identity_email_verifications
      WHERE principal_id=p_principal_id;
    INSERT INTO keel_meta.identity_email_verifications
        (principal_id,token_digest,requested_at,expires_at)
        VALUES (p_principal_id,p_token_digest,clock_timestamp(),p_expires_at);
    RETURN 'recorded';
END $$;
REVOKE ALL ON FUNCTION keel_meta.record_identity_verification(uuid,bytea,timestamptz) FROM PUBLIC;

CREATE FUNCTION keel_meta.consume_identity_verification(p_token_digest bytea)
RETURNS TABLE(outcome text,out_principal_id uuid)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,keel_meta,pg_temp AS $$
DECLARE target uuid;
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'keel_identity','MEMBER') THEN
        RAISE EXCEPTION 'identity capability is required';
    END IF;
    IF p_token_digest IS NULL OR octet_length(p_token_digest)<>32 THEN
        RAISE EXCEPTION 'identity verification consume is invalid';
    END IF;
    SELECT principal_id INTO target FROM keel_meta.identity_email_verifications
      WHERE token_digest=p_token_digest FOR UPDATE;
    IF target IS NULL THEN
        RETURN QUERY SELECT 'unknown'::text,NULL::uuid;
        RETURN;
    END IF;
    UPDATE keel_meta.identity_email_verifications v SET consumed_at=clock_timestamp()
      WHERE v.token_digest=p_token_digest AND v.consumed_at IS NULL;
    IF NOT FOUND THEN
        RETURN QUERY SELECT 'duplicate'::text,target;
        RETURN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM keel_meta.identity_email_verifications v
                     WHERE v.token_digest=p_token_digest AND v.expires_at>clock_timestamp()) THEN
        RETURN QUERY SELECT 'expired'::text,target;
        RETURN;
    END IF;
    UPDATE keel_meta.identity_principals p
       SET state='active',verified_at=clock_timestamp()
     WHERE p.principal_id=target AND p.state='pending_verification';
    IF NOT FOUND THEN
        RAISE EXCEPTION 'identity principal vanished during verification';
    END IF;
    RETURN QUERY SELECT 'verified'::text,target;
END $$;
REVOKE ALL ON FUNCTION keel_meta.consume_identity_verification(bytea) FROM PUBLIC;

CREATE FUNCTION keel_meta.record_identity_session(
    p_session_id uuid,p_principal_id uuid,p_token_digest bytea,p_expires_at timestamptz)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,keel_meta,pg_temp AS $$
DECLARE state text;
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'keel_identity','MEMBER') THEN
        RAISE EXCEPTION 'identity capability is required';
    END IF;
    IF p_session_id IS NULL OR p_session_id='00000000-0000-0000-0000-000000000000'::uuid OR
       p_principal_id IS NULL OR octet_length(p_token_digest)<>32 OR p_expires_at IS NULL THEN
        RAISE EXCEPTION 'identity session record is invalid';
    END IF;
    SELECT principal_state INTO state FROM keel_meta.identity_principals
      WHERE principal_id=p_principal_id FOR UPDATE;
    IF state IS NULL OR state<>'active' THEN
        RETURN 'principal_inactive';
    END IF;
    IF p_expires_at<=clock_timestamp() OR
       p_expires_at>clock_timestamp()+INTERVAL '30 days' THEN
        RAISE EXCEPTION 'identity session window is out of bounds';
    END IF;
    INSERT INTO keel_meta.identity_sessions
        (session_id,principal_id,token_digest,created_at,expires_at)
        VALUES (p_session_id,p_principal_id,p_token_digest,clock_timestamp(),p_expires_at);
    RETURN 'created';
END $$;
REVOKE ALL ON FUNCTION keel_meta.record_identity_session(uuid,uuid,bytea,timestamptz) FROM PUBLIC;

CREATE FUNCTION keel_meta.identity_session_for(p_token_digest bytea)
RETURNS TABLE(out_session_id uuid,out_principal_id uuid,out_principal_state text,
              out_created_at timestamptz,out_expires_at timestamptz,out_revoked_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,keel_meta,pg_temp AS $$
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'keel_identity','MEMBER') THEN
        RAISE EXCEPTION 'identity capability is required';
    END IF;
    IF p_token_digest IS NULL OR octet_length(p_token_digest)<>32 THEN
        RAISE EXCEPTION 'identity session lookup is invalid';
    END IF;
    RETURN QUERY
        SELECT s.session_id,s.principal_id,p.state,s.created_at,s.expires_at,s.revoked_at
          FROM keel_meta.identity_sessions s
          JOIN keel_meta.identity_principals p ON p.principal_id=s.principal_id
         WHERE s.token_digest=p_token_digest;
END $$;
REVOKE ALL ON FUNCTION keel_meta.identity_session_for(bytea) FROM PUBLIC;

CREATE FUNCTION keel_meta.revoke_identity_session(p_session_id uuid)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,keel_meta,pg_temp AS $$
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'keel_identity','MEMBER') THEN
        RAISE EXCEPTION 'identity capability is required';
    END IF;
    IF p_session_id IS NULL OR p_session_id='00000000-0000-0000-0000-000000000000'::uuid THEN
        RAISE EXCEPTION 'identity session revoke is invalid';
    END IF;
    UPDATE keel_meta.identity_sessions s SET revoked_at=clock_timestamp()
      WHERE s.session_id=p_session_id AND s.revoked_at IS NULL;
    IF NOT FOUND THEN
        RETURN 'unknown_session';
    END IF;
    RETURN 'revoked';
END $$;
REVOKE ALL ON FUNCTION keel_meta.revoke_identity_session(uuid) FROM PUBLIC;

GRANT USAGE ON SCHEMA keel_meta TO keel_identity;
GRANT EXECUTE ON FUNCTION keel_meta.create_identity_principal(uuid,bytea,text,uuid) TO keel_identity;
GRANT EXECUTE ON FUNCTION keel_meta.identity_password_credential(bytea) TO keel_identity;
GRANT EXECUTE ON FUNCTION keel_meta.record_identity_verification(uuid,bytea,timestamptz) TO keel_identity;
GRANT EXECUTE ON FUNCTION keel_meta.consume_identity_verification(bytea) TO keel_identity;
GRANT EXECUTE ON FUNCTION keel_meta.record_identity_session(uuid,uuid,bytea,timestamptz) TO keel_identity;
GRANT EXECUTE ON FUNCTION keel_meta.identity_session_for(bytea) TO keel_identity;
GRANT EXECUTE ON FUNCTION keel_meta.revoke_identity_session(uuid) TO keel_identity;
