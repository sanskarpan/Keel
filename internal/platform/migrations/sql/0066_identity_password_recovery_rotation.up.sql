-- K8.11 slice 2: password recovery with rotation and session revocation.
-- Adds a one-shot password-reset capability: active principals record a bounded
-- reset request, then atomically consume it to rotate the Argon2id credential
-- and revoke every live session (takeover boundary). A standalone revoke-all
-- supports owner lockout. The credentials guard is replaced to allow only
-- versioned rotation through the capability; deletes stay refused and direct
-- table access stays revoked.

CREATE TABLE keel_meta.identity_password_resets (
    principal_id uuid NOT NULL REFERENCES keel_meta.identity_principals(principal_id),
    token_digest bytea NOT NULL CHECK (octet_length(token_digest)=32),
    requested_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    CONSTRAINT identity_password_reset_token_unique UNIQUE (token_digest),
    CONSTRAINT identity_password_reset_window CHECK (expires_at>requested_at),
    CONSTRAINT identity_password_reset_shape CHECK (consumed_at IS NULL OR consumed_at>=requested_at)
);
ALTER TABLE keel_meta.identity_password_resets ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.identity_password_resets FORCE ROW LEVEL SECURITY;
CREATE POLICY identity_password_resets_schema_owner ON keel_meta.identity_password_resets
    TO keel_schema_owner USING (true) WITH CHECK (true);
REVOKE ALL ON keel_meta.identity_password_resets FROM PUBLIC,keel_app,keel_worker,keel_operator,
    keel_budget_control,keel_rate_control,keel_rate_status,keel_ai_worker,keel_projector,
    keel_file_processor,keel_retrieval_indexer,keel_context_vault,keel_context_policy,
    keel_context_erasure,keel_context_erasure_worker,keel_context_legal_hold,
    keel_context_replay,keel_agent,keel_callback,keel_webhook,keel_identity;

CREATE FUNCTION keel_meta.guard_identity_password_resets_row()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    IF TG_OP='DELETE' THEN
        -- a resend replaces only an unconsumed pending request.
        IF OLD.consumed_at IS NOT NULL OR
           current_user<>'keel_schema_owner' OR
           NOT pg_catalog.pg_has_role(session_user,'keel_identity','MEMBER') THEN
            RAISE EXCEPTION 'consumed resets are immutable';
        END IF;
        RETURN OLD;
    END IF;
    IF current_user<>'keel_schema_owner' OR
       NOT pg_catalog.pg_has_role(session_user,'keel_identity','MEMBER') THEN
        RAISE EXCEPTION 'identity resets are capability-managed';
    END IF;
    IF NEW.principal_id<>OLD.principal_id OR NEW.token_digest<>OLD.token_digest OR
       NEW.requested_at<>OLD.requested_at OR NEW.expires_at<>OLD.expires_at OR
       OLD.consumed_at IS NOT NULL OR NEW.consumed_at IS NULL THEN
        RAISE EXCEPTION 'reset rows may only move pending to consumed';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER identity_password_resets_guard BEFORE UPDATE OR DELETE
    ON keel_meta.identity_password_resets FOR EACH ROW
    EXECUTE FUNCTION keel_meta.guard_identity_password_resets_row();
REVOKE ALL ON FUNCTION keel_meta.guard_identity_password_resets_row() FROM PUBLIC;

-- Rotation is now an audited capability path: only a versioned hash change.
CREATE OR REPLACE FUNCTION keel_meta.guard_identity_credentials_row()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    IF TG_OP='DELETE' THEN
        RAISE EXCEPTION 'identity credentials have no delete path';
    END IF;
    IF current_user<>'keel_schema_owner' OR
       NOT pg_catalog.pg_has_role(session_user,'keel_identity','MEMBER') THEN
        RAISE EXCEPTION 'identity credentials are capability-managed';
    END IF;
    IF NEW.principal_id<>OLD.principal_id OR NEW.created_at<>OLD.created_at THEN
        RAISE EXCEPTION 'identity credential identity is immutable';
    END IF;
    IF NEW.version<>OLD.version+1 OR NEW.password_hash=OLD.password_hash OR
       length(NEW.password_hash) NOT BETWEEN 1 AND 256 THEN
        RAISE EXCEPTION 'credential rotation is versioned';
    END IF;
    RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION keel_meta.guard_identity_credentials_row() FROM PUBLIC;

CREATE FUNCTION keel_meta.record_identity_password_reset(
    p_principal_id uuid,p_token_digest bytea,p_expires_at timestamptz)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,keel_meta,pg_temp AS $$
DECLARE current_state text;
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'keel_identity','MEMBER') THEN
        RAISE EXCEPTION 'identity capability is required';
    END IF;
    IF p_principal_id IS NULL OR p_token_digest IS NULL OR
       octet_length(p_token_digest)<>32 OR p_expires_at IS NULL THEN
        RAISE EXCEPTION 'identity reset request is invalid';
    END IF;
    SELECT state INTO current_state FROM keel_meta.identity_principals
      WHERE principal_id=p_principal_id FOR UPDATE;
    IF current_state IS NULL OR current_state<>'active' THEN
        RETURN 'not_active';
    END IF;
    IF p_expires_at<=clock_timestamp() OR
       p_expires_at>clock_timestamp()+INTERVAL '24 hours' THEN
        RAISE EXCEPTION 'identity reset window is out of bounds';
    END IF;
    IF EXISTS (SELECT 1 FROM keel_meta.identity_password_resets v
                 WHERE v.token_digest=p_token_digest) THEN
        RETURN 'token_reuse';
    END IF;
    DELETE FROM keel_meta.identity_password_resets
      WHERE principal_id=p_principal_id AND consumed_at IS NULL;
    INSERT INTO keel_meta.identity_password_resets
        (principal_id,token_digest,requested_at,expires_at)
        VALUES (p_principal_id,p_token_digest,clock_timestamp(),p_expires_at);
    RETURN 'recorded';
END $$;
REVOKE ALL ON FUNCTION keel_meta.record_identity_password_reset(uuid,bytea,timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION keel_meta.record_identity_password_reset(uuid,bytea,timestamptz) TO keel_identity;

CREATE FUNCTION keel_meta.rotate_identity_credential(
    p_token_digest bytea,p_new_hash text)
RETURNS TABLE(outcome text,out_principal_id uuid)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,keel_meta,pg_temp AS $$
DECLARE target uuid;
DECLARE expiry timestamptz;
DECLARE current_state text;
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'keel_identity','MEMBER') THEN
        RAISE EXCEPTION 'identity capability is required';
    END IF;
    IF p_token_digest IS NULL OR octet_length(p_token_digest)<>32 OR
       p_new_hash IS NULL OR length(p_new_hash) NOT BETWEEN 1 AND 256 THEN
        RAISE EXCEPTION 'identity rotation is invalid';
    END IF;
    IF p_new_hash NOT LIKE '$argon2id$%' THEN
        RAISE EXCEPTION 'identity rotation hash is invalid';
    END IF;
    SELECT principal_id,expires_at INTO target,expiry
      FROM keel_meta.identity_password_resets
      WHERE token_digest=p_token_digest FOR UPDATE;
    IF target IS NULL THEN
        RETURN QUERY SELECT 'unknown'::text,NULL::uuid;
        RETURN;
    END IF;
    UPDATE keel_meta.identity_password_resets v SET consumed_at=clock_timestamp()
      WHERE v.token_digest=p_token_digest AND v.consumed_at IS NULL;
    IF NOT FOUND THEN
        RETURN QUERY SELECT 'duplicate'::text,target;
        RETURN;
    END IF;
    IF expiry<=clock_timestamp() THEN
        RETURN QUERY SELECT 'expired'::text,target;
        RETURN;
    END IF;
    SELECT state INTO current_state FROM keel_meta.identity_principals
      WHERE principal_id=target FOR UPDATE;
    IF current_state IS NULL THEN
        RAISE EXCEPTION 'identity principal vanished during rotation';
    END IF;
    IF current_state<>'active' THEN
        RETURN QUERY SELECT 'principal_inactive'::text,target;
        RETURN;
    END IF;
    UPDATE keel_meta.identity_credentials c
       SET password_hash=p_new_hash,version=c.version+1
     WHERE c.principal_id=target;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'identity credential vanished during rotation';
    END IF;
    UPDATE keel_meta.identity_sessions s SET revoked_at=clock_timestamp()
      WHERE s.principal_id=target AND s.revoked_at IS NULL;
    RETURN QUERY SELECT 'rotated'::text,target;
END $$;
REVOKE ALL ON FUNCTION keel_meta.rotate_identity_credential(bytea,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION keel_meta.rotate_identity_credential(bytea,text) TO keel_identity;

CREATE FUNCTION keel_meta.revoke_all_identity_sessions(p_principal_id uuid)
RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,keel_meta,pg_temp AS $$
DECLARE revoked integer := 0;
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'keel_identity','MEMBER') THEN
        RAISE EXCEPTION 'identity capability is required';
    END IF;
    IF p_principal_id IS NULL OR p_principal_id='00000000-0000-0000-0000-000000000000'::uuid THEN
        RAISE EXCEPTION 'identity revoke-all is invalid';
    END IF;
    UPDATE keel_meta.identity_sessions s SET revoked_at=clock_timestamp()
      WHERE s.principal_id=p_principal_id AND s.revoked_at IS NULL;
    GET DIAGNOSTICS revoked = ROW_COUNT;
    RETURN revoked;
END $$;
REVOKE ALL ON FUNCTION keel_meta.revoke_all_identity_sessions(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION keel_meta.revoke_all_identity_sessions(uuid) TO keel_identity;
