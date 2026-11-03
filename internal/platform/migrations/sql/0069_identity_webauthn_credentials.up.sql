-- K8.11 slice 5: WebAuthn credential and ceremony-challenge storage.
-- Registration binds a credential public key to an active principal through a
-- single-use registration challenge; authentication challenges gate later
-- assertions. Sign counts advance monotonically with clone detection left to
-- the caller (a non-advancing counter while one is expected is reported, not
-- applied). Ceremony cryptography (attestation/assertion verification) arrives
-- with the HTTP ceremony slice; this migration owns only the durable,
-- capability-gated state. All access is through keel_identity-gated SECURITY
-- DEFINER functions; both tables carry forced RLS with no direct grants.

CREATE TABLE keel_meta.identity_webauthn_credentials (
    credential_id bytea NOT NULL PRIMARY KEY CHECK (octet_length(credential_id) BETWEEN 1 AND 1024),
    principal_id uuid NOT NULL REFERENCES keel_meta.identity_principals(principal_id),
    public_key bytea NOT NULL CHECK (octet_length(public_key) BETWEEN 1 AND 2048),
    sign_count bigint NOT NULL DEFAULT 0 CHECK (sign_count>=0),
    transports text NOT NULL DEFAULT '' CHECK (length(transports)<=128),
    backup_eligible boolean NOT NULL DEFAULT false,
    backup_state boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    last_used_at timestamptz,
    CONSTRAINT identity_webauthn_credential_use_shape CHECK (last_used_at IS NULL OR last_used_at>=created_at)
);
ALTER TABLE keel_meta.identity_webauthn_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.identity_webauthn_credentials FORCE ROW LEVEL SECURITY;
CREATE POLICY identity_webauthn_credentials_schema_owner ON keel_meta.identity_webauthn_credentials
    TO keel_schema_owner USING (true) WITH CHECK (true);
REVOKE ALL ON keel_meta.identity_webauthn_credentials FROM PUBLIC,keel_app,keel_worker,keel_operator,
    keel_budget_control,keel_rate_control,keel_rate_status,keel_ai_worker,keel_projector,
    keel_file_processor,keel_retrieval_indexer,keel_context_vault,keel_context_policy,
    keel_context_erasure,keel_context_erasure_worker,keel_context_legal_hold,
    keel_context_replay,keel_agent,keel_callback,keel_webhook,keel_identity;

CREATE TABLE keel_meta.identity_webauthn_challenges (
    challenge_id uuid NOT NULL PRIMARY KEY CHECK (challenge_id<>'00000000-0000-0000-0000-000000000000'::uuid),
    principal_id uuid NOT NULL REFERENCES keel_meta.identity_principals(principal_id),
    purpose text NOT NULL CHECK (purpose IN ('identity-webauthn-registration-v1','identity-webauthn-authentication-v1')),
    challenge bytea NOT NULL CHECK (octet_length(challenge)=32),
    requested_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    CONSTRAINT identity_webauthn_challenge_unique UNIQUE (challenge),
    CONSTRAINT identity_webauthn_challenge_window CHECK (expires_at>requested_at),
    CONSTRAINT identity_webauthn_challenge_shape CHECK (consumed_at IS NULL OR consumed_at>=requested_at)
);
ALTER TABLE keel_meta.identity_webauthn_challenges ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.identity_webauthn_challenges FORCE ROW LEVEL SECURITY;
CREATE POLICY identity_webauthn_challenges_schema_owner ON keel_meta.identity_webauthn_challenges
    TO keel_schema_owner USING (true) WITH CHECK (true);
REVOKE ALL ON keel_meta.identity_webauthn_challenges FROM PUBLIC,keel_app,keel_worker,keel_operator,
    keel_budget_control,keel_rate_control,keel_rate_status,keel_ai_worker,keel_projector,
    keel_file_processor,keel_retrieval_indexer,keel_context_vault,keel_context_policy,
    keel_context_erasure,keel_context_erasure_worker,keel_context_legal_hold,
    keel_context_replay,keel_agent,keel_callback,keel_webhook,keel_identity;

CREATE FUNCTION keel_meta.guard_identity_webauthn_credentials_row()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    IF TG_OP='DELETE' THEN
        RAISE EXCEPTION 'identity credentials have no delete path in this slice';
    END IF;
    IF current_user<>'keel_schema_owner' OR
       NOT pg_catalog.pg_has_role(session_user,'keel_identity','MEMBER') THEN
        RAISE EXCEPTION 'identity credentials are capability-managed';
    END IF;
    IF TG_OP='INSERT' THEN
        IF NEW.sign_count<>0 OR NEW.last_used_at IS NOT NULL THEN
            RAISE EXCEPTION 'identity credentials start unused';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.credential_id<>OLD.credential_id OR NEW.principal_id<>OLD.principal_id OR
       NEW.public_key<>OLD.public_key OR NEW.transports<>OLD.transports OR
       NEW.backup_eligible<>OLD.backup_eligible OR NEW.backup_state<>OLD.backup_state OR
       NEW.created_at<>OLD.created_at THEN
        RAISE EXCEPTION 'identity credential identity is immutable';
    END IF;
    IF NEW.sign_count<OLD.sign_count OR
       (NEW.sign_count=OLD.sign_count AND OLD.sign_count<>0) THEN
        RAISE EXCEPTION 'identity sign counts advance monotonically';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER identity_webauthn_credentials_guard BEFORE INSERT OR UPDATE OR DELETE
    ON keel_meta.identity_webauthn_credentials FOR EACH ROW
    EXECUTE FUNCTION keel_meta.guard_identity_webauthn_credentials_row();
REVOKE ALL ON FUNCTION keel_meta.guard_identity_webauthn_credentials_row() FROM PUBLIC;

CREATE FUNCTION keel_meta.guard_identity_webauthn_challenges_row()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    IF TG_OP='DELETE' THEN
        -- a resend replaces only an unconsumed pending challenge.
        IF OLD.consumed_at IS NOT NULL OR
           current_user<>'keel_schema_owner' OR
           NOT pg_catalog.pg_has_role(session_user,'keel_identity','MEMBER') THEN
            RAISE EXCEPTION 'consumed challenges are immutable';
        END IF;
        RETURN OLD;
    END IF;
    IF current_user<>'keel_schema_owner' OR
       NOT pg_catalog.pg_has_role(session_user,'keel_identity','MEMBER') THEN
        RAISE EXCEPTION 'identity challenges are capability-managed';
    END IF;
    IF NEW.principal_id<>OLD.principal_id OR NEW.purpose<>OLD.purpose OR
       NEW.challenge<>OLD.challenge OR NEW.requested_at<>OLD.requested_at OR
       NEW.expires_at<>OLD.expires_at OR
       OLD.consumed_at IS NOT NULL OR NEW.consumed_at IS NULL THEN
        RAISE EXCEPTION 'challenge rows may only move pending to consumed';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER identity_webauthn_challenges_guard BEFORE UPDATE OR DELETE
    ON keel_meta.identity_webauthn_challenges FOR EACH ROW
    EXECUTE FUNCTION keel_meta.guard_identity_webauthn_challenges_row();
REVOKE ALL ON FUNCTION keel_meta.guard_identity_webauthn_challenges_row() FROM PUBLIC;

CREATE FUNCTION keel_meta.record_identity_webauthn_challenge(
    p_challenge_id uuid,p_principal_id uuid,p_purpose text,p_challenge bytea,p_expires_at timestamptz)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,keel_meta,pg_temp AS $$
DECLARE current_state text;
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'keel_identity','MEMBER') THEN
        RAISE EXCEPTION 'identity capability is required';
    END IF;
    IF p_challenge_id IS NULL OR p_challenge_id='00000000-0000-0000-0000-000000000000'::uuid OR
       p_principal_id IS NULL OR
       (p_purpose<>'identity-webauthn-registration-v1' AND p_purpose<>'identity-webauthn-authentication-v1') OR
       p_challenge IS NULL OR octet_length(p_challenge)<>32 OR p_expires_at IS NULL THEN
        RAISE EXCEPTION 'identity challenge request is invalid';
    END IF;
    SELECT state INTO current_state FROM keel_meta.identity_principals
      WHERE principal_id=p_principal_id FOR UPDATE;
    IF current_state IS NULL OR current_state<>'active' THEN
        RETURN 'not_active';
    END IF;
    IF p_expires_at<=clock_timestamp() OR
       p_expires_at>clock_timestamp()+INTERVAL '10 minutes' THEN
        RAISE EXCEPTION 'identity challenge window is out of bounds';
    END IF;
    IF EXISTS (SELECT 1 FROM keel_meta.identity_webauthn_challenges c
                 WHERE c.challenge=p_challenge) THEN
        RETURN 'challenge_reuse';
    END IF;
    DELETE FROM keel_meta.identity_webauthn_challenges
      WHERE principal_id=p_principal_id AND purpose=p_purpose AND consumed_at IS NULL;
    INSERT INTO keel_meta.identity_webauthn_challenges
        (challenge_id,principal_id,purpose,challenge,requested_at,expires_at)
        VALUES (p_challenge_id,p_principal_id,p_purpose,p_challenge,clock_timestamp(),p_expires_at);
    RETURN 'recorded';
END $$;
REVOKE ALL ON FUNCTION keel_meta.record_identity_webauthn_challenge(uuid,uuid,text,bytea,timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION keel_meta.record_identity_webauthn_challenge(uuid,uuid,text,bytea,timestamptz) TO keel_identity;

CREATE FUNCTION keel_meta.consume_identity_webauthn_challenge(p_challenge_id uuid)
RETURNS TABLE(outcome text,out_principal_id uuid,out_purpose text,out_challenge bytea)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,keel_meta,pg_temp AS $$
DECLARE
    target uuid;
    purpose text;
    nonce bytea;
    expiry timestamptz;
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'keel_identity','MEMBER') THEN
        RAISE EXCEPTION 'identity capability is required';
    END IF;
    IF p_challenge_id IS NULL OR p_challenge_id='00000000-0000-0000-0000-000000000000'::uuid THEN
        RAISE EXCEPTION 'identity challenge consume is invalid';
    END IF;
    SELECT principal_id,purpose,challenge,expires_at INTO target,purpose,nonce,expiry
      FROM keel_meta.identity_webauthn_challenges
      WHERE challenge_id=p_challenge_id FOR UPDATE;
    IF target IS NULL THEN
        RETURN QUERY SELECT 'unknown'::text,NULL::uuid,NULL::text,NULL::bytea;
        RETURN;
    END IF;
    UPDATE keel_meta.identity_webauthn_challenges c SET consumed_at=clock_timestamp()
      WHERE c.challenge_id=p_challenge_id AND c.consumed_at IS NULL;
    IF NOT FOUND THEN
        RETURN QUERY SELECT 'duplicate'::text,target,purpose,nonce;
        RETURN;
    END IF;
    IF expiry<=clock_timestamp() THEN
        RETURN QUERY SELECT 'expired'::text,target,purpose,nonce;
        RETURN;
    END IF;
    RETURN QUERY SELECT 'ready'::text,target,purpose,nonce;
END $$;
REVOKE ALL ON FUNCTION keel_meta.consume_identity_webauthn_challenge(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION keel_meta.consume_identity_webauthn_challenge(uuid) TO keel_identity;

CREATE FUNCTION keel_meta.register_identity_webauthn_credential(
    p_challenge_id uuid,p_credential_id bytea,p_public_key bytea,p_transports text,
    p_backup_eligible boolean,p_backup_state boolean)
RETURNS TABLE(outcome text,out_principal_id uuid)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,keel_meta,pg_temp AS $$
DECLARE
    target uuid;
    purpose text;
    expiry timestamptz;
    current_state text;
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'keel_identity','MEMBER') THEN
        RAISE EXCEPTION 'identity capability is required';
    END IF;
    IF p_challenge_id IS NULL OR p_challenge_id='00000000-0000-0000-0000-000000000000'::uuid OR
       p_credential_id IS NULL OR octet_length(p_credential_id) NOT BETWEEN 1 AND 1024 OR
       p_public_key IS NULL OR octet_length(p_public_key) NOT BETWEEN 1 AND 2048 OR
       p_transports IS NULL OR length(p_transports)>128 OR
       p_backup_eligible IS NULL OR p_backup_state IS NULL THEN
        RAISE EXCEPTION 'identity credential registration is invalid';
    END IF;
    SELECT principal_id,purpose,expires_at INTO target,purpose,expiry
      FROM keel_meta.identity_webauthn_challenges
      WHERE challenge_id=p_challenge_id FOR UPDATE;
    IF target IS NULL THEN
        RETURN QUERY SELECT 'unknown'::text,NULL::uuid;
        RETURN;
    END IF;
    UPDATE keel_meta.identity_webauthn_challenges c SET consumed_at=clock_timestamp()
      WHERE c.challenge_id=p_challenge_id AND c.consumed_at IS NULL;
    IF NOT FOUND THEN
        RETURN QUERY SELECT 'duplicate'::text,target;
        RETURN;
    END IF;
    IF expiry<=clock_timestamp() THEN
        RETURN QUERY SELECT 'expired'::text,target;
        RETURN;
    END IF;
    IF purpose<>'identity-webauthn-registration-v1' THEN
        RETURN QUERY SELECT 'wrong_purpose'::text,target;
        RETURN;
    END IF;
    SELECT state INTO current_state FROM keel_meta.identity_principals
      WHERE principal_id=target FOR UPDATE;
    IF current_state IS NULL THEN
        RAISE EXCEPTION 'identity principal vanished during registration';
    END IF;
    IF current_state<>'active' THEN
        RETURN QUERY SELECT 'principal_inactive'::text,target;
        RETURN;
    END IF;
    IF EXISTS (SELECT 1 FROM keel_meta.identity_webauthn_credentials k
                 WHERE k.credential_id=p_credential_id) THEN
        RETURN QUERY SELECT 'credential_reuse'::text,target;
        RETURN;
    END IF;
    INSERT INTO keel_meta.identity_webauthn_credentials
        (credential_id,principal_id,public_key,sign_count,transports,backup_eligible,backup_state,created_at)
        VALUES (p_credential_id,target,p_public_key,0,p_transports,p_backup_eligible,p_backup_state,clock_timestamp());
    RETURN QUERY SELECT 'registered'::text,target;
END $$;
REVOKE ALL ON FUNCTION keel_meta.register_identity_webauthn_credential(uuid,bytea,bytea,text,boolean,boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION keel_meta.register_identity_webauthn_credential(uuid,bytea,bytea,text,boolean,boolean) TO keel_identity;

CREATE FUNCTION keel_meta.identity_webauthn_keys_for(p_principal_id uuid)
RETURNS TABLE(out_credential_id bytea,out_public_key bytea,out_sign_count bigint,
              out_transports text,out_backup_eligible boolean,out_backup_state boolean)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,keel_meta,pg_temp AS $$
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'keel_identity','MEMBER') THEN
        RAISE EXCEPTION 'identity capability is required';
    END IF;
    IF p_principal_id IS NULL OR p_principal_id='00000000-0000-0000-0000-000000000000'::uuid THEN
        RAISE EXCEPTION 'identity key lookup is invalid';
    END IF;
    RETURN QUERY
        SELECT k.credential_id,k.public_key,k.sign_count,k.transports,k.backup_eligible,k.backup_state
          FROM keel_meta.identity_webauthn_credentials k
         WHERE k.principal_id=p_principal_id;
END $$;
REVOKE ALL ON FUNCTION keel_meta.identity_webauthn_keys_for(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION keel_meta.identity_webauthn_keys_for(uuid) TO keel_identity;

CREATE FUNCTION keel_meta.advance_identity_webauthn_sign_count(
    p_credential_id bytea,p_presented bigint)
RETURNS TABLE(outcome text,out_principal_id uuid)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,keel_meta,pg_temp AS $$
DECLARE
    target uuid;
    stored bigint;
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'keel_identity','MEMBER') THEN
        RAISE EXCEPTION 'identity capability is required';
    END IF;
    IF p_credential_id IS NULL OR octet_length(p_credential_id) NOT BETWEEN 1 AND 1024 OR
       p_presented IS NULL OR p_presented<0 THEN
        RAISE EXCEPTION 'identity sign count advance is invalid';
    END IF;
    SELECT principal_id,sign_count INTO target,stored
      FROM keel_meta.identity_webauthn_credentials
      WHERE credential_id=p_credential_id FOR UPDATE;
    IF target IS NULL THEN
        RETURN QUERY SELECT 'unknown'::text,NULL::uuid;
        RETURN;
    END IF;
    IF NOT (stored=0 AND p_presented=0) AND p_presented<=stored THEN
        RETURN QUERY SELECT 'cloned'::text,target;
        RETURN;
    END IF;
    UPDATE keel_meta.identity_webauthn_credentials k
       SET sign_count=p_presented,last_used_at=clock_timestamp()
     WHERE k.credential_id=p_credential_id;
    RETURN QUERY SELECT 'advanced'::text,target;
END $$;
REVOKE ALL ON FUNCTION keel_meta.advance_identity_webauthn_sign_count(bytea,bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION keel_meta.advance_identity_webauthn_sign_count(bytea,bigint) TO keel_identity;
