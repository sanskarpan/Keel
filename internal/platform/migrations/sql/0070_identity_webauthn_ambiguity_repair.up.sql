-- K8.11 repair of 0069: challenge consume/register used an ambiguous name.
-- Both functions declared a `purpose` variable and then selected the
-- `purpose` column into it, so PostgreSQL aborted with SQLSTATE 42702
-- (column reference is ambiguous) before any row was touched. This replaces
-- both functions with a distinctly named variable and identical semantics.
-- Applied files are immutable; this is the forward repair per the
-- migrations README.

CREATE OR REPLACE FUNCTION keel_meta.consume_identity_webauthn_challenge(p_challenge_id uuid)
RETURNS TABLE(outcome text,out_principal_id uuid,out_purpose text,out_challenge bytea)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,keel_meta,pg_temp AS $$
DECLARE
    target uuid;
    challenge_purpose text;
    nonce bytea;
    expiry timestamptz;
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'keel_identity','MEMBER') THEN
        RAISE EXCEPTION 'identity capability is required';
    END IF;
    IF p_challenge_id IS NULL OR p_challenge_id='00000000-0000-0000-0000-000000000000'::uuid THEN
        RAISE EXCEPTION 'identity challenge consume is invalid';
    END IF;
    SELECT principal_id,purpose,challenge,expires_at INTO target,challenge_purpose,nonce,expiry
      FROM keel_meta.identity_webauthn_challenges
      WHERE challenge_id=p_challenge_id FOR UPDATE;
    IF target IS NULL THEN
        RETURN QUERY SELECT 'unknown'::text,NULL::uuid,NULL::text,NULL::bytea;
        RETURN;
    END IF;
    UPDATE keel_meta.identity_webauthn_challenges c SET consumed_at=clock_timestamp()
      WHERE c.challenge_id=p_challenge_id AND c.consumed_at IS NULL;
    IF NOT FOUND THEN
        RETURN QUERY SELECT 'duplicate'::text,target,challenge_purpose,nonce;
        RETURN;
    END IF;
    IF expiry<=clock_timestamp() THEN
        RETURN QUERY SELECT 'expired'::text,target,challenge_purpose,nonce;
        RETURN;
    END IF;
    RETURN QUERY SELECT 'ready'::text,target,challenge_purpose,nonce;
END $$;
REVOKE ALL ON FUNCTION keel_meta.consume_identity_webauthn_challenge(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION keel_meta.consume_identity_webauthn_challenge(uuid) TO keel_identity;

CREATE OR REPLACE FUNCTION keel_meta.register_identity_webauthn_credential(
    p_challenge_id uuid,p_credential_id bytea,p_public_key bytea,p_transports text,
    p_backup_eligible boolean,p_backup_state boolean)
RETURNS TABLE(outcome text,out_principal_id uuid)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,keel_meta,pg_temp AS $$
DECLARE
    target uuid;
    challenge_purpose text;
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
    SELECT principal_id,purpose,expires_at INTO target,challenge_purpose,expiry
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
    IF challenge_purpose<>'identity-webauthn-registration-v1' THEN
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
