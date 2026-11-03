-- K8.11 repair of 0063: lock-time principal lookup used a wrong projection name.
-- The verification and session record functions selected principal_state, which
-- does not exist on keel_meta.identity_principals (the column is state), so both
-- SECURITY DEFINER calls aborted with SQLSTATE 42703 before any row lock was
-- taken. This migration replaces both functions with corrected projections.
-- Applied files are immutable; this is the forward repair per the migrations README.

CREATE OR REPLACE FUNCTION keel_meta.record_identity_verification(
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
        RAISE EXCEPTION 'identity verification request is invalid';
    END IF;
    SELECT state INTO current_state FROM keel_meta.identity_principals
      WHERE principal_id=p_principal_id FOR UPDATE;
    IF current_state IS NULL OR current_state<>'pending_verification' THEN
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
GRANT EXECUTE ON FUNCTION keel_meta.record_identity_verification(uuid,bytea,timestamptz) TO keel_identity;

CREATE OR REPLACE FUNCTION keel_meta.record_identity_session(
    p_session_id uuid,p_principal_id uuid,p_token_digest bytea,p_expires_at timestamptz)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,keel_meta,pg_temp AS $$
DECLARE current_state text;
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'keel_identity','MEMBER') THEN
        RAISE EXCEPTION 'identity capability is required';
    END IF;
    IF p_session_id IS NULL OR p_session_id='00000000-0000-0000-0000-000000000000'::uuid OR
       p_principal_id IS NULL OR p_token_digest IS NULL OR
       octet_length(p_token_digest)<>32 OR p_expires_at IS NULL THEN
        RAISE EXCEPTION 'identity session record is invalid';
    END IF;
    SELECT state INTO current_state FROM keel_meta.identity_principals
      WHERE principal_id=p_principal_id FOR UPDATE;
    IF current_state IS NULL OR current_state<>'active' THEN
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
GRANT EXECUTE ON FUNCTION keel_meta.record_identity_session(uuid,uuid,bytea,timestamptz) TO keel_identity;
