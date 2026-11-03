-- K8.11 repair of 0063: bootstrap duplicates are an outcome, not an abort.
-- 0063_identity_principals_sessions introduced create_identity_principal but left
-- the unique email digest as a raw SQLSTATE 23505 abort. The Go repository treats
-- duplicate bootstrap as a benign conflict outcome, so this migration replaces the
-- function to map the identity_principal_email_unique violation to that outcome
-- and re-raise anything else. Applied files are immutable; this is the forward
-- repair per the migrations README.

CREATE OR REPLACE FUNCTION keel_meta.create_identity_principal(
    p_principal_id uuid,p_email_digest bytea,p_password_hash text,p_tenant uuid)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,keel_meta,pg_temp AS $$
DECLARE
    violated text;
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'keel_identity','MEMBER') THEN
        RAISE EXCEPTION 'identity capability is required';
    END IF;
    IF p_principal_id IS NULL OR p_principal_id='00000000-0000-0000-0000-000000000000'::uuid OR
       p_email_digest IS NULL OR octet_length(p_email_digest)<>32 OR
       p_password_hash IS NULL OR length(p_password_hash) NOT BETWEEN 1 AND 256 THEN
        RAISE EXCEPTION 'identity bootstrap is invalid';
    END IF;
    BEGIN
        INSERT INTO keel_meta.identity_principals (principal_id,email_digest,tenant_id)
            VALUES (p_principal_id,p_email_digest,p_tenant);
    EXCEPTION
        WHEN unique_violation THEN
            GET STACKED DIAGNOSTICS violated = CONSTRAINT_NAME;
            IF violated='identity_principal_email_unique' THEN
                RETURN 'duplicate_email';
            END IF;
            RAISE;
    END;
    INSERT INTO keel_meta.identity_credentials (principal_id,password_hash)
        VALUES (p_principal_id,p_password_hash);
    RETURN 'created';
END $$;

REVOKE ALL ON FUNCTION keel_meta.create_identity_principal(uuid,bytea,text,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION keel_meta.create_identity_principal(uuid,bytea,text,uuid) TO keel_identity;
