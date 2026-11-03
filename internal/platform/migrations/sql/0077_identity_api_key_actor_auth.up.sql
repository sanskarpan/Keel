-- K8.11 repair of 0076: key issue/revoke/disable lacked actor authorization.
-- The three functions were capability-gated only, so any holder of the
-- keel_identity capability could mint or kill keys for any organization.
-- This replaces them with actor-checked variants that require owner/admin
-- membership in the service principal's organization, and drops the
-- unguarded originals. Signatures change, so CREATE OR REPLACE cannot be
-- used. Applied files are immutable; this is the forward repair per the
-- migrations README.

DROP FUNCTION keel_meta.issue_identity_api_key(uuid,uuid,text,bytea,timestamptz);
DROP FUNCTION keel_meta.revoke_identity_api_key(uuid);
DROP FUNCTION keel_meta.disable_identity_service_principal(uuid);

CREATE FUNCTION keel_meta.issue_identity_api_key(
    p_key_id uuid,p_actor_id uuid,p_service_principal_id uuid,
    p_prefix text,p_key_digest bytea,p_expires_at timestamptz)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,keel_meta,pg_temp AS $$
DECLARE sp_org uuid;
DECLARE actor_role text;
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'keel_identity','MEMBER') THEN
        RAISE EXCEPTION 'identity capability is required';
    END IF;
    IF p_key_id IS NULL OR p_key_id='00000000-0000-0000-0000-000000000000'::uuid OR
       p_actor_id IS NULL OR p_service_principal_id IS NULL OR
       p_prefix IS NULL OR p_prefix !~ '^[A-Za-z0-9_-]{8}$' OR
       p_key_digest IS NULL OR octet_length(p_key_digest)<>32 THEN
        RAISE EXCEPTION 'identity API key issue is invalid';
    END IF;
    SELECT org_id INTO sp_org FROM keel_meta.identity_service_principals s
      WHERE s.service_principal_id=p_service_principal_id AND s.disabled_at IS NULL;
    IF sp_org IS NULL THEN
        RETURN 'unknown_principal';
    END IF;
    SELECT role INTO actor_role FROM keel_meta.identity_memberships
      WHERE org_id=sp_org AND principal_id=p_actor_id;
    IF actor_role IS NULL OR (actor_role<>'owner' AND actor_role<>'admin') THEN
        RETURN 'not_authorized';
    END IF;
    IF EXISTS (SELECT 1 FROM keel_meta.identity_api_keys k
                 WHERE k.key_digest=p_key_digest) THEN
        RETURN 'key_reuse';
    END IF;
    IF p_expires_at IS NOT NULL AND p_expires_at<=clock_timestamp() THEN
        RAISE EXCEPTION 'identity API key window is out of bounds';
    END IF;
    INSERT INTO keel_meta.identity_api_keys
        (key_id,service_principal_id,prefix,key_digest,created_at,expires_at)
        VALUES (p_key_id,p_service_principal_id,p_prefix,p_key_digest,clock_timestamp(),p_expires_at);
    RETURN 'issued';
END $$;
REVOKE ALL ON FUNCTION keel_meta.issue_identity_api_key(uuid,uuid,uuid,text,bytea,timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION keel_meta.issue_identity_api_key(uuid,uuid,uuid,text,bytea,timestamptz) TO keel_identity;

CREATE FUNCTION keel_meta.revoke_identity_api_key(p_actor_id uuid,p_key_id uuid)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,keel_meta,pg_temp AS $$
DECLARE sp_org uuid;
DECLARE actor_role text;
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'keel_identity','MEMBER') THEN
        RAISE EXCEPTION 'identity capability is required';
    END IF;
    IF p_actor_id IS NULL OR p_key_id IS NULL OR
       p_key_id='00000000-0000-0000-0000-000000000000'::uuid THEN
        RAISE EXCEPTION 'identity API key revoke is invalid';
    END IF;
    SELECT s.org_id INTO sp_org
      FROM keel_meta.identity_api_keys k
      JOIN keel_meta.identity_service_principals s
        ON s.service_principal_id=k.service_principal_id
     WHERE k.key_id=p_key_id AND k.revoked_at IS NULL;
    IF sp_org IS NULL THEN
        RETURN 'unknown_key';
    END IF;
    SELECT role INTO actor_role FROM keel_meta.identity_memberships
      WHERE org_id=sp_org AND principal_id=p_actor_id;
    IF actor_role IS NULL OR (actor_role<>'owner' AND actor_role<>'admin') THEN
        RETURN 'not_authorized';
    END IF;
    UPDATE keel_meta.identity_api_keys k SET revoked_at=clock_timestamp()
      WHERE k.key_id=p_key_id AND k.revoked_at IS NULL;
    IF NOT FOUND THEN
        RETURN 'unknown_key';
    END IF;
    RETURN 'revoked';
END $$;
REVOKE ALL ON FUNCTION keel_meta.revoke_identity_api_key(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION keel_meta.revoke_identity_api_key(uuid,uuid) TO keel_identity;

CREATE FUNCTION keel_meta.disable_identity_service_principal(p_actor_id uuid,p_service_principal_id uuid)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,keel_meta,pg_temp AS $$
DECLARE sp_org uuid;
DECLARE actor_role text;
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'keel_identity','MEMBER') THEN
        RAISE EXCEPTION 'identity capability is required';
    END IF;
    IF p_actor_id IS NULL OR p_service_principal_id IS NULL OR
       p_service_principal_id='00000000-0000-0000-0000-000000000000'::uuid THEN
        RAISE EXCEPTION 'identity service principal disable is invalid';
    END IF;
    SELECT org_id INTO sp_org FROM keel_meta.identity_service_principals s
      WHERE s.service_principal_id=p_service_principal_id AND s.disabled_at IS NULL;
    IF sp_org IS NULL THEN
        RETURN 'unknown_principal';
    END IF;
    SELECT role INTO actor_role FROM keel_meta.identity_memberships
      WHERE org_id=sp_org AND principal_id=p_actor_id;
    IF actor_role IS NULL OR (actor_role<>'owner' AND actor_role<>'admin') THEN
        RETURN 'not_authorized';
    END IF;
    UPDATE keel_meta.identity_service_principals s SET disabled_at=clock_timestamp()
      WHERE s.service_principal_id=p_service_principal_id AND s.disabled_at IS NULL;
    UPDATE keel_meta.identity_api_keys k SET revoked_at=clock_timestamp()
      WHERE k.service_principal_id=p_service_principal_id AND k.revoked_at IS NULL;
    RETURN 'disabled';
END $$;
REVOKE ALL ON FUNCTION keel_meta.disable_identity_service_principal(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION keel_meta.disable_identity_service_principal(uuid,uuid) TO keel_identity;
