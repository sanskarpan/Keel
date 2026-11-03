-- K8.11/K8.2 slice 18: service principal lookup and key listing.
-- Rotation UX needs to see which keys exist. service_principal_org resolves
-- the owning org for one service principal (empty when unknown); keys_for_
-- service_principal returns every key with lifecycle timestamps for owners
-- and admins of that org, and nothing otherwise. Both are read-only
-- capability-gated functions; all writes stay on the existing paths.

CREATE FUNCTION keel_meta.service_principal_org(p_service_principal_id uuid)
RETURNS TABLE(out_org_id uuid)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,keel_meta,pg_temp AS $$
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'keel_identity','MEMBER') THEN
        RAISE EXCEPTION 'identity capability is required';
    END IF;
    IF p_service_principal_id IS NULL OR
       p_service_principal_id='00000000-0000-0000-0000-000000000000'::uuid THEN
        RAISE EXCEPTION 'identity service principal lookup is invalid';
    END IF;
    RETURN QUERY
        SELECT s.org_id FROM keel_meta.identity_service_principals s
         WHERE s.service_principal_id=p_service_principal_id;
END $$;
REVOKE ALL ON FUNCTION keel_meta.service_principal_org(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION keel_meta.service_principal_org(uuid) TO keel_identity;

CREATE FUNCTION keel_meta.keys_for_service_principal(p_actor_id uuid,p_service_principal_id uuid)
RETURNS TABLE(out_key_id uuid,out_prefix text,out_created_at timestamptz,
              out_expires_at timestamptz,out_revoked_at timestamptz,out_last_used_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,keel_meta,pg_temp AS $$
DECLARE actor_role text;
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'keel_identity','MEMBER') THEN
        RAISE EXCEPTION 'identity capability is required';
    END IF;
    IF p_actor_id IS NULL OR p_service_principal_id IS NULL THEN
        RAISE EXCEPTION 'identity key list is invalid';
    END IF;
    SELECT m.role INTO actor_role
      FROM keel_meta.identity_service_principals s
      JOIN keel_meta.identity_memberships m ON m.org_id=s.org_id
     WHERE s.service_principal_id=p_service_principal_id AND m.principal_id=p_actor_id;
    IF actor_role IS NULL OR (actor_role<>'owner' AND actor_role<>'admin') THEN
        RETURN;
    END IF;
    RETURN QUERY
        SELECT k.key_id,k.prefix,k.created_at,k.expires_at,k.revoked_at,k.last_used_at
          FROM keel_meta.identity_api_keys k
         WHERE k.service_principal_id=p_service_principal_id
         ORDER BY k.created_at,k.key_id;
END $$;
REVOKE ALL ON FUNCTION keel_meta.keys_for_service_principal(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION keel_meta.keys_for_service_principal(uuid,uuid) TO keel_identity;
