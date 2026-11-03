-- K8.11/K8.2 slice 15: membership directory reads and invite revocation.
-- Owners and admins can list an org's members and its pending invites, and
-- revoke a pending invite before it is accepted. Consumed invites are
-- history and cannot be revoked. Reads are capability-gated like writes:
-- only the SECURITY DEFINER functions expose rows, and each one re-checks
-- that the actor holds owner/admin membership in the target org.

CREATE FUNCTION keel_meta.members_for_organization(p_actor_id uuid,p_org_id uuid)
RETURNS TABLE(out_principal_id uuid,out_role text,out_created_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,keel_meta,pg_temp AS $$
DECLARE actor_role text;
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'keel_identity','MEMBER') THEN
        RAISE EXCEPTION 'identity capability is required';
    END IF;
    IF p_actor_id IS NULL OR p_org_id IS NULL THEN
        RAISE EXCEPTION 'identity membership list is invalid';
    END IF;
    SELECT role INTO actor_role FROM keel_meta.identity_memberships
      WHERE org_id=p_org_id AND principal_id=p_actor_id;
    IF actor_role IS NULL OR (actor_role<>'owner' AND actor_role<>'admin') THEN
        RETURN;
    END IF;
    RETURN QUERY
        SELECT m.principal_id,m.role,m.created_at
          FROM keel_meta.identity_memberships m
         WHERE m.org_id=p_org_id
         ORDER BY m.created_at,m.principal_id;
END $$;
REVOKE ALL ON FUNCTION keel_meta.members_for_organization(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION keel_meta.members_for_organization(uuid,uuid) TO keel_identity;

CREATE FUNCTION keel_meta.invites_for_organization(p_actor_id uuid,p_org_id uuid)
RETURNS TABLE(out_invite_id uuid,out_email_digest bytea,out_role text,
              out_requested_at timestamptz,out_expires_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,keel_meta,pg_temp AS $$
DECLARE actor_role text;
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'keel_identity','MEMBER') THEN
        RAISE EXCEPTION 'identity capability is required';
    END IF;
    IF p_actor_id IS NULL OR p_org_id IS NULL THEN
        RAISE EXCEPTION 'identity invite list is invalid';
    END IF;
    SELECT role INTO actor_role FROM keel_meta.identity_memberships
      WHERE org_id=p_org_id AND principal_id=p_actor_id;
    IF actor_role IS NULL OR (actor_role<>'owner' AND actor_role<>'admin') THEN
        RETURN;
    END IF;
    RETURN QUERY
        SELECT i.invite_id,i.email_digest,i.role,i.requested_at,i.expires_at
          FROM keel_meta.identity_invites i
         WHERE i.org_id=p_org_id AND i.consumed_at IS NULL
         ORDER BY i.requested_at,i.invite_id;
END $$;
REVOKE ALL ON FUNCTION keel_meta.invites_for_organization(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION keel_meta.invites_for_organization(uuid,uuid) TO keel_identity;

CREATE FUNCTION keel_meta.revoke_organization_invite(p_actor_id uuid,p_invite_id uuid)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,keel_meta,pg_temp AS $$
DECLARE
    target_org uuid;
    actor_role text;
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'keel_identity','MEMBER') THEN
        RAISE EXCEPTION 'identity capability is required';
    END IF;
    IF p_actor_id IS NULL OR p_invite_id IS NULL THEN
        RAISE EXCEPTION 'identity invite revoke is invalid';
    END IF;
    SELECT org_id INTO target_org FROM keel_meta.identity_invites
      WHERE invite_id=p_invite_id AND consumed_at IS NULL;
    IF target_org IS NULL THEN
        RETURN 'unknown_invite';
    END IF;
    SELECT role INTO actor_role FROM keel_meta.identity_memberships
      WHERE org_id=target_org AND principal_id=p_actor_id;
    IF actor_role IS NULL OR (actor_role<>'owner' AND actor_role<>'admin') THEN
        RETURN 'not_authorized';
    END IF;
    DELETE FROM keel_meta.identity_invites WHERE invite_id=p_invite_id;
    IF NOT FOUND THEN
        RETURN 'unknown_invite';
    END IF;
    RETURN 'revoked';
END $$;
REVOKE ALL ON FUNCTION keel_meta.revoke_organization_invite(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION keel_meta.revoke_organization_invite(uuid,uuid) TO keel_identity;
