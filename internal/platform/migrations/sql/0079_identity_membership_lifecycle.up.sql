-- K8.11/K8.2 slice 17: member role changes, removal and invite expiry reap.
-- Owners set admin/member seats (never the owner seat, which moves only by
-- transfer); owners and admins remove non-owner members, and any non-owner
-- may leave unilaterally. The last owner can neither be demoted nor removed
-- nor leave, so no path orphans an organization. Expired pending invites
-- are reaped per org by an owner/admin. The tenant stays first-bound for
-- life: leaving never rebinds. The memberships guard is replaced to allow
-- exactly these transitions: owner/admin/member role moves except into or
-- out of owner, and deletes of non-owner rows, all capability-gated.

CREATE OR REPLACE FUNCTION keel_meta.guard_identity_memberships_row()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    IF current_user<>'keel_schema_owner' OR
       NOT pg_catalog.pg_has_role(session_user,'keel_identity','MEMBER') THEN
        RAISE EXCEPTION 'identity memberships are capability-managed';
    END IF;
    IF TG_OP='INSERT' THEN
        RETURN NEW;
    END IF;
    IF TG_OP='DELETE' THEN
        IF OLD.role='owner' THEN
            RAISE EXCEPTION 'identity owners leave only by transfer';
        END IF;
        RETURN OLD;
    END IF;
    IF NEW.org_id<>OLD.org_id OR NEW.principal_id<>OLD.principal_id OR
       NEW.created_at<>OLD.created_at THEN
        RAISE EXCEPTION 'identity membership identity is immutable';
    END IF;
    IF NOT ((OLD.role='owner' AND NEW.role='admin') OR
            (OLD.role='admin' AND NEW.role='owner') OR
            (OLD.role='member' AND NEW.role='owner') OR
            (OLD.role='admin' AND NEW.role='member') OR
            (OLD.role='member' AND NEW.role='admin')) THEN
        RAISE EXCEPTION 'membership roles change only by transfer or owner promotion';
    END IF;
    RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION keel_meta.guard_identity_memberships_row() FROM PUBLIC;

CREATE FUNCTION keel_meta.set_organization_member_role(
    p_actor_id uuid,p_org_id uuid,p_member_id uuid,p_role text)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,keel_meta,pg_temp AS $$
DECLARE
    actor_role text;
    target_role text;
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'keel_identity','MEMBER') THEN
        RAISE EXCEPTION 'identity capability is required';
    END IF;
    IF p_actor_id IS NULL OR p_org_id IS NULL OR p_member_id IS NULL OR
       (p_role<>'admin' AND p_role<>'member') THEN
        RAISE EXCEPTION 'identity role change is invalid';
    END IF;
    SELECT role INTO actor_role FROM keel_meta.identity_memberships
      WHERE org_id=p_org_id AND principal_id=p_actor_id FOR UPDATE;
    IF actor_role IS NULL OR actor_role<>'owner' THEN
        RETURN 'not_authorized';
    END IF;
    SELECT role INTO target_role FROM keel_meta.identity_memberships
      WHERE org_id=p_org_id AND principal_id=p_member_id FOR UPDATE;
    IF target_role IS NULL THEN
        RETURN 'not_member';
    END IF;
    IF target_role='owner' THEN
        RETURN 'owner_immutable';
    END IF;
    IF target_role=p_role THEN
        RETURN 'unchanged';
    END IF;
    UPDATE keel_meta.identity_memberships SET role=p_role
      WHERE org_id=p_org_id AND principal_id=p_member_id;
    RETURN 'changed';
END $$;
REVOKE ALL ON FUNCTION keel_meta.set_organization_member_role(uuid,uuid,uuid,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION keel_meta.set_organization_member_role(uuid,uuid,uuid,text) TO keel_identity;

CREATE FUNCTION keel_meta.remove_organization_member(
    p_actor_id uuid,p_org_id uuid,p_member_id uuid)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,keel_meta,pg_temp AS $$
DECLARE
    actor_role text;
    target_role text;
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'keel_identity','MEMBER') THEN
        RAISE EXCEPTION 'identity capability is required';
    END IF;
    IF p_actor_id IS NULL OR p_org_id IS NULL OR p_member_id IS NULL THEN
        RAISE EXCEPTION 'identity membership remove is invalid';
    END IF;
    SELECT role INTO actor_role FROM keel_meta.identity_memberships
      WHERE org_id=p_org_id AND principal_id=p_actor_id FOR UPDATE;
    IF actor_role IS NULL THEN
        RETURN 'not_authorized';
    END IF;
    SELECT role INTO target_role FROM keel_meta.identity_memberships
      WHERE org_id=p_org_id AND principal_id=p_member_id FOR UPDATE;
    IF target_role IS NULL THEN
        RETURN 'not_member';
    END IF;
    IF target_role='owner' THEN
        RETURN 'owner_immutable';
    END IF;
    IF p_actor_id<>p_member_id AND actor_role='member' THEN
        RETURN 'not_authorized';
    END IF;
    DELETE FROM keel_meta.identity_memberships
      WHERE org_id=p_org_id AND principal_id=p_member_id;
    RETURN 'removed';
END $$;
REVOKE ALL ON FUNCTION keel_meta.remove_organization_member(uuid,uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION keel_meta.remove_organization_member(uuid,uuid,uuid) TO keel_identity;

CREATE FUNCTION keel_meta.reap_expired_organization_invites(p_actor_id uuid,p_org_id uuid)
RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,keel_meta,pg_temp AS $$
DECLARE
    actor_role text;
    reaped integer := 0;
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'keel_identity','MEMBER') THEN
        RAISE EXCEPTION 'identity capability is required';
    END IF;
    IF p_actor_id IS NULL OR p_org_id IS NULL THEN
        RAISE EXCEPTION 'identity invite reap is invalid';
    END IF;
    SELECT role INTO actor_role FROM keel_meta.identity_memberships
      WHERE org_id=p_org_id AND principal_id=p_actor_id;
    IF actor_role IS NULL OR (actor_role<>'owner' AND actor_role<>'admin') THEN
        RETURN -1;
    END IF;
    DELETE FROM keel_meta.identity_invites
      WHERE org_id=p_org_id AND consumed_at IS NULL AND expires_at<=clock_timestamp();
    GET DIAGNOSTICS reaped = ROW_COUNT;
    RETURN reaped;
END $$;
REVOKE ALL ON FUNCTION keel_meta.reap_expired_organization_invites(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION keel_meta.reap_expired_organization_invites(uuid,uuid) TO keel_identity;
