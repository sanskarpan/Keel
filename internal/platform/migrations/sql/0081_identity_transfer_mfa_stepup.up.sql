-- K8.11/K8.2 slice 19: MFA step-up for ownership transfer.
-- Transferring an organization is the highest-risk single action in the
-- identity surface: a password-only account takeover must not be enough to
-- steal it. The transfer function now requires the acting owner to hold at
-- least one registered WebAuthn credential; otherwise it reports
-- mfa_required and changes nothing. Self-transfer stays a no-op success and
-- needs no ceremony. No other path changes.

CREATE OR REPLACE FUNCTION keel_meta.transfer_organization_ownership(
    p_actor_id uuid,p_org_id uuid,p_new_owner_id uuid)
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
    IF p_actor_id IS NULL OR p_org_id IS NULL OR p_new_owner_id IS NULL THEN
        RAISE EXCEPTION 'identity ownership transfer is invalid';
    END IF;
    IF p_actor_id=p_new_owner_id THEN
        RETURN 'transferred';
    END IF;
    IF p_actor_id<p_new_owner_id THEN
        SELECT role INTO actor_role FROM keel_meta.identity_memberships
          WHERE org_id=p_org_id AND principal_id=p_actor_id FOR UPDATE;
        SELECT role INTO target_role FROM keel_meta.identity_memberships
          WHERE org_id=p_org_id AND principal_id=p_new_owner_id FOR UPDATE;
    ELSE
        SELECT role INTO target_role FROM keel_meta.identity_memberships
          WHERE org_id=p_org_id AND principal_id=p_new_owner_id FOR UPDATE;
        SELECT role INTO actor_role FROM keel_meta.identity_memberships
          WHERE org_id=p_org_id AND principal_id=p_actor_id FOR UPDATE;
    END IF;
    IF actor_role IS NULL OR actor_role<>'owner' THEN
        RETURN 'not_authorized';
    END IF;
    IF target_role IS NULL THEN
        RETURN 'not_member';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM keel_meta.identity_webauthn_credentials k
                     WHERE k.principal_id=p_actor_id) THEN
        RETURN 'mfa_required';
    END IF;
    IF target_role='owner' THEN
        RETURN 'transferred';
    END IF;
    UPDATE keel_meta.identity_memberships SET role='admin'
      WHERE org_id=p_org_id AND principal_id=p_actor_id;
    UPDATE keel_meta.identity_memberships SET role='owner'
      WHERE org_id=p_org_id AND principal_id=p_new_owner_id;
    RETURN 'transferred';
END $$;
REVOKE ALL ON FUNCTION keel_meta.transfer_organization_ownership(uuid,uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION keel_meta.transfer_organization_ownership(uuid,uuid,uuid) TO keel_identity;
