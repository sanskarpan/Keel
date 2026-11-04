-- K8.11/K8.2 slice 10: email invites and immediate owner transfer.
-- Invites name an email digest (the invitee may not have an account yet) plus
-- a single-use token; acceptance binds a matching active principal. Owner
-- transfer is immediate and audited: the current owner becomes admin and the
-- target admin/member becomes owner in one transaction, so no path orphans
-- an organization. Self-transfer is a no-op success. The memberships guard
-- is relaxed for exactly that owner/admin swap; every other direct mutation,
-- including deletes, stays refused. All access is through keel_identity-gated
-- SECURITY DEFINER functions; invites carry forced RLS with no direct grants.

CREATE TABLE keel_meta.identity_invites (
    invite_id uuid NOT NULL PRIMARY KEY CHECK (invite_id<>'00000000-0000-0000-0000-000000000000'::uuid),
    org_id uuid NOT NULL REFERENCES keel_meta.identity_organizations(org_id),
    email_digest bytea NOT NULL CHECK (octet_length(email_digest)=32),
    token_digest bytea NOT NULL CHECK (octet_length(token_digest)=32),
    role text NOT NULL CHECK (role IN ('admin','member')),
    invited_by uuid NOT NULL REFERENCES keel_meta.identity_principals(principal_id),
    requested_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    CONSTRAINT identity_invite_token_unique UNIQUE (token_digest),
    CONSTRAINT identity_invite_window CHECK (expires_at>requested_at),
    CONSTRAINT identity_invite_shape CHECK (consumed_at IS NULL OR consumed_at>=requested_at)
);
ALTER TABLE keel_meta.identity_invites ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.identity_invites FORCE ROW LEVEL SECURITY;
CREATE POLICY identity_invites_schema_owner ON keel_meta.identity_invites
    TO keel_schema_owner USING (true) WITH CHECK (true);
REVOKE ALL ON keel_meta.identity_invites FROM PUBLIC,keel_app,keel_worker,keel_operator,
    keel_budget_control,keel_rate_control,keel_rate_status,keel_ai_worker,keel_projector,
    keel_file_processor,keel_retrieval_indexer,keel_context_vault,keel_context_policy,
    keel_context_erasure,keel_context_erasure_worker,keel_context_legal_hold,
    keel_context_replay,keel_agent,keel_callback,keel_webhook,keel_identity;

CREATE FUNCTION keel_meta.guard_identity_invites_row()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    IF TG_OP='DELETE' THEN
        -- a resend replaces only an unconsumed pending invite.
        IF OLD.consumed_at IS NOT NULL OR
           current_user<>'keel_schema_owner' OR
           NOT pg_catalog.pg_has_role(session_user,'keel_identity','MEMBER') THEN
            RAISE EXCEPTION 'consumed invites are immutable';
        END IF;
        RETURN OLD;
    END IF;
    IF current_user<>'keel_schema_owner' OR
       NOT pg_catalog.pg_has_role(session_user,'keel_identity','MEMBER') THEN
        RAISE EXCEPTION 'identity invites are capability-managed';
    END IF;
    IF NEW.invite_id<>OLD.invite_id OR NEW.org_id<>OLD.org_id OR
       NEW.email_digest<>OLD.email_digest OR NEW.token_digest<>OLD.token_digest OR
       NEW.role<>OLD.role OR NEW.invited_by<>OLD.invited_by OR
       NEW.requested_at<>OLD.requested_at OR NEW.expires_at<>OLD.expires_at OR
       OLD.consumed_at IS NOT NULL OR NEW.consumed_at IS NULL THEN
        RAISE EXCEPTION 'invite rows may only move pending to consumed';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER identity_invites_guard BEFORE UPDATE OR DELETE
    ON keel_meta.identity_invites FOR EACH ROW
    EXECUTE FUNCTION keel_meta.guard_identity_invites_row();
REVOKE ALL ON FUNCTION keel_meta.guard_identity_invites_row() FROM PUBLIC;

-- Owner transfer is the only permitted role mutation: owner and admin swap
-- atomically inside one transaction.
CREATE OR REPLACE FUNCTION keel_meta.guard_identity_memberships_row()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    IF TG_OP='DELETE' THEN
        RAISE EXCEPTION 'identity memberships have no delete path in this slice';
    END IF;
    IF current_user<>'keel_schema_owner' OR
       NOT pg_catalog.pg_has_role(session_user,'keel_identity','MEMBER') THEN
        RAISE EXCEPTION 'identity memberships are capability-managed';
    END IF;
    IF TG_OP='INSERT' THEN
        RETURN NEW;
    END IF;
    IF NEW.org_id<>OLD.org_id OR NEW.principal_id<>OLD.principal_id OR
       NEW.created_at<>OLD.created_at THEN
        RAISE EXCEPTION 'identity membership identity is immutable';
    END IF;
    IF NOT ((OLD.role='owner' AND NEW.role='admin') OR
            (OLD.role='admin' AND NEW.role='owner')) THEN
        RAISE EXCEPTION 'membership roles change only by owner transfer';
    END IF;
    RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION keel_meta.guard_identity_memberships_row() FROM PUBLIC;

CREATE FUNCTION keel_meta.invite_organization_member(
    p_invite_id uuid,p_actor_id uuid,p_org_id uuid,p_email_digest bytea,
    p_token_digest bytea,p_role text,p_expires_at timestamptz)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,keel_meta,pg_temp AS $$
DECLARE actor_role text;
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'keel_identity','MEMBER') THEN
        RAISE EXCEPTION 'identity capability is required';
    END IF;
    IF p_invite_id IS NULL OR p_invite_id='00000000-0000-0000-0000-000000000000'::uuid OR
       p_actor_id IS NULL OR p_org_id IS NULL OR
       p_email_digest IS NULL OR octet_length(p_email_digest)<>32 OR
       p_token_digest IS NULL OR octet_length(p_token_digest)<>32 OR
       (p_role<>'admin' AND p_role<>'member') OR p_expires_at IS NULL THEN
        RAISE EXCEPTION 'identity invite is invalid';
    END IF;
    SELECT role INTO actor_role FROM keel_meta.identity_memberships
      WHERE org_id=p_org_id AND principal_id=p_actor_id;
    IF actor_role IS NULL OR (actor_role<>'owner' AND actor_role<>'admin') THEN
        RETURN 'not_authorized';
    END IF;
    IF EXISTS (SELECT 1 FROM keel_meta.identity_principals p
                 JOIN keel_meta.identity_memberships m ON m.principal_id=p.principal_id
                WHERE m.org_id=p_org_id AND p.email_digest=p_email_digest) THEN
        RETURN 'already_member';
    END IF;
    IF EXISTS (SELECT 1 FROM keel_meta.identity_invites i
                 WHERE i.token_digest=p_token_digest) THEN
        RETURN 'token_reuse';
    END IF;
    IF p_expires_at<=clock_timestamp() OR
       p_expires_at>clock_timestamp()+INTERVAL '7 days' THEN
        RAISE EXCEPTION 'identity invite window is out of bounds';
    END IF;
    DELETE FROM keel_meta.identity_invites
      WHERE org_id=p_org_id AND email_digest=p_email_digest AND consumed_at IS NULL;
    INSERT INTO keel_meta.identity_invites
        (invite_id,org_id,email_digest,token_digest,role,invited_by,requested_at,expires_at)
        VALUES (p_invite_id,p_org_id,p_email_digest,p_token_digest,p_role,p_actor_id,clock_timestamp(),p_expires_at);
    RETURN 'invited';
END $$;
REVOKE ALL ON FUNCTION keel_meta.invite_organization_member(uuid,uuid,uuid,bytea,bytea,text,timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION keel_meta.invite_organization_member(uuid,uuid,uuid,bytea,bytea,text,timestamptz) TO keel_identity;

CREATE FUNCTION keel_meta.accept_organization_invite(p_token_digest bytea,p_principal_id uuid)
RETURNS TABLE(outcome text,out_org_id uuid)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,keel_meta,pg_temp AS $$
DECLARE
    target uuid;
    invite_org uuid;
    invite_email bytea;
    invite_role text;
    expiry timestamptz;
    principal_email bytea;
    principal_state text;
    principal_tenant uuid;
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'keel_identity','MEMBER') THEN
        RAISE EXCEPTION 'identity capability is required';
    END IF;
    IF p_token_digest IS NULL OR octet_length(p_token_digest)<>32 OR p_principal_id IS NULL THEN
        RAISE EXCEPTION 'identity invite accept is invalid';
    END IF;
    SELECT invite_id,org_id,email_digest,role,expires_at INTO target,invite_org,invite_email,invite_role,expiry
      FROM keel_meta.identity_invites
      WHERE token_digest=p_token_digest FOR UPDATE;
    IF target IS NULL THEN
        RETURN QUERY SELECT 'unknown'::text,NULL::uuid;
        RETURN;
    END IF;
    UPDATE keel_meta.identity_invites i SET consumed_at=clock_timestamp()
      WHERE i.token_digest=p_token_digest AND i.consumed_at IS NULL;
    IF NOT FOUND THEN
        RETURN QUERY SELECT 'duplicate'::text,invite_org;
        RETURN;
    END IF;
    IF expiry<=clock_timestamp() THEN
        RETURN QUERY SELECT 'expired'::text,invite_org;
        RETURN;
    END IF;
    SELECT email_digest,state,tenant_id INTO principal_email,principal_state,principal_tenant
      FROM keel_meta.identity_principals
      WHERE principal_id=p_principal_id FOR UPDATE;
    IF principal_state IS NULL OR principal_state<>'active' THEN
        RETURN QUERY SELECT 'not_active'::text,invite_org;
        RETURN;
    END IF;
    IF principal_email<>invite_email THEN
        RETURN QUERY SELECT 'email_mismatch'::text,invite_org;
        RETURN;
    END IF;
    IF EXISTS (SELECT 1 FROM keel_meta.identity_memberships m
                 WHERE m.org_id=invite_org AND m.principal_id=p_principal_id) THEN
        RETURN QUERY SELECT 'already_member'::text,invite_org;
        RETURN;
    END IF;
    INSERT INTO keel_meta.identity_memberships (org_id,principal_id,role,created_at)
        VALUES (invite_org,p_principal_id,invite_role,clock_timestamp());
    IF principal_tenant IS NULL THEN
        UPDATE keel_meta.identity_principals SET tenant_id=invite_org
          WHERE principal_id=p_principal_id;
    END IF;
    RETURN QUERY SELECT 'accepted'::text,invite_org;
END $$;
REVOKE ALL ON FUNCTION keel_meta.accept_organization_invite(bytea,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION keel_meta.accept_organization_invite(bytea,uuid) TO keel_identity;

CREATE FUNCTION keel_meta.transfer_organization_ownership(
    p_actor_id uuid,p_org_id uuid,p_new_owner_id uuid)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,keel_meta,pg_temp AS $$
DECLARE actor_role text;
DECLARE target_role text;
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
    -- Lock in uuid order so concurrent transfers cannot deadlock.
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
