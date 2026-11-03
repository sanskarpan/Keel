-- K8.11/K8.1 slice 9: multi-org memberships with per-session active org.
-- Owner direction selects several memberships per principal with an explicit
-- active-org switch on each session. This migration drops the single-membership
-- unique constraint, carries the active org on the session row, and replaces
-- the organization functions so founding and joining never refuse a principal
-- that already belongs elsewhere: the tenant stays first-bound (primary) and
-- only an unbound principal binds on entry. The sessions guard is replaced to
-- permit capability-gated org transitions while keeping every other field
-- immutable; only switch_identity_session_org may move it, and only to an
-- organization the session's principal belongs to. Revoked or expired
-- sessions do not switch.

ALTER TABLE keel_meta.identity_memberships DROP CONSTRAINT identity_membership_principal_unique;

ALTER TABLE keel_meta.identity_sessions
    ADD COLUMN org_id uuid REFERENCES keel_meta.identity_organizations(org_id);

CREATE OR REPLACE FUNCTION keel_meta.guard_identity_sessions_row()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    IF TG_OP='DELETE' OR NEW.session_id<>OLD.session_id OR NEW.principal_id<>OLD.principal_id OR
       NEW.token_digest<>OLD.token_digest OR NEW.created_at<>OLD.created_at OR
       NEW.expires_at<>OLD.expires_at OR (OLD.revoked_at IS NOT NULL AND NEW.revoked_at<>OLD.revoked_at) THEN
        RAISE EXCEPTION 'identity sessions are capability-managed history';
    END IF;
    IF current_user<>'keel_schema_owner' OR
       NOT pg_catalog.pg_has_role(session_user,'keel_identity','MEMBER') THEN
        RAISE EXCEPTION 'identity sessions are capability-managed';
    END IF;
    RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION keel_meta.guard_identity_sessions_row() FROM PUBLIC;

CREATE OR REPLACE FUNCTION keel_meta.create_identity_organization(
    p_org_id uuid,p_principal_id uuid,p_slug text,p_display_name text,p_region text)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,keel_meta,pg_temp AS $$
DECLARE
    current_state text;
    current_tenant uuid;
    violated text;
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'keel_identity','MEMBER') THEN
        RAISE EXCEPTION 'identity capability is required';
    END IF;
    IF p_org_id IS NULL OR p_org_id='00000000-0000-0000-0000-000000000000'::uuid OR
       p_principal_id IS NULL OR p_slug IS NULL OR p_display_name IS NULL OR p_region IS NULL THEN
        RAISE EXCEPTION 'identity organization create is invalid';
    END IF;
    SELECT state,tenant_id INTO current_state,current_tenant FROM keel_meta.identity_principals
      WHERE principal_id=p_principal_id FOR UPDATE;
    IF current_state IS NULL OR current_state<>'active' THEN
        RETURN 'not_active';
    END IF;
    BEGIN
        INSERT INTO keel_meta.identity_organizations (org_id,slug,display_name,region,created_at)
            VALUES (p_org_id,p_slug,p_display_name,p_region,clock_timestamp());
    EXCEPTION
        WHEN unique_violation THEN
            GET STACKED DIAGNOSTICS violated = CONSTRAINT_NAME;
            IF violated='identity_organization_slug_unique' THEN
                RETURN 'slug_conflict';
            END IF;
            RAISE;
    END;
    INSERT INTO keel_meta.identity_memberships (org_id,principal_id,role,created_at)
        VALUES (p_org_id,p_principal_id,'owner',clock_timestamp());
    IF current_tenant IS NULL THEN
        UPDATE keel_meta.identity_principals SET tenant_id=p_org_id
          WHERE principal_id=p_principal_id;
    END IF;
    RETURN 'created';
END $$;
REVOKE ALL ON FUNCTION keel_meta.create_identity_organization(uuid,uuid,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION keel_meta.create_identity_organization(uuid,uuid,text,text,text) TO keel_identity;

CREATE OR REPLACE FUNCTION keel_meta.add_organization_member(
    p_actor_id uuid,p_org_id uuid,p_member_id uuid,p_role text)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,keel_meta,pg_temp AS $$
DECLARE
    actor_role text;
    member_state text;
    member_tenant uuid;
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'keel_identity','MEMBER') THEN
        RAISE EXCEPTION 'identity capability is required';
    END IF;
    IF p_actor_id IS NULL OR p_org_id IS NULL OR p_member_id IS NULL OR
       (p_role<>'admin' AND p_role<>'member') THEN
        RAISE EXCEPTION 'identity membership add is invalid';
    END IF;
    SELECT role INTO actor_role FROM keel_meta.identity_memberships
      WHERE org_id=p_org_id AND principal_id=p_actor_id;
    IF actor_role IS NULL OR (actor_role<>'owner' AND actor_role<>'admin') THEN
        RETURN 'not_authorized';
    END IF;
    SELECT state,tenant_id INTO member_state,member_tenant FROM keel_meta.identity_principals
      WHERE principal_id=p_member_id FOR UPDATE;
    IF member_state IS NULL OR member_state<>'active' THEN
        RETURN 'not_active';
    END IF;
    IF EXISTS (SELECT 1 FROM keel_meta.identity_memberships
                 WHERE org_id=p_org_id AND principal_id=p_member_id) THEN
        RETURN 'already_member';
    END IF;
    INSERT INTO keel_meta.identity_memberships (org_id,principal_id,role,created_at)
        VALUES (p_org_id,p_member_id,p_role,clock_timestamp());
    IF member_tenant IS NULL THEN
        UPDATE keel_meta.identity_principals SET tenant_id=p_org_id
          WHERE principal_id=p_member_id;
    END IF;
    RETURN 'added';
END $$;
REVOKE ALL ON FUNCTION keel_meta.add_organization_member(uuid,uuid,uuid,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION keel_meta.add_organization_member(uuid,uuid,uuid,text) TO keel_identity;

-- The session lookup gains the active-org column, which changes its return
-- type; CREATE OR REPLACE cannot do that, so drop first. Callers move to
-- the seven-column shape with this migration.
DROP FUNCTION keel_meta.identity_session_for(bytea);

CREATE FUNCTION keel_meta.identity_session_for(p_token_digest bytea)
RETURNS TABLE(out_session_id uuid,out_principal_id uuid,out_principal_state text,
              out_created_at timestamptz,out_expires_at timestamptz,out_revoked_at timestamptz,
              out_org_id uuid)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,keel_meta,pg_temp AS $$
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'keel_identity','MEMBER') THEN
        RAISE EXCEPTION 'identity capability is required';
    END IF;
    IF p_token_digest IS NULL OR octet_length(p_token_digest)<>32 THEN
        RAISE EXCEPTION 'identity session lookup is invalid';
    END IF;
    RETURN QUERY
        SELECT s.session_id,s.principal_id,p.state,s.created_at,s.expires_at,s.revoked_at,s.org_id
          FROM keel_meta.identity_sessions s
          JOIN keel_meta.identity_principals p ON p.principal_id=s.principal_id
         WHERE s.token_digest=p_token_digest;
END $$;
REVOKE ALL ON FUNCTION keel_meta.identity_session_for(bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION keel_meta.identity_session_for(bytea) TO keel_identity;

CREATE FUNCTION keel_meta.switch_identity_session_org(p_session_id uuid,p_org_id uuid)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,keel_meta,pg_temp AS $$
DECLARE
    owner uuid;
    revoked timestamptz;
    expiry timestamptz;
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'keel_identity','MEMBER') THEN
        RAISE EXCEPTION 'identity capability is required';
    END IF;
    IF p_session_id IS NULL OR p_session_id='00000000-0000-0000-0000-000000000000'::uuid OR
       p_org_id IS NULL OR p_org_id='00000000-0000-0000-0000-000000000000'::uuid THEN
        RAISE EXCEPTION 'identity session switch is invalid';
    END IF;
    SELECT principal_id,revoked_at,expires_at INTO owner,revoked,expiry
      FROM keel_meta.identity_sessions
      WHERE session_id=p_session_id FOR UPDATE;
    IF owner IS NULL OR revoked IS NOT NULL OR expiry<=clock_timestamp() THEN
        RETURN 'unknown_session';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM keel_meta.identity_memberships m
                     WHERE m.org_id=p_org_id AND m.principal_id=owner) THEN
        RETURN 'not_member';
    END IF;
    UPDATE keel_meta.identity_sessions s SET org_id=p_org_id
      WHERE s.session_id=p_session_id;
    RETURN 'switched';
END $$;
REVOKE ALL ON FUNCTION keel_meta.switch_identity_session_org(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION keel_meta.switch_identity_session_org(uuid,uuid) TO keel_identity;
