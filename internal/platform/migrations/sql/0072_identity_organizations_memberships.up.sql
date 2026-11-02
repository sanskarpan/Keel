-- K8.11/K8.1 slice 7: organizations, memberships and tenant binding.
-- Principals bootstrap unbound (tenant_id NULL); creating or joining an
-- organization binds the principal's tenant to the organization id exactly
-- once. Membership roles are owner/admin/member with no transfer, demotion
-- or removal path in this slice, so no organization can lose its owner
-- through this surface. Invites, owner transfer, service principals and
-- tenant-context wiring arrive with the K8.1/K8.2 slices; this migration
-- owns only the durable state and the capability-gated transitions.
-- All access is through keel_identity-gated SECURITY DEFINER functions;
-- both tables carry forced RLS with no direct grants.

CREATE TABLE keel_meta.identity_organizations (
    org_id uuid NOT NULL PRIMARY KEY CHECK (org_id<>'00000000-0000-0000-0000-000000000000'::uuid),
    slug text NOT NULL CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$'),
    display_name text NOT NULL CHECK (length(display_name) BETWEEN 1 AND 128 AND display_name NOT LIKE '%'||chr(10)||'%'),
    region text NOT NULL CHECK (region ~ '^[a-z][a-z0-9-]{0,31}$'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT identity_organization_slug_unique UNIQUE (slug)
);
ALTER TABLE keel_meta.identity_organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.identity_organizations FORCE ROW LEVEL SECURITY;
CREATE POLICY identity_organizations_schema_owner ON keel_meta.identity_organizations
    TO keel_schema_owner USING (true) WITH CHECK (true);
REVOKE ALL ON keel_meta.identity_organizations FROM PUBLIC,keel_app,keel_worker,keel_operator,
    keel_budget_control,keel_rate_control,keel_rate_status,keel_ai_worker,keel_projector,
    keel_file_processor,keel_retrieval_indexer,keel_context_vault,keel_context_policy,
    keel_context_erasure,keel_context_erasure_worker,keel_context_legal_hold,
    keel_context_replay,keel_agent,keel_callback,keel_webhook,keel_identity;

CREATE TABLE keel_meta.identity_memberships (
    org_id uuid NOT NULL REFERENCES keel_meta.identity_organizations(org_id),
    principal_id uuid NOT NULL REFERENCES keel_meta.identity_principals(principal_id),
    role text NOT NULL CHECK (role IN ('owner','admin','member')),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (org_id,principal_id),
    CONSTRAINT identity_membership_principal_unique UNIQUE (principal_id)
);
ALTER TABLE keel_meta.identity_memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.identity_memberships FORCE ROW LEVEL SECURITY;
CREATE POLICY identity_memberships_schema_owner ON keel_meta.identity_memberships
    TO keel_schema_owner USING (true) WITH CHECK (true);
REVOKE ALL ON keel_meta.identity_memberships FROM PUBLIC,keel_app,keel_worker,keel_operator,
    keel_budget_control,keel_rate_control,keel_rate_status,keel_ai_worker,keel_projector,
    keel_file_processor,keel_retrieval_indexer,keel_context_vault,keel_context_policy,
    keel_context_erasure,keel_context_erasure_worker,keel_context_legal_hold,
    keel_context_replay,keel_agent,keel_callback,keel_webhook,keel_identity;

-- Tenant binding is now a first-class transition: NULL to exactly one org id.
CREATE OR REPLACE FUNCTION keel_meta.guard_identity_principals_row()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    IF TG_OP='DELETE' THEN
        RAISE EXCEPTION 'identity principals have no delete path';
    END IF;
    IF current_user<>'keel_schema_owner' OR
       NOT pg_catalog.pg_has_role(session_user,'keel_identity','MEMBER') THEN
        RAISE EXCEPTION 'identity principals are capability-managed';
    END IF;
    IF NEW.principal_id<>OLD.principal_id OR NEW.email_digest<>OLD.email_digest OR
       NEW.created_at<>OLD.created_at THEN
        RAISE EXCEPTION 'identity principal identity is immutable';
    END IF;
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id THEN
        -- the only permitted tenant move is first binding: NULL to one org id.
        IF OLD.tenant_id IS NOT NULL OR NEW.tenant_id IS NULL OR
           NEW.tenant_id='00000000-0000-0000-0000-000000000000'::uuid OR
           NEW.state<>OLD.state OR
           NEW.verified_at IS DISTINCT FROM OLD.verified_at OR
           NEW.disabled_at IS DISTINCT FROM OLD.disabled_at THEN
            RAISE EXCEPTION 'identity tenant rebinding is refused';
        END IF;
        RETURN NEW;
    END IF;
    IF NOT (OLD.state='pending_verification' AND NEW.state='active' AND
            NEW.verified_at IS NOT NULL AND NEW.disabled_at IS NULL) THEN
        RAISE EXCEPTION 'direct principal mutations are refused';
    END IF;
    RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION keel_meta.guard_identity_principals_row() FROM PUBLIC;

CREATE FUNCTION keel_meta.guard_identity_organizations_row()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    IF TG_OP='DELETE' THEN
        RAISE EXCEPTION 'identity organizations have no delete path in this slice';
    END IF;
    IF TG_OP='UPDATE' THEN
        RAISE EXCEPTION 'identity organizations are immutable in this slice';
    END IF;
    IF current_user<>'keel_schema_owner' OR
       NOT pg_catalog.pg_has_role(session_user,'keel_identity','MEMBER') THEN
        RAISE EXCEPTION 'identity organizations are capability-managed';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER identity_organizations_guard BEFORE INSERT OR UPDATE OR DELETE
    ON keel_meta.identity_organizations FOR EACH ROW
    EXECUTE FUNCTION keel_meta.guard_identity_organizations_row();
REVOKE ALL ON FUNCTION keel_meta.guard_identity_organizations_row() FROM PUBLIC;

CREATE FUNCTION keel_meta.guard_identity_memberships_row()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    IF TG_OP='DELETE' THEN
        RAISE EXCEPTION 'identity memberships have no delete path in this slice';
    END IF;
    IF TG_OP='UPDATE' THEN
        RAISE EXCEPTION 'identity memberships are immutable in this slice';
    END IF;
    IF current_user<>'keel_schema_owner' OR
       NOT pg_catalog.pg_has_role(session_user,'keel_identity','MEMBER') THEN
        RAISE EXCEPTION 'identity memberships are capability-managed';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER identity_memberships_guard BEFORE INSERT OR UPDATE OR DELETE
    ON keel_meta.identity_memberships FOR EACH ROW
    EXECUTE FUNCTION keel_meta.guard_identity_memberships_row();
REVOKE ALL ON FUNCTION keel_meta.guard_identity_memberships_row() FROM PUBLIC;

CREATE FUNCTION keel_meta.create_identity_organization(
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
    IF current_tenant IS NOT NULL THEN
        RETURN 'already_bound';
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
    UPDATE keel_meta.identity_principals SET tenant_id=p_org_id
      WHERE principal_id=p_principal_id;
    RETURN 'created';
END $$;
REVOKE ALL ON FUNCTION keel_meta.create_identity_organization(uuid,uuid,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION keel_meta.create_identity_organization(uuid,uuid,text,text,text) TO keel_identity;

CREATE FUNCTION keel_meta.add_organization_member(
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
                 WHERE principal_id=p_member_id) THEN
        RETURN 'already_member';
    END IF;
    IF member_tenant IS NOT NULL AND member_tenant<>p_org_id THEN
        RETURN 'tenant_conflict';
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

CREATE FUNCTION keel_meta.organizations_for(p_principal_id uuid)
RETURNS TABLE(out_org_id uuid,out_slug text,out_display_name text,out_region text,out_role text)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,keel_meta,pg_temp AS $$
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'keel_identity','MEMBER') THEN
        RAISE EXCEPTION 'identity capability is required';
    END IF;
    IF p_principal_id IS NULL OR p_principal_id='00000000-0000-0000-0000-000000000000'::uuid THEN
        RAISE EXCEPTION 'identity organization lookup is invalid';
    END IF;
    RETURN QUERY
        SELECT o.org_id,o.slug,o.display_name,o.region,m.role
          FROM keel_meta.identity_memberships m
          JOIN keel_meta.identity_organizations o ON o.org_id=m.org_id
         WHERE m.principal_id=p_principal_id;
END $$;
REVOKE ALL ON FUNCTION keel_meta.organizations_for(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION keel_meta.organizations_for(uuid) TO keel_identity;
