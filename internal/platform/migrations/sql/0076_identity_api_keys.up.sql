-- K8.11/K8.2 slice 12: API-key service principals.
-- A service principal is a machine identity owned by exactly one
-- organization. Each holds bearer keys: the wire form carries a public
-- prefix for log-safe identification while only a purpose-bound digest is
-- stored. Rotation is issue-then-revoke (overlap supported); revocation and
-- expiry are terminal. Verification reports unknown/revoked/expired/valid
-- and stamps last use on success. All access is through keel_identity-gated
-- SECURITY DEFINER functions; both tables carry forced RLS with no direct
-- grants.

CREATE TABLE keel_meta.identity_service_principals (
    service_principal_id uuid NOT NULL PRIMARY KEY CHECK (service_principal_id<>'00000000-0000-0000-0000-000000000000'::uuid),
    org_id uuid NOT NULL REFERENCES keel_meta.identity_organizations(org_id),
    name text NOT NULL CHECK (length(name) BETWEEN 1 AND 64 AND name NOT LIKE '%'||chr(10)||'%'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    disabled_at timestamptz
);
ALTER TABLE keel_meta.identity_service_principals ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.identity_service_principals FORCE ROW LEVEL SECURITY;
CREATE POLICY identity_service_principals_schema_owner ON keel_meta.identity_service_principals
    TO keel_schema_owner USING (true) WITH CHECK (true);
REVOKE ALL ON keel_meta.identity_service_principals FROM PUBLIC,keel_app,keel_worker,keel_operator,
    keel_budget_control,keel_rate_control,keel_rate_status,keel_ai_worker,keel_projector,
    keel_file_processor,keel_retrieval_indexer,keel_context_vault,keel_context_policy,
    keel_context_erasure,keel_context_erasure_worker,keel_context_legal_hold,
    keel_context_replay,keel_agent,keel_callback,keel_webhook,keel_identity;

CREATE TABLE keel_meta.identity_api_keys (
    key_id uuid NOT NULL PRIMARY KEY CHECK (key_id<>'00000000-0000-0000-0000-000000000000'::uuid),
    service_principal_id uuid NOT NULL REFERENCES keel_meta.identity_service_principals(service_principal_id),
    prefix text NOT NULL CHECK (prefix ~ '^[A-Za-z0-9_-]{8}$'),
    key_digest bytea NOT NULL CHECK (octet_length(key_digest)=32),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz,
    revoked_at timestamptz,
    last_used_at timestamptz,
    CONSTRAINT identity_api_key_digest_unique UNIQUE (key_digest),
    CONSTRAINT identity_api_key_window CHECK (expires_at IS NULL OR expires_at>created_at),
    CONSTRAINT identity_api_key_shape CHECK (
        (revoked_at IS NULL AND last_used_at IS NULL) OR
        (revoked_at IS NULL AND last_used_at IS NOT NULL AND last_used_at>=created_at) OR
        (revoked_at IS NOT NULL AND revoked_at>=created_at AND
         (last_used_at IS NULL OR last_used_at>=created_at)))
);
ALTER TABLE keel_meta.identity_api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.identity_api_keys FORCE ROW LEVEL SECURITY;
CREATE POLICY identity_api_keys_schema_owner ON keel_meta.identity_api_keys
    TO keel_schema_owner USING (true) WITH CHECK (true);
REVOKE ALL ON keel_meta.identity_api_keys FROM PUBLIC,keel_app,keel_worker,keel_operator,
    keel_budget_control,keel_rate_control,keel_rate_status,keel_ai_worker,keel_projector,
    keel_file_processor,keel_retrieval_indexer,keel_context_vault,keel_context_policy,
    keel_context_erasure,keel_context_erasure_worker,keel_context_legal_hold,
    keel_context_replay,keel_agent,keel_callback,keel_webhook,keel_identity;

CREATE FUNCTION keel_meta.guard_identity_service_principals_row()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    IF TG_OP='DELETE' THEN
        RAISE EXCEPTION 'identity service principals have no delete path in this slice';
    END IF;
    IF current_user<>'keel_schema_owner' OR
       NOT pg_catalog.pg_has_role(session_user,'keel_identity','MEMBER') THEN
        RAISE EXCEPTION 'identity service principals are capability-managed';
    END IF;
    IF TG_OP='INSERT' THEN
        IF NEW.disabled_at IS NOT NULL THEN
            RAISE EXCEPTION 'identity service principals start enabled';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.service_principal_id<>OLD.service_principal_id OR NEW.org_id<>OLD.org_id OR
       NEW.name<>OLD.name OR NEW.created_at<>OLD.created_at OR
       OLD.disabled_at IS NOT NULL OR NEW.disabled_at IS NULL THEN
        RAISE EXCEPTION 'service principals only disable once';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER identity_service_principals_guard BEFORE INSERT OR UPDATE OR DELETE
    ON keel_meta.identity_service_principals FOR EACH ROW
    EXECUTE FUNCTION keel_meta.guard_identity_service_principals_row();
REVOKE ALL ON FUNCTION keel_meta.guard_identity_service_principals_row() FROM PUBLIC;

CREATE FUNCTION keel_meta.guard_identity_api_keys_row()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    IF TG_OP='DELETE' THEN
        RAISE EXCEPTION 'identity API keys are capability-managed history';
    END IF;
    IF current_user<>'keel_schema_owner' OR
       NOT pg_catalog.pg_has_role(session_user,'keel_identity','MEMBER') THEN
        RAISE EXCEPTION 'identity API keys are capability-managed';
    END IF;
    IF TG_OP='INSERT' THEN
        IF NEW.revoked_at IS NOT NULL OR NEW.last_used_at IS NOT NULL THEN
            RAISE EXCEPTION 'identity API keys start live and unused';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.key_id<>OLD.key_id OR NEW.service_principal_id<>OLD.service_principal_id OR
       NEW.prefix<>OLD.prefix OR NEW.key_digest<>OLD.key_digest OR
       NEW.created_at<>OLD.created_at OR NEW.expires_at IS DISTINCT FROM OLD.expires_at OR
       (OLD.revoked_at IS NOT NULL AND NEW.revoked_at<>OLD.revoked_at) THEN
        RAISE EXCEPTION 'identity API keys are immutable except revocation';
    END IF;
    IF OLD.revoked_at IS NULL AND NEW.revoked_at IS NULL AND
       NEW.last_used_at IS DISTINCT FROM OLD.last_used_at THEN
        -- use stamps advance on live keys only.
        IF NEW.last_used_at IS NULL OR NEW.last_used_at<OLD.created_at THEN
            RAISE EXCEPTION 'identity API key use stamps advance monotonically';
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL AND
       NEW.last_used_at IS NOT DISTINCT FROM OLD.last_used_at THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'identity API key transitions are revoke or use-stamp only';
END $$;
CREATE TRIGGER identity_api_keys_guard BEFORE INSERT OR UPDATE OR DELETE
    ON keel_meta.identity_api_keys FOR EACH ROW
    EXECUTE FUNCTION keel_meta.guard_identity_api_keys_row();
REVOKE ALL ON FUNCTION keel_meta.guard_identity_api_keys_row() FROM PUBLIC;

CREATE FUNCTION keel_meta.create_identity_service_principal(
    p_service_principal_id uuid,p_actor_id uuid,p_org_id uuid,p_name text)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,keel_meta,pg_temp AS $$
DECLARE actor_role text;
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'keel_identity','MEMBER') THEN
        RAISE EXCEPTION 'identity capability is required';
    END IF;
    IF p_service_principal_id IS NULL OR p_service_principal_id='00000000-0000-0000-0000-000000000000'::uuid OR
       p_actor_id IS NULL OR p_org_id IS NULL OR p_name IS NULL OR length(p_name) NOT BETWEEN 1 AND 64 THEN
        RAISE EXCEPTION 'identity service principal create is invalid';
    END IF;
    SELECT role INTO actor_role FROM keel_meta.identity_memberships
      WHERE org_id=p_org_id AND principal_id=p_actor_id;
    IF actor_role IS NULL OR (actor_role<>'owner' AND actor_role<>'admin') THEN
        RETURN 'not_authorized';
    END IF;
    INSERT INTO keel_meta.identity_service_principals
        (service_principal_id,org_id,name,created_at)
        VALUES (p_service_principal_id,p_org_id,p_name,clock_timestamp());
    RETURN 'created';
END $$;
REVOKE ALL ON FUNCTION keel_meta.create_identity_service_principal(uuid,uuid,uuid,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION keel_meta.create_identity_service_principal(uuid,uuid,uuid,text) TO keel_identity;

CREATE FUNCTION keel_meta.issue_identity_api_key(
    p_key_id uuid,p_service_principal_id uuid,p_prefix text,p_key_digest bytea,p_expires_at timestamptz)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,keel_meta,pg_temp AS $$
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'keel_identity','MEMBER') THEN
        RAISE EXCEPTION 'identity capability is required';
    END IF;
    IF p_key_id IS NULL OR p_key_id='00000000-0000-0000-0000-000000000000'::uuid OR
       p_service_principal_id IS NULL OR p_prefix IS NULL OR NOT p_prefix ~ '^[A-Za-z0-9_-]{8}$' OR
       p_key_digest IS NULL OR octet_length(p_key_digest)<>32 THEN
        RAISE EXCEPTION 'identity API key issue is invalid';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM keel_meta.identity_service_principals s
                     WHERE s.service_principal_id=p_service_principal_id AND s.disabled_at IS NULL) THEN
        RETURN 'unknown_principal';
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
REVOKE ALL ON FUNCTION keel_meta.issue_identity_api_key(uuid,uuid,text,bytea,timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION keel_meta.issue_identity_api_key(uuid,uuid,text,bytea,timestamptz) TO keel_identity;

CREATE FUNCTION keel_meta.verify_identity_api_key(p_key_digest bytea)
RETURNS TABLE(outcome text,out_key_id uuid,out_service_principal_id uuid,out_org_id uuid)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,keel_meta,pg_temp AS $$
DECLARE
    key uuid;
    principal uuid;
    org uuid;
    expiry timestamptz;
    revoked timestamptz;
    disabled timestamptz;
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'keel_identity','MEMBER') THEN
        RAISE EXCEPTION 'identity capability is required';
    END IF;
    IF p_key_digest IS NULL OR octet_length(p_key_digest)<>32 THEN
        RAISE EXCEPTION 'identity API key verify is invalid';
    END IF;
    SELECT k.key_id,k.service_principal_id,s.org_id,k.expires_at,k.revoked_at,s.disabled_at
      INTO key,principal,org,expiry,revoked,disabled
      FROM keel_meta.identity_api_keys k
      JOIN keel_meta.identity_service_principals s
        ON s.service_principal_id=k.service_principal_id
     WHERE k.key_digest=p_key_digest FOR UPDATE OF k;
    IF key IS NULL THEN
        RETURN QUERY SELECT 'unknown'::text,NULL::uuid,NULL::uuid,NULL::uuid;
        RETURN;
    END IF;
    IF revoked IS NOT NULL OR disabled IS NOT NULL THEN
        RETURN QUERY SELECT 'revoked'::text,key,principal,org;
        RETURN;
    END IF;
    IF expiry IS NOT NULL AND expiry<=clock_timestamp() THEN
        RETURN QUERY SELECT 'expired'::text,key,principal,org;
        RETURN;
    END IF;
    UPDATE keel_meta.identity_api_keys k SET last_used_at=clock_timestamp()
      WHERE k.key_id=key;
    RETURN QUERY SELECT 'valid'::text,key,principal,org;
END $$;
REVOKE ALL ON FUNCTION keel_meta.verify_identity_api_key(bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION keel_meta.verify_identity_api_key(bytea) TO keel_identity;

CREATE FUNCTION keel_meta.revoke_identity_api_key(p_key_id uuid)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,keel_meta,pg_temp AS $$
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'keel_identity','MEMBER') THEN
        RAISE EXCEPTION 'identity capability is required';
    END IF;
    IF p_key_id IS NULL OR p_key_id='00000000-0000-0000-0000-000000000000'::uuid THEN
        RAISE EXCEPTION 'identity API key revoke is invalid';
    END IF;
    UPDATE keel_meta.identity_api_keys k SET revoked_at=clock_timestamp()
      WHERE k.key_id=p_key_id AND k.revoked_at IS NULL;
    IF NOT FOUND THEN
        RETURN 'unknown_key';
    END IF;
    RETURN 'revoked';
END $$;
REVOKE ALL ON FUNCTION keel_meta.revoke_identity_api_key(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION keel_meta.revoke_identity_api_key(uuid) TO keel_identity;

CREATE FUNCTION keel_meta.disable_identity_service_principal(p_service_principal_id uuid)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,keel_meta,pg_temp AS $$
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'keel_identity','MEMBER') THEN
        RAISE EXCEPTION 'identity capability is required';
    END IF;
    IF p_service_principal_id IS NULL OR
       p_service_principal_id='00000000-0000-0000-0000-000000000000'::uuid THEN
        RAISE EXCEPTION 'identity service principal disable is invalid';
    END IF;
    UPDATE keel_meta.identity_service_principals s SET disabled_at=clock_timestamp()
      WHERE s.service_principal_id=p_service_principal_id AND s.disabled_at IS NULL;
    IF NOT FOUND THEN
        RETURN 'unknown_principal';
    END IF;
    UPDATE keel_meta.identity_api_keys k SET revoked_at=clock_timestamp()
      WHERE k.service_principal_id=p_service_principal_id AND k.revoked_at IS NULL;
    RETURN 'disabled';
END $$;
REVOKE ALL ON FUNCTION keel_meta.disable_identity_service_principal(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION keel_meta.disable_identity_service_principal(uuid) TO keel_identity;
