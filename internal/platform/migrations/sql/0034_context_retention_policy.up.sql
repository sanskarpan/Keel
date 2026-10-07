CREATE TABLE keel_meta.context_retention_policies (
    tenant_id uuid NOT NULL CHECK (tenant_id <> '00000000-0000-0000-0000-000000000000'::uuid),
    purpose text NOT NULL CHECK (purpose IN ('read_only_replay','incident_review')),
    policy_version bigint NOT NULL CHECK (policy_version > 0),
    enabled boolean NOT NULL,
    retention_seconds integer,
    consent_id uuid CHECK (consent_id IS NULL OR consent_id <> '00000000-0000-0000-0000-000000000000'::uuid),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id,purpose,policy_version),
    CHECK ((enabled AND retention_seconds IS NOT NULL AND retention_seconds BETWEEN 1 AND 31536000 AND consent_id IS NOT NULL) OR
           (NOT enabled AND retention_seconds IS NULL AND consent_id IS NULL))
);

CREATE TABLE keel_meta.context_retention_policy_heads (
    tenant_id uuid NOT NULL,
    purpose text NOT NULL,
    policy_version bigint NOT NULL,
    PRIMARY KEY (tenant_id,purpose),
    FOREIGN KEY (tenant_id,purpose,policy_version)
        REFERENCES keel_meta.context_retention_policies (tenant_id,purpose,policy_version)
);

ALTER TABLE keel_meta.context_retention_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.context_retention_policies FORCE ROW LEVEL SECURITY;
CREATE POLICY context_retention_policies_scope ON keel_meta.context_retention_policies
    TO keel_context_policy,keel_context_vault
    USING (tenant_id=(SELECT keel_private.current_tenant_id()))
    WITH CHECK (tenant_id=(SELECT keel_private.current_tenant_id()));
CREATE POLICY context_retention_policies_schema_owner ON keel_meta.context_retention_policies
    TO keel_schema_owner USING (true) WITH CHECK (true);

ALTER TABLE keel_meta.context_retention_policy_heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.context_retention_policy_heads FORCE ROW LEVEL SECURITY;
CREATE POLICY context_retention_policy_heads_scope ON keel_meta.context_retention_policy_heads
    TO keel_context_policy,keel_context_vault
    USING (tenant_id=(SELECT keel_private.current_tenant_id()))
    WITH CHECK (tenant_id=(SELECT keel_private.current_tenant_id()));
CREATE POLICY context_retention_policy_heads_schema_owner ON keel_meta.context_retention_policy_heads
    TO keel_schema_owner USING (true) WITH CHECK (true);

GRANT USAGE ON SCHEMA keel_meta TO keel_context_policy;
GRANT SELECT,INSERT ON keel_meta.context_retention_policies TO keel_context_policy;
GRANT SELECT ON keel_meta.context_retention_policy_heads TO keel_context_policy;
GRANT INSERT ON keel_meta.context_retention_policy_heads TO keel_context_policy;
GRANT UPDATE (policy_version) ON keel_meta.context_retention_policy_heads TO keel_context_policy;
GRANT SELECT ON keel_meta.context_retention_policies,keel_meta.context_retention_policy_heads TO keel_context_vault;
GRANT USAGE ON SCHEMA keel_private TO keel_context_policy;
GRANT EXECUTE ON FUNCTION keel_private.current_tenant_id() TO keel_context_policy;

CREATE FUNCTION keel_meta.guard_context_retention_policy()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    IF TG_OP<>'INSERT' THEN
        RAISE EXCEPTION 'context retention policy snapshots are immutable';
    END IF;
    NEW.created_at := clock_timestamp();
    RETURN NEW;
END $$;
CREATE TRIGGER context_retention_policy_immutable
    BEFORE INSERT OR UPDATE OR DELETE ON keel_meta.context_retention_policies
    FOR EACH ROW EXECUTE FUNCTION keel_meta.guard_context_retention_policy();
REVOKE ALL ON FUNCTION keel_meta.guard_context_retention_policy() FROM PUBLIC;

CREATE FUNCTION keel_meta.guard_context_retention_policy_head()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,keel_meta AS $$
BEGIN
    IF TG_OP='DELETE' OR (TG_OP='UPDATE' AND
       (NEW.tenant_id<>OLD.tenant_id OR NEW.purpose<>OLD.purpose OR NEW.policy_version<=OLD.policy_version)) THEN
        RAISE EXCEPTION 'context retention policy head must advance monotonically';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM keel_meta.context_retention_policies p
        WHERE p.tenant_id=NEW.tenant_id AND p.purpose=NEW.purpose AND p.policy_version=NEW.policy_version) THEN
        RAISE EXCEPTION 'context retention policy head requires an immutable snapshot';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER context_retention_policy_head_guard
    BEFORE INSERT OR UPDATE OR DELETE ON keel_meta.context_retention_policy_heads
    FOR EACH ROW EXECUTE FUNCTION keel_meta.guard_context_retention_policy_head();
REVOKE ALL ON FUNCTION keel_meta.guard_context_retention_policy_head() FROM PUBLIC;

ALTER TABLE keel_meta.context_vault_records
    ADD COLUMN purpose text CHECK (purpose IS NULL OR purpose IN ('read_only_replay','incident_review')),
    ADD COLUMN retention_policy_version bigint CHECK (retention_policy_version IS NULL OR retention_policy_version>0),
    ADD COLUMN consent_id uuid CHECK (consent_id IS NULL OR consent_id<>'00000000-0000-0000-0000-000000000000'::uuid),
    ADD CONSTRAINT context_vault_retention_snapshot_fk
        FOREIGN KEY (tenant_id,purpose,retention_policy_version)
        REFERENCES keel_meta.context_retention_policies (tenant_id,purpose,policy_version),
    ADD CONSTRAINT context_vault_retention_snapshot_complete
        CHECK ((purpose IS NULL AND retention_policy_version IS NULL AND consent_id IS NULL) OR
               (purpose IS NOT NULL AND retention_policy_version IS NOT NULL AND consent_id IS NOT NULL));

CREATE OR REPLACE FUNCTION keel_meta.context_vault_set_database_time()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,keel_meta,keel_private,pg_temp AS $$
DECLARE
    active_version bigint;
    policy_enabled boolean;
    policy_seconds integer;
    policy_consent uuid;
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'keel_context_vault','MEMBER') OR
       NEW.tenant_id IS DISTINCT FROM keel_private.current_tenant_id() THEN
        RAISE EXCEPTION 'context retention policy is unavailable';
    END IF;
    NEW.created_at := clock_timestamp();
    SELECT h.policy_version,p.enabled,p.retention_seconds,p.consent_id
      INTO active_version,policy_enabled,policy_seconds,policy_consent
      FROM keel_meta.context_retention_policy_heads h
      JOIN keel_meta.context_retention_policies p
        ON p.tenant_id=h.tenant_id AND p.purpose=h.purpose AND p.policy_version=h.policy_version
     WHERE h.tenant_id=NEW.tenant_id AND h.purpose=NEW.purpose
     FOR SHARE OF h;
    IF NOT FOUND OR NOT policy_enabled OR active_version<>NEW.retention_policy_version THEN
        RAISE EXCEPTION 'context retention policy is unavailable';
    END IF;
    NEW.consent_id := policy_consent;
    NEW.expires_at := NEW.created_at + policy_seconds * interval '1 second';
    RETURN NEW;
END $$;

REVOKE INSERT (tenant_id,record_id,version,policy_digest,algorithm,key_id,wrapped_dek,nonce,ciphertext,expires_at)
    ON keel_meta.context_vault_records FROM keel_context_vault;
GRANT INSERT (tenant_id,record_id,version,policy_digest,purpose,retention_policy_version,algorithm,key_id,wrapped_dek,nonce,ciphertext)
    ON keel_meta.context_vault_records TO keel_context_vault;
