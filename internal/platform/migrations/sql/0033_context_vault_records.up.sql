CREATE TABLE keel_meta.context_vault_records (
    tenant_id uuid NOT NULL CHECK (tenant_id <> '00000000-0000-0000-0000-000000000000'::uuid),
    record_id uuid NOT NULL CHECK (record_id <> '00000000-0000-0000-0000-000000000000'::uuid),
    version bigint NOT NULL CHECK (version > 0),
    policy_digest text NOT NULL CHECK (policy_digest ~ '^sha256:[0-9a-f]{64}$'),
    algorithm text NOT NULL CHECK (algorithm = 'AES-256-GCM'),
    key_id text NOT NULL CHECK (key_id ~ '^[A-Za-z0-9._:/-]{1,128}$'),
    wrapped_dek bytea NOT NULL CHECK (octet_length(wrapped_dek) BETWEEN 1 AND 8192),
    nonce bytea NOT NULL CHECK (octet_length(nonce) = 12),
    ciphertext bytea NOT NULL CHECK (octet_length(ciphertext) BETWEEN 16 AND 1048592),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL CHECK (expires_at > created_at),
    PRIMARY KEY (tenant_id, record_id, version)
);

ALTER TABLE keel_meta.context_vault_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.context_vault_records FORCE ROW LEVEL SECURITY;
CREATE POLICY context_vault_records_tenant ON keel_meta.context_vault_records
    TO keel_context_vault
    USING (tenant_id = (SELECT keel_private.current_tenant_id()) AND expires_at > statement_timestamp())
    WITH CHECK (tenant_id = (SELECT keel_private.current_tenant_id()) AND expires_at > statement_timestamp());
CREATE POLICY context_vault_records_schema_owner ON keel_meta.context_vault_records
    TO keel_schema_owner USING (true) WITH CHECK (true);

REVOKE ALL ON keel_meta.context_vault_records FROM PUBLIC, keel_app, keel_context_owner, keel_budget_control,
	keel_rate_control, keel_rate_status, keel_ai_worker, keel_worker, keel_operator, keel_projector,
	keel_file_processor, keel_retrieval_indexer, keel_context_vault, keel_agent;
GRANT USAGE ON SCHEMA keel_meta TO keel_context_vault;
GRANT SELECT ON keel_meta.context_vault_records TO keel_context_vault;
GRANT INSERT (tenant_id, record_id, version, policy_digest, algorithm, key_id, wrapped_dek, nonce, ciphertext, expires_at)
    ON keel_meta.context_vault_records TO keel_context_vault;
GRANT USAGE ON SCHEMA keel_private TO keel_context_vault;
GRANT EXECUTE ON FUNCTION keel_private.current_tenant_id() TO keel_context_vault;

CREATE FUNCTION keel_meta.context_vault_set_database_time()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    NEW.created_at := clock_timestamp();
    IF NEW.expires_at <= NEW.created_at THEN
        RAISE EXCEPTION 'context vault expiry must be in the future';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER context_vault_database_time BEFORE INSERT ON keel_meta.context_vault_records
    FOR EACH ROW EXECUTE FUNCTION keel_meta.context_vault_set_database_time();
REVOKE ALL ON FUNCTION keel_meta.context_vault_set_database_time() FROM PUBLIC;

CREATE FUNCTION keel_meta.reject_context_vault_mutation()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    RAISE EXCEPTION 'context vault record versions are immutable';
END $$;
CREATE TRIGGER context_vault_immutable BEFORE UPDATE OR DELETE ON keel_meta.context_vault_records
    FOR EACH ROW EXECUTE FUNCTION keel_meta.reject_context_vault_mutation();
REVOKE ALL ON FUNCTION keel_meta.reject_context_vault_mutation() FROM PUBLIC;
