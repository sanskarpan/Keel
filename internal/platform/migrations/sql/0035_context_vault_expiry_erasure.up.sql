CREATE TABLE keel_meta.context_vault_erasure_receipts (
    tenant_id uuid NOT NULL,
    record_id uuid NOT NULL,
    version bigint NOT NULL CHECK (version>0),
    purpose text NOT NULL CHECK (purpose IN ('read_only_replay','incident_review')),
    retention_policy_version bigint NOT NULL CHECK (retention_policy_version>0),
    consent_id uuid NOT NULL CHECK (consent_id<>'00000000-0000-0000-0000-000000000000'::uuid),
    expires_at timestamptz NOT NULL,
    deleted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    envelope_sha256 text NOT NULL CHECK (envelope_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    PRIMARY KEY (tenant_id,record_id,version),
    FOREIGN KEY (tenant_id,purpose,retention_policy_version)
        REFERENCES keel_meta.context_retention_policies (tenant_id,purpose,policy_version)
);

ALTER TABLE keel_meta.context_vault_erasure_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.context_vault_erasure_receipts FORCE ROW LEVEL SECURITY;
CREATE POLICY context_vault_erasure_receipts_schema_owner ON keel_meta.context_vault_erasure_receipts
    TO keel_schema_owner USING (true) WITH CHECK (true);
REVOKE ALL ON keel_meta.context_vault_erasure_receipts FROM PUBLIC,keel_app,keel_worker,keel_operator,
    keel_context_vault,keel_context_policy,keel_context_erasure,keel_agent;
REVOKE ALL ON keel_meta.context_vault_records FROM keel_context_erasure;

CREATE FUNCTION keel_meta.context_vault_envelope_sha256(
    p_tenant_id uuid,p_record_id uuid,p_version bigint,p_policy_digest text,
    p_algorithm text,p_key_id text,p_wrapped_dek bytea,p_nonce bytea,p_ciphertext bytea)
RETURNS text LANGUAGE sql IMMUTABLE STRICT SET search_path=pg_catalog AS $$
    SELECT 'sha256:' || pg_catalog.encode(pg_catalog.sha256(
        pg_catalog.convert_to(p_tenant_id::text || '/' || p_record_id::text || '/' || p_version::text || '/' ||
            p_policy_digest || '/' || p_algorithm || '/' || p_key_id || '/', 'UTF8') ||
        p_wrapped_dek || p_nonce || p_ciphertext), 'hex')
$$;
REVOKE ALL ON FUNCTION keel_meta.context_vault_envelope_sha256(uuid,uuid,bigint,text,text,text,bytea,bytea,bytea) FROM PUBLIC;

CREATE FUNCTION keel_meta.guard_context_vault_mutation()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,keel_meta AS $$
DECLARE expected_digest text;
BEGIN
    IF TG_OP='UPDATE' THEN
        RAISE EXCEPTION 'context vault record versions are immutable';
    END IF;
    IF TG_OP='DELETE' AND current_user='keel_schema_owner' AND
       pg_catalog.pg_has_role(session_user,'keel_context_erasure','MEMBER') THEN
        expected_digest := keel_meta.context_vault_envelope_sha256(
            OLD.tenant_id,OLD.record_id,OLD.version,OLD.policy_digest,OLD.algorithm,OLD.key_id,
            OLD.wrapped_dek,OLD.nonce,OLD.ciphertext);
        IF EXISTS (SELECT 1 FROM keel_meta.context_vault_erasure_receipts receipt
            WHERE receipt.tenant_id=OLD.tenant_id AND receipt.record_id=OLD.record_id AND
                  receipt.version=OLD.version AND receipt.purpose=OLD.purpose AND
                  receipt.retention_policy_version=OLD.retention_policy_version AND
                  receipt.consent_id=OLD.consent_id AND receipt.expires_at=OLD.expires_at AND
                  receipt.envelope_sha256=expected_digest) THEN
            RETURN OLD;
        END IF;
    END IF;
    RAISE EXCEPTION 'context vault record versions are immutable';
END $$;
CREATE OR REPLACE TRIGGER context_vault_immutable
    BEFORE UPDATE OR DELETE ON keel_meta.context_vault_records
    FOR EACH ROW EXECUTE FUNCTION keel_meta.guard_context_vault_mutation();
REVOKE ALL ON FUNCTION keel_meta.guard_context_vault_mutation() FROM PUBLIC;

CREATE FUNCTION keel_meta.guard_context_vault_erasure_receipt()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    RAISE EXCEPTION 'context vault erasure receipts are immutable';
END $$;
CREATE TRIGGER context_vault_erasure_receipt_immutable
    BEFORE UPDATE OR DELETE ON keel_meta.context_vault_erasure_receipts
    FOR EACH ROW EXECUTE FUNCTION keel_meta.guard_context_vault_erasure_receipt();
REVOKE ALL ON FUNCTION keel_meta.guard_context_vault_erasure_receipt() FROM PUBLIC;

CREATE FUNCTION keel_meta.erase_expired_context_vault(p_batch_size integer)
RETURNS integer LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,keel_meta,keel_private,pg_temp AS $$
DECLARE
    authorized_tenant uuid;
    record_row keel_meta.context_vault_records%ROWTYPE;
    deleted_count integer := 0;
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'keel_context_erasure','MEMBER') THEN
        RAISE EXCEPTION 'context erasure capability is required';
    END IF;
    authorized_tenant := keel_private.current_tenant_id();
    IF authorized_tenant IS NULL THEN
        RAISE EXCEPTION 'context erasure tenant scope is required';
    END IF;
    IF p_batch_size IS NULL OR p_batch_size<1 OR p_batch_size>100 THEN
        RAISE EXCEPTION 'context erasure batch size is outside the supported bound';
    END IF;

    FOR record_row IN
        SELECT * FROM keel_meta.context_vault_records
         WHERE tenant_id=authorized_tenant AND expires_at<=statement_timestamp()
         ORDER BY expires_at,record_id,version
         LIMIT p_batch_size
         FOR UPDATE SKIP LOCKED
    LOOP
        INSERT INTO keel_meta.context_vault_erasure_receipts
            (tenant_id,record_id,version,purpose,retention_policy_version,consent_id,expires_at,envelope_sha256)
        VALUES (record_row.tenant_id,record_row.record_id,record_row.version,record_row.purpose,
            record_row.retention_policy_version,record_row.consent_id,record_row.expires_at,
            keel_meta.context_vault_envelope_sha256(record_row.tenant_id,record_row.record_id,
                record_row.version,record_row.policy_digest,record_row.algorithm,record_row.key_id,
                record_row.wrapped_dek,record_row.nonce,record_row.ciphertext));
        DELETE FROM keel_meta.context_vault_records
         WHERE tenant_id=record_row.tenant_id AND record_id=record_row.record_id AND version=record_row.version;
        deleted_count := deleted_count+1;
    END LOOP;
    RETURN deleted_count;
END $$;
REVOKE ALL ON FUNCTION keel_meta.erase_expired_context_vault(integer) FROM PUBLIC;
GRANT USAGE ON SCHEMA keel_meta TO keel_context_erasure;
GRANT USAGE ON SCHEMA keel_private TO keel_context_erasure;
GRANT EXECUTE ON FUNCTION keel_private.current_tenant_id() TO keel_context_erasure;
GRANT EXECUTE ON FUNCTION keel_meta.erase_expired_context_vault(integer) TO keel_context_erasure;
