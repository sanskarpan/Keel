-- K8.11 slice 6: WebAuthn direct credential store for verified ceremonies.
-- The ceremony handler consumes the challenge first (single-use before
-- cryptography runs), verifies attestation with the go-webauthn library, then
-- stores the key through this function. Splitting store from consume keeps a
-- crashed ceremony from stranding a half-registered key while the consumed
-- challenge still blocks replay of the same response. The credentials guard
-- is relaxed for inserts only: a ceremony may present a nonzero opening
-- counter, so inserts require only an unset last_used_at; updates still
-- advance monotonically and deletes stay refused.

CREATE OR REPLACE FUNCTION keel_meta.guard_identity_webauthn_credentials_row()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    IF TG_OP='DELETE' THEN
        RAISE EXCEPTION 'identity credentials have no delete path in this slice';
    END IF;
    IF current_user<>'keel_schema_owner' OR
       NOT pg_catalog.pg_has_role(session_user,'keel_identity','MEMBER') THEN
        RAISE EXCEPTION 'identity credentials are capability-managed';
    END IF;
    IF TG_OP='INSERT' THEN
        IF NEW.last_used_at IS NOT NULL THEN
            RAISE EXCEPTION 'identity credentials start unused';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.credential_id<>OLD.credential_id OR NEW.principal_id<>OLD.principal_id OR
       NEW.public_key<>OLD.public_key OR NEW.transports<>OLD.transports OR
       NEW.backup_eligible<>OLD.backup_eligible OR NEW.backup_state<>OLD.backup_state OR
       NEW.created_at<>OLD.created_at THEN
        RAISE EXCEPTION 'identity credential identity is immutable';
    END IF;
    IF NEW.sign_count<OLD.sign_count OR
       (NEW.sign_count=OLD.sign_count AND OLD.sign_count<>0) THEN
        RAISE EXCEPTION 'identity sign counts advance monotonically';
    END IF;
    RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION keel_meta.guard_identity_webauthn_credentials_row() FROM PUBLIC;

CREATE FUNCTION keel_meta.store_identity_webauthn_credential(
    p_principal_id uuid,p_credential_id bytea,p_public_key bytea,p_transports text,
    p_backup_eligible boolean,p_backup_state boolean,p_sign_count bigint)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,keel_meta,pg_temp AS $$
DECLARE current_state text;
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'keel_identity','MEMBER') THEN
        RAISE EXCEPTION 'identity capability is required';
    END IF;
    IF p_principal_id IS NULL OR p_principal_id='00000000-0000-0000-0000-000000000000'::uuid OR
       p_credential_id IS NULL OR octet_length(p_credential_id) NOT BETWEEN 1 AND 1024 OR
       p_public_key IS NULL OR octet_length(p_public_key) NOT BETWEEN 1 AND 2048 OR
       p_transports IS NULL OR length(p_transports)>128 OR
       p_backup_eligible IS NULL OR p_backup_state IS NULL OR
       p_sign_count IS NULL OR p_sign_count<0 THEN
        RAISE EXCEPTION 'identity credential store is invalid';
    END IF;
    SELECT state INTO current_state FROM keel_meta.identity_principals
      WHERE principal_id=p_principal_id FOR UPDATE;
    IF current_state IS NULL OR current_state<>'active' THEN
        RETURN 'principal_inactive';
    END IF;
    IF EXISTS (SELECT 1 FROM keel_meta.identity_webauthn_credentials k
                 WHERE k.credential_id=p_credential_id) THEN
        RETURN 'credential_reuse';
    END IF;
    INSERT INTO keel_meta.identity_webauthn_credentials
        (credential_id,principal_id,public_key,sign_count,transports,backup_eligible,backup_state,created_at)
        VALUES (p_credential_id,p_principal_id,p_public_key,p_sign_count,p_transports,
                p_backup_eligible,p_backup_state,clock_timestamp());
    RETURN 'stored';
END $$;
REVOKE ALL ON FUNCTION keel_meta.store_identity_webauthn_credential(uuid,bytea,bytea,text,boolean,boolean,bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION keel_meta.store_identity_webauthn_credential(uuid,bytea,bytea,text,boolean,boolean,bigint) TO keel_identity;
