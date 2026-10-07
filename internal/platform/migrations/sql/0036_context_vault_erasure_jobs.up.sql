CREATE TABLE keel_meta.context_vault_erasure_jobs (
    tenant_id uuid NOT NULL CHECK (tenant_id<>'00000000-0000-0000-0000-000000000000'::uuid),
    record_id uuid NOT NULL CHECK (record_id<>'00000000-0000-0000-0000-000000000000'::uuid),
    version bigint NOT NULL CHECK (version>0),
    expires_at timestamptz NOT NULL,
    state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','leased','blocked','complete')),
    attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count BETWEEN 0 AND 12),
    failure_count integer NOT NULL DEFAULT 0 CHECK (failure_count BETWEEN 0 AND 12),
    available_at timestamptz NOT NULL,
    last_error_code text CHECK (last_error_code IS NULL OR last_error_code ~ '^[a-z0-9][a-z0-9_]{0,63}$'),
    lease_owner text CHECK (lease_owner IS NULL OR lease_owner ~ '^[a-z0-9][a-z0-9._:-]{1,63}$'),
    lease_epoch bigint NOT NULL DEFAULT 0 CHECK (lease_epoch>=0),
    lease_until timestamptz,
    blocked_at timestamptz,
    completed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id,record_id,version),
    CHECK ((lease_owner IS NULL)=(lease_until IS NULL)),
    CHECK (lease_owner IS NULL OR state='leased'),
    CHECK ((state='blocked')=(blocked_at IS NOT NULL)),
    CHECK ((state='complete')=(completed_at IS NOT NULL))
);

ALTER TABLE keel_meta.context_vault_erasure_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.context_vault_erasure_jobs FORCE ROW LEVEL SECURITY;
CREATE POLICY context_vault_erasure_jobs_worker ON keel_meta.context_vault_erasure_jobs
    TO keel_context_erasure_worker USING (tenant_id=(SELECT keel_private.current_tenant_id()))
    WITH CHECK (tenant_id=(SELECT keel_private.current_tenant_id()));
CREATE POLICY context_vault_erasure_jobs_schema_owner ON keel_meta.context_vault_erasure_jobs
    TO keel_schema_owner USING (true) WITH CHECK (true);
REVOKE ALL ON keel_meta.context_vault_erasure_jobs FROM PUBLIC,keel_app,keel_worker,keel_operator,
    keel_context_vault,keel_context_policy,keel_context_erasure,keel_context_erasure_worker,keel_agent;

CREATE INDEX context_vault_erasure_jobs_claim_idx
    ON keel_meta.context_vault_erasure_jobs (tenant_id,available_at,expires_at,record_id,version)
    WHERE state='pending';
CREATE INDEX context_vault_erasure_jobs_expired_lease_idx
    ON keel_meta.context_vault_erasure_jobs (tenant_id,lease_until,record_id,version)
    WHERE state='leased';

CREATE FUNCTION keel_meta.guard_context_vault_erasure_job()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,keel_meta,pg_temp AS $$
BEGIN
    IF TG_OP='INSERT' THEN
        IF NEW.state<>'pending' OR NEW.attempt_count<>0 OR NEW.failure_count<>0 OR NEW.last_error_code IS NOT NULL OR
           NEW.lease_owner IS NOT NULL OR NEW.lease_until IS NOT NULL OR NEW.lease_epoch<>0 OR
           NEW.blocked_at IS NOT NULL OR NEW.completed_at IS NOT NULL OR NEW.available_at<>NEW.expires_at THEN
            RAISE EXCEPTION 'context erasure jobs must begin pending at their database expiry';
        END IF;
        RETURN NEW;
    END IF;
    IF TG_OP='DELETE' OR NEW.tenant_id<>OLD.tenant_id OR NEW.record_id<>OLD.record_id OR NEW.version<>OLD.version OR
       NEW.expires_at<>OLD.expires_at OR NEW.created_at<>OLD.created_at OR NEW.updated_at<=OLD.updated_at OR
       NEW.attempt_count<OLD.attempt_count OR NEW.attempt_count>OLD.attempt_count+1 OR
       NEW.failure_count<OLD.failure_count OR NEW.failure_count>OLD.failure_count+1 OR
       NEW.lease_epoch<OLD.lease_epoch OR NEW.lease_epoch>OLD.lease_epoch+1 THEN
        RAISE EXCEPTION 'context erasure job identity and counters must advance monotonically';
    END IF;
    IF OLD.state='pending' AND NEW.state='leased' AND NEW.lease_owner IS NOT NULL AND
       NEW.lease_epoch=OLD.lease_epoch+1 AND NEW.attempt_count=OLD.attempt_count+1 AND
       NEW.failure_count=OLD.failure_count AND NEW.available_at=OLD.available_at AND
       NEW.lease_until>clock_timestamp() AND NEW.lease_until<=clock_timestamp()+interval '15 minutes'+interval '1 second' AND
       NEW.last_error_code IS NULL AND NEW.blocked_at IS NULL AND NEW.completed_at IS NULL AND
       OLD.available_at<=clock_timestamp() AND OLD.failure_count<12 THEN
        RETURN NEW;
    END IF;
    IF OLD.state='leased' AND OLD.lease_until<=clock_timestamp() AND NEW.state IN ('pending','blocked') AND
       NEW.lease_owner IS NULL AND NEW.lease_until IS NULL AND NEW.lease_epoch=OLD.lease_epoch AND
       NEW.attempt_count=OLD.attempt_count AND NEW.failure_count=OLD.failure_count+1 AND
       NEW.completed_at IS NULL AND NEW.last_error_code IS NOT NULL AND
       ((NEW.state='pending' AND NEW.failure_count<12 AND NEW.blocked_at IS NULL AND NEW.available_at>=OLD.lease_until) OR
        (NEW.state='blocked' AND NEW.failure_count=12 AND NEW.blocked_at IS NOT NULL AND
         NEW.last_error_code='attempts_exhausted' AND NEW.available_at=OLD.available_at)) THEN
        RETURN NEW;
    END IF;
    IF OLD.state='leased' AND NEW.state='pending' AND OLD.lease_owner IS NOT NULL AND OLD.lease_until>clock_timestamp() AND
       NEW.lease_owner IS NULL AND NEW.lease_until IS NULL AND NEW.lease_epoch=OLD.lease_epoch AND
       NEW.attempt_count=OLD.attempt_count AND NEW.failure_count=OLD.failure_count+1 AND
       NEW.available_at>clock_timestamp() AND NEW.available_at<=clock_timestamp()+interval '24 hours'+interval '1 second' AND
       NEW.last_error_code IS NOT NULL AND NEW.blocked_at IS NULL AND NEW.completed_at IS NULL THEN
        RETURN NEW;
    END IF;
    IF OLD.state='leased' AND NEW.state='blocked' AND OLD.lease_owner IS NOT NULL AND OLD.lease_until>clock_timestamp() AND
       NEW.lease_owner IS NULL AND NEW.lease_until IS NULL AND NEW.lease_epoch=OLD.lease_epoch AND
       NEW.attempt_count=OLD.attempt_count AND NEW.failure_count=OLD.failure_count+1 AND
       NEW.available_at=OLD.available_at AND NEW.last_error_code='attempts_exhausted' AND
       NEW.blocked_at IS NOT NULL AND NEW.completed_at IS NULL THEN
        RETURN NEW;
    END IF;
    IF OLD.state='leased' AND NEW.state='complete' AND OLD.lease_owner IS NOT NULL AND OLD.lease_until>clock_timestamp() AND
       NEW.lease_owner IS NULL AND NEW.lease_until IS NULL AND NEW.lease_epoch=OLD.lease_epoch AND
       NEW.attempt_count=OLD.attempt_count AND NEW.failure_count=OLD.failure_count AND
       NEW.available_at=OLD.available_at AND NEW.last_error_code IS NULL AND
       NEW.blocked_at IS NULL AND NEW.completed_at IS NOT NULL THEN
        RETURN NEW;
    END IF;
    IF OLD.state='pending' AND NEW.state='complete' AND NEW.lease_owner IS NULL AND NEW.lease_until IS NULL AND
       NEW.lease_epoch=OLD.lease_epoch AND NEW.attempt_count=OLD.attempt_count AND NEW.failure_count=OLD.failure_count AND
       NEW.available_at=OLD.available_at AND NEW.last_error_code IS NULL AND NEW.blocked_at IS NULL AND NEW.completed_at IS NOT NULL THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'invalid context erasure job transition: % -> %',OLD.state,NEW.state;
END $$;
CREATE TRIGGER context_vault_erasure_job_guard BEFORE INSERT OR UPDATE OR DELETE
    ON keel_meta.context_vault_erasure_jobs FOR EACH ROW EXECUTE FUNCTION keel_meta.guard_context_vault_erasure_job();
REVOKE ALL ON FUNCTION keel_meta.guard_context_vault_erasure_job() FROM PUBLIC;

CREATE FUNCTION keel_meta.schedule_context_vault_erasure_job()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,keel_meta,keel_private,pg_temp AS $$
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'keel_context_vault','MEMBER') OR
       NEW.tenant_id IS DISTINCT FROM keel_private.current_tenant_id() THEN
        RAISE EXCEPTION 'context erasure schedule is unavailable';
    END IF;
    INSERT INTO keel_meta.context_vault_erasure_jobs(tenant_id,record_id,version,expires_at,available_at)
    VALUES (NEW.tenant_id,NEW.record_id,NEW.version,NEW.expires_at,NEW.expires_at)
    ON CONFLICT (tenant_id,record_id,version) DO NOTHING;
    RETURN NEW;
END $$;
CREATE TRIGGER context_vault_erasure_schedule AFTER INSERT ON keel_meta.context_vault_records
    FOR EACH ROW EXECUTE FUNCTION keel_meta.schedule_context_vault_erasure_job();
REVOKE ALL ON FUNCTION keel_meta.schedule_context_vault_erasure_job() FROM PUBLIC;

INSERT INTO keel_meta.context_vault_erasure_jobs(tenant_id,record_id,version,expires_at,available_at)
SELECT tenant_id,record_id,version,expires_at,expires_at FROM keel_meta.context_vault_records
ON CONFLICT (tenant_id,record_id,version) DO NOTHING;

CREATE FUNCTION keel_meta.claim_context_vault_erasure_job(p_worker_id text,p_lease_milliseconds integer)
RETURNS TABLE(tenant_id uuid,record_id uuid,version bigint,expires_at timestamptz,lease_epoch bigint,attempt_count integer,failure_count integer)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,keel_meta,keel_private,pg_temp AS $$
DECLARE authorized_tenant uuid;
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'keel_context_erasure_worker','MEMBER') THEN
        RAISE EXCEPTION 'context erasure worker capability is required';
    END IF;
    authorized_tenant := keel_private.current_tenant_id();
    IF authorized_tenant IS NULL OR p_worker_id IS NULL OR p_worker_id !~ '^[a-z0-9][a-z0-9._:-]{1,63}$' OR
       p_lease_milliseconds IS NULL OR p_lease_milliseconds<1000 OR p_lease_milliseconds>900000 THEN
        RAISE EXCEPTION 'context erasure claim scope or lease is invalid';
    END IF;

    WITH expired AS (
        SELECT j.tenant_id,j.record_id,j.version FROM keel_meta.context_vault_erasure_jobs j
         WHERE j.tenant_id=authorized_tenant AND j.state='leased' AND j.lease_until<=clock_timestamp()
         ORDER BY j.lease_until,j.record_id,j.version LIMIT 100 FOR UPDATE SKIP LOCKED
    )
    UPDATE keel_meta.context_vault_erasure_jobs j SET
        failure_count=j.failure_count+1,
        state=CASE WHEN j.failure_count+1>=12 THEN 'blocked' ELSE 'pending' END,
        available_at=CASE WHEN j.failure_count+1>=12 THEN j.available_at ELSE clock_timestamp() END,
        last_error_code=CASE WHEN j.failure_count+1>=12 THEN 'attempts_exhausted' ELSE 'worker_lease_expired' END,
        blocked_at=CASE WHEN j.failure_count+1>=12 THEN clock_timestamp() ELSE NULL END,
        lease_owner=NULL,lease_until=NULL,updated_at=clock_timestamp()
    FROM expired e WHERE j.tenant_id=e.tenant_id AND j.record_id=e.record_id AND j.version=e.version;

    RETURN QUERY WITH candidate AS (
        SELECT j.tenant_id,j.record_id,j.version FROM keel_meta.context_vault_erasure_jobs j
         WHERE j.tenant_id=authorized_tenant AND j.state='pending' AND j.available_at<=clock_timestamp() AND j.failure_count<12
         ORDER BY j.available_at,j.expires_at,j.record_id,j.version LIMIT 1 FOR UPDATE SKIP LOCKED
    )
    UPDATE keel_meta.context_vault_erasure_jobs j SET state='leased',attempt_count=j.attempt_count+1,
        lease_epoch=j.lease_epoch+1,lease_owner=p_worker_id,
        lease_until=clock_timestamp()+p_lease_milliseconds*interval '1 millisecond',last_error_code=NULL,updated_at=clock_timestamp()
    FROM candidate c WHERE j.tenant_id=c.tenant_id AND j.record_id=c.record_id AND j.version=c.version
    RETURNING j.tenant_id,j.record_id,j.version,j.expires_at,j.lease_epoch,j.attempt_count,j.failure_count;
END $$;
REVOKE ALL ON FUNCTION keel_meta.claim_context_vault_erasure_job(text,integer) FROM PUBLIC;

CREATE FUNCTION keel_meta.process_context_vault_erasure_job(
    p_record_id uuid,p_version bigint,p_worker_id text,p_lease_epoch bigint)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,keel_meta,keel_private,pg_temp AS $$
DECLARE
    authorized_tenant uuid;
    job_row keel_meta.context_vault_erasure_jobs%ROWTYPE;
    record_row keel_meta.context_vault_records%ROWTYPE;
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'keel_context_erasure_worker','MEMBER') THEN
        RAISE EXCEPTION 'context erasure worker capability is required';
    END IF;
    authorized_tenant := keel_private.current_tenant_id();
    IF authorized_tenant IS NULL OR p_record_id IS NULL OR p_version IS NULL OR p_version<1 OR
       p_worker_id IS NULL OR p_worker_id !~ '^[a-z0-9][a-z0-9._:-]{1,63}$' OR p_lease_epoch IS NULL OR p_lease_epoch<1 THEN
        RAISE EXCEPTION 'context erasure job identity is invalid';
    END IF;
    SELECT * INTO job_row FROM keel_meta.context_vault_erasure_jobs j
     WHERE j.tenant_id=authorized_tenant AND j.record_id=p_record_id AND j.version=p_version
       AND j.state='leased' AND j.lease_owner=p_worker_id AND j.lease_epoch=p_lease_epoch
       AND j.lease_until>clock_timestamp()
     FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'context erasure lease is no longer current';
    END IF;

    SELECT * INTO record_row FROM keel_meta.context_vault_records r
     WHERE r.tenant_id=authorized_tenant AND r.record_id=p_record_id AND r.version=p_version
       AND r.expires_at<=statement_timestamp()
     FOR UPDATE SKIP LOCKED;
    IF NOT FOUND THEN
        IF EXISTS (SELECT 1 FROM keel_meta.context_vault_erasure_receipts r
            WHERE r.tenant_id=authorized_tenant AND r.record_id=p_record_id AND r.version=p_version) THEN
            UPDATE keel_meta.context_vault_erasure_jobs SET state='complete',lease_owner=NULL,lease_until=NULL,
                last_error_code=NULL,completed_at=clock_timestamp(),updated_at=clock_timestamp()
             WHERE tenant_id=authorized_tenant AND record_id=p_record_id AND version=p_version;
            RETURN false;
        END IF;
        RAISE EXCEPTION 'expired context record is unavailable for erasure';
    END IF;

    INSERT INTO keel_meta.context_vault_erasure_receipts
        (tenant_id,record_id,version,purpose,retention_policy_version,consent_id,expires_at,envelope_sha256)
    VALUES (record_row.tenant_id,record_row.record_id,record_row.version,record_row.purpose,
        record_row.retention_policy_version,record_row.consent_id,record_row.expires_at,
        keel_meta.context_vault_envelope_sha256(record_row.tenant_id,record_row.record_id,
            record_row.version,record_row.policy_digest,record_row.algorithm,record_row.key_id,
            record_row.wrapped_dek,record_row.nonce,record_row.ciphertext));
    DELETE FROM keel_meta.context_vault_records
     WHERE tenant_id=authorized_tenant AND record_id=p_record_id AND version=p_version;
    UPDATE keel_meta.context_vault_erasure_jobs SET state='complete',lease_owner=NULL,lease_until=NULL,
        last_error_code=NULL,completed_at=clock_timestamp(),updated_at=clock_timestamp()
     WHERE tenant_id=authorized_tenant AND record_id=p_record_id AND version=p_version;
    RETURN true;
END $$;
REVOKE ALL ON FUNCTION keel_meta.process_context_vault_erasure_job(uuid,bigint,text,bigint) FROM PUBLIC;

CREATE FUNCTION keel_meta.retry_context_vault_erasure_job(
    p_record_id uuid,p_version bigint,p_worker_id text,p_lease_epoch bigint,p_error_code text,p_backoff_milliseconds integer)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,keel_meta,keel_private,pg_temp AS $$
DECLARE authorized_tenant uuid; next_failures integer; next_state text;
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'keel_context_erasure_worker','MEMBER') THEN
        RAISE EXCEPTION 'context erasure worker capability is required';
    END IF;
    authorized_tenant := keel_private.current_tenant_id();
    IF authorized_tenant IS NULL OR p_record_id IS NULL OR p_version IS NULL OR p_version<1 OR
       p_worker_id IS NULL OR p_worker_id !~ '^[a-z0-9][a-z0-9._:-]{1,63}$' OR p_lease_epoch IS NULL OR p_lease_epoch<1 OR
       p_error_code IS NULL OR p_error_code !~ '^[a-z0-9][a-z0-9_]{0,63}$' OR p_error_code='attempts_exhausted' OR
       p_backoff_milliseconds IS NULL OR p_backoff_milliseconds<1000 OR p_backoff_milliseconds>86400000 THEN
        RAISE EXCEPTION 'context erasure retry metadata is invalid';
    END IF;
    UPDATE keel_meta.context_vault_erasure_jobs SET
        failure_count=failure_count+1,
        state=CASE WHEN failure_count+1>=12 THEN 'blocked' ELSE 'pending' END,
        available_at=CASE WHEN failure_count+1>=12 THEN available_at ELSE clock_timestamp()+p_backoff_milliseconds*interval '1 millisecond' END,
        last_error_code=CASE WHEN failure_count+1>=12 THEN 'attempts_exhausted' ELSE p_error_code END,
        blocked_at=CASE WHEN failure_count+1>=12 THEN clock_timestamp() ELSE NULL END,
        lease_owner=NULL,lease_until=NULL,updated_at=clock_timestamp()
     WHERE tenant_id=authorized_tenant AND record_id=p_record_id AND version=p_version AND state='leased'
       AND lease_owner=p_worker_id AND lease_epoch=p_lease_epoch AND lease_until>clock_timestamp()
     RETURNING failure_count,state INTO next_failures,next_state;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'context erasure lease is no longer current';
    END IF;
    RETURN next_state;
END $$;
REVOKE ALL ON FUNCTION keel_meta.retry_context_vault_erasure_job(uuid,bigint,text,bigint,text,integer) FROM PUBLIC;

GRANT USAGE ON SCHEMA keel_meta,keel_private TO keel_context_erasure_worker;
GRANT EXECUTE ON FUNCTION keel_private.current_tenant_id() TO keel_context_erasure_worker;
GRANT EXECUTE ON FUNCTION keel_meta.claim_context_vault_erasure_job(text,integer) TO keel_context_erasure_worker;
GRANT EXECUTE ON FUNCTION keel_meta.process_context_vault_erasure_job(uuid,bigint,text,bigint) TO keel_context_erasure_worker;
GRANT EXECUTE ON FUNCTION keel_meta.retry_context_vault_erasure_job(uuid,bigint,text,bigint,text,integer) TO keel_context_erasure_worker;

CREATE OR REPLACE FUNCTION keel_meta.guard_context_vault_mutation()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,keel_meta AS $$
DECLARE expected_digest text;
BEGIN
    IF TG_OP='UPDATE' THEN
        RAISE EXCEPTION 'context vault record versions are immutable';
    END IF;
    IF TG_OP='DELETE' AND current_user='keel_schema_owner' AND
       (pg_catalog.pg_has_role(session_user,'keel_context_erasure','MEMBER') OR
        pg_catalog.pg_has_role(session_user,'keel_context_erasure_worker','MEMBER')) THEN
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
