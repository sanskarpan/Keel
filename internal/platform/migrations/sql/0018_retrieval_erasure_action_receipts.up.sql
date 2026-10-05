-- K3.5: immutable cleanup plans and lease-fenced action receipts.
-- Every durable erasure request gets the same conservative minimum manifest.
-- A deployment may explicitly attest an action as not applicable; silently
-- omitting an action can never make a job complete.
CREATE TABLE keel_meta.retrieval_erasure_action_manifest (
    tenant_id uuid NOT NULL,
    visibility_key text NOT NULL,
    job_id uuid NOT NULL,
    action_key text NOT NULL CHECK (action_key IN (
        'legal_hold_check','supplier_source_objects','derived_index',
        'cache_revocation','queued_work_revocation','backup_expiry'
    )),
    required boolean NOT NULL DEFAULT true CHECK (required),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id,visibility_key,job_id,action_key),
    FOREIGN KEY (tenant_id,visibility_key,job_id)
        REFERENCES keel_meta.retrieval_erasure_jobs (tenant_id,visibility_key,job_id)
);

CREATE OR REPLACE FUNCTION keel_meta.seed_retrieval_erasure_action_manifest()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,keel_meta,pg_temp AS $$
BEGIN
    INSERT INTO keel_meta.retrieval_erasure_action_manifest
        (tenant_id,visibility_key,job_id,action_key)
    VALUES
        (NEW.tenant_id,NEW.visibility_key,NEW.job_id,'legal_hold_check'),
        (NEW.tenant_id,NEW.visibility_key,NEW.job_id,'supplier_source_objects'),
        (NEW.tenant_id,NEW.visibility_key,NEW.job_id,'derived_index'),
        (NEW.tenant_id,NEW.visibility_key,NEW.job_id,'cache_revocation'),
        (NEW.tenant_id,NEW.visibility_key,NEW.job_id,'queued_work_revocation'),
        (NEW.tenant_id,NEW.visibility_key,NEW.job_id,'backup_expiry');
    RETURN NEW;
END $$;
CREATE TRIGGER retrieval_erasure_action_manifest_seed
    AFTER INSERT ON keel_meta.retrieval_erasure_jobs
    FOR EACH ROW EXECUTE FUNCTION keel_meta.seed_retrieval_erasure_action_manifest();

CREATE OR REPLACE FUNCTION keel_meta.reject_retrieval_erasure_manifest_mutation()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,keel_meta,pg_temp AS $$
BEGIN
    RAISE EXCEPTION 'retrieval erasure action manifests are immutable';
END $$;
CREATE TRIGGER retrieval_erasure_action_manifest_immutable
    BEFORE UPDATE OR DELETE ON keel_meta.retrieval_erasure_action_manifest
    FOR EACH ROW EXECUTE FUNCTION keel_meta.reject_retrieval_erasure_manifest_mutation();

-- Backfill any jobs created before this migration. Existing jobs remain
-- incomplete until each action has a receipt or a reviewed not-applicable one.
INSERT INTO keel_meta.retrieval_erasure_action_manifest
    (tenant_id,visibility_key,job_id,action_key)
SELECT j.tenant_id,j.visibility_key,j.job_id,a.action_key
FROM keel_meta.retrieval_erasure_jobs j
CROSS JOIN (VALUES ('legal_hold_check'),('supplier_source_objects'),('derived_index'),
                   ('cache_revocation'),('queued_work_revocation'),('backup_expiry')) AS a(action_key)
ON CONFLICT DO NOTHING;

CREATE TABLE keel_meta.retrieval_erasure_action_receipts (
    tenant_id uuid NOT NULL,
    visibility_key text NOT NULL,
    job_id uuid NOT NULL,
    action_key text NOT NULL,
    lease_owner text NOT NULL CHECK (lease_owner ~ '^[a-z0-9][a-z0-9._:-]{1,63}$'),
    lease_epoch bigint NOT NULL CHECK (lease_epoch > 0),
    disposition text NOT NULL CHECK (disposition IN ('complete','not_applicable')),
    decision_actor_id uuid NOT NULL,
    decision_reason text,
    receipt_sha256 bytea NOT NULL CHECK (octet_length(receipt_sha256)=32),
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id,visibility_key,job_id,action_key),
    FOREIGN KEY (tenant_id,visibility_key,job_id,action_key)
        REFERENCES keel_meta.retrieval_erasure_action_manifest (tenant_id,visibility_key,job_id,action_key),
    CHECK ((disposition='complete' AND decision_reason IS NULL) OR
           (disposition='not_applicable' AND length(btrim(decision_reason)) BETWEEN 1 AND 512)),
    CHECK (action_key<>'legal_hold_check' OR disposition='complete')
);

CREATE OR REPLACE FUNCTION keel_meta.guard_retrieval_erasure_action_receipt()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,keel_meta,pg_temp AS $$
BEGIN
    IF TG_OP<>'INSERT' THEN
        RAISE EXCEPTION 'retrieval erasure action receipts are append-only';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM keel_meta.retrieval_erasure_jobs j
        WHERE j.tenant_id=NEW.tenant_id AND j.visibility_key=NEW.visibility_key AND j.job_id=NEW.job_id
          AND j.state='cleanup_pending' AND j.lease_epoch=NEW.lease_epoch
          AND j.lease_owner=NEW.lease_owner AND j.lease_until>clock_timestamp()
    ) THEN
        RAISE EXCEPTION 'erasure receipt requires the current live job lease';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER retrieval_erasure_action_receipt_guard
    BEFORE INSERT OR UPDATE OR DELETE ON keel_meta.retrieval_erasure_action_receipts
    FOR EACH ROW EXECUTE FUNCTION keel_meta.guard_retrieval_erasure_action_receipt();

CREATE OR REPLACE FUNCTION keel_meta.guard_retrieval_erasure_job()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,keel_meta,pg_temp AS $$
DECLARE eligibility_state text; eligibility_generation bigint;
BEGIN
    IF TG_OP='INSERT' THEN
        IF NEW.state<>'fenced' OR NEW.attempt_count<>0 OR NEW.last_error_code IS NOT NULL OR
           NEW.lease_owner IS NOT NULL OR NEW.lease_until IS NOT NULL OR NEW.lease_epoch<>0 OR
           NEW.blocked_at IS NOT NULL OR NEW.completed_at IS NOT NULL THEN
            RAISE EXCEPTION 'erasure jobs must begin fenced and unleased';
        END IF;
        IF NOT EXISTS (SELECT 1 FROM keel_meta.retrieval_source_eligibility e
            WHERE e.tenant_id=NEW.tenant_id AND e.visibility_key=NEW.visibility_key
              AND e.document_version_id=NEW.document_version_id AND e.state='withdrawn'
              AND e.generation=NEW.eligibility_generation) THEN
            RAISE EXCEPTION 'erasure job requires a matching durable withdrawal fence';
        END IF;
        RETURN NEW;
    END IF;
    IF TG_OP='DELETE' OR NEW.tenant_id<>OLD.tenant_id OR NEW.visibility_key<>OLD.visibility_key OR
       NEW.job_id<>OLD.job_id OR NEW.requested_by<>OLD.requested_by OR NEW.document_version_id<>OLD.document_version_id OR
       NEW.eligibility_generation<>OLD.eligibility_generation OR NEW.requested_at<>OLD.requested_at OR
       NEW.updated_at<=OLD.updated_at OR NEW.attempt_count<OLD.attempt_count OR
       NEW.attempt_count>OLD.attempt_count+1 OR NEW.lease_epoch<OLD.lease_epoch OR NEW.lease_epoch>OLD.lease_epoch+1 OR
       NEW.available_at<OLD.available_at THEN
        RAISE EXCEPTION 'erasure job identity and retry metadata must advance monotonically';
    END IF;
    SELECT state,generation INTO eligibility_state,eligibility_generation
      FROM keel_meta.retrieval_source_eligibility
     WHERE tenant_id=NEW.tenant_id AND visibility_key=NEW.visibility_key
       AND document_version_id=NEW.document_version_id;
    IF eligibility_state IS DISTINCT FROM 'withdrawn' OR eligibility_generation<>NEW.eligibility_generation THEN
        RAISE EXCEPTION 'erasure job lost its matching withdrawal fence';
    END IF;

    IF OLD.state='fenced' THEN
        IF NEW.state<>'cleanup_pending' OR NEW.lease_owner IS NULL OR NEW.lease_epoch<>OLD.lease_epoch+1 OR
           NEW.attempt_count<>OLD.attempt_count+1 OR NEW.available_at<>OLD.available_at OR
           NEW.lease_until<=clock_timestamp() OR NEW.lease_until>clock_timestamp()+interval '15 minutes'+interval '1 second' OR
           NEW.last_error_code IS NOT NULL OR NEW.blocked_at IS NOT NULL OR NEW.completed_at IS NOT NULL THEN
            RAISE EXCEPTION 'fenced erasure jobs may only be claimed';
        END IF;
        RETURN NEW;
    END IF;

    IF OLD.state='cleanup_pending' THEN
        IF NEW.state='cleanup_pending' AND NEW.lease_owner IS NOT NULL AND
           NEW.lease_epoch=OLD.lease_epoch+1 AND NEW.attempt_count=OLD.attempt_count+1 AND
           NEW.available_at=OLD.available_at AND NEW.lease_until>clock_timestamp() AND
           NEW.lease_until<=clock_timestamp()+interval '15 minutes'+interval '1 second' AND
           NEW.last_error_code IS NULL AND NEW.blocked_at IS NULL AND NEW.completed_at IS NULL AND
           (OLD.lease_owner IS NULL OR OLD.lease_until<=clock_timestamp()) AND
           OLD.available_at<=clock_timestamp() AND OLD.attempt_count<12 THEN
            RETURN NEW;
        END IF;
        IF NEW.state='cleanup_pending' AND NEW.lease_owner=OLD.lease_owner AND OLD.lease_owner IS NOT NULL AND
           OLD.lease_until>clock_timestamp() AND NEW.lease_epoch=OLD.lease_epoch AND NEW.attempt_count=OLD.attempt_count AND
           NEW.lease_until>OLD.lease_until AND NEW.available_at=OLD.available_at AND
           NEW.lease_until<=clock_timestamp()+interval '15 minutes'+interval '1 second' AND
           NEW.last_error_code IS NOT DISTINCT FROM OLD.last_error_code AND
           NEW.blocked_at IS NULL AND NEW.completed_at IS NULL THEN
            RETURN NEW;
        END IF;
        IF NEW.state='cleanup_pending' AND NEW.lease_owner IS NULL AND OLD.lease_owner IS NOT NULL AND
           OLD.lease_until>clock_timestamp() AND NEW.lease_epoch=OLD.lease_epoch AND
           NEW.attempt_count=OLD.attempt_count AND NEW.available_at>OLD.available_at AND
           NEW.available_at>clock_timestamp() AND
           NEW.available_at<=clock_timestamp()+interval '24 hours'+interval '1 second' AND
           NEW.last_error_code IS NOT NULL AND NEW.blocked_at IS NULL AND NEW.completed_at IS NULL THEN
            RETURN NEW;
        END IF;
        IF NEW.state='complete' AND OLD.lease_owner IS NOT NULL AND OLD.lease_until>clock_timestamp() AND
           NEW.lease_owner IS NULL AND NEW.lease_epoch=OLD.lease_epoch AND NEW.attempt_count=OLD.attempt_count AND
           NEW.available_at=OLD.available_at AND NEW.last_error_code IS NULL AND NEW.completed_at IS NOT NULL AND
           NEW.blocked_at IS NULL THEN
            IF EXISTS (
                SELECT 1 FROM keel_meta.retrieval_erasure_action_manifest m
                WHERE m.tenant_id=OLD.tenant_id AND m.visibility_key=OLD.visibility_key AND m.job_id=OLD.job_id
                  AND m.required AND NOT EXISTS (
                      SELECT 1 FROM keel_meta.retrieval_erasure_action_receipts r
                      WHERE r.tenant_id=m.tenant_id AND r.visibility_key=m.visibility_key
                        AND r.job_id=m.job_id AND r.action_key=m.action_key
                        AND r.lease_epoch<=OLD.lease_epoch
                  )
            ) THEN RAISE EXCEPTION 'erasure job cannot complete until every required action has a receipt'; END IF;
            IF NOT EXISTS (SELECT 1 FROM keel_meta.retrieval_erasure_action_manifest m
                WHERE m.tenant_id=OLD.tenant_id AND m.visibility_key=OLD.visibility_key AND m.job_id=OLD.job_id) THEN
                RAISE EXCEPTION 'erasure job cannot complete without an action manifest';
            END IF;
            RETURN NEW;
        END IF;
        IF NEW.state='blocked' AND NEW.lease_owner IS NULL AND NEW.lease_epoch=OLD.lease_epoch AND
           NEW.attempt_count=OLD.attempt_count AND NEW.completed_at IS NULL AND NEW.blocked_at IS NOT NULL AND
           NEW.last_error_code IS NOT NULL AND
           ((OLD.lease_owner IS NOT NULL AND OLD.lease_until>clock_timestamp()) OR
            (OLD.attempt_count>=12 AND NEW.last_error_code='attempts_exhausted' AND
             (OLD.lease_owner IS NULL OR OLD.lease_until<=clock_timestamp()))) THEN
            RETURN NEW;
        END IF;
    END IF;
    RAISE EXCEPTION 'invalid retrieval erasure job transition: % -> %',OLD.state,NEW.state;
END $$;

ALTER TABLE keel_meta.retrieval_erasure_action_manifest ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.retrieval_erasure_action_manifest FORCE ROW LEVEL SECURITY;
CREATE POLICY retrieval_erasure_action_manifest_scope ON keel_meta.retrieval_erasure_action_manifest
    TO keel_app,keel_retrieval_indexer
    USING (tenant_id=(SELECT keel_private.current_tenant_id()) AND
           visibility_key=nullif(current_setting('keel.visibility_key',true),''))
    WITH CHECK (tenant_id=(SELECT keel_private.current_tenant_id()) AND
                visibility_key=nullif(current_setting('keel.visibility_key',true),''));
ALTER TABLE keel_meta.retrieval_erasure_action_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.retrieval_erasure_action_receipts FORCE ROW LEVEL SECURITY;
CREATE POLICY retrieval_erasure_action_receipts_scope ON keel_meta.retrieval_erasure_action_receipts
    TO keel_app,keel_retrieval_indexer
    USING (tenant_id=(SELECT keel_private.current_tenant_id()) AND
           visibility_key=nullif(current_setting('keel.visibility_key',true),''))
    WITH CHECK (tenant_id=(SELECT keel_private.current_tenant_id()) AND
                visibility_key=nullif(current_setting('keel.visibility_key',true),''));

REVOKE ALL ON keel_meta.retrieval_erasure_action_manifest,keel_meta.retrieval_erasure_action_receipts
    FROM PUBLIC,keel_agent,keel_worker,keel_projector,keel_operator,keel_file_processor;
GRANT SELECT ON keel_meta.retrieval_erasure_action_manifest,keel_meta.retrieval_erasure_action_receipts
    TO keel_app,keel_retrieval_indexer;
GRANT INSERT ON keel_meta.retrieval_erasure_action_manifest TO keel_app;
GRANT INSERT ON keel_meta.retrieval_erasure_action_receipts TO keel_retrieval_indexer;
REVOKE ALL ON FUNCTION keel_meta.seed_retrieval_erasure_action_manifest(),
    keel_meta.reject_retrieval_erasure_manifest_mutation(),
    keel_meta.guard_retrieval_erasure_action_receipt() FROM PUBLIC;
