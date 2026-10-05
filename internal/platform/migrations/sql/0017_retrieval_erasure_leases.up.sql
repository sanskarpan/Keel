-- K3.5: lease-fenced, bounded retries for durable retrieval erasure work.
ALTER TABLE keel_meta.retrieval_erasure_jobs
    ADD COLUMN available_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    ADD COLUMN lease_owner text,
    ADD COLUMN lease_epoch bigint NOT NULL DEFAULT 0 CHECK (lease_epoch>=0),
    ADD COLUMN lease_until timestamptz,
    ADD COLUMN blocked_at timestamptz,
    ADD COLUMN completed_at timestamptz;

ALTER TABLE keel_meta.retrieval_erasure_jobs
    DROP CONSTRAINT retrieval_erasure_jobs_attempt_count_check,
    ADD CONSTRAINT retrieval_erasure_jobs_attempt_count_check CHECK (attempt_count BETWEEN 0 AND 12),
    ADD CONSTRAINT retrieval_erasure_jobs_lease_pair_check CHECK ((lease_owner IS NULL)=(lease_until IS NULL)),
    ADD CONSTRAINT retrieval_erasure_jobs_lease_owner_check CHECK (lease_owner IS NULL OR lease_owner ~ '^[a-z0-9][a-z0-9._:-]{1,63}$'),
    ADD CONSTRAINT retrieval_erasure_jobs_lease_state_check CHECK (lease_owner IS NULL OR state='cleanup_pending'),
    ADD CONSTRAINT retrieval_erasure_jobs_blocked_time_check CHECK ((state='blocked')=(blocked_at IS NOT NULL)),
    ADD CONSTRAINT retrieval_erasure_jobs_completed_time_check CHECK ((state='complete')=(completed_at IS NOT NULL));

CREATE INDEX retrieval_erasure_jobs_claim_idx
    ON keel_meta.retrieval_erasure_jobs (tenant_id,visibility_key,available_at,requested_at,job_id)
    WHERE state IN ('fenced','cleanup_pending');

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
           NEW.last_error_code IS NOT NULL OR
           NEW.blocked_at IS NOT NULL OR NEW.completed_at IS NOT NULL THEN
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

GRANT UPDATE (state,updated_at,attempt_count,last_error_code,available_at,lease_owner,lease_epoch,
    lease_until,blocked_at,completed_at) ON keel_meta.retrieval_erasure_jobs TO keel_retrieval_indexer;
