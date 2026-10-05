-- K3.5: source authorization fences and durable erasure requests.
-- Visibility is the current Keel retrieval cohort boundary. User-level ACLs and
-- source-object deletion are owned by the upstream content/identity adapter.
CREATE TABLE keel_meta.retrieval_source_eligibility (
    tenant_id uuid NOT NULL,
    visibility_key text NOT NULL CHECK (visibility_key ~ '^[a-z0-9][a-z0-9._:-]{1,63}$'),
    document_version_id uuid NOT NULL,
    state text NOT NULL CHECK (state IN ('active','withdrawn')),
    generation bigint NOT NULL CHECK (generation > 0),
    changed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id,visibility_key,document_version_id)
);

-- Existing indexed source versions begin eligible in exactly their existing
-- cohort. A later withdrawal is sticky and cannot be undone by a rebuild.
-- The schema owner is subject to FORCE RLS on retrieval_chunks. Temporarily
-- disable its row policy in this transactional migration so no historical
-- source is omitted from the authoritative ledger; restore it before commit.
ALTER TABLE keel_meta.retrieval_chunks DISABLE ROW LEVEL SECURITY;
INSERT INTO keel_meta.retrieval_source_eligibility
    (tenant_id,visibility_key,document_version_id,state,generation)
SELECT DISTINCT tenant_id,visibility_key,document_version_id,'active',1
FROM keel_meta.retrieval_chunks
ON CONFLICT DO NOTHING;
ALTER TABLE keel_meta.retrieval_chunks ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.retrieval_chunks FORCE ROW LEVEL SECURITY;

CREATE INDEX retrieval_source_eligibility_state_idx
    ON keel_meta.retrieval_source_eligibility (tenant_id,visibility_key,state,document_version_id);

CREATE TABLE keel_meta.retrieval_erasure_jobs (
    tenant_id uuid NOT NULL,
    visibility_key text NOT NULL,
    job_id uuid NOT NULL,
    requested_by uuid NOT NULL,
    document_version_id uuid NOT NULL,
    eligibility_generation bigint NOT NULL CHECK (eligibility_generation > 0),
    state text NOT NULL DEFAULT 'fenced' CHECK (state IN ('fenced','cleanup_pending','blocked','complete')),
    requested_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count BETWEEN 0 AND 1000),
    last_error_code text CHECK (last_error_code IS NULL OR last_error_code ~ '^[a-z0-9_]{1,64}$'),
    PRIMARY KEY (tenant_id,visibility_key,job_id),
    UNIQUE (tenant_id,visibility_key,document_version_id,job_id),
    FOREIGN KEY (tenant_id,visibility_key,document_version_id)
        REFERENCES keel_meta.retrieval_source_eligibility (tenant_id,visibility_key,document_version_id),
    CHECK (updated_at >= requested_at)
);
CREATE INDEX retrieval_erasure_jobs_pending_idx
    ON keel_meta.retrieval_erasure_jobs (tenant_id,visibility_key,state,requested_at,job_id);

CREATE OR REPLACE FUNCTION keel_meta.guard_retrieval_source_eligibility()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,keel_meta,pg_temp AS $$
BEGIN
    IF TG_OP='INSERT' THEN
        IF NEW.state<>'active' OR NEW.generation<>1 THEN
            RAISE EXCEPTION 'source eligibility must begin active at generation one';
        END IF;
        RETURN NEW;
    END IF;
    IF TG_OP='DELETE' THEN
        RAISE EXCEPTION 'source eligibility tombstones are retained';
    END IF;
    IF NEW.tenant_id<>OLD.tenant_id OR NEW.visibility_key<>OLD.visibility_key OR
       NEW.document_version_id<>OLD.document_version_id OR OLD.state<>'active' OR
       NEW.state<>'withdrawn' OR NEW.generation<>OLD.generation+1 OR NEW.changed_at<=OLD.changed_at THEN
        RAISE EXCEPTION 'source eligibility is immutable except for one-way withdrawal';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER retrieval_source_eligibility_guard
    BEFORE INSERT OR UPDATE OR DELETE ON keel_meta.retrieval_source_eligibility
    FOR EACH ROW EXECUTE FUNCTION keel_meta.guard_retrieval_source_eligibility();

CREATE OR REPLACE FUNCTION keel_meta.guard_retrieval_erasure_job()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,keel_meta,pg_temp AS $$
BEGIN
    IF TG_OP='INSERT' THEN
        IF NEW.state<>'fenced' OR NEW.attempt_count<>0 OR NEW.last_error_code IS NOT NULL THEN
            RAISE EXCEPTION 'erasure jobs must start fenced and unattempted';
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
       NEW.updated_at<=OLD.updated_at OR NEW.attempt_count<OLD.attempt_count OR NEW.attempt_count>OLD.attempt_count+1 THEN
        RAISE EXCEPTION 'erasure job identity is immutable and updates must be monotonic';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM keel_meta.retrieval_source_eligibility e
        WHERE e.tenant_id=NEW.tenant_id AND e.visibility_key=NEW.visibility_key
          AND e.document_version_id=NEW.document_version_id AND e.state='withdrawn'
          AND e.generation=NEW.eligibility_generation) THEN
        RAISE EXCEPTION 'erasure job lost its withdrawal fence';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER retrieval_erasure_job_guard
    BEFORE INSERT OR UPDATE OR DELETE ON keel_meta.retrieval_erasure_jobs
    FOR EACH ROW EXECUTE FUNCTION keel_meta.guard_retrieval_erasure_job();

CREATE OR REPLACE FUNCTION keel_meta.guard_retrieval_chunk_eligibility()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,keel_meta,pg_temp AS $$
DECLARE current_state text;
BEGIN
    IF TG_OP<>'INSERT' THEN RETURN NEW; END IF;
    INSERT INTO keel_meta.retrieval_source_eligibility
        (tenant_id,visibility_key,document_version_id,state,generation)
    VALUES (NEW.tenant_id,NEW.visibility_key,NEW.document_version_id,'active',1)
    ON CONFLICT DO NOTHING;
    SELECT state INTO current_state FROM keel_meta.retrieval_source_eligibility
     WHERE tenant_id=NEW.tenant_id AND visibility_key=NEW.visibility_key
       AND document_version_id=NEW.document_version_id FOR SHARE;
    IF current_state IS DISTINCT FROM 'active' THEN
        RAISE EXCEPTION 'withdrawn source versions cannot be reintroduced into retrieval builds';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER retrieval_chunk_eligibility_guard
    BEFORE INSERT ON keel_meta.retrieval_chunks
    FOR EACH ROW EXECUTE FUNCTION keel_meta.guard_retrieval_chunk_eligibility();

ALTER TABLE keel_meta.retrieval_source_eligibility ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.retrieval_source_eligibility FORCE ROW LEVEL SECURITY;
CREATE POLICY retrieval_source_eligibility_scope ON keel_meta.retrieval_source_eligibility
    TO keel_app,keel_retrieval_indexer
    USING (tenant_id=(SELECT keel_private.current_tenant_id()) AND
           visibility_key=nullif(current_setting('keel.visibility_key',true),''))
    WITH CHECK (tenant_id=(SELECT keel_private.current_tenant_id()) AND
                visibility_key=nullif(current_setting('keel.visibility_key',true),''));
ALTER TABLE keel_meta.retrieval_erasure_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.retrieval_erasure_jobs FORCE ROW LEVEL SECURITY;
CREATE POLICY retrieval_erasure_jobs_scope ON keel_meta.retrieval_erasure_jobs
    TO keel_app,keel_retrieval_indexer
    USING (tenant_id=(SELECT keel_private.current_tenant_id()) AND
           visibility_key=nullif(current_setting('keel.visibility_key',true),''))
    WITH CHECK (tenant_id=(SELECT keel_private.current_tenant_id()) AND
                visibility_key=nullif(current_setting('keel.visibility_key',true),''));

REVOKE ALL ON keel_meta.retrieval_source_eligibility,keel_meta.retrieval_erasure_jobs
    FROM PUBLIC,keel_agent,keel_worker,keel_projector,keel_operator,keel_file_processor;
GRANT SELECT,UPDATE (state,generation,changed_at) ON keel_meta.retrieval_source_eligibility TO keel_app;
GRANT SELECT,INSERT ON keel_meta.retrieval_source_eligibility TO keel_retrieval_indexer;
-- PostgreSQL requires UPDATE privilege to take row locks with FOR SHARE. The
-- trigger still prevents indexers from mutating eligibility or reactivating rows.
GRANT UPDATE (state) ON keel_meta.retrieval_source_eligibility TO keel_retrieval_indexer;
GRANT SELECT,INSERT ON keel_meta.retrieval_erasure_jobs TO keel_app,keel_retrieval_indexer;
GRANT USAGE ON SCHEMA keel_meta TO keel_app,keel_retrieval_indexer;
GRANT SELECT ON keel_meta.retrieval_source_eligibility TO keel_app;
REVOKE ALL ON FUNCTION keel_meta.guard_retrieval_source_eligibility(),
    keel_meta.guard_retrieval_erasure_job(),keel_meta.guard_retrieval_chunk_eligibility() FROM PUBLIC;
