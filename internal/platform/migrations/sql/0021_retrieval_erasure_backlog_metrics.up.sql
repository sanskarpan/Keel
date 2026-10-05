-- K3.5: bounded oldest-first scans for scope-local erasure backlog metrics.
CREATE INDEX retrieval_erasure_jobs_backlog_idx
    ON keel_meta.retrieval_erasure_jobs (tenant_id,visibility_key,requested_at,job_id)
    WHERE state IN ('fenced','cleanup_pending','blocked');
