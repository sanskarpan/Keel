-- Keep API writes append-only while allowing the worker to remove only expired feed rows.
CREATE INDEX state_updates_retention_idx ON keel_meta.state_updates (tenant_id, created_at, sequence);
DROP POLICY state_updates_tenant_isolation ON keel_meta.state_updates;
CREATE POLICY state_updates_app_tenant ON keel_meta.state_updates
    TO keel_app USING (tenant_id = (SELECT keel_private.current_tenant_id()))
    WITH CHECK (tenant_id = (SELECT keel_private.current_tenant_id()));
CREATE POLICY state_updates_worker_read ON keel_meta.state_updates
    FOR SELECT TO keel_worker USING (tenant_id = (SELECT keel_private.current_tenant_id()));
CREATE POLICY state_updates_worker_prune ON keel_meta.state_updates
    FOR DELETE TO keel_worker USING (
        tenant_id = (SELECT keel_private.current_tenant_id())
        AND created_at <= statement_timestamp() - interval '24 hours'
    );

REVOKE ALL ON keel_meta.state_updates FROM keel_worker, PUBLIC;
GRANT SELECT, DELETE ON keel_meta.state_updates TO keel_worker;
