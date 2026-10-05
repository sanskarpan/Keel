-- The agent can read only the fixed summary projection. The protected
-- session_user mapping remains the tenant source; caller GUCs are ignored.
GRANT USAGE ON SCHEMA keel_meta TO keel_agent;
REVOKE ALL ON keel_meta.order_heads FROM keel_agent;
GRANT SELECT (order_id, status, version, updated_at)
    ON keel_meta.order_heads TO keel_agent;

CREATE POLICY order_heads_agent_summary_read ON keel_meta.order_heads
    FOR SELECT TO keel_agent
    USING (tenant_id = (SELECT keel_private.current_tenant_id()));

CREATE VIEW keel_meta.agent_order_summary
WITH (security_invoker = true)
AS
SELECT order_id, status, version, updated_at
FROM keel_meta.order_heads;

REVOKE ALL ON keel_meta.agent_order_summary FROM PUBLIC;
GRANT SELECT ON keel_meta.agent_order_summary TO keel_agent;
