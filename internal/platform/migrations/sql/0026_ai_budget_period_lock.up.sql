-- Lock the current budget period through a narrowly scoped SECURITY DEFINER
-- function so the application role does not need table UPDATE privileges.
CREATE POLICY ai_budget_period_heads_schema_owner ON keel_meta.ai_budget_period_heads
    TO keel_schema_owner USING (true) WITH CHECK (true);

CREATE FUNCTION keel_meta.lock_ai_budget_period(p_tenant uuid)
RETURNS TABLE(period_id uuid)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,keel_meta,keel_private,pg_temp AS $$
DECLARE selected_period uuid;
BEGIN
    IF p_tenant IS DISTINCT FROM keel_private.current_tenant_id() THEN
        RAISE EXCEPTION 'budget period tenant context mismatch';
    END IF;
    SELECT h.period_id INTO selected_period
      FROM keel_meta.ai_budget_period_heads h
     WHERE h.tenant_id=p_tenant AND h.scope='inference'
     FOR SHARE;
    IF NOT FOUND THEN RETURN; END IF;
    period_id := selected_period;
    RETURN NEXT;
END $$;

REVOKE ALL ON FUNCTION keel_meta.lock_ai_budget_period(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION keel_meta.lock_ai_budget_period(uuid) TO keel_app;
