-- Separate read-only status scraping from the rate-control credential that
-- can write the Redis recovery fence.
CREATE OR REPLACE FUNCTION keel_meta.read_rate_limit_degraded_window_state(p_home_region text)
RETURNS TABLE(window_present boolean, active boolean, admission_open boolean,
              seconds_until_expiry double precision, observed_at timestamptz,
              recovered_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, keel_meta, pg_temp AS $$
DECLARE
    window_row keel_meta.rate_limit_degraded_windows%ROWTYPE;
    now_at timestamptz := clock_timestamp();
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'keel_rate_status','MEMBER')
       OR p_home_region IS NULL OR p_home_region !~ '^[a-z][a-z0-9._-]{0,63}$' THEN
        RAISE EXCEPTION 'invalid or unauthorized degraded window status request';
    END IF;

    SELECT * INTO window_row FROM keel_meta.rate_limit_degraded_windows
     WHERE home_region=p_home_region;
    IF NOT FOUND THEN
        RETURN QUERY SELECT false,false,false,0::double precision,now_at,NULL::timestamptz;
        RETURN;
    END IF;

    RETURN QUERY SELECT true,window_row.active,
        window_row.active AND now_at < window_row.expires_at,
        GREATEST(0,EXTRACT(EPOCH FROM (window_row.expires_at-now_at)))::double precision,
        now_at,window_row.recovered_at;
END $$;

REVOKE ALL ON FUNCTION keel_meta.read_rate_limit_degraded_window_state(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION keel_meta.read_rate_limit_degraded_window_state(text) FROM keel_rate_control;
GRANT USAGE ON SCHEMA keel_meta TO keel_rate_status;
GRANT EXECUTE ON FUNCTION keel_meta.read_rate_limit_degraded_window_state(text) TO keel_rate_status;
