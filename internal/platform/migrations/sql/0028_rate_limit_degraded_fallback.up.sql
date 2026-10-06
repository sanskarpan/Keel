-- A degraded safe-read allowance is durable and shared through PostgreSQL.
-- It is used only while the tenant-home-region Redis authority is unavailable.
CREATE TABLE keel_meta.rate_limit_degraded_fleet_policies (
    home_region text PRIMARY KEY CHECK (home_region ~ '^[a-z][a-z0-9._-]{0,63}$'),
    policy_sha256 bytea NOT NULL CHECK (octet_length(policy_sha256) = 32),
    capacity_units bigint NOT NULL CHECK (capacity_units BETWEEN 1 AND 1000000000000),
    refill_units_per_second bigint NOT NULL CHECK (refill_units_per_second BETWEEN 1 AND 100000000),
    enabled boolean NOT NULL DEFAULT false,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE keel_meta.rate_limit_degraded_tenant_policies (
    tenant_id uuid NOT NULL,
    home_region text NOT NULL CHECK (home_region ~ '^[a-z][a-z0-9._-]{0,63}$'),
    route_id text NOT NULL CHECK (route_id ~ '^[a-z][a-z0-9._-]{0,127}$'),
    policy_sha256 bytea NOT NULL CHECK (octet_length(policy_sha256) = 32),
    capacity_units bigint NOT NULL CHECK (capacity_units BETWEEN 1 AND 1000000000000),
    refill_units_per_second bigint NOT NULL CHECK (refill_units_per_second BETWEEN 1 AND 100000000),
    enabled boolean NOT NULL DEFAULT false,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, home_region, route_id)
);

CREATE TABLE keel_meta.rate_limit_degraded_windows (
    home_region text PRIMARY KEY CHECK (home_region ~ '^[a-z][a-z0-9._-]{0,63}$'),
    outage_id uuid NOT NULL,
    started_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    active boolean NOT NULL DEFAULT true,
    recovered_at timestamptz,
    CHECK (started_at < expires_at),
    CHECK (expires_at <= started_at + interval '60 seconds'),
    CHECK (active = (recovered_at IS NULL))
);

CREATE TABLE keel_meta.rate_limit_degraded_fleet_buckets (
    home_region text PRIMARY KEY CHECK (home_region ~ '^[a-z][a-z0-9._-]{0,63}$'),
    tokens_micro bigint NOT NULL CHECK (tokens_micro >= 0),
    updated_at timestamptz NOT NULL
);

CREATE TABLE keel_meta.rate_limit_degraded_tenant_buckets (
    tenant_id uuid NOT NULL,
    home_region text NOT NULL CHECK (home_region ~ '^[a-z][a-z0-9._-]{0,63}$'),
    route_id text NOT NULL CHECK (route_id ~ '^[a-z][a-z0-9._-]{0,127}$'),
    tokens_micro bigint NOT NULL CHECK (tokens_micro >= 0),
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, home_region, route_id),
    FOREIGN KEY (tenant_id, home_region, route_id)
        REFERENCES keel_meta.rate_limit_degraded_tenant_policies (tenant_id, home_region, route_id) ON DELETE CASCADE
);

CREATE TABLE keel_meta.rate_limit_degraded_receipts (
    tenant_id uuid NOT NULL,
    home_region text NOT NULL CHECK (home_region ~ '^[a-z][a-z0-9._-]{0,63}$'),
    route_id text NOT NULL CHECK (route_id ~ '^[a-z][a-z0-9._-]{0,127}$'),
    request_id uuid NOT NULL,
    policy_sha256 bytea NOT NULL CHECK (octet_length(policy_sha256) = 32),
    fleet_policy_sha256 bytea NOT NULL CHECK (octet_length(fleet_policy_sha256) = 32),
    outage_id uuid NOT NULL,
    allowed boolean NOT NULL,
    remaining_units bigint NOT NULL CHECK (remaining_units >= 0),
    retry_after_ms bigint NOT NULL CHECK (retry_after_ms >= 0),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, home_region, route_id, request_id),
    FOREIGN KEY (tenant_id, home_region, route_id)
        REFERENCES keel_meta.rate_limit_degraded_tenant_policies (tenant_id, home_region, route_id) ON DELETE CASCADE,
    CHECK (created_at < expires_at)
);
CREATE INDEX rate_limit_degraded_receipts_expiry_idx
    ON keel_meta.rate_limit_degraded_receipts (expires_at);

-- Control-plane policies and admission state are never directly writable/readable by the app.
-- The SECURITY DEFINER admission function enforces tenant context and exact policy identity.
ALTER TABLE keel_meta.rate_limit_degraded_fleet_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.rate_limit_degraded_fleet_policies FORCE ROW LEVEL SECURITY;
CREATE POLICY rate_limit_degraded_fleet_policies_owner ON keel_meta.rate_limit_degraded_fleet_policies
    TO keel_schema_owner USING (true) WITH CHECK (true);
CREATE POLICY rate_limit_degraded_fleet_policies_control ON keel_meta.rate_limit_degraded_fleet_policies
    TO keel_rate_control USING (true) WITH CHECK (true);

ALTER TABLE keel_meta.rate_limit_degraded_tenant_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.rate_limit_degraded_tenant_policies FORCE ROW LEVEL SECURITY;
CREATE POLICY rate_limit_degraded_tenant_policies_owner ON keel_meta.rate_limit_degraded_tenant_policies
    TO keel_schema_owner USING (true) WITH CHECK (true);
CREATE POLICY rate_limit_degraded_tenant_policies_control ON keel_meta.rate_limit_degraded_tenant_policies
    TO keel_rate_control USING (tenant_id = (SELECT keel_private.current_tenant_id()))
    WITH CHECK (tenant_id = (SELECT keel_private.current_tenant_id()));

ALTER TABLE keel_meta.rate_limit_degraded_windows ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.rate_limit_degraded_windows FORCE ROW LEVEL SECURITY;
CREATE POLICY rate_limit_degraded_windows_owner ON keel_meta.rate_limit_degraded_windows
    TO keel_schema_owner USING (true) WITH CHECK (true);

ALTER TABLE keel_meta.rate_limit_degraded_fleet_buckets ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.rate_limit_degraded_fleet_buckets FORCE ROW LEVEL SECURITY;
CREATE POLICY rate_limit_degraded_fleet_buckets_owner ON keel_meta.rate_limit_degraded_fleet_buckets
    TO keel_schema_owner USING (true) WITH CHECK (true);

ALTER TABLE keel_meta.rate_limit_degraded_tenant_buckets ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.rate_limit_degraded_tenant_buckets FORCE ROW LEVEL SECURITY;
CREATE POLICY rate_limit_degraded_tenant_buckets_owner ON keel_meta.rate_limit_degraded_tenant_buckets
    TO keel_schema_owner USING (true) WITH CHECK (true);

ALTER TABLE keel_meta.rate_limit_degraded_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.rate_limit_degraded_receipts FORCE ROW LEVEL SECURITY;
CREATE POLICY rate_limit_degraded_receipts_owner ON keel_meta.rate_limit_degraded_receipts
    TO keel_schema_owner USING (true) WITH CHECK (true);

REVOKE ALL ON keel_meta.rate_limit_degraded_fleet_policies,
    keel_meta.rate_limit_degraded_tenant_policies,
    keel_meta.rate_limit_degraded_windows,
    keel_meta.rate_limit_degraded_fleet_buckets,
    keel_meta.rate_limit_degraded_tenant_buckets,
    keel_meta.rate_limit_degraded_receipts FROM PUBLIC, keel_app;
GRANT USAGE ON SCHEMA keel_meta TO keel_app, keel_rate_control;
GRANT SELECT, INSERT, UPDATE ON keel_meta.rate_limit_degraded_fleet_policies TO keel_rate_control;
GRANT SELECT, INSERT, UPDATE, DELETE ON keel_meta.rate_limit_degraded_tenant_policies TO keel_rate_control;
GRANT USAGE ON SCHEMA keel_private TO keel_schema_owner, keel_rate_control;
GRANT EXECUTE ON FUNCTION keel_private.current_tenant_id() TO keel_schema_owner, keel_rate_control;

CREATE FUNCTION keel_meta.admit_safe_read_degraded(
    p_tenant_id uuid, p_home_region text, p_route_id text, p_request_id uuid, p_policy_sha256 bytea
) RETURNS TABLE(decision_code integer, allowed boolean, remaining_units bigint, retry_after_ms bigint,
                replayed boolean, outage_id uuid, window_expires_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, keel_meta, keel_private, pg_temp AS $$
DECLARE
    now_at timestamptz := clock_timestamp();
    fleet_policy keel_meta.rate_limit_degraded_fleet_policies%ROWTYPE;
    tenant_policy keel_meta.rate_limit_degraded_tenant_policies%ROWTYPE;
    window_row keel_meta.rate_limit_degraded_windows%ROWTYPE;
    receipt keel_meta.rate_limit_degraded_receipts%ROWTYPE;
    fleet_tokens bigint;
    tenant_tokens bigint;
    fleet_refill bigint;
    tenant_refill bigint;
    fleet_cost bigint;
    tenant_cost bigint;
    fleet_retry bigint;
    tenant_retry bigint;
    fleet_capacity_micro numeric;
    tenant_capacity_micro numeric;
    elapsed_micro numeric;
    remaining bigint;
    retry_ms bigint;
    is_allowed boolean;
BEGIN
    IF p_tenant_id IS DISTINCT FROM keel_private.current_tenant_id()
       OR p_home_region IS NULL OR p_home_region !~ '^[a-z][a-z0-9._-]{0,63}$'
       OR p_route_id IS NULL OR p_route_id !~ '^[a-z][a-z0-9._-]{0,127}$'
       OR p_request_id IS NULL OR p_policy_sha256 IS NULL OR octet_length(p_policy_sha256) <> 32 THEN
        RAISE EXCEPTION 'invalid safe-read degraded admission identity';
    END IF;

    SELECT * INTO fleet_policy FROM keel_meta.rate_limit_degraded_fleet_policies
     WHERE home_region = p_home_region AND enabled FOR SHARE;
    IF NOT FOUND THEN
        RETURN QUERY SELECT 2, false, 0::bigint, 0::bigint, false, NULL::uuid, NULL::timestamptz;
        RETURN;
    END IF;
    SELECT * INTO tenant_policy FROM keel_meta.rate_limit_degraded_tenant_policies
     WHERE tenant_id = p_tenant_id AND home_region = p_home_region AND route_id = p_route_id
       AND enabled FOR SHARE;
    IF NOT FOUND THEN
        RETURN QUERY SELECT 2, false, 0::bigint, 0::bigint, false, NULL::uuid, NULL::timestamptz;
        RETURN;
    END IF;
    -- Reject stale policy generations before any write can open/extend the
    -- shared regional outage fence.
    IF tenant_policy.policy_sha256 <> p_policy_sha256 THEN
        RETURN QUERY SELECT 2, false, 0::bigint, 0::bigint, false, NULL::uuid, NULL::timestamptz;
        RETURN;
    END IF;

    INSERT INTO keel_meta.rate_limit_degraded_windows(home_region,outage_id,started_at,expires_at,active)
    VALUES(p_home_region,pg_catalog.gen_random_uuid(),now_at,now_at+interval '60 seconds',true)
    ON CONFLICT (home_region) DO NOTHING;
    SELECT * INTO window_row FROM keel_meta.rate_limit_degraded_windows
     WHERE home_region = p_home_region FOR UPDATE;
    -- The call may have waited for another transaction's regional lock. Use
    -- database time after acquiring it so lock contention cannot admit past
    -- the hard outage-window deadline.
    now_at := clock_timestamp();

    -- Serialize exact retries behind the same regional row lock before checking
    -- receipts. This avoids a unique-key race that could otherwise turn a
    -- concurrent replay into a database error (the transaction still rolls back).
    SELECT * INTO receipt FROM keel_meta.rate_limit_degraded_receipts r
     WHERE r.tenant_id = p_tenant_id AND r.home_region = p_home_region
       AND r.route_id = p_route_id AND r.request_id = p_request_id AND r.expires_at > now_at;
    IF FOUND THEN
        IF receipt.policy_sha256 <> p_policy_sha256 OR receipt.policy_sha256 <> tenant_policy.policy_sha256
           OR receipt.fleet_policy_sha256 <> fleet_policy.policy_sha256 THEN
            RETURN QUERY SELECT -1, false, 0::bigint, 0::bigint, true, receipt.outage_id, NULL::timestamptz;
        ELSE
            RETURN QUERY SELECT CASE WHEN receipt.allowed THEN 1 ELSE 0 END, receipt.allowed,
                receipt.remaining_units, receipt.retry_after_ms, true, receipt.outage_id, NULL::timestamptz;
        END IF;
        RETURN;
    END IF;

    -- Remove a stale receipt for this exact idempotency key before reuse. The
    -- bounded sweep below is intentionally not relied upon for key correctness.
    DELETE FROM keel_meta.rate_limit_degraded_receipts
     WHERE tenant_id=p_tenant_id AND home_region=p_home_region
       AND route_id=p_route_id AND request_id=p_request_id AND expires_at <= now_at;

    -- Bounded cleanup prevents receipt storage growing with every outage. One call removes at most 100 rows.
    WITH stale AS (
        SELECT ctid FROM keel_meta.rate_limit_degraded_receipts
         WHERE expires_at <= now_at ORDER BY expires_at LIMIT 100 FOR UPDATE SKIP LOCKED
    ) DELETE FROM keel_meta.rate_limit_degraded_receipts r USING stale WHERE r.ctid = stale.ctid;
    IF NOT window_row.active THEN
        window_row.outage_id := pg_catalog.gen_random_uuid();
        window_row.started_at := now_at;
        window_row.expires_at := now_at + interval '60 seconds';
        window_row.active := true;
        window_row.recovered_at := NULL;
        UPDATE keel_meta.rate_limit_degraded_windows w SET outage_id=window_row.outage_id,
            started_at=window_row.started_at,expires_at=window_row.expires_at,active=true,recovered_at=NULL
         WHERE w.home_region=p_home_region;
    END IF;
    IF now_at >= window_row.expires_at THEN
        RETURN QUERY SELECT 3, false, 0::bigint, 0::bigint, false, window_row.outage_id, window_row.expires_at;
        RETURN;
    END IF;

    fleet_capacity_micro := fleet_policy.capacity_units::numeric * 1000000;
    tenant_capacity_micro := tenant_policy.capacity_units::numeric * 1000000;
    fleet_cost := 1000000;
    tenant_cost := 1000000;

    INSERT INTO keel_meta.rate_limit_degraded_fleet_buckets(home_region,tokens_micro,updated_at)
    VALUES(p_home_region,(fleet_policy.capacity_units*1000000),now_at)
    ON CONFLICT (home_region) DO NOTHING;
    SELECT b.tokens_micro INTO fleet_tokens FROM keel_meta.rate_limit_degraded_fleet_buckets b
     WHERE b.home_region=p_home_region FOR UPDATE;

    INSERT INTO keel_meta.rate_limit_degraded_tenant_buckets(tenant_id,home_region,route_id,tokens_micro,updated_at)
    VALUES(p_tenant_id,p_home_region,p_route_id,tenant_policy.capacity_units*1000000,now_at)
    ON CONFLICT (tenant_id,home_region,route_id) DO NOTHING;
    SELECT b.tokens_micro INTO tenant_tokens FROM keel_meta.rate_limit_degraded_tenant_buckets b
     WHERE b.tenant_id=p_tenant_id AND b.home_region=p_home_region AND b.route_id=p_route_id FOR UPDATE;

    SELECT updated_at INTO now_at FROM keel_meta.rate_limit_degraded_fleet_buckets WHERE home_region=p_home_region;
    elapsed_micro := GREATEST(0,EXTRACT(EPOCH FROM (clock_timestamp()-now_at))*1000000);
    fleet_tokens := LEAST(fleet_capacity_micro,fleet_tokens::numeric+elapsed_micro*fleet_policy.refill_units_per_second)::bigint;
    UPDATE keel_meta.rate_limit_degraded_fleet_buckets SET tokens_micro=fleet_tokens,updated_at=clock_timestamp()
     WHERE home_region=p_home_region;

    SELECT updated_at INTO now_at FROM keel_meta.rate_limit_degraded_tenant_buckets
     WHERE tenant_id=p_tenant_id AND home_region=p_home_region AND route_id=p_route_id;
    elapsed_micro := GREATEST(0,EXTRACT(EPOCH FROM (clock_timestamp()-now_at))*1000000);
    tenant_tokens := LEAST(tenant_capacity_micro,tenant_tokens::numeric+elapsed_micro*tenant_policy.refill_units_per_second)::bigint;

    fleet_refill := fleet_policy.refill_units_per_second;
    tenant_refill := tenant_policy.refill_units_per_second;
    IF fleet_tokens >= fleet_cost AND tenant_tokens >= tenant_cost THEN
        is_allowed := true;
        fleet_tokens := fleet_tokens - fleet_cost;
        tenant_tokens := tenant_tokens - tenant_cost;
        retry_ms := 0;
    ELSE
        is_allowed := false;
        fleet_retry := CASE WHEN fleet_tokens >= fleet_cost THEN 0 ELSE CEIL((fleet_cost-fleet_tokens)::numeric*1000/(fleet_refill::numeric*1000000))::bigint END;
        tenant_retry := CASE WHEN tenant_tokens >= tenant_cost THEN 0 ELSE CEIL((tenant_cost-tenant_tokens)::numeric*1000/(tenant_refill::numeric*1000000))::bigint END;
        retry_ms := GREATEST(fleet_retry,tenant_retry);
    END IF;
    remaining := LEAST(floor(fleet_tokens::numeric/1000000),floor(tenant_tokens::numeric/1000000))::bigint;
    UPDATE keel_meta.rate_limit_degraded_fleet_buckets SET tokens_micro=fleet_tokens,updated_at=clock_timestamp()
     WHERE home_region=p_home_region;
    UPDATE keel_meta.rate_limit_degraded_tenant_buckets SET tokens_micro=tenant_tokens,updated_at=clock_timestamp()
     WHERE tenant_id=p_tenant_id AND home_region=p_home_region AND route_id=p_route_id;
    INSERT INTO keel_meta.rate_limit_degraded_receipts(tenant_id,home_region,route_id,request_id,policy_sha256,fleet_policy_sha256,
        outage_id,allowed,remaining_units,retry_after_ms,created_at,expires_at)
    VALUES(p_tenant_id,p_home_region,p_route_id,p_request_id,p_policy_sha256,fleet_policy.policy_sha256,window_row.outage_id,
        is_allowed,remaining,retry_ms,clock_timestamp(),clock_timestamp()+interval '10 minutes');
    RETURN QUERY SELECT CASE WHEN is_allowed THEN 1 ELSE 0 END,is_allowed,remaining,retry_ms,false,
        window_row.outage_id,window_row.expires_at;
END $$;

CREATE FUNCTION keel_meta.mark_rate_limit_redis_healthy(p_home_region text,p_verified_healthy_for interval)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, keel_meta, pg_temp AS $$
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'keel_rate_control','MEMBER')
       OR p_home_region IS NULL OR p_home_region !~ '^[a-z][a-z0-9._-]{0,63}$'
       OR p_verified_healthy_for < interval '5 seconds' OR p_verified_healthy_for > interval '1 hour' THEN
        RAISE EXCEPTION 'invalid or unauthorized Redis recovery fence';
    END IF;
    UPDATE keel_meta.rate_limit_degraded_windows SET active=false,recovered_at=clock_timestamp()
     WHERE home_region=p_home_region AND active;
END $$;

REVOKE ALL ON FUNCTION keel_meta.admit_safe_read_degraded(uuid,text,text,uuid,bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION keel_meta.admit_safe_read_degraded(uuid,text,text,uuid,bytea) TO keel_app;
REVOKE ALL ON FUNCTION keel_meta.mark_rate_limit_redis_healthy(text,interval) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION keel_meta.mark_rate_limit_redis_healthy(text,interval) TO keel_rate_control;
