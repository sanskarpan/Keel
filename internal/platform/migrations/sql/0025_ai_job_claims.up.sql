-- Tenant-local fair queueing for the future provider executor. The queue never
-- contains prompt or response content; it references only durable admission.
ALTER TABLE keel_meta.ai_budget_reservations
    ADD CONSTRAINT ai_budget_reservations_exact_attempt_key
    UNIQUE (tenant_id,inference_id,attempt_id,period_id,scope);

CREATE TABLE keel_meta.ai_execution_profiles (
    tenant_id uuid NOT NULL,
    provider_id text NOT NULL CHECK (provider_id ~ '^[a-z][a-z0-9._-]{0,79}$'),
    model_id text NOT NULL CHECK (model_id ~ '^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,119}$'),
    policy_sha256 bytea NOT NULL CHECK (octet_length(policy_sha256)=32),
    max_concurrency integer NOT NULL CHECK (max_concurrency BETWEEN 1 AND 256),
    max_queue_depth integer NOT NULL CHECK (max_queue_depth BETWEEN 1 AND 100000),
    max_output_tokens integer NOT NULL CHECK (max_output_tokens BETWEEN 1 AND 131072),
    max_attempt_duration_ms integer NOT NULL CHECK (max_attempt_duration_ms BETWEEN 1000 AND 900000),
    enabled boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id,provider_id,model_id)
);

CREATE TABLE keel_meta.ai_job_fairness (
    tenant_id uuid NOT NULL,
    provider_id text NOT NULL,
    model_id text NOT NULL,
    principal_sha256 bytea NOT NULL CHECK (octet_length(principal_sha256)=32),
    last_claimed_at timestamptz,
    claim_count bigint NOT NULL DEFAULT 0 CHECK (claim_count>=0),
    PRIMARY KEY (tenant_id,provider_id,model_id,principal_sha256)
);

CREATE TABLE keel_meta.ai_jobs (
    tenant_id uuid NOT NULL,
    inference_id uuid NOT NULL,
    attempt_id uuid NOT NULL,
    period_id uuid NOT NULL,
    scope text NOT NULL CHECK (scope='inference'),
    provider_id text NOT NULL,
    model_id text NOT NULL,
    policy_sha256 bytea NOT NULL CHECK (octet_length(policy_sha256)=32),
    principal_sha256 bytea NOT NULL CHECK (octet_length(principal_sha256)=32),
    max_output_tokens integer NOT NULL CHECK (max_output_tokens>0),
    state text NOT NULL DEFAULT 'queued' CHECK (state IN ('queued','leased')),
    available_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count>=0),
    lease_owner text CHECK (lease_owner IS NULL OR lease_owner ~ '^[A-Za-z0-9._~-]{1,120}$'),
    lease_epoch bigint NOT NULL DEFAULT 0 CHECK (lease_epoch>=0),
    lease_until timestamptz,
    attempt_deadline_at timestamptz,
    PRIMARY KEY (tenant_id,inference_id),
    UNIQUE (tenant_id,attempt_id),
    FOREIGN KEY (tenant_id,provider_id,model_id)
        REFERENCES keel_meta.ai_execution_profiles(tenant_id,provider_id,model_id),
    FOREIGN KEY (tenant_id,provider_id,model_id,principal_sha256)
        REFERENCES keel_meta.ai_job_fairness(tenant_id,provider_id,model_id,principal_sha256),
    FOREIGN KEY (tenant_id,inference_id,attempt_id)
        REFERENCES keel_meta.ai_inference_admissions(tenant_id,inference_id,attempt_id),
    FOREIGN KEY (tenant_id,inference_id,attempt_id,period_id,scope)
        REFERENCES keel_meta.ai_budget_reservations(tenant_id,inference_id,attempt_id,period_id,scope),
    CHECK ((state='leased')=(lease_owner IS NOT NULL)),
    CHECK ((state='leased')=(lease_until IS NOT NULL)),
    CHECK ((state='leased')=(attempt_deadline_at IS NOT NULL))
);

CREATE INDEX ai_jobs_fair_claim_idx ON keel_meta.ai_jobs
    (tenant_id,provider_id,model_id,available_at,created_at,inference_id) WHERE state='queued';
CREATE INDEX ai_jobs_active_concurrency_idx ON keel_meta.ai_jobs
    (tenant_id,provider_id,model_id) WHERE state='leased';

ALTER TABLE keel_meta.ai_execution_profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.ai_execution_profiles FORCE ROW LEVEL SECURITY;
CREATE POLICY ai_execution_profiles_tenant ON keel_meta.ai_execution_profiles
    TO keel_app,keel_ai_worker USING (tenant_id=(SELECT keel_private.current_tenant_id()));
CREATE POLICY ai_execution_profiles_schema_owner ON keel_meta.ai_execution_profiles
    TO keel_schema_owner USING (true) WITH CHECK (true);
ALTER TABLE keel_meta.ai_job_fairness ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.ai_job_fairness FORCE ROW LEVEL SECURITY;
CREATE POLICY ai_job_fairness_tenant ON keel_meta.ai_job_fairness
    TO keel_app,keel_ai_worker USING (tenant_id=(SELECT keel_private.current_tenant_id()))
    WITH CHECK (tenant_id=(SELECT keel_private.current_tenant_id()));
CREATE POLICY ai_job_fairness_schema_owner ON keel_meta.ai_job_fairness
    TO keel_schema_owner USING (true) WITH CHECK (true);
ALTER TABLE keel_meta.ai_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.ai_jobs FORCE ROW LEVEL SECURITY;
CREATE POLICY ai_jobs_tenant ON keel_meta.ai_jobs
    TO keel_app,keel_ai_worker USING (tenant_id=(SELECT keel_private.current_tenant_id()))
    WITH CHECK (tenant_id=(SELECT keel_private.current_tenant_id()));
CREATE POLICY ai_jobs_schema_owner ON keel_meta.ai_jobs
    TO keel_schema_owner USING (true) WITH CHECK (true);

-- SECURITY DEFINER queue admission must verify the exact source reservation and
-- policy digest despite FORCE RLS on the billing tables.
CREATE POLICY ai_inference_admissions_schema_owner ON keel_meta.ai_inference_admissions
    TO keel_schema_owner USING (true) WITH CHECK (true);
CREATE POLICY ai_budget_reservations_schema_owner ON keel_meta.ai_budget_reservations
    TO keel_schema_owner USING (true) WITH CHECK (true);

REVOKE ALL ON keel_meta.ai_execution_profiles,keel_meta.ai_job_fairness,keel_meta.ai_jobs FROM PUBLIC;
GRANT USAGE ON SCHEMA keel_meta TO keel_app,keel_ai_worker;
GRANT SELECT ON keel_meta.ai_execution_profiles TO keel_app,keel_ai_worker;
GRANT SELECT (tenant_id,provider_id,model_id,principal_sha256) ON keel_meta.ai_job_fairness TO keel_app;
GRANT INSERT (tenant_id,provider_id,model_id,principal_sha256) ON keel_meta.ai_job_fairness TO keel_app;
GRANT SELECT ON keel_meta.ai_jobs TO keel_app;
GRANT INSERT (tenant_id,inference_id,attempt_id,period_id,scope,provider_id,model_id,policy_sha256,principal_sha256,max_output_tokens)
    ON keel_meta.ai_jobs TO keel_app;
GRANT SELECT,INSERT,UPDATE (last_claimed_at,claim_count) ON keel_meta.ai_job_fairness TO keel_schema_owner;
GRANT SELECT,INSERT,UPDATE (state,attempt_count,lease_owner,lease_epoch,lease_until,attempt_deadline_at)
    ON keel_meta.ai_jobs TO keel_schema_owner;

CREATE FUNCTION keel_meta.guard_ai_job_transition()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,keel_meta,keel_private,pg_temp AS $$
BEGIN
    IF (OLD.tenant_id,OLD.inference_id,OLD.attempt_id,OLD.period_id,OLD.scope,OLD.provider_id,OLD.model_id,
        OLD.policy_sha256,OLD.principal_sha256,OLD.max_output_tokens,OLD.available_at,OLD.created_at)
       IS DISTINCT FROM
       (NEW.tenant_id,NEW.inference_id,NEW.attempt_id,NEW.period_id,NEW.scope,NEW.provider_id,NEW.model_id,
        NEW.policy_sha256,NEW.principal_sha256,NEW.max_output_tokens,NEW.available_at,NEW.created_at) THEN
        RAISE EXCEPTION 'AI job identity and execution bounds are immutable';
    END IF;
    IF OLD.state='queued' AND NEW.state='leased' THEN
        IF NEW.lease_epoch<>OLD.lease_epoch+1 OR NEW.attempt_count<>OLD.attempt_count+1 OR
           NEW.lease_owner IS NULL OR NEW.lease_until<=clock_timestamp() OR
           NEW.attempt_deadline_at<=NEW.lease_until THEN
            RAISE EXCEPTION 'invalid AI job lease claim';
        END IF;
    ELSIF OLD.state='leased' AND NEW.state='leased' THEN
        IF NEW.lease_owner<>OLD.lease_owner OR NEW.lease_epoch<>OLD.lease_epoch OR
           NEW.attempt_count<>OLD.attempt_count OR NEW.lease_until<=OLD.lease_until OR
           NEW.lease_until>OLD.attempt_deadline_at OR NEW.attempt_deadline_at<>OLD.attempt_deadline_at OR
           OLD.lease_until<=clock_timestamp() THEN
            RAISE EXCEPTION 'invalid or expired AI job lease renewal';
        END IF;
    ELSE
        RAISE EXCEPTION 'invalid AI job state transition';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER ai_job_transition_guard BEFORE UPDATE ON keel_meta.ai_jobs
    FOR EACH ROW EXECUTE FUNCTION keel_meta.guard_ai_job_transition();

CREATE FUNCTION keel_meta.guard_ai_job_enqueue()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,keel_meta,pg_temp AS $$
DECLARE admission_policy bytea; admission_principal bytea; reservation_state text; configured_policy bytea; token_cap integer; queue_cap integer; queued_count integer;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended(NEW.tenant_id::text||'|'||NEW.provider_id||'|'||NEW.model_id,0));
    IF NEW.state<>'queued' OR NEW.attempt_count<>0 OR NEW.lease_epoch<>0 OR NEW.lease_owner IS NOT NULL OR
       NEW.lease_until IS NOT NULL OR NEW.attempt_deadline_at IS NOT NULL THEN
        RAISE EXCEPTION 'AI jobs must enter the queue in the unclaimed state';
    END IF;
    SELECT a.policy_sha256,a.principal_binding_sha256 INTO admission_policy,admission_principal
      FROM keel_meta.ai_inference_admissions a
     WHERE a.tenant_id=NEW.tenant_id AND a.inference_id=NEW.inference_id AND a.attempt_id=NEW.attempt_id;
    SELECT r.liability_state INTO reservation_state
      FROM keel_meta.ai_budget_reservations r
     WHERE r.tenant_id=NEW.tenant_id AND r.inference_id=NEW.inference_id AND r.attempt_id=NEW.attempt_id
       AND r.period_id=NEW.period_id AND r.scope=NEW.scope
     FOR UPDATE;
    SELECT p.policy_sha256,p.max_output_tokens,p.max_queue_depth INTO configured_policy,token_cap,queue_cap
      FROM keel_meta.ai_execution_profiles p
     WHERE p.tenant_id=NEW.tenant_id AND p.provider_id=NEW.provider_id AND p.model_id=NEW.model_id AND p.enabled;
    IF admission_policy IS NULL OR admission_principal IS DISTINCT FROM NEW.principal_sha256 OR reservation_state IS DISTINCT FROM 'reserved' OR
       configured_policy IS DISTINCT FROM NEW.policy_sha256 OR admission_policy IS DISTINCT FROM NEW.policy_sha256 OR
       token_cap IS NULL OR NEW.max_output_tokens>token_cap THEN
        RAISE EXCEPTION 'AI job does not match active reserved admission and execution profile';
    END IF;
    SELECT count(*) INTO queued_count FROM keel_meta.ai_jobs j
     WHERE j.tenant_id=NEW.tenant_id AND j.provider_id=NEW.provider_id AND j.model_id=NEW.model_id AND j.state='queued';
    IF queued_count>=queue_cap THEN RAISE EXCEPTION 'AI execution queue is at capacity'; END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER ai_job_enqueue_guard BEFORE INSERT ON keel_meta.ai_jobs
    FOR EACH ROW EXECUTE FUNCTION keel_meta.guard_ai_job_enqueue();

CREATE FUNCTION keel_meta.claim_ai_job(p_tenant uuid,p_provider text,p_model text,p_worker text,p_lease_ms integer)
RETURNS TABLE(inference_id uuid,attempt_id uuid,lease_epoch bigint,attempt_count integer,max_output_tokens integer,
              lease_until timestamptz,attempt_deadline_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,keel_meta,keel_private,pg_temp AS $$
DECLARE cap_concurrency integer; cap_duration integer; is_enabled boolean; configured_policy bytea; token_cap integer; in_flight integer;
        selected_inference uuid; selected_attempt uuid; selected_principal bytea; selected_epoch bigint;
        selected_count integer; selected_tokens integer;
BEGIN
    IF p_tenant IS DISTINCT FROM keel_private.current_tenant_id() OR p_provider !~ '^[a-z][a-z0-9._-]{0,79}$'
       OR p_model !~ '^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,119}$' OR p_worker !~ '^[A-Za-z0-9._~-]{1,120}$'
       OR p_lease_ms NOT BETWEEN 1 AND 30000 THEN
        RAISE EXCEPTION 'invalid AI job claim';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended(p_tenant::text||'|'||p_provider||'|'||p_model,0));
    SELECT max_concurrency,max_attempt_duration_ms,enabled,policy_sha256,max_output_tokens
      INTO cap_concurrency,cap_duration,is_enabled,configured_policy,token_cap
      FROM keel_meta.ai_execution_profiles WHERE tenant_id=p_tenant AND provider_id=p_provider AND model_id=p_model;
    IF NOT FOUND OR NOT is_enabled THEN RETURN; END IF;
    SELECT count(*) INTO in_flight FROM keel_meta.ai_jobs
     WHERE tenant_id=p_tenant AND provider_id=p_provider AND model_id=p_model AND state='leased';
    IF in_flight>=cap_concurrency THEN RETURN; END IF;
    SELECT j.inference_id,j.attempt_id,j.principal_sha256,j.lease_epoch,j.attempt_count,j.max_output_tokens
      INTO selected_inference,selected_attempt,selected_principal,selected_epoch,selected_count,selected_tokens
      FROM keel_meta.ai_jobs j JOIN keel_meta.ai_job_fairness f
        ON f.tenant_id=j.tenant_id AND f.provider_id=j.provider_id AND f.model_id=j.model_id AND f.principal_sha256=j.principal_sha256
     WHERE j.tenant_id=p_tenant AND j.provider_id=p_provider AND j.model_id=p_model AND j.state='queued'
       AND j.available_at<=clock_timestamp() AND j.policy_sha256=configured_policy AND j.max_output_tokens<=token_cap
     ORDER BY f.last_claimed_at ASC NULLS FIRST,j.available_at,j.created_at,j.inference_id
     LIMIT 1 FOR UPDATE OF j,f SKIP LOCKED;
    IF NOT FOUND THEN RETURN; END IF;
    UPDATE keel_meta.ai_jobs j SET state='leased',lease_owner=p_worker,lease_epoch=selected_epoch+1,
      attempt_count=selected_count+1,
      attempt_deadline_at=n.ts+(cap_duration*interval '1 millisecond'),
      lease_until=LEAST(n.ts+(p_lease_ms*interval '1 millisecond'),n.ts+((cap_duration-1)*interval '1 millisecond'))
      FROM (SELECT clock_timestamp() AS ts) n
     WHERE j.tenant_id=p_tenant AND j.inference_id=selected_inference
     RETURNING j.inference_id,j.attempt_id,j.lease_epoch,j.attempt_count,j.max_output_tokens,j.lease_until,j.attempt_deadline_at
      INTO inference_id,attempt_id,lease_epoch,attempt_count,max_output_tokens,lease_until,attempt_deadline_at;
    UPDATE keel_meta.ai_job_fairness SET last_claimed_at=clock_timestamp(),claim_count=claim_count+1
     WHERE tenant_id=p_tenant AND provider_id=p_provider AND model_id=p_model AND principal_sha256=selected_principal;
    RETURN NEXT;
END $$;

CREATE FUNCTION keel_meta.renew_ai_job_lease(p_tenant uuid,p_inference uuid,p_worker text,p_epoch bigint,p_lease_ms integer)
RETURNS timestamptz LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,keel_meta,keel_private,pg_temp AS $$
DECLARE renewed_until timestamptz;
BEGIN
    IF p_tenant IS DISTINCT FROM keel_private.current_tenant_id() OR p_worker !~ '^[A-Za-z0-9._~-]{1,120}$'
       OR p_epoch<1 OR p_lease_ms NOT BETWEEN 1 AND 30000 THEN
        RAISE EXCEPTION 'invalid AI job lease renewal';
    END IF;
    UPDATE keel_meta.ai_jobs SET lease_until=LEAST(clock_timestamp()+(p_lease_ms*interval '1 millisecond'),attempt_deadline_at)
     WHERE tenant_id=p_tenant AND inference_id=p_inference AND state='leased' AND lease_owner=p_worker
       AND lease_epoch=p_epoch AND lease_until>clock_timestamp() AND attempt_deadline_at>clock_timestamp()
       AND LEAST(clock_timestamp()+(p_lease_ms*interval '1 millisecond'),attempt_deadline_at)>lease_until
     RETURNING lease_until INTO renewed_until;
    IF NOT FOUND THEN RAISE EXCEPTION 'AI job lease is no longer current'; END IF;
    RETURN renewed_until;
END $$;

REVOKE ALL ON FUNCTION keel_meta.claim_ai_job(uuid,text,text,text,integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION keel_meta.renew_ai_job_lease(uuid,uuid,text,bigint,integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION keel_meta.guard_ai_job_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION keel_meta.guard_ai_job_enqueue() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION keel_meta.claim_ai_job(uuid,text,text,text,integer) TO keel_ai_worker;
GRANT EXECUTE ON FUNCTION keel_meta.renew_ai_job_lease(uuid,uuid,text,bigint,integer) TO keel_ai_worker;
