-- Provider outcomes are immutable decisions coupled to K4.3 liability changes.
-- Unknown attempts retain their lease slot and budget reserve until resolution.
DO $$
DECLARE check_name text;
BEGIN
    FOR check_name IN
        SELECT conname FROM pg_catalog.pg_constraint
         WHERE conrelid='keel_meta.ai_jobs'::regclass AND contype='c'
           AND pg_catalog.pg_get_constraintdef(oid) ILIKE '%state%'
    LOOP
        EXECUTE format('ALTER TABLE keel_meta.ai_jobs DROP CONSTRAINT %I',check_name);
    END LOOP;
END $$;

ALTER TABLE keel_meta.ai_jobs
    ADD COLUMN outcome_kind text,
    ADD COLUMN outcome_source_ref text,
    ADD COLUMN outcome_worker_id text,
    ADD CONSTRAINT ai_jobs_outcome_shape CHECK (
        (state IN ('queued','leased') AND outcome_kind IS NULL AND outcome_source_ref IS NULL AND outcome_worker_id IS NULL) OR
        (state='unknown' AND outcome_kind='unknown' AND outcome_source_ref IS NOT NULL AND outcome_worker_id IS NOT NULL) OR
        (state='succeeded' AND outcome_kind IN ('confirmed','reconciled_confirmed') AND outcome_source_ref IS NOT NULL AND outcome_worker_id IS NOT NULL) OR
        (state='no_charge' AND outcome_kind IN ('no_charge','reconciled_no_charge') AND outcome_source_ref IS NOT NULL AND outcome_worker_id IS NOT NULL)
    ),
    ADD CONSTRAINT ai_jobs_lease_owner_shape CHECK ((state IN ('leased','unknown'))=(lease_owner IS NOT NULL)),
    ADD CONSTRAINT ai_jobs_lease_until_shape CHECK ((state IN ('leased','unknown'))=(lease_until IS NOT NULL)),
    ADD CONSTRAINT ai_jobs_deadline_shape CHECK ((state IN ('leased','unknown'))=(attempt_deadline_at IS NOT NULL));
CREATE POLICY ai_usage_ledger_schema_owner ON keel_meta.ai_usage_ledger
    TO keel_schema_owner USING (true) WITH CHECK (true);

ALTER TABLE keel_meta.ai_jobs ADD CONSTRAINT ai_jobs_state_check
    CHECK (state IN ('queued','leased','unknown','succeeded','no_charge'));
CREATE INDEX ai_jobs_expired_lease_idx ON keel_meta.ai_jobs(tenant_id,lease_until,inference_id)
    WHERE state='leased';

CREATE OR REPLACE FUNCTION keel_meta.guard_ai_job_transition()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,keel_meta,pg_temp AS $$
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
           NEW.attempt_deadline_at<=NEW.lease_until OR NEW.outcome_kind IS NOT NULL OR NEW.outcome_source_ref IS NOT NULL OR NEW.outcome_worker_id IS NOT NULL THEN
            RAISE EXCEPTION 'invalid AI job lease claim';
        END IF;
    ELSIF OLD.state='leased' AND NEW.state='leased' THEN
        IF NEW.lease_owner<>OLD.lease_owner OR NEW.lease_epoch<>OLD.lease_epoch OR
           NEW.attempt_count<>OLD.attempt_count OR NEW.lease_until<=OLD.lease_until OR
           NEW.lease_until>OLD.attempt_deadline_at OR NEW.attempt_deadline_at<>OLD.attempt_deadline_at OR
           OLD.lease_until<=clock_timestamp() OR NEW.outcome_kind IS NOT NULL OR NEW.outcome_source_ref IS NOT NULL OR NEW.outcome_worker_id IS NOT NULL THEN
            RAISE EXCEPTION 'invalid or expired AI job lease renewal';
        END IF;
    ELSIF OLD.state='leased' AND NEW.state='unknown' THEN
        IF (NEW.lease_owner,NEW.lease_epoch,NEW.attempt_count,NEW.lease_until,NEW.attempt_deadline_at)
           IS DISTINCT FROM (OLD.lease_owner,OLD.lease_epoch,OLD.attempt_count,OLD.lease_until,OLD.attempt_deadline_at)
           OR NEW.outcome_kind<>'unknown' OR NEW.outcome_source_ref IS NULL OR NEW.outcome_worker_id<>OLD.lease_owner THEN
            RAISE EXCEPTION 'invalid ambiguous AI job outcome';
        END IF;
    ELSIF OLD.state='leased' AND NEW.state IN ('succeeded','no_charge') THEN
        IF (NEW.lease_owner,NEW.lease_epoch,NEW.attempt_count,NEW.lease_until,NEW.attempt_deadline_at)
           IS DISTINCT FROM (NULL::text,OLD.lease_epoch,OLD.attempt_count,NULL::timestamptz,NULL::timestamptz)
           OR NEW.outcome_kind NOT IN ('confirmed','no_charge') OR NEW.outcome_source_ref IS NULL OR NEW.outcome_worker_id<>OLD.lease_owner THEN
            RAISE EXCEPTION 'invalid terminal AI job outcome';
        END IF;
    ELSIF OLD.state='unknown' AND NEW.state IN ('succeeded','no_charge') THEN
        IF (NEW.lease_owner,NEW.lease_epoch,NEW.attempt_count,NEW.lease_until,NEW.attempt_deadline_at)
           IS DISTINCT FROM (NULL::text,OLD.lease_epoch,OLD.attempt_count,NULL::timestamptz,NULL::timestamptz)
           OR NEW.outcome_kind NOT IN ('reconciled_confirmed','reconciled_no_charge') OR NEW.outcome_source_ref IS NULL OR
           NEW.outcome_worker_id<>OLD.outcome_worker_id THEN
            RAISE EXCEPTION 'invalid reconciled AI job outcome';
        END IF;
    ELSE
        RAISE EXCEPTION 'invalid AI job state transition';
    END IF;
    RETURN NEW;
END $$;

CREATE FUNCTION keel_meta.record_ai_job_outcome(p_tenant uuid,p_inference uuid,p_worker text,p_epoch bigint,p_kind text,p_source text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,keel_meta,keel_private,pg_temp AS $$
DECLARE current_state text; current_kind text; current_source text; current_worker text; current_owner text; current_epoch bigint;
        next_state text; budget_state text; evidence_exists boolean;
BEGIN
    IF p_tenant IS DISTINCT FROM keel_private.current_tenant_id() OR p_worker !~ '^[A-Za-z0-9._~-]{1,120}$'
       OR p_epoch<1 OR p_kind NOT IN ('unknown','confirmed','no_charge') OR p_source !~ '^[A-Za-z0-9._:/~-]{1,160}$' THEN
        RAISE EXCEPTION 'invalid AI job outcome';
    END IF;
    next_state:=CASE p_kind WHEN 'unknown' THEN 'unknown' WHEN 'confirmed' THEN 'succeeded' ELSE 'no_charge' END;
    SELECT r.liability_state INTO budget_state FROM keel_meta.ai_budget_reservations r
     WHERE r.tenant_id=p_tenant AND r.inference_id=p_inference FOR UPDATE;
    IF (p_kind='unknown' AND budget_state IS DISTINCT FROM 'unknown') OR
       (p_kind IN ('confirmed','no_charge') AND budget_state IS DISTINCT FROM 'settled') THEN
        RAISE EXCEPTION 'AI job outcome requires matching durable budget disposition';
    END IF;
    SELECT EXISTS(SELECT 1 FROM keel_meta.ai_usage_ledger l WHERE l.tenant_id=p_tenant AND l.inference_id=p_inference
      AND l.entry_kind=p_kind AND l.source_ref=p_source) INTO evidence_exists;
    IF NOT evidence_exists THEN RAISE EXCEPTION 'AI job outcome requires matching immutable ledger evidence'; END IF;
    SELECT state,outcome_kind,outcome_source_ref,outcome_worker_id,lease_owner,lease_epoch
      INTO current_state,current_kind,current_source,current_worker,current_owner,current_epoch
      FROM keel_meta.ai_jobs WHERE tenant_id=p_tenant AND inference_id=p_inference;
    IF FOUND THEN
        IF current_state=next_state AND current_kind=p_kind AND current_source=p_source AND current_worker=p_worker AND current_epoch=p_epoch THEN RETURN true; END IF;
        IF current_state<>'leased' OR current_owner<>p_worker OR current_epoch<>p_epoch THEN
            RAISE EXCEPTION 'AI job lease is no longer current';
        END IF;
    ELSE
        RAISE EXCEPTION 'AI job lease is no longer current';
    END IF;
    UPDATE keel_meta.ai_jobs SET state=next_state,outcome_kind=p_kind,outcome_source_ref=p_source,outcome_worker_id=p_worker,
        lease_owner=CASE WHEN next_state='unknown' THEN lease_owner ELSE NULL END,
        lease_until=CASE WHEN next_state='unknown' THEN lease_until ELSE NULL END,
        attempt_deadline_at=CASE WHEN next_state='unknown' THEN attempt_deadline_at ELSE NULL END
     WHERE tenant_id=p_tenant AND inference_id=p_inference AND state='leased' AND lease_owner=p_worker AND lease_epoch=p_epoch;
    IF NOT FOUND THEN RAISE EXCEPTION 'AI job lease is no longer current'; END IF;
    RETURN true;
END $$;

CREATE FUNCTION keel_meta.expire_ai_job(p_tenant uuid,p_inference uuid,p_worker text,p_epoch bigint,p_source text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,keel_meta,keel_private,pg_temp AS $$
DECLARE current_state text; current_kind text; current_source text; current_worker text; current_epoch bigint;
        budget_state text; evidence_exists boolean;
BEGIN
    IF p_tenant IS DISTINCT FROM keel_private.current_tenant_id() OR p_worker !~ '^[A-Za-z0-9._~-]{1,120}$'
       OR p_epoch<1 OR p_source !~ '^[A-Za-z0-9._:/~-]{1,160}$' THEN RAISE EXCEPTION 'invalid expired AI job transition'; END IF;
    SELECT r.liability_state INTO budget_state FROM keel_meta.ai_budget_reservations r
     WHERE r.tenant_id=p_tenant AND r.inference_id=p_inference FOR UPDATE;
    IF budget_state IS DISTINCT FROM 'unknown' THEN RAISE EXCEPTION 'expired AI job transition requires unknown budget liability'; END IF;
    SELECT EXISTS(SELECT 1 FROM keel_meta.ai_usage_ledger l WHERE l.tenant_id=p_tenant AND l.inference_id=p_inference
      AND l.entry_kind='unknown') INTO evidence_exists;
    IF NOT evidence_exists THEN RAISE EXCEPTION 'expired AI job transition requires unknown ledger evidence'; END IF;
    SELECT state,outcome_kind,outcome_source_ref,outcome_worker_id,lease_epoch
      INTO current_state,current_kind,current_source,current_worker,current_epoch
      FROM keel_meta.ai_jobs WHERE tenant_id=p_tenant AND inference_id=p_inference;
    IF FOUND AND current_state='unknown' AND current_kind='unknown' AND current_source=p_source
       AND current_worker=p_worker AND current_epoch=p_epoch THEN RETURN false; END IF;
    UPDATE keel_meta.ai_jobs SET state='unknown',outcome_kind='unknown',outcome_source_ref=p_source,outcome_worker_id=p_worker
     WHERE tenant_id=p_tenant AND inference_id=p_inference AND state='leased' AND lease_owner=p_worker AND lease_epoch=p_epoch
       AND (lease_until<=clock_timestamp() OR attempt_deadline_at<=clock_timestamp());
    IF NOT FOUND THEN RAISE EXCEPTION 'AI job lease is not expired or no longer current'; END IF;
    RETURN true;
END $$;

CREATE FUNCTION keel_meta.list_expired_ai_jobs(p_tenant uuid,p_limit integer)
RETURNS TABLE(inference_id uuid,worker_id text,lease_epoch bigint)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,keel_meta,keel_private,pg_temp AS $$
BEGIN
    IF p_tenant IS DISTINCT FROM keel_private.current_tenant_id() OR p_limit NOT BETWEEN 1 AND 100 THEN RAISE EXCEPTION 'invalid expired AI job scan'; END IF;
    RETURN QUERY SELECT j.inference_id,j.lease_owner,j.lease_epoch FROM keel_meta.ai_jobs j
     WHERE j.tenant_id=p_tenant AND j.state='leased' AND (j.lease_until<=clock_timestamp() OR j.attempt_deadline_at<=clock_timestamp())
     ORDER BY j.lease_until,j.inference_id LIMIT p_limit;
END $$;

CREATE FUNCTION keel_meta.resolve_ai_job_outcome(p_tenant uuid,p_inference uuid,p_kind text,p_source text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,keel_meta,keel_private,pg_temp AS $$
DECLARE next_state text; next_kind text; current_state text; current_kind text; current_source text; current_worker text;
        budget_state text; ledger_amount bigint;
BEGIN
    IF p_tenant IS DISTINCT FROM keel_private.current_tenant_id() OR p_kind NOT IN ('confirmed','no_charge')
       OR p_source !~ '^[A-Za-z0-9._:/~-]{1,160}$' THEN RAISE EXCEPTION 'invalid reconciled AI job outcome'; END IF;
    next_state:=CASE p_kind WHEN 'confirmed' THEN 'succeeded' ELSE 'no_charge' END;
    next_kind:=CASE p_kind WHEN 'confirmed' THEN 'reconciled_confirmed' ELSE 'reconciled_no_charge' END;
    SELECT r.liability_state INTO budget_state FROM keel_meta.ai_budget_reservations r
     WHERE r.tenant_id=p_tenant AND r.inference_id=p_inference;
    SELECT l.amount_micro_usd INTO ledger_amount FROM keel_meta.ai_usage_ledger l WHERE l.tenant_id=p_tenant AND l.inference_id=p_inference
      AND l.entry_kind='reconciliation' AND l.source_ref=p_source;
    IF budget_state IS DISTINCT FROM 'settled' OR NOT FOUND OR
       (p_kind='confirmed' AND ledger_amount<=0) OR (p_kind='no_charge' AND ledger_amount<>0) THEN
        RAISE EXCEPTION 'AI job resolution requires an authorized durable reconciliation';
    END IF;
    SELECT state,outcome_kind,outcome_source_ref,outcome_worker_id INTO current_state,current_kind,current_source,current_worker
      FROM keel_meta.ai_jobs WHERE tenant_id=p_tenant AND inference_id=p_inference;
    IF FOUND AND current_state=next_state AND current_kind=next_kind AND current_source=p_source THEN RETURN true; END IF;
    UPDATE keel_meta.ai_jobs SET state=next_state,outcome_kind=next_kind,outcome_source_ref=p_source,
        lease_owner=NULL,lease_until=NULL,attempt_deadline_at=NULL
     WHERE tenant_id=p_tenant AND inference_id=p_inference AND state='unknown';
    IF NOT FOUND THEN RAISE EXCEPTION 'AI job is not awaiting outcome reconciliation'; END IF;
    RETURN true;
END $$;

CREATE OR REPLACE FUNCTION keel_meta.claim_ai_job(p_tenant uuid,p_provider text,p_model text,p_worker text,p_lease_ms integer)
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
       OR p_lease_ms NOT BETWEEN 1 AND 30000 THEN RAISE EXCEPTION 'invalid AI job claim'; END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended(p_tenant::text||'|'||p_provider||'|'||p_model,0));
    SELECT p.max_concurrency,p.max_attempt_duration_ms,p.enabled,p.policy_sha256,p.max_output_tokens
      INTO cap_concurrency,cap_duration,is_enabled,configured_policy,token_cap
      FROM keel_meta.ai_execution_profiles p WHERE p.tenant_id=p_tenant AND p.provider_id=p_provider AND p.model_id=p_model;
    IF NOT FOUND OR NOT is_enabled THEN RETURN; END IF;
    SELECT count(*) INTO in_flight FROM keel_meta.ai_jobs
     WHERE tenant_id=p_tenant AND provider_id=p_provider AND model_id=p_model AND state IN ('leased','unknown');
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

REVOKE ALL ON FUNCTION keel_meta.record_ai_job_outcome(uuid,uuid,text,bigint,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION keel_meta.expire_ai_job(uuid,uuid,text,bigint,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION keel_meta.list_expired_ai_jobs(uuid,integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION keel_meta.resolve_ai_job_outcome(uuid,uuid,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION keel_meta.record_ai_job_outcome(uuid,uuid,text,bigint,text,text) TO keel_app,keel_ai_worker;
GRANT EXECUTE ON FUNCTION keel_meta.expire_ai_job(uuid,uuid,text,bigint,text) TO keel_app,keel_ai_worker;
GRANT EXECUTE ON FUNCTION keel_meta.list_expired_ai_jobs(uuid,integer) TO keel_ai_worker;
GRANT EXECUTE ON FUNCTION keel_meta.resolve_ai_job_outcome(uuid,uuid,text,text) TO keel_app;
