-- Content-free provider attempt plans and append-only outcomes. This migration
-- creates an audit boundary only; no provider dispatch is enabled here.
CREATE TABLE keel_meta.ai_provider_attempt_plans (
    tenant_id uuid NOT NULL,
    inference_id uuid NOT NULL,
    primary_attempt_id uuid NOT NULL,
    fallback_attempt_id uuid,
    period_id uuid NOT NULL,
    scope text NOT NULL CHECK (scope='inference'),
    policy_sha256 bytea NOT NULL CHECK (octet_length(policy_sha256)=32),
    primary_capability jsonb NOT NULL CHECK (jsonb_typeof(primary_capability)='object'),
    primary_capability_sha256 bytea NOT NULL CHECK (octet_length(primary_capability_sha256)=32),
    fallback_capability jsonb CHECK (fallback_capability IS NULL OR jsonb_typeof(fallback_capability)='object'),
    fallback_capability_sha256 bytea CHECK (fallback_capability_sha256 IS NULL OR octet_length(fallback_capability_sha256)=32),
    fallback_allowance_micro_usd bigint NOT NULL CHECK (fallback_allowance_micro_usd>=0),
    reserved_liability_micro_usd bigint NOT NULL CHECK (reserved_liability_micro_usd>0),
    deadline_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id,inference_id),
    UNIQUE (tenant_id,primary_attempt_id),
    UNIQUE (tenant_id,fallback_attempt_id),
    FOREIGN KEY (tenant_id,inference_id,primary_attempt_id,period_id,scope)
        REFERENCES keel_meta.ai_budget_reservations(tenant_id,inference_id,attempt_id,period_id,scope),
    CHECK ((fallback_capability IS NULL)=(fallback_attempt_id IS NULL)),
    CHECK ((fallback_capability IS NULL)=(fallback_capability_sha256 IS NULL)),
    CHECK ((fallback_capability IS NULL)=(fallback_allowance_micro_usd=0)),
    CHECK (fallback_attempt_id IS NULL OR fallback_attempt_id<>primary_attempt_id)
);

CREATE TABLE keel_meta.ai_provider_attempt_outcomes (
    tenant_id uuid NOT NULL,
    inference_id uuid NOT NULL,
    attempt_id uuid NOT NULL,
    attempt_ordinal smallint NOT NULL CHECK (attempt_ordinal IN (1,2)),
    lease_owner text NOT NULL CHECK (lease_owner ~ '^[A-Za-z0-9._~-]{1,120}$'),
    lease_epoch bigint NOT NULL CHECK (lease_epoch>0),
    acceptance text NOT NULL CHECK (acceptance IN ('rejected_before_acceptance','accepted','unknown')),
    charge_state text NOT NULL CHECK (charge_state IN ('confirmed_no_charge','confirmed_charge','unknown')),
    failure_class text NOT NULL CHECK (failure_class IN ('none','connect_before_send','rate_limited_rejected','unavailable_rejected','timeout','provider_error')),
    provider_output_seen boolean NOT NULL,
    client_token_bytes bigint NOT NULL CHECK (client_token_bytes>=0),
    usage_micro_usd bigint NOT NULL CHECK (usage_micro_usd>=0),
    finished_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id,inference_id,attempt_id),
    FOREIGN KEY (tenant_id,inference_id) REFERENCES keel_meta.ai_provider_attempt_plans(tenant_id,inference_id),
    CHECK ((charge_state='confirmed_charge')=(usage_micro_usd>0)),
    CHECK (charge_state<>'confirmed_no_charge' OR usage_micro_usd=0),
    CHECK (charge_state<>'unknown' OR usage_micro_usd=0)
);
CREATE INDEX ai_provider_attempt_outcomes_inference_idx
    ON keel_meta.ai_provider_attempt_outcomes(tenant_id,inference_id,created_at);

ALTER TABLE keel_meta.ai_provider_attempt_plans ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.ai_provider_attempt_plans FORCE ROW LEVEL SECURITY;
CREATE POLICY ai_provider_attempt_plans_tenant ON keel_meta.ai_provider_attempt_plans
    TO keel_app,keel_ai_worker USING (tenant_id=(SELECT keel_private.current_tenant_id()))
    WITH CHECK (tenant_id=(SELECT keel_private.current_tenant_id()));
CREATE POLICY ai_provider_attempt_plans_schema_owner ON keel_meta.ai_provider_attempt_plans
    TO keel_schema_owner USING (true) WITH CHECK (true);
ALTER TABLE keel_meta.ai_provider_attempt_outcomes ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.ai_provider_attempt_outcomes FORCE ROW LEVEL SECURITY;
CREATE POLICY ai_provider_attempt_outcomes_tenant ON keel_meta.ai_provider_attempt_outcomes
    TO keel_ai_worker USING (tenant_id=(SELECT keel_private.current_tenant_id()))
    WITH CHECK (tenant_id=(SELECT keel_private.current_tenant_id()));
CREATE POLICY ai_provider_attempt_outcomes_schema_owner ON keel_meta.ai_provider_attempt_outcomes
    TO keel_schema_owner USING (true) WITH CHECK (true);

REVOKE ALL ON keel_meta.ai_provider_attempt_plans,keel_meta.ai_provider_attempt_outcomes FROM PUBLIC;
GRANT SELECT ON keel_meta.ai_provider_attempt_plans TO keel_app,keel_ai_worker;
GRANT SELECT ON keel_meta.ai_provider_attempt_outcomes TO keel_ai_worker;

CREATE FUNCTION keel_meta.persist_ai_provider_attempt_plan(p_tenant uuid,p_inference uuid,p_plan jsonb)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,keel_meta,keel_private,pg_temp AS $$
DECLARE j record; r record; plan_policy bytea; primary_attempt uuid; fallback_attempt uuid;
        primary_cap jsonb; fallback_cap jsonb; primary_digest bytea; fallback_digest bytea;
        fallback_allowance bigint; liability bigint; deadline timestamptz;
        prior keel_meta.ai_provider_attempt_plans%ROWTYPE;
BEGIN
    IF p_tenant IS DISTINCT FROM keel_private.current_tenant_id() OR jsonb_typeof(p_plan)<>'object' THEN
        RAISE EXCEPTION 'invalid AI provider attempt plan';
    END IF;
    primary_attempt:=(p_plan->>'primary_attempt_id')::uuid;
    fallback_attempt:=NULLIF(p_plan->>'fallback_attempt_id','')::uuid;
    plan_policy:=decode(p_plan->>'policy_sha256','hex');
    primary_cap:=p_plan->'primary_capability'; fallback_cap:=NULLIF(p_plan->'fallback_capability','null'::jsonb);
    primary_digest:=decode(p_plan->>'primary_capability_sha256','hex');
    fallback_digest:=CASE WHEN p_plan->>'fallback_capability_sha256' IS NULL THEN NULL
                          ELSE decode(p_plan->>'fallback_capability_sha256','hex') END;
    fallback_allowance:=(p_plan->>'fallback_allowance_micro_usd')::bigint;
    liability:=(p_plan->>'reserved_liability_micro_usd')::bigint;
    deadline:=(p_plan->>'deadline_at')::timestamptz;
    IF octet_length(plan_policy)<>32 OR octet_length(primary_digest)<>32 OR primary_attempt IS NULL OR jsonb_typeof(primary_cap)<>'object'
       OR jsonb_object_length(primary_cap)<>6
       OR NOT (primary_cap ?& ARRAY['provider_id','provider_version','model_id','artifact_digest','supports_idempotency','maximum_attempt_liability_micro_usd'])
       OR fallback_allowance<0 OR liability<=0
       OR (fallback_cap IS NULL)<>(fallback_attempt IS NULL)
       OR (fallback_cap IS NULL)<>(fallback_digest IS NULL)
       OR (fallback_cap IS NULL)<>(fallback_allowance=0) THEN
        RAISE EXCEPTION 'invalid AI provider attempt plan fields';
    END IF;
    SELECT * INTO j FROM keel_meta.ai_jobs WHERE tenant_id=p_tenant AND inference_id=p_inference FOR UPDATE;
    SELECT * INTO r FROM keel_meta.ai_budget_reservations WHERE tenant_id=p_tenant AND inference_id=p_inference FOR UPDATE;
    IF j.inference_id IS NULL OR r.inference_id IS NULL OR j.attempt_id<>primary_attempt OR r.attempt_id<>primary_attempt
       OR r.period_id<>j.period_id OR liability<>r.amount_micro_usd
       OR j.policy_sha256<>plan_policy OR primary_cap->>'provider_id'<>j.provider_id
       OR primary_cap->>'model_id'<>j.model_id OR primary_cap->>'maximum_attempt_liability_micro_usd' IS NULL
       OR (primary_cap->>'maximum_attempt_liability_micro_usd')::bigint<=0
       OR (primary_cap->>'maximum_attempt_liability_micro_usd')::bigint>liability
       OR primary_cap->>'provider_version' !~ '^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$'
       OR primary_cap->>'artifact_digest' !~ '^[0-9a-f]{64}$'
       OR primary_cap->>'supports_idempotency' NOT IN ('true','false') THEN
        RAISE EXCEPTION 'AI provider attempt plan does not match queued reserved admission';
    END IF;
    IF fallback_cap IS NOT NULL AND (jsonb_typeof(fallback_cap)<>'object'
       OR jsonb_object_length(fallback_cap)<>6
       OR NOT (fallback_cap ?& ARRAY['provider_id','provider_version','model_id','artifact_digest','supports_idempotency','maximum_attempt_liability_micro_usd'])
       OR (fallback_cap->>'provider_id') !~ '^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$'
       OR (fallback_cap->>'model_id') !~ '^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$'
       OR (fallback_cap->>'maximum_attempt_liability_micro_usd') IS NULL
       OR (fallback_cap->>'maximum_attempt_liability_micro_usd')::bigint<=0
       OR fallback_cap->>'provider_version' !~ '^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$'
       OR fallback_cap->>'artifact_digest' !~ '^[0-9a-f]{64}$'
       OR fallback_cap->>'supports_idempotency' NOT IN ('true','false')
       OR fallback_allowance<(fallback_cap->>'maximum_attempt_liability_micro_usd')::bigint
       OR liability-(primary_cap->>'maximum_attempt_liability_micro_usd')::bigint<fallback_allowance
       OR NOT EXISTS (SELECT 1 FROM keel_meta.ai_execution_profiles p
          WHERE p.tenant_id=p_tenant AND p.provider_id=fallback_cap->>'provider_id'
            AND p.model_id=fallback_cap->>'model_id' AND p.policy_sha256=plan_policy AND p.enabled)) THEN
        RAISE EXCEPTION 'invalid AI provider fallback liability';
    END IF;
    SELECT * INTO prior FROM keel_meta.ai_provider_attempt_plans WHERE tenant_id=p_tenant AND inference_id=p_inference;
    IF FOUND THEN
        IF (prior.primary_attempt_id,prior.fallback_attempt_id,prior.policy_sha256,prior.primary_capability,
            prior.primary_capability_sha256,prior.fallback_capability,prior.fallback_capability_sha256,
            prior.fallback_allowance_micro_usd,prior.reserved_liability_micro_usd,prior.deadline_at)
           IS DISTINCT FROM
           (primary_attempt,fallback_attempt,plan_policy,primary_cap,primary_digest,fallback_cap,fallback_digest,
            fallback_allowance,liability,deadline) THEN
            RAISE EXCEPTION 'conflicting AI provider attempt plan replay';
        END IF;
        RETURN true;
    END IF;
    IF j.state<>'queued' OR r.liability_state<>'reserved' OR deadline<=clock_timestamp() THEN
        RAISE EXCEPTION 'new AI provider attempt plan requires a queued reserved admission';
    END IF;
    INSERT INTO keel_meta.ai_provider_attempt_plans(tenant_id,inference_id,primary_attempt_id,fallback_attempt_id,
        period_id,scope,policy_sha256,primary_capability,primary_capability_sha256,fallback_capability,
        fallback_capability_sha256,fallback_allowance_micro_usd,
        reserved_liability_micro_usd,deadline_at)
    VALUES(p_tenant,p_inference,primary_attempt,fallback_attempt,j.period_id,j.scope,plan_policy,primary_cap,
        primary_digest,fallback_cap,fallback_digest,fallback_allowance,liability,deadline);
    RETURN true;
END $$;

CREATE FUNCTION keel_meta.record_ai_provider_attempt_outcome(
    p_tenant uuid,p_inference uuid,p_worker text,p_epoch bigint,p_attempt uuid,p_acceptance text,p_charge text,
    p_failure text,p_output_seen boolean,p_token_bytes bigint,p_usage bigint,p_finished_at timestamptz)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,keel_meta,keel_private,pg_temp AS $$
DECLARE j record; plan keel_meta.ai_provider_attempt_plans%ROWTYPE; prior keel_meta.ai_provider_attempt_outcomes%ROWTYPE;
        primary_outcome keel_meta.ai_provider_attempt_outcomes%ROWTYPE; attempt_ordinal smallint;
BEGIN
    IF p_tenant IS DISTINCT FROM keel_private.current_tenant_id() OR p_worker !~ '^[A-Za-z0-9._~-]{1,120}$'
       OR p_epoch<1 OR p_acceptance NOT IN ('rejected_before_acceptance','accepted','unknown')
       OR p_charge NOT IN ('confirmed_no_charge','confirmed_charge','unknown')
       OR p_failure NOT IN ('none','connect_before_send','rate_limited_rejected','unavailable_rejected','timeout','provider_error')
       OR p_token_bytes<0 OR p_usage<0 OR p_finished_at IS NULL
       OR (p_charge='confirmed_charge')<>(p_usage>0) OR (p_charge<>'confirmed_charge' AND p_usage<>0)
       OR (p_charge='confirmed_charge' AND p_acceptance<>'accepted')
       OR (p_failure IN ('connect_before_send','rate_limited_rejected','unavailable_rejected')
           AND (p_acceptance<>'rejected_before_acceptance' OR p_charge<>'confirmed_no_charge'
                OR p_output_seen OR p_token_bytes<>0)) THEN
        RAISE EXCEPTION 'invalid AI provider attempt outcome';
    END IF;
    SELECT * INTO j FROM keel_meta.ai_jobs WHERE tenant_id=p_tenant AND inference_id=p_inference FOR UPDATE;
    SELECT * INTO plan FROM keel_meta.ai_provider_attempt_plans WHERE tenant_id=p_tenant AND inference_id=p_inference;
    IF p_attempt=plan.primary_attempt_id THEN
        attempt_ordinal:=1;
    ELSIF p_attempt=plan.fallback_attempt_id THEN
        attempt_ordinal:=2;
    END IF;
    SELECT * INTO prior FROM keel_meta.ai_provider_attempt_outcomes
     WHERE tenant_id=p_tenant AND inference_id=p_inference AND attempt_id=p_attempt;
    IF FOUND THEN
        IF (prior.attempt_ordinal,prior.lease_owner,prior.lease_epoch,prior.acceptance,prior.charge_state,prior.failure_class,
            prior.provider_output_seen,prior.client_token_bytes,prior.usage_micro_usd,prior.finished_at)
           IS DISTINCT FROM (attempt_ordinal,p_worker,p_epoch,p_acceptance,p_charge,p_failure,p_output_seen,p_token_bytes,p_usage,p_finished_at) THEN
            RAISE EXCEPTION 'conflicting AI provider attempt outcome replay';
        END IF;
        RETURN true;
    END IF;
    IF j.inference_id IS NULL OR plan.inference_id IS NULL OR j.state<>'leased'
       OR j.lease_owner<>p_worker OR j.lease_epoch<>p_epoch
       OR j.lease_until<=clock_timestamp() OR j.attempt_deadline_at<=clock_timestamp()
       OR p_finished_at>j.attempt_deadline_at OR p_finished_at>plan.deadline_at OR (p_attempt<>plan.primary_attempt_id
          AND p_attempt IS DISTINCT FROM plan.fallback_attempt_id) OR attempt_ordinal IS NULL THEN
        RAISE EXCEPTION 'AI provider attempt outcome requires the current fenced lease';
    END IF;
    IF attempt_ordinal=2 THEN
        SELECT * INTO primary_outcome FROM keel_meta.ai_provider_attempt_outcomes
         WHERE tenant_id=p_tenant AND inference_id=p_inference AND attempt_id=plan.primary_attempt_id;
        IF NOT FOUND OR primary_outcome.acceptance<>'rejected_before_acceptance'
           OR primary_outcome.charge_state<>'confirmed_no_charge' OR primary_outcome.provider_output_seen
           OR primary_outcome.client_token_bytes<>0
           OR primary_outcome.failure_class NOT IN ('connect_before_send','rate_limited_rejected','unavailable_rejected')
           OR p_finished_at<=primary_outcome.finished_at THEN
            RAISE EXCEPTION 'AI provider fallback requires a later proven pre-acceptance no-charge failure';
        END IF;
    END IF;
    INSERT INTO keel_meta.ai_provider_attempt_outcomes(tenant_id,inference_id,attempt_id,attempt_ordinal,lease_owner,lease_epoch,
        acceptance,charge_state,failure_class,provider_output_seen,client_token_bytes,usage_micro_usd,finished_at)
    VALUES(p_tenant,p_inference,p_attempt,attempt_ordinal,p_worker,p_epoch,p_acceptance,p_charge,p_failure,p_output_seen,p_token_bytes,p_usage,p_finished_at);
    RETURN true;
END $$;

CREATE FUNCTION keel_meta.reject_ai_provider_attempt_outcome_mutation()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN RAISE EXCEPTION 'AI provider attempt outcomes are append-only'; END $$;
CREATE TRIGGER ai_provider_attempt_outcomes_immutable BEFORE UPDATE OR DELETE
    ON keel_meta.ai_provider_attempt_outcomes FOR EACH ROW EXECUTE FUNCTION keel_meta.reject_ai_provider_attempt_outcome_mutation();

REVOKE ALL ON FUNCTION keel_meta.persist_ai_provider_attempt_plan(uuid,uuid,jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION keel_meta.record_ai_provider_attempt_outcome(uuid,uuid,text,bigint,uuid,text,text,text,boolean,bigint,bigint,timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION keel_meta.persist_ai_provider_attempt_plan(uuid,uuid,jsonb) TO keel_app;
GRANT EXECUTE ON FUNCTION keel_meta.record_ai_provider_attempt_outcome(uuid,uuid,text,bigint,uuid,text,text,text,boolean,bigint,bigint,timestamptz) TO keel_ai_worker;
