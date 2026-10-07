-- Couple terminal attempt evidence to K4.3 accounting and K4.4 job state in
-- one database transaction. This still does not dispatch provider requests.
CREATE TABLE keel_meta.ai_provider_attempt_settlements (
    tenant_id uuid NOT NULL,
    inference_id uuid NOT NULL,
    attempt_id uuid NOT NULL,
    attempt_ordinal smallint NOT NULL CHECK (attempt_ordinal IN (1,2)),
    disposition text NOT NULL CHECK (disposition IN ('fallback_ready','settled_confirmed','settled_no_charge','retained_unknown')),
    amount_micro_usd bigint NOT NULL CHECK ((disposition='settled_confirmed')=(amount_micro_usd>0)
        AND (disposition='settled_confirmed' OR amount_micro_usd=0)),
    source_ref text NOT NULL CHECK (source_ref ~ '^[A-Za-z0-9._:/~-]{1,160}$'),
    worker_id text NOT NULL CHECK (worker_id ~ '^[A-Za-z0-9._~-]{1,120}$'),
    lease_epoch bigint NOT NULL CHECK (lease_epoch>0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id,inference_id,attempt_id,disposition),
    FOREIGN KEY (tenant_id,inference_id,attempt_id)
        REFERENCES keel_meta.ai_provider_attempt_outcomes(tenant_id,inference_id,attempt_id)
);
CREATE UNIQUE INDEX ai_provider_attempt_one_terminal_disposition_idx
    ON keel_meta.ai_provider_attempt_settlements(tenant_id,inference_id)
    WHERE disposition<>'fallback_ready';

ALTER TABLE keel_meta.ai_provider_attempt_settlements ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.ai_provider_attempt_settlements FORCE ROW LEVEL SECURITY;
CREATE POLICY ai_provider_attempt_settlements_tenant ON keel_meta.ai_provider_attempt_settlements
    TO keel_ai_worker USING (tenant_id=(SELECT keel_private.current_tenant_id()))
    WITH CHECK (tenant_id=(SELECT keel_private.current_tenant_id()));
CREATE POLICY ai_provider_attempt_settlements_schema_owner ON keel_meta.ai_provider_attempt_settlements
    TO keel_schema_owner USING (true) WITH CHECK (true);
REVOKE ALL ON keel_meta.ai_provider_attempt_settlements FROM PUBLIC,keel_app,keel_ai_worker;

CREATE FUNCTION keel_meta.reject_ai_provider_attempt_settlement_mutation()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN RAISE EXCEPTION 'AI provider attempt settlements are append-only'; END $$;
CREATE TRIGGER ai_provider_attempt_settlements_immutable BEFORE UPDATE OR DELETE
    ON keel_meta.ai_provider_attempt_settlements FOR EACH ROW EXECUTE FUNCTION keel_meta.reject_ai_provider_attempt_settlement_mutation();

CREATE FUNCTION keel_meta.settle_ai_provider_attempt(
    p_tenant uuid,p_inference uuid,p_worker text,p_epoch bigint,p_attempt uuid,p_acceptance text,p_charge text,
    p_failure text,p_output_seen boolean,p_token_bytes bigint,p_usage bigint,p_finished_at timestamptz,p_source text)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,keel_meta,keel_private,pg_temp AS $$
DECLARE plan keel_meta.ai_provider_attempt_plans%ROWTYPE; observed keel_meta.ai_provider_attempt_outcomes%ROWTYPE;
        prior keel_meta.ai_provider_attempt_settlements%ROWTYPE; job record; terminal_prior record;
        budget_kind text; disposition text; amount bigint; recorded boolean;
BEGIN
    IF p_tenant IS DISTINCT FROM keel_private.current_tenant_id() OR p_source IS NULL
       OR p_source !~ '^[A-Za-z0-9._:/~-]{1,160}$' THEN
        RAISE EXCEPTION 'invalid AI provider attempt settlement';
    END IF;
    SELECT keel_meta.record_ai_provider_attempt_outcome(p_tenant,p_inference,p_worker,p_epoch,p_attempt,
        p_acceptance,p_charge,p_failure,p_output_seen,p_token_bytes,p_usage,p_finished_at) INTO recorded;
    IF NOT recorded THEN RAISE EXCEPTION 'AI provider attempt outcome was not recorded'; END IF;
    SELECT * INTO plan FROM keel_meta.ai_provider_attempt_plans
     WHERE tenant_id=p_tenant AND inference_id=p_inference;
    SELECT * INTO observed FROM keel_meta.ai_provider_attempt_outcomes
     WHERE tenant_id=p_tenant AND inference_id=p_inference AND attempt_id=p_attempt;
    IF plan.inference_id IS NULL OR observed.attempt_id IS NULL THEN
        RAISE EXCEPTION 'AI provider attempt settlement is missing its durable plan or outcome';
    END IF;

    SELECT * INTO prior FROM keel_meta.ai_provider_attempt_settlements s
     WHERE s.tenant_id=p_tenant AND s.inference_id=p_inference AND s.attempt_id=p_attempt
       AND s.disposition='fallback_ready' FOR UPDATE;
    IF FOUND THEN
        IF (prior.attempt_ordinal,prior.source_ref,prior.worker_id,prior.lease_epoch)
           IS DISTINCT FROM (observed.attempt_ordinal,p_source,p_worker,p_epoch) THEN
            RAISE EXCEPTION 'conflicting AI provider fallback disposition replay';
        END IF;
        SELECT state,lease_owner,lease_epoch,lease_until,attempt_deadline_at
          INTO job FROM keel_meta.ai_jobs WHERE tenant_id=p_tenant AND inference_id=p_inference;
        IF FOUND AND job.state='leased' AND job.lease_owner=p_worker AND job.lease_epoch=p_epoch
           AND job.lease_until>clock_timestamp() AND job.attempt_deadline_at>clock_timestamp()
           AND plan.deadline_at>clock_timestamp() THEN
            RETURN 'fallback_ready';
        END IF;
        SELECT * INTO terminal_prior FROM keel_meta.ai_provider_attempt_settlements s
         WHERE s.tenant_id=p_tenant AND s.inference_id=p_inference AND s.disposition<>'fallback_ready';
        IF FOUND THEN RETURN 'fallback_consumed'; END IF;
    END IF;

    IF observed.charge_state='confirmed_charge' THEN
        budget_kind:='confirmed'; amount:=observed.usage_micro_usd; disposition:='settled_confirmed';
    ELSIF observed.charge_state='unknown' THEN
        budget_kind:='unknown'; amount:=0; disposition:='retained_unknown';
    ELSIF observed.attempt_ordinal=1 AND plan.fallback_attempt_id IS NOT NULL
       AND observed.acceptance='rejected_before_acceptance' AND observed.charge_state='confirmed_no_charge'
       AND NOT observed.provider_output_seen AND observed.client_token_bytes=0
       AND observed.failure_class IN ('connect_before_send','rate_limited_rejected','unavailable_rejected') THEN
        SELECT state,lease_owner,lease_epoch,lease_until,attempt_deadline_at
          INTO job FROM keel_meta.ai_jobs WHERE tenant_id=p_tenant AND inference_id=p_inference;
        IF FOUND AND job.state='leased' AND job.lease_owner=p_worker AND job.lease_epoch=p_epoch
           AND job.lease_until>clock_timestamp() AND job.attempt_deadline_at>clock_timestamp()
           AND plan.deadline_at>clock_timestamp() THEN
            INSERT INTO keel_meta.ai_provider_attempt_settlements(tenant_id,inference_id,attempt_id,attempt_ordinal,
                disposition,amount_micro_usd,source_ref,worker_id,lease_epoch)
            VALUES(p_tenant,p_inference,p_attempt,observed.attempt_ordinal,'fallback_ready',0,p_source,p_worker,p_epoch);
            RETURN 'fallback_ready';
        END IF;
        budget_kind:='no_charge'; amount:=0; disposition:='settled_no_charge';
    ELSE
        budget_kind:='no_charge'; amount:=0; disposition:='settled_no_charge';
    END IF;

    SELECT * INTO prior FROM keel_meta.ai_provider_attempt_settlements s
     WHERE s.tenant_id=p_tenant AND s.inference_id=p_inference AND s.disposition<>'fallback_ready' FOR UPDATE;
    IF FOUND THEN
        IF (prior.attempt_id,prior.attempt_ordinal,prior.disposition,prior.amount_micro_usd,
            prior.source_ref,prior.worker_id,prior.lease_epoch)
           IS DISTINCT FROM
           (p_attempt,observed.attempt_ordinal,disposition,amount,p_source,p_worker,p_epoch) THEN
            RAISE EXCEPTION 'conflicting AI provider attempt settlement replay';
        END IF;
        RETURN disposition;
    END IF;

    PERFORM keel_meta.apply_ai_job_outcome(p_tenant,p_inference,p_worker,p_epoch,budget_kind,amount,p_source);
    INSERT INTO keel_meta.ai_provider_attempt_settlements(tenant_id,inference_id,attempt_id,attempt_ordinal,
        disposition,amount_micro_usd,source_ref,worker_id,lease_epoch)
    VALUES(p_tenant,p_inference,p_attempt,observed.attempt_ordinal,disposition,amount,p_source,p_worker,p_epoch);
    RETURN disposition;
END $$;

REVOKE ALL ON FUNCTION keel_meta.settle_ai_provider_attempt(uuid,uuid,text,bigint,uuid,text,text,text,boolean,bigint,bigint,timestamptz,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION keel_meta.settle_ai_provider_attempt(uuid,uuid,text,bigint,uuid,text,text,text,boolean,bigint,bigint,timestamptz,text) TO keel_ai_worker;
