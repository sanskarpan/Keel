CREATE TABLE keel_meta.webhook_delivery_state (
    tenant_id uuid NOT NULL,
    delivery_id text NOT NULL,
    state text NOT NULL CHECK (state IN ('pending','in_flight','delivered','failed','exhausted')),
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 100),
    first_attempt_at timestamptz,
    next_attempt_at timestamptz,
    lease_epoch bigint NOT NULL DEFAULT 0 CHECK (lease_epoch BETWEEN 0 AND 9007199254740991),
    lease_expires_at timestamptz,
    delivered_at timestamptz,
    finished_at timestamptz,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id,delivery_id),
    CONSTRAINT webhook_delivery_state_delivery_fk FOREIGN KEY (tenant_id,delivery_id)
        REFERENCES keel_meta.webhook_deliveries (tenant_id,delivery_id),
    CONSTRAINT webhook_delivery_state_shape CHECK (
        (state='pending' AND next_attempt_at IS NOT NULL AND lease_expires_at IS NULL
            AND delivered_at IS NULL AND finished_at IS NULL)
        OR (state='in_flight' AND next_attempt_at IS NULL AND lease_expires_at IS NOT NULL
            AND delivered_at IS NULL AND finished_at IS NULL)
        OR (state='delivered' AND next_attempt_at IS NULL AND lease_expires_at IS NULL
            AND delivered_at IS NOT NULL AND finished_at IS NOT NULL)
        OR (state IN ('failed','exhausted') AND next_attempt_at IS NULL AND lease_expires_at IS NULL
            AND delivered_at IS NULL AND finished_at IS NOT NULL)
    ),
    CONSTRAINT webhook_delivery_state_first_attempt CHECK (
        (attempts=0) = (first_attempt_at IS NULL)
    )
);
CREATE INDEX webhook_delivery_state_due ON keel_meta.webhook_delivery_state (tenant_id,next_attempt_at)
    WHERE state='pending';
CREATE INDEX webhook_delivery_state_leased ON keel_meta.webhook_delivery_state (tenant_id,lease_expires_at)
    WHERE state='in_flight';
ALTER TABLE keel_meta.webhook_delivery_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.webhook_delivery_state FORCE ROW LEVEL SECURITY;
CREATE POLICY webhook_delivery_state_schema_owner ON keel_meta.webhook_delivery_state
    TO keel_schema_owner USING (true) WITH CHECK (true);
REVOKE ALL ON keel_meta.webhook_delivery_state FROM PUBLIC,keel_app,keel_worker,keel_operator,
    keel_budget_control,keel_rate_control,keel_ai_worker,keel_projector,keel_file_processor,
    keel_retrieval_indexer,keel_context_vault,keel_context_policy,keel_context_erasure,
    keel_context_erasure_worker,keel_context_legal_hold,keel_context_replay,keel_agent,
    keel_callback,keel_webhook;

CREATE TABLE keel_meta.webhook_delivery_attempts (
    attempt_row_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id uuid NOT NULL,
    delivery_id text NOT NULL,
    attempt_number integer NOT NULL CHECK (attempt_number BETWEEN 1 AND 100),
    attempt_id text NOT NULL CHECK (attempt_id ~ '^[A-Za-z0-9_-]{8,64}$'),
    lease_epoch bigint NOT NULL CHECK (lease_epoch BETWEEN 1 AND 9007199254740991),
    outcome text NOT NULL CHECK (outcome IN ('delivered','retryable','permanent')),
    http_status integer NOT NULL CHECK (http_status BETWEEN 0 AND 599),
    latency_ms integer NOT NULL CHECK (latency_ms BETWEEN 0 AND 600000),
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT webhook_delivery_attempts_delivery_fk FOREIGN KEY (tenant_id,delivery_id)
        REFERENCES keel_meta.webhook_deliveries (tenant_id,delivery_id),
    CONSTRAINT webhook_delivery_attempts_number_unique
        UNIQUE (tenant_id,delivery_id,attempt_number),
    CONSTRAINT webhook_delivery_attempts_id_unique UNIQUE (attempt_id),
    CONSTRAINT webhook_delivery_attempts_delivered_status CHECK (
        outcome<>'delivered' OR http_status BETWEEN 200 AND 299
    )
);
ALTER TABLE keel_meta.webhook_delivery_attempts ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.webhook_delivery_attempts FORCE ROW LEVEL SECURITY;
CREATE POLICY webhook_delivery_attempts_schema_owner ON keel_meta.webhook_delivery_attempts
    TO keel_schema_owner USING (true) WITH CHECK (true);
REVOKE ALL ON keel_meta.webhook_delivery_attempts FROM PUBLIC,keel_app,keel_worker,keel_operator,
    keel_budget_control,keel_rate_control,keel_ai_worker,keel_projector,keel_file_processor,
    keel_retrieval_indexer,keel_context_vault,keel_context_policy,keel_context_erasure,
    keel_context_erasure_worker,keel_context_legal_hold,keel_context_replay,keel_agent,
    keel_callback,keel_webhook;

CREATE FUNCTION keel_meta.create_webhook_delivery_state()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,keel_meta AS $$
BEGIN
    INSERT INTO keel_meta.webhook_delivery_state (tenant_id,delivery_id,state,next_attempt_at)
    VALUES (NEW.tenant_id,NEW.delivery_id,'pending',NEW.created_at);
    RETURN NEW;
END $$;
CREATE TRIGGER webhook_delivery_state_created AFTER INSERT ON keel_meta.webhook_deliveries
    FOR EACH ROW EXECUTE FUNCTION keel_meta.create_webhook_delivery_state();
REVOKE ALL ON FUNCTION keel_meta.create_webhook_delivery_state() FROM PUBLIC;

INSERT INTO keel_meta.webhook_delivery_state (tenant_id,delivery_id,state,next_attempt_at)
SELECT d.tenant_id,d.delivery_id,'pending',d.created_at
  FROM keel_meta.webhook_deliveries d
 WHERE NOT EXISTS (
     SELECT 1 FROM keel_meta.webhook_delivery_state s
      WHERE s.tenant_id=d.tenant_id AND s.delivery_id=d.delivery_id);

CREATE FUNCTION keel_meta.guard_webhook_delivery_state()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    IF TG_OP='DELETE' THEN
        RAISE EXCEPTION 'webhook delivery state rows cannot be deleted';
    END IF;
    IF NEW.tenant_id<>OLD.tenant_id OR NEW.delivery_id<>OLD.delivery_id THEN
        RAISE EXCEPTION 'webhook delivery state identity is immutable';
    END IF;
    IF NEW.attempts<OLD.attempts OR NEW.lease_epoch<OLD.lease_epoch THEN
        RAISE EXCEPTION 'webhook delivery state counters are monotonic';
    END IF;
    IF OLD.first_attempt_at IS NOT NULL AND NEW.first_attempt_at IS DISTINCT FROM OLD.first_attempt_at THEN
        RAISE EXCEPTION 'webhook delivery first attempt is immutable';
    END IF;
    IF OLD.state IN ('delivered','failed','exhausted') THEN
        RAISE EXCEPTION 'webhook delivery state is terminal';
    END IF;
    IF OLD.state='pending' AND NEW.state NOT IN ('pending','in_flight') THEN
        RAISE EXCEPTION 'webhook delivery state transition is invalid';
    END IF;
    IF OLD.state='in_flight' AND NEW.state NOT IN ('in_flight','pending','delivered','failed','exhausted') THEN
        RAISE EXCEPTION 'webhook delivery state transition is invalid';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER webhook_delivery_state_guarded BEFORE UPDATE OR DELETE
    ON keel_meta.webhook_delivery_state FOR EACH ROW
    EXECUTE FUNCTION keel_meta.guard_webhook_delivery_state();
REVOKE ALL ON FUNCTION keel_meta.guard_webhook_delivery_state() FROM PUBLIC;

CREATE FUNCTION keel_meta.reject_webhook_delivery_attempt_mutation()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    RAISE EXCEPTION 'webhook delivery attempts are append-only';
END $$;
CREATE TRIGGER webhook_delivery_attempt_immutable BEFORE UPDATE OR DELETE
    ON keel_meta.webhook_delivery_attempts FOR EACH ROW
    EXECUTE FUNCTION keel_meta.reject_webhook_delivery_attempt_mutation();
REVOKE ALL ON FUNCTION keel_meta.reject_webhook_delivery_attempt_mutation() FROM PUBLIC;

CREATE FUNCTION keel_meta.lease_webhook_deliveries(p_limit integer,p_lease_seconds integer)
RETURNS TABLE(event_id text,endpoint_id text,subscription_version integer,delivery_id text,
    attempt_number integer,attempt_id text,lease_epoch bigint,lease_expires_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,keel_meta,keel_private,pg_temp AS $$
DECLARE authorized_tenant uuid;
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'keel_webhook','MEMBER') THEN
        RAISE EXCEPTION 'webhook delivery capability is required';
    END IF;
    authorized_tenant:=keel_private.current_tenant_id();
    IF authorized_tenant IS NULL THEN
        RAISE EXCEPTION 'webhook delivery tenant context is required';
    END IF;
    IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 100 OR
       p_lease_seconds IS NULL OR p_lease_seconds NOT BETWEEN 5 AND 300 THEN
        RAISE EXCEPTION 'webhook delivery lease is invalid';
    END IF;

    RETURN QUERY
    WITH due AS (
        SELECT s.tenant_id,s.delivery_id
          FROM keel_meta.webhook_delivery_state s
         WHERE s.tenant_id=authorized_tenant
           AND ((s.state='pending' AND s.next_attempt_at<=clock_timestamp())
             OR (s.state='in_flight' AND s.lease_expires_at<=clock_timestamp()))
         ORDER BY coalesce(s.next_attempt_at,s.lease_expires_at)
         LIMIT p_limit
         FOR UPDATE SKIP LOCKED
    ), leased AS (
        UPDATE keel_meta.webhook_delivery_state s
           SET state='in_flight',
               attempts=s.attempts+1,
               first_attempt_at=coalesce(s.first_attempt_at,clock_timestamp()),
               next_attempt_at=NULL,
               lease_epoch=s.lease_epoch+1,
               lease_expires_at=clock_timestamp()+(p_lease_seconds*interval '1 second'),
               updated_at=clock_timestamp()
          FROM due
         WHERE s.tenant_id=due.tenant_id AND s.delivery_id=due.delivery_id
        RETURNING s.tenant_id,s.delivery_id,s.attempts,s.lease_epoch,s.lease_expires_at
    )
    SELECT d.event_id,d.endpoint_id,d.subscription_version,l.delivery_id,l.attempts,
           gen_random_uuid()::text,l.lease_epoch,l.lease_expires_at
      FROM leased l
      JOIN keel_meta.webhook_deliveries d
        ON d.tenant_id=l.tenant_id AND d.delivery_id=l.delivery_id
     ORDER BY l.lease_expires_at,l.delivery_id;
END $$;
REVOKE ALL ON FUNCTION keel_meta.lease_webhook_deliveries(integer,integer) FROM PUBLIC;

CREATE FUNCTION keel_meta.record_webhook_attempt(
    p_delivery_id text,p_attempt_number integer,p_attempt_id text,p_lease_epoch bigint,
    p_outcome text,p_http_status integer,p_latency_ms integer,p_next_attempt_at timestamptz)
RETURNS TABLE(state text,attempts integer,next_attempt_at timestamptz,finished_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,keel_meta,keel_private,pg_temp AS $$
DECLARE authorized_tenant uuid;
        recorded_state text;
        recorded_attempts integer;
        recorded_next timestamptz;
        recorded_finished timestamptz;
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'keel_webhook','MEMBER') THEN
        RAISE EXCEPTION 'webhook delivery capability is required';
    END IF;
    authorized_tenant:=keel_private.current_tenant_id();
    IF authorized_tenant IS NULL OR
       p_delivery_id IS NULL OR p_delivery_id !~ '^[A-Za-z0-9_-]{8,64}$' OR
       p_attempt_number IS NULL OR p_attempt_number NOT BETWEEN 1 AND 100 OR
       p_attempt_id IS NULL OR p_attempt_id !~ '^[A-Za-z0-9_-]{8,64}$' OR
       p_lease_epoch IS NULL OR p_lease_epoch NOT BETWEEN 1 AND 9007199254740991 OR
       p_outcome IS NULL OR p_outcome NOT IN ('delivered','retryable','permanent') OR
       p_http_status IS NULL OR p_http_status NOT BETWEEN 0 AND 599 OR
       p_latency_ms IS NULL OR p_latency_ms NOT BETWEEN 0 AND 600000 THEN
        RAISE EXCEPTION 'webhook delivery attempt is invalid';
    END IF;
    IF p_outcome='delivered' AND p_http_status NOT BETWEEN 200 AND 299 THEN
        RAISE EXCEPTION 'webhook delivered attempt requires a 2xx status';
    END IF;
    IF p_outcome<>'retryable' AND p_next_attempt_at IS NOT NULL THEN
        RAISE EXCEPTION 'webhook terminal attempt cannot schedule a retry';
    END IF;
    IF p_next_attempt_at IS NOT NULL AND
       p_next_attempt_at<clock_timestamp()-interval '30 seconds' THEN
        RAISE EXCEPTION 'webhook retry must be scheduled in the future';
    END IF;

    UPDATE keel_meta.webhook_delivery_state s
       SET state=CASE
               WHEN p_outcome='delivered' THEN 'delivered'
               WHEN p_outcome='permanent' THEN 'failed'
               WHEN p_next_attempt_at IS NOT NULL THEN 'pending'
               ELSE 'exhausted'
           END,
           next_attempt_at=CASE WHEN p_outcome='retryable' THEN p_next_attempt_at END,
           lease_expires_at=NULL,
           delivered_at=CASE WHEN p_outcome='delivered' THEN clock_timestamp() END,
           finished_at=CASE
                   WHEN p_outcome='retryable' AND p_next_attempt_at IS NOT NULL THEN NULL
                   ELSE clock_timestamp()
               END,
           updated_at=clock_timestamp()
     WHERE s.tenant_id=authorized_tenant AND s.delivery_id=p_delivery_id
       AND s.state='in_flight' AND s.lease_epoch=p_lease_epoch AND s.attempts=p_attempt_number
    RETURNING s.state,s.attempts,s.next_attempt_at,s.finished_at
      INTO recorded_state,recorded_attempts,recorded_next,recorded_finished;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'webhook delivery attempt is not leased by this epoch';
    END IF;

    INSERT INTO keel_meta.webhook_delivery_attempts
        (tenant_id,delivery_id,attempt_number,attempt_id,lease_epoch,outcome,http_status,latency_ms)
    VALUES (authorized_tenant,p_delivery_id,p_attempt_number,p_attempt_id,p_lease_epoch,
        p_outcome,p_http_status,p_latency_ms);

    RETURN QUERY SELECT recorded_state,recorded_attempts,recorded_next,recorded_finished;
END $$;
REVOKE ALL ON FUNCTION keel_meta.record_webhook_attempt(text,integer,text,bigint,text,integer,integer,timestamptz)
    FROM PUBLIC;

GRANT EXECUTE ON FUNCTION keel_meta.lease_webhook_deliveries(integer,integer) TO keel_webhook;
GRANT EXECUTE ON FUNCTION keel_meta.record_webhook_attempt(text,integer,text,bigint,text,integer,integer,timestamptz)
    TO keel_webhook;
