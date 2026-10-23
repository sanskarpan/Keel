CREATE TABLE keel_meta.webhook_replay_transitions (
    tenant_id uuid NOT NULL CHECK (tenant_id<>'00000000-0000-0000-0000-000000000000'::uuid),
    replay_id text NOT NULL CHECK (replay_id ~ '^[A-Za-z0-9_-]{8,64}$'),
    delivery_id text NOT NULL CHECK (delivery_id ~ '^[A-Za-z0-9_-]{8,64}$'),
    prior_state text NOT NULL CHECK (prior_state IN ('failed','exhausted')),
    prior_attempts integer NOT NULL CHECK (prior_attempts BETWEEN 1 AND 100),
    prior_finished_at timestamptz NOT NULL,
    prior_lease_epoch bigint NOT NULL CHECK (prior_lease_epoch BETWEEN 0 AND 9007199254740991),
    authorized_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id,replay_id),
    CONSTRAINT webhook_replay_transitions_delivery_unique UNIQUE (tenant_id,delivery_id),
    CONSTRAINT webhook_replay_transitions_replay_fk FOREIGN KEY (tenant_id,replay_id)
        REFERENCES keel_meta.webhook_replays (tenant_id,replay_id),
    CONSTRAINT webhook_replay_transitions_delivery_fk FOREIGN KEY (tenant_id,delivery_id)
        REFERENCES keel_meta.webhook_deliveries (tenant_id,delivery_id)
);
ALTER TABLE keel_meta.webhook_replay_transitions ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.webhook_replay_transitions FORCE ROW LEVEL SECURITY;
CREATE POLICY webhook_replay_transitions_schema_owner ON keel_meta.webhook_replay_transitions
    TO keel_schema_owner USING (true) WITH CHECK (true);
REVOKE ALL ON keel_meta.webhook_replay_transitions FROM PUBLIC,keel_app,keel_worker,keel_operator,
    keel_budget_control,keel_rate_control,keel_ai_worker,keel_projector,keel_file_processor,
    keel_retrieval_indexer,keel_context_vault,keel_context_policy,keel_context_erasure,
    keel_context_erasure_worker,keel_context_legal_hold,keel_context_replay,keel_agent,
    keel_callback,keel_webhook;

CREATE FUNCTION keel_meta.reject_webhook_replay_transition_mutation()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    RAISE EXCEPTION 'webhook replay transitions are immutable';
END $$;
CREATE TRIGGER webhook_replay_transition_immutable BEFORE UPDATE OR DELETE
    ON keel_meta.webhook_replay_transitions FOR EACH ROW
    EXECUTE FUNCTION keel_meta.reject_webhook_replay_transition_mutation();
REVOKE ALL ON FUNCTION keel_meta.reject_webhook_replay_transition_mutation() FROM PUBLIC;

CREATE FUNCTION keel_meta.authorize_webhook_replay_requeue(
    p_replay_id text,p_delivery_id text,p_requested_by text,p_reason text)
RETURNS TABLE(r_replay_id text,r_delivery_id text,r_requested_by text,r_reason text,
    r_requested_at timestamptz,r_prior_state text,r_prior_attempts integer,
    r_prior_finished_at timestamptz,r_prior_lease_epoch bigint,r_authorized_at timestamptz,
    r_created boolean)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,keel_meta,keel_private,pg_temp AS $$
DECLARE authorized_tenant uuid;
        current_state text;
        current_attempts integer;
        current_finished_at timestamptz;
        current_lease_epoch bigint;
        delivery_endpoint text;
        delivery_subscription integer;
        stored_replay_id text;
        stored_delivery_id text;
        stored_requested_by text;
        stored_reason text;
        stored_requested_at timestamptz;
        transition_delivery text;
        transition_state text;
        transition_attempts integer;
        transition_finished_at timestamptz;
        transition_lease_epoch bigint;
        transition_authorized_at timestamptz;
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'keel_operator','MEMBER') THEN
        RAISE EXCEPTION 'webhook replay capability is required';
    END IF;
    authorized_tenant:=keel_private.current_tenant_id();
    IF authorized_tenant IS NULL OR
       p_replay_id IS NULL OR p_replay_id !~ '^[A-Za-z0-9_-]{8,64}$' OR
       p_delivery_id IS NULL OR p_delivery_id !~ '^[A-Za-z0-9_-]{8,64}$' OR
       p_requested_by IS NULL OR p_requested_by !~ '^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}$' OR
       p_reason IS NULL OR p_reason<>btrim(p_reason) OR
           length(p_reason) NOT BETWEEN 1 AND 512 OR p_reason ~ '[[:cntrl:]]' THEN
        RAISE EXCEPTION 'webhook replay request is invalid';
    END IF;

    SELECT s.state,s.attempts,s.finished_at,s.lease_epoch,d.endpoint_id,d.subscription_version
      INTO current_state,current_attempts,current_finished_at,current_lease_epoch,
          delivery_endpoint,delivery_subscription
      FROM keel_meta.webhook_delivery_state s
      JOIN keel_meta.webhook_deliveries d
        ON d.tenant_id=s.tenant_id AND d.delivery_id=s.delivery_id
     WHERE s.tenant_id=authorized_tenant AND s.delivery_id=p_delivery_id
     FOR UPDATE OF s;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'webhook replay delivery was not found';
    END IF;

    SELECT t.delivery_id,t.prior_state,t.prior_attempts,t.prior_finished_at,
           t.prior_lease_epoch,t.authorized_at,
           r.requested_by,r.reason,r.requested_at
      INTO transition_delivery,transition_state,transition_attempts,transition_finished_at,
          transition_lease_epoch,transition_authorized_at,
          stored_requested_by,stored_reason,stored_requested_at
      FROM keel_meta.webhook_replay_transitions t
      JOIN keel_meta.webhook_replays r
        ON r.tenant_id=t.tenant_id AND r.replay_id=t.replay_id
     WHERE t.tenant_id=authorized_tenant AND t.replay_id=p_replay_id;
    IF FOUND THEN
        IF transition_delivery<>p_delivery_id OR stored_requested_by<>p_requested_by OR
           stored_reason<>p_reason THEN
            RAISE EXCEPTION 'webhook replay request conflicts with an existing replay';
        END IF;
        RETURN QUERY SELECT p_replay_id,p_delivery_id,stored_requested_by,stored_reason,
            stored_requested_at,transition_state,transition_attempts,transition_finished_at,
            transition_lease_epoch,transition_authorized_at,false;
        RETURN;
    END IF;

    SELECT r.replay_id,r.delivery_id,r.requested_by,r.reason,r.requested_at
      INTO stored_replay_id,stored_delivery_id,stored_requested_by,stored_reason,
          stored_requested_at
      FROM keel_meta.webhook_replays r
     WHERE r.tenant_id=authorized_tenant AND r.replay_id=p_replay_id;
    IF FOUND THEN
        IF stored_delivery_id<>p_delivery_id OR stored_requested_by<>p_requested_by OR
           stored_reason<>p_reason THEN
            RAISE EXCEPTION 'webhook replay request conflicts with an existing replay';
        END IF;
    ELSE
        IF EXISTS (
            SELECT 1 FROM keel_meta.webhook_replays r
             WHERE r.tenant_id=authorized_tenant AND r.delivery_id=p_delivery_id) THEN
            RAISE EXCEPTION 'webhook delivery was already replayed';
        END IF;
    END IF;

    IF current_state NOT IN ('failed','exhausted') OR current_attempts<1 OR
       current_finished_at IS NULL THEN
        RAISE EXCEPTION 'webhook delivery is not eligible for replay';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM keel_meta.webhook_endpoints e
         WHERE e.tenant_id=authorized_tenant AND e.endpoint_id=delivery_endpoint
           AND e.subscription_version=delivery_subscription AND e.status='active'
           AND e.key_id IS NOT NULL AND e.key_id<>'') THEN
        RAISE EXCEPTION 'webhook replay endpoint is not eligible';
    END IF;

    IF stored_replay_id IS NULL THEN
        INSERT INTO keel_meta.webhook_replays
            (tenant_id,replay_id,delivery_id,requested_by,reason)
        VALUES (authorized_tenant,p_replay_id,p_delivery_id,p_requested_by,p_reason)
        ON CONFLICT DO NOTHING
        RETURNING webhook_replays.requested_by,webhook_replays.reason,
            webhook_replays.requested_at
          INTO stored_requested_by,stored_reason,stored_requested_at;
        IF NOT FOUND THEN
            SELECT r.requested_by,r.reason,r.requested_at
              INTO stored_requested_by,stored_reason,stored_requested_at
              FROM keel_meta.webhook_replays r
             WHERE r.tenant_id=authorized_tenant AND r.replay_id=p_replay_id;
            IF NOT FOUND OR stored_requested_by<>p_requested_by OR
               stored_reason<>p_reason THEN
                RAISE EXCEPTION 'webhook replay request conflicts with an existing replay';
            END IF;
        END IF;
    END IF;

    INSERT INTO keel_meta.webhook_replay_transitions
        (tenant_id,replay_id,delivery_id,prior_state,prior_attempts,prior_finished_at,
         prior_lease_epoch,authorized_at)
    VALUES (authorized_tenant,p_replay_id,p_delivery_id,current_state,current_attempts,
        current_finished_at,current_lease_epoch,clock_timestamp())
    RETURNING webhook_replay_transitions.authorized_at
      INTO transition_authorized_at;

    UPDATE keel_meta.webhook_delivery_state s
       SET state='pending',
           next_attempt_at=clock_timestamp(),
           lease_expires_at=NULL,
           delivered_at=NULL,
           finished_at=NULL,
           updated_at=clock_timestamp()
     WHERE s.tenant_id=authorized_tenant AND s.delivery_id=p_delivery_id
       AND s.state=current_state AND s.attempts=current_attempts
       AND s.finished_at IS NOT DISTINCT FROM current_finished_at
       AND s.lease_epoch=current_lease_epoch;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'webhook replay state changed during authorization';
    END IF;

    RETURN QUERY SELECT p_replay_id,p_delivery_id,stored_requested_by,stored_reason,
        stored_requested_at,current_state,current_attempts,current_finished_at,
        current_lease_epoch,transition_authorized_at,true;
END $$;
ALTER FUNCTION keel_meta.authorize_webhook_replay_requeue(text,text,text,text)
    OWNER TO keel_schema_owner;
REVOKE ALL ON FUNCTION keel_meta.authorize_webhook_replay_requeue(text,text,text,text)
    FROM PUBLIC,keel_app,keel_webhook;
GRANT EXECUTE ON FUNCTION keel_meta.authorize_webhook_replay_requeue(text,text,text,text)
    TO keel_operator;

CREATE OR REPLACE FUNCTION keel_meta.guard_webhook_delivery_state()
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
        IF OLD.state IN ('failed','exhausted') AND NEW.state='pending'
           AND NEW.attempts=OLD.attempts AND NEW.lease_epoch=OLD.lease_epoch
           AND NEW.first_attempt_at IS NOT DISTINCT FROM OLD.first_attempt_at
           AND NEW.next_attempt_at IS NOT NULL
           AND NEW.lease_expires_at IS NULL
           AND NEW.delivered_at IS NULL
           AND NEW.finished_at IS NULL
           AND EXISTS (
               SELECT 1 FROM keel_meta.webhook_replay_transitions t
                WHERE t.tenant_id=OLD.tenant_id AND t.delivery_id=OLD.delivery_id
                  AND t.prior_state=OLD.state
                  AND t.prior_attempts=OLD.attempts
                  AND t.prior_finished_at IS NOT DISTINCT FROM OLD.finished_at
                  AND t.prior_lease_epoch=OLD.lease_epoch) THEN
            RETURN NEW;
        END IF;
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
REVOKE ALL ON FUNCTION keel_meta.guard_webhook_delivery_state() FROM PUBLIC;

GRANT USAGE ON SCHEMA keel_meta,keel_private TO keel_operator;
GRANT EXECUTE ON FUNCTION keel_private.current_tenant_id() TO keel_operator;
