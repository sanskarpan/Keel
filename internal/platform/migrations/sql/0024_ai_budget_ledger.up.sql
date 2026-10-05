CREATE TABLE keel_meta.ai_budget_accounts (
    tenant_id uuid NOT NULL,
    period_id uuid NOT NULL,
    scope text NOT NULL CHECK (scope = 'inference'),
    period_start timestamptz NOT NULL,
    period_end timestamptz NOT NULL,
    currency text NOT NULL CHECK (currency = 'USD'),
    hard_limit_micro_usd bigint NOT NULL CHECK (hard_limit_micro_usd > 0),
    committed_micro_usd numeric NOT NULL DEFAULT 0 CHECK (committed_micro_usd >= 0),
    reserved_micro_usd numeric NOT NULL DEFAULT 0 CHECK (reserved_micro_usd >= 0),
    overrun_blocked boolean NOT NULL DEFAULT false,
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, period_id, scope),
    CHECK (period_start < period_end)
);

-- Exactly one selected period is addressable for new admissions per tenant/scope. Older account
-- rows remain available for settlement by their immutable period identity.
CREATE TABLE keel_meta.ai_budget_period_heads (
    tenant_id uuid NOT NULL,
    scope text NOT NULL CHECK (scope = 'inference'),
    period_id uuid NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, scope),
    FOREIGN KEY (tenant_id, period_id, scope)
        REFERENCES keel_meta.ai_budget_accounts (tenant_id, period_id, scope)
);

CREATE TABLE keel_meta.ai_inference_admissions (
    tenant_id uuid NOT NULL,
    inference_id uuid NOT NULL,
    attempt_id uuid NOT NULL,
    period_id uuid NOT NULL,
    scope text NOT NULL CHECK (scope = 'inference'),
    principal_binding_sha256 bytea NOT NULL CHECK (octet_length(principal_binding_sha256) = 32),
    request_sha256 bytea NOT NULL CHECK (octet_length(request_sha256) = 32),
    policy_sha256 bytea NOT NULL CHECK (octet_length(policy_sha256) = 32),
    rate_card_id text NOT NULL CHECK (length(rate_card_id) BETWEEN 1 AND 80),
    rate_card_version text NOT NULL CHECK (length(rate_card_version) BETWEEN 1 AND 40),
    rate_card_sha256 bytea NOT NULL CHECK (octet_length(rate_card_sha256) = 32),
    quote_sha256 bytea NOT NULL CHECK (octet_length(quote_sha256) = 32),
    max_liability_micro_usd bigint NOT NULL CHECK (max_liability_micro_usd > 0),
    currency text NOT NULL CHECK (currency = 'USD'),
    quoted_at timestamptz NOT NULL,
    rate_effective_from timestamptz NOT NULL,
    rate_effective_until timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK (rate_effective_from <= quoted_at AND quoted_at < rate_effective_until),
    PRIMARY KEY (tenant_id, inference_id),
    UNIQUE (tenant_id, attempt_id),
    UNIQUE (tenant_id, inference_id, attempt_id),
    UNIQUE (tenant_id, inference_id, attempt_id, period_id, scope),
    FOREIGN KEY (tenant_id, period_id, scope)
        REFERENCES keel_meta.ai_budget_accounts (tenant_id, period_id, scope)
);

CREATE TABLE keel_meta.ai_budget_reservations (
    tenant_id uuid NOT NULL,
    reservation_id uuid NOT NULL,
    inference_id uuid NOT NULL,
    attempt_id uuid NOT NULL,
    period_id uuid NOT NULL,
    scope text NOT NULL CHECK (scope = 'inference'),
    amount_micro_usd bigint NOT NULL CHECK (amount_micro_usd > 0),
    liability_state text NOT NULL CHECK (liability_state IN ('reserved', 'unknown', 'settled', 'released')),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, reservation_id),
    UNIQUE (tenant_id, inference_id),
    UNIQUE (tenant_id, attempt_id),
    FOREIGN KEY (tenant_id, inference_id, attempt_id, period_id, scope)
        REFERENCES keel_meta.ai_inference_admissions (tenant_id, inference_id, attempt_id, period_id, scope),
    FOREIGN KEY (tenant_id, period_id, scope)
        REFERENCES keel_meta.ai_budget_accounts (tenant_id, period_id, scope)
);
CREATE INDEX ai_budget_reservations_period_state_idx
    ON keel_meta.ai_budget_reservations (tenant_id, period_id, liability_state);

CREATE TABLE keel_meta.ai_usage_ledger (
    tenant_id uuid NOT NULL,
    entry_id uuid NOT NULL,
    inference_id uuid NOT NULL,
    attempt_id uuid NOT NULL,
    entry_kind text NOT NULL CHECK (entry_kind IN ('unknown', 'estimated', 'confirmed', 'no_charge', 'reconciliation', 'adjustment')),
    amount_micro_usd bigint NOT NULL CHECK (entry_kind = 'adjustment' OR amount_micro_usd >= 0),
    confidence text NOT NULL CHECK (confidence IN ('exact', 'estimated', 'unknown')),
    currency text NOT NULL CHECK (currency = 'USD'),
    source_ref text NOT NULL CHECK (length(source_ref) BETWEEN 1 AND 160),
    reconciled_by text CHECK (reconciled_by IS NULL OR reconciled_by ~ '^principal:[A-Za-z0-9._~-]{1,120}$'),
    reason_code text CHECK (reason_code IS NULL OR reason_code ~ '^[a-z][a-z0-9_]{1,39}$'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, entry_id),
    UNIQUE (tenant_id, attempt_id, entry_kind, source_ref),
    FOREIGN KEY (tenant_id, inference_id, attempt_id)
        REFERENCES keel_meta.ai_inference_admissions (tenant_id, inference_id, attempt_id),
    CHECK ((entry_kind = 'unknown') = (confidence = 'unknown')),
    CHECK ((entry_kind = 'estimated') = (confidence = 'estimated')),
    CHECK (entry_kind NOT IN ('confirmed', 'no_charge', 'reconciliation', 'adjustment') OR confidence = 'exact'),
    CHECK (entry_kind NOT IN ('reconciliation','adjustment') OR (reconciled_by IS NOT NULL AND reason_code IS NOT NULL)),
    CHECK (entry_kind IN ('reconciliation','adjustment') OR (reconciled_by IS NULL AND reason_code IS NULL)),
    CHECK (entry_kind <> 'no_charge' OR amount_micro_usd = 0)
);
CREATE INDEX ai_usage_ledger_inference_idx
    ON keel_meta.ai_usage_ledger (tenant_id, inference_id, created_at);

CREATE TABLE keel_meta.ai_budget_control_events (
    tenant_id uuid NOT NULL,
    event_id uuid NOT NULL,
    period_id uuid NOT NULL,
    scope text NOT NULL CHECK (scope = 'inference'),
    actor_ref text NOT NULL CHECK (actor_ref ~ '^principal:[A-Za-z0-9._~-]{1,120}$'),
    reason_code text NOT NULL CHECK (reason_code ~ '^[a-z][a-z0-9_]{1,39}$'),
    previous_limit_micro_usd bigint NOT NULL CHECK (previous_limit_micro_usd > 0),
    new_limit_micro_usd bigint NOT NULL CHECK (new_limit_micro_usd > 0),
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, event_id),
    FOREIGN KEY (tenant_id, period_id, scope)
        REFERENCES keel_meta.ai_budget_accounts (tenant_id, period_id, scope)
);

ALTER TABLE keel_meta.ai_budget_accounts ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.ai_budget_accounts FORCE ROW LEVEL SECURITY;
CREATE POLICY ai_budget_accounts_tenant ON keel_meta.ai_budget_accounts
    TO keel_app, keel_budget_control USING (tenant_id = (SELECT keel_private.current_tenant_id()))
    WITH CHECK (tenant_id = (SELECT keel_private.current_tenant_id()));
CREATE POLICY ai_budget_accounts_schema_owner ON keel_meta.ai_budget_accounts
    TO keel_schema_owner USING (true) WITH CHECK (true);
ALTER TABLE keel_meta.ai_budget_period_heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.ai_budget_period_heads FORCE ROW LEVEL SECURITY;
CREATE POLICY ai_budget_period_heads_tenant ON keel_meta.ai_budget_period_heads
    TO keel_app, keel_budget_control USING (tenant_id = (SELECT keel_private.current_tenant_id()))
    WITH CHECK (tenant_id = (SELECT keel_private.current_tenant_id()));
ALTER TABLE keel_meta.ai_inference_admissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.ai_inference_admissions FORCE ROW LEVEL SECURITY;
CREATE POLICY ai_inference_admissions_tenant ON keel_meta.ai_inference_admissions
    TO keel_app USING (tenant_id = (SELECT keel_private.current_tenant_id()))
    WITH CHECK (tenant_id = (SELECT keel_private.current_tenant_id()));
ALTER TABLE keel_meta.ai_budget_reservations ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.ai_budget_reservations FORCE ROW LEVEL SECURITY;
CREATE POLICY ai_budget_reservations_tenant ON keel_meta.ai_budget_reservations
    TO keel_app USING (tenant_id = (SELECT keel_private.current_tenant_id()))
    WITH CHECK (tenant_id = (SELECT keel_private.current_tenant_id()));
ALTER TABLE keel_meta.ai_usage_ledger ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.ai_usage_ledger FORCE ROW LEVEL SECURITY;
CREATE POLICY ai_usage_ledger_tenant ON keel_meta.ai_usage_ledger
    TO keel_app USING (tenant_id = (SELECT keel_private.current_tenant_id()))
    WITH CHECK (tenant_id = (SELECT keel_private.current_tenant_id()));
ALTER TABLE keel_meta.ai_budget_control_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.ai_budget_control_events FORCE ROW LEVEL SECURITY;
CREATE POLICY ai_budget_control_events_tenant ON keel_meta.ai_budget_control_events
    TO keel_budget_control USING (tenant_id = (SELECT keel_private.current_tenant_id()))
    WITH CHECK (tenant_id = (SELECT keel_private.current_tenant_id()));
CREATE POLICY ai_budget_control_events_schema_owner ON keel_meta.ai_budget_control_events
    TO keel_schema_owner USING (true) WITH CHECK (true);

REVOKE ALL ON keel_meta.ai_budget_accounts, keel_meta.ai_budget_period_heads, keel_meta.ai_inference_admissions,
    keel_meta.ai_budget_reservations, keel_meta.ai_usage_ledger,
    keel_meta.ai_budget_control_events FROM PUBLIC;
GRANT USAGE ON SCHEMA keel_meta TO keel_app, keel_budget_control;
GRANT SELECT ON keel_meta.ai_budget_accounts TO keel_app;
GRANT SELECT ON keel_meta.ai_budget_period_heads TO keel_app, keel_budget_control;
GRANT UPDATE (committed_micro_usd, reserved_micro_usd, overrun_blocked, version)
    ON keel_meta.ai_budget_accounts TO keel_app;
GRANT SELECT ON keel_meta.ai_budget_accounts TO keel_budget_control;
GRANT SELECT ON keel_meta.ai_budget_control_events TO keel_budget_control;
GRANT SELECT, INSERT ON keel_meta.ai_inference_admissions TO keel_app;
GRANT SELECT, INSERT ON keel_meta.ai_budget_reservations TO keel_app;
GRANT UPDATE (liability_state) ON keel_meta.ai_budget_reservations TO keel_app;
GRANT SELECT, INSERT ON keel_meta.ai_usage_ledger TO keel_app;

CREATE FUNCTION keel_meta.raise_ai_budget_limit(
    p_tenant_id uuid, p_event_id uuid, p_period_id uuid, p_actor_ref text, p_reason_code text, p_new_limit bigint
) RETURNS void LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, keel_meta, keel_private, pg_temp AS $$
DECLARE
    prior_limit bigint;
    committed_total numeric;
    reserved_total numeric;
    prior_period_id uuid;
    prior_actor_ref text;
    prior_reason_code text;
    prior_new_limit bigint;
BEGIN
    IF p_tenant_id IS DISTINCT FROM keel_private.current_tenant_id() THEN
        RAISE EXCEPTION 'budget-control tenant context mismatch';
    END IF;
    IF p_event_id IS NULL OR p_period_id IS NULL OR p_new_limit <= 0
       OR p_actor_ref !~ '^principal:[A-Za-z0-9._~-]{1,120}$'
       OR p_reason_code !~ '^[a-z][a-z0-9_]{1,39}$' THEN
        RAISE EXCEPTION 'invalid budget-control event';
    END IF;
    SELECT hard_limit_micro_usd, committed_micro_usd, reserved_micro_usd
      INTO prior_limit, committed_total, reserved_total
      FROM keel_meta.ai_budget_accounts
     WHERE tenant_id=p_tenant_id AND period_id=p_period_id AND scope='inference'
     FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'budget account is unavailable'; END IF;
    SELECT period_id,actor_ref,reason_code,new_limit_micro_usd
      INTO prior_period_id,prior_actor_ref,prior_reason_code,prior_new_limit
      FROM keel_meta.ai_budget_control_events
     WHERE tenant_id=p_tenant_id AND event_id=p_event_id;
    IF FOUND THEN
        IF prior_period_id=p_period_id AND prior_actor_ref=p_actor_ref
           AND prior_reason_code=p_reason_code AND prior_new_limit=p_new_limit THEN
            RETURN;
        END IF;
        RAISE EXCEPTION 'budget-control event ID conflicts with an earlier operation';
    END IF;
    IF committed_total + reserved_total > p_new_limit THEN
        RAISE EXCEPTION 'new budget limit is below committed and reserved liability';
    END IF;
    UPDATE keel_meta.ai_budget_accounts
       SET hard_limit_micro_usd=p_new_limit, overrun_blocked=false, version=version+1
     WHERE tenant_id=p_tenant_id AND period_id=p_period_id AND scope='inference';
    INSERT INTO keel_meta.ai_budget_control_events
        (tenant_id,event_id,period_id,scope,actor_ref,reason_code,previous_limit_micro_usd,new_limit_micro_usd)
    VALUES (p_tenant_id,p_event_id,p_period_id,'inference',p_actor_ref,p_reason_code,prior_limit,p_new_limit);
END $$;
REVOKE ALL ON FUNCTION keel_meta.raise_ai_budget_limit(uuid,uuid,uuid,text,text,bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION keel_meta.raise_ai_budget_limit(uuid,uuid,uuid,text,text,bigint) TO keel_budget_control;

CREATE FUNCTION keel_meta.guard_ai_budget_reservation_transition()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, keel_meta, pg_temp AS $$
BEGIN
    IF (OLD.tenant_id, OLD.reservation_id, OLD.inference_id, OLD.attempt_id, OLD.period_id, OLD.scope, OLD.amount_micro_usd, OLD.created_at)
       IS DISTINCT FROM
       (NEW.tenant_id, NEW.reservation_id, NEW.inference_id, NEW.attempt_id, NEW.period_id, NEW.scope, NEW.amount_micro_usd, NEW.created_at) THEN
        RAISE EXCEPTION 'AI reservation identity and amount are immutable';
    END IF;
    IF OLD.liability_state = NEW.liability_state THEN RETURN NEW; END IF;
    IF NOT ((OLD.liability_state = 'reserved' AND NEW.liability_state IN ('unknown','settled','released')) OR
            (OLD.liability_state = 'unknown' AND NEW.liability_state IN ('settled','released'))) THEN
        RAISE EXCEPTION 'invalid AI reservation liability transition';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER ai_budget_reservation_transition_guard
    BEFORE UPDATE ON keel_meta.ai_budget_reservations
    FOR EACH ROW EXECUTE FUNCTION keel_meta.guard_ai_budget_reservation_transition();

CREATE FUNCTION keel_meta.guard_ai_budget_reopen()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, keel_meta, pg_temp AS $$
BEGIN
    IF OLD.overrun_blocked AND NOT NEW.overrun_blocked
       AND current_user <> 'keel_schema_owner' THEN
        RAISE EXCEPTION 'overrun recovery must use the authorized budget-control function';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER ai_budget_reopen_guard
    BEFORE UPDATE OF overrun_blocked ON keel_meta.ai_budget_accounts
    FOR EACH ROW EXECUTE FUNCTION keel_meta.guard_ai_budget_reopen();

CREATE FUNCTION keel_meta.reject_ai_ledger_mutation()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, keel_meta, pg_temp AS $$
BEGIN
    RAISE EXCEPTION 'AI usage and budget control ledgers are append-only';
END $$;
CREATE TRIGGER ai_usage_ledger_immutable
    BEFORE UPDATE OR DELETE ON keel_meta.ai_usage_ledger
    FOR EACH ROW EXECUTE FUNCTION keel_meta.reject_ai_ledger_mutation();
CREATE TRIGGER ai_budget_control_events_immutable
    BEFORE UPDATE OR DELETE ON keel_meta.ai_budget_control_events
    FOR EACH ROW EXECUTE FUNCTION keel_meta.reject_ai_ledger_mutation();
