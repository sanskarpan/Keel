-- Freeze the review plan at submission and serialize human decisions against the
-- same case row used by Temporal deadline expiry.
ALTER TABLE keel_meta.supplier_case_events
    DROP CONSTRAINT supplier_case_events_event_type_check,
    ADD CONSTRAINT supplier_case_events_event_type_check CHECK (event_type IN (
        'supplier.case.created', 'supplier.case.evidence-added', 'supplier.case.submitted',
        'supplier.case.approval-decided', 'supplier.case.expired'
    ));
ALTER TABLE keel_meta.supplier_workflow_intents
    DROP CONSTRAINT supplier_workflow_intents_intent_type_check,
    ADD CONSTRAINT supplier_workflow_intents_intent_type_check CHECK (intent_type IN (
        'supplier.case.created', 'supplier.case.evidence-added', 'supplier.case.submitted',
        'supplier.case.approval-decided', 'supplier.case.expired'
    ));
ALTER TABLE keel_meta.supplier_workflow_dispatch
    DROP CONSTRAINT supplier_workflow_dispatch_intent_type_check,
    ADD CONSTRAINT supplier_workflow_dispatch_intent_type_check CHECK (intent_type IN (
        'supplier.case.created', 'supplier.case.evidence-added', 'supplier.case.submitted',
        'supplier.case.approval-decided', 'supplier.case.expired'
    )),
    DROP CONSTRAINT supplier_workflow_dispatch_aggregate_version_check,
    ADD CONSTRAINT supplier_workflow_dispatch_aggregate_version_check CHECK (aggregate_version BETWEEN 1 AND 135);

ALTER TABLE keel_meta.supplier_case_events
    ADD COLUMN decision_id uuid,
    ADD CONSTRAINT supplier_case_event_decision_shape CHECK
        ((event_type = 'supplier.case.approval-decided') = (decision_id IS NOT NULL)),
    ADD CONSTRAINT supplier_case_event_decision_identity UNIQUE (tenant_id, case_id, aggregate_version, decision_id);

CREATE TABLE keel_meta.supplier_case_approval_plans (
    tenant_id uuid NOT NULL,
    case_id uuid NOT NULL,
    step_key text NOT NULL CHECK (step_key ~ '^[a-z][a-z0-9._-]{0,63}$'),
    required_role text NOT NULL CHECK (required_role ~ '^[a-z][a-z0-9:_-]{0,63}$'),
    depends_on text[] NOT NULL CHECK (cardinality(depends_on) <= 32),
    policy_version integer NOT NULL,
    policy_digest bytea NOT NULL CHECK (octet_length(policy_digest) = 32),
    evidence_digest bytea NOT NULL CHECK (octet_length(evidence_digest) = 32),
    plan_digest bytea NOT NULL CHECK (octet_length(plan_digest) = 32),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, case_id, step_key),
    FOREIGN KEY (tenant_id, case_id) REFERENCES keel_meta.supplier_cases (tenant_id, case_id),
    CHECK (policy_version > 0)
);

CREATE TABLE keel_meta.supplier_case_reviewer_grants (
    tenant_id uuid NOT NULL,
    principal_ref text NOT NULL CHECK (principal_ref ~ '^principal:[A-Za-z0-9._~-]{1,120}$'),
    role_key text NOT NULL CHECK (role_key ~ '^[a-z][a-z0-9:_-]{0,63}$'),
    granted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    revoked_at timestamptz,
    PRIMARY KEY (tenant_id, principal_ref, role_key),
    CHECK (revoked_at IS NULL OR revoked_at >= granted_at)
);

CREATE TABLE keel_meta.supplier_case_delegations (
    tenant_id uuid NOT NULL,
    delegation_id uuid NOT NULL,
    delegator_ref text NOT NULL CHECK (delegator_ref ~ '^principal:[A-Za-z0-9._~-]{1,120}$'),
    delegatee_ref text NOT NULL CHECK (delegatee_ref ~ '^principal:[A-Za-z0-9._~-]{1,120}$'),
    role_key text NOT NULL CHECK (role_key ~ '^[a-z][a-z0-9:_-]{0,63}$'),
    starts_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, delegation_id),
    UNIQUE (tenant_id, delegator_ref, delegatee_ref, role_key, starts_at),
    CHECK (delegator_ref <> delegatee_ref AND expires_at > starts_at),
    CHECK (revoked_at IS NULL OR revoked_at >= created_at)
);
CREATE INDEX supplier_case_delegations_active_idx
    ON keel_meta.supplier_case_delegations (tenant_id, delegatee_ref, role_key, starts_at, expires_at)
    WHERE revoked_at IS NULL;

CREATE TABLE keel_meta.supplier_case_decisions (
    tenant_id uuid NOT NULL,
    case_id uuid NOT NULL,
    decision_id uuid NOT NULL,
    step_key text NOT NULL,
    actor_ref text NOT NULL CHECK (actor_ref ~ '^principal:[A-Za-z0-9._~-]{1,120}$'),
    effective_role text NOT NULL CHECK (effective_role ~ '^[a-z][a-z0-9:_-]{0,63}$'),
    outcome text NOT NULL CHECK (outcome IN ('approve', 'reject')),
    reason text NOT NULL DEFAULT '' CHECK (length(reason) <= 500),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    aggregate_version bigint NOT NULL,
    accepted_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, case_id, decision_id),
    UNIQUE (tenant_id, case_id, step_key),
    UNIQUE (tenant_id, decision_id),
    UNIQUE (tenant_id, case_id, aggregate_version),
    FOREIGN KEY (tenant_id, case_id, step_key)
        REFERENCES keel_meta.supplier_case_approval_plans (tenant_id, case_id, step_key),
    FOREIGN KEY (tenant_id, case_id, aggregate_version)
        REFERENCES keel_meta.supplier_case_events (tenant_id, case_id, aggregate_version)
        DEFERRABLE INITIALLY DEFERRED
);

-- A plan row is valid only for the exact case policy and evidence frozen at submit.
CREATE FUNCTION keel_meta.guard_supplier_case_approval_plan()
RETURNS trigger LANGUAGE plpgsql
SET search_path = pg_catalog, keel_meta, pg_temp
AS $$
DECLARE c keel_meta.supplier_cases%ROWTYPE; p jsonb; policy_step jsonb;
BEGIN
    SELECT * INTO c FROM keel_meta.supplier_cases
    WHERE tenant_id=NEW.tenant_id AND case_id=NEW.case_id FOR UPDATE;
    IF c.case_state <> 'collecting' OR c.policy_version <> NEW.policy_version OR
       c.policy_digest <> NEW.policy_digest OR c.evidence_digest <> NEW.evidence_digest THEN
        RAISE EXCEPTION 'approval plan must bind the case policy and evidence snapshot';
    END IF;
    SELECT policy_definition INTO p FROM keel_meta.supplier_review_policies
    WHERE tenant_id=NEW.tenant_id AND policy_id=c.policy_id AND version=c.policy_version;
    SELECT steps.value INTO policy_step FROM jsonb_array_elements(p->'steps') AS steps(value)
    WHERE steps.value->>'key'=NEW.step_key;
    IF policy_step IS NULL OR policy_step->>'role' <> NEW.required_role OR
       COALESCE(ARRAY(SELECT jsonb_array_elements_text(policy_step->'depends_on')), ARRAY[]::text[]) <> NEW.depends_on THEN
        RAISE EXCEPTION 'approval plan step differs from immutable policy';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER supplier_case_approval_plan_guard
    BEFORE INSERT ON keel_meta.supplier_case_approval_plans
    FOR EACH ROW EXECUTE FUNCTION keel_meta.guard_supplier_case_approval_plan();

-- Step decisions require current direct assignment or one active, non-revoked
-- delegation from an assigned reviewer. Chained delegation is never followed.
CREATE FUNCTION keel_meta.guard_supplier_case_decision()
RETURNS trigger LANGUAGE plpgsql
SET search_path = pg_catalog, keel_meta, pg_temp
AS $$
DECLARE c keel_meta.supplier_cases%ROWTYPE; submitter text; creator text; authorized boolean;
BEGIN
    SELECT * INTO c FROM keel_meta.supplier_cases
    WHERE tenant_id=NEW.tenant_id AND case_id=NEW.case_id FOR UPDATE;
    NEW.accepted_at := clock_timestamp();
    IF c.case_state <> 'submitted' OR c.deadline_at <= clock_timestamp() OR
       NEW.accepted_at >= c.deadline_at OR NEW.effective_role IS DISTINCT FROM (
           SELECT required_role FROM keel_meta.supplier_case_approval_plans
           WHERE tenant_id=NEW.tenant_id AND case_id=NEW.case_id AND step_key=NEW.step_key
             AND policy_digest=c.policy_digest AND evidence_digest=c.evidence_digest) THEN
        RAISE EXCEPTION 'supplier case decision is not eligible before deadline';
    END IF;
    IF EXISTS (
        SELECT 1 FROM keel_meta.supplier_case_approval_plans p
        CROSS JOIN LATERAL unnest(p.depends_on) AS dependency(step_key)
        LEFT JOIN keel_meta.supplier_case_decisions d
          ON d.tenant_id=p.tenant_id AND d.case_id=p.case_id AND d.step_key=dependency.step_key
        WHERE p.tenant_id=NEW.tenant_id AND p.case_id=NEW.case_id AND p.step_key=NEW.step_key
          AND d.outcome IS DISTINCT FROM 'approve'
    ) THEN
        RAISE EXCEPTION 'approval step dependencies are incomplete';
    END IF;
    SELECT actor_ref INTO creator FROM keel_meta.supplier_case_events
    WHERE tenant_id=NEW.tenant_id AND case_id=NEW.case_id AND aggregate_version=1;
    SELECT actor_ref INTO submitter FROM keel_meta.supplier_case_events
    WHERE tenant_id=NEW.tenant_id AND case_id=NEW.case_id AND event_type='supplier.case.submitted';
    IF NEW.actor_ref IN (creator,submitter) THEN
        RAISE EXCEPTION 'requester cannot decide own supplier case';
    END IF;
    SELECT EXISTS (
        SELECT 1 FROM keel_meta.supplier_case_reviewer_grants g
        WHERE g.tenant_id=NEW.tenant_id AND g.principal_ref=NEW.actor_ref
          AND g.role_key=NEW.effective_role AND g.revoked_at IS NULL AND g.granted_at<=NEW.accepted_at
    ) OR EXISTS (
        SELECT 1 FROM keel_meta.supplier_case_delegations d
        JOIN keel_meta.supplier_case_reviewer_grants g
          ON g.tenant_id=d.tenant_id AND g.principal_ref=d.delegator_ref AND g.role_key=d.role_key
        WHERE d.tenant_id=NEW.tenant_id AND d.delegatee_ref=NEW.actor_ref
          AND d.role_key=NEW.effective_role AND d.revoked_at IS NULL
          AND d.starts_at<=NEW.accepted_at AND NEW.accepted_at<d.expires_at
          AND g.revoked_at IS NULL AND g.granted_at<=NEW.accepted_at
    ) INTO authorized;
    IF NOT authorized THEN RAISE EXCEPTION 'approver lacks current role or delegation'; END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER supplier_case_decision_guard
    BEFORE INSERT ON keel_meta.supplier_case_decisions
    FOR EACH ROW EXECUTE FUNCTION keel_meta.guard_supplier_case_decision();

CREATE FUNCTION keel_meta.verify_supplier_case_decision_event()
RETURNS trigger LANGUAGE plpgsql
SET search_path = pg_catalog, keel_meta, pg_temp
AS $$
DECLARE e keel_meta.supplier_case_events%ROWTYPE; data jsonb; expected_state text;
    approved_count bigint; required_count bigint; case_policy_digest bytea; case_evidence_digest bytea;
BEGIN
    SELECT * INTO e FROM keel_meta.supplier_case_events
    WHERE tenant_id=NEW.tenant_id AND case_id=NEW.case_id AND aggregate_version=NEW.aggregate_version;
    IF e.event_type <> 'supplier.case.approval-decided' OR e.actor_ref <> NEW.actor_ref OR e.occurred_at <> NEW.accepted_at THEN
        RAISE EXCEPTION 'decision requires a matching immutable case event';
    END IF;
    data := convert_from(e.event_data,'UTF8')::jsonb;
    IF data->>'decision_id' <> NEW.decision_id::text OR data->>'step_key' <> NEW.step_key OR
       data->>'outcome' <> NEW.outcome THEN
        RAISE EXCEPTION 'decision differs from its immutable event';
    END IF;
    SELECT policy_digest,evidence_digest INTO case_policy_digest,case_evidence_digest
    FROM keel_meta.supplier_cases WHERE tenant_id=NEW.tenant_id AND case_id=NEW.case_id;
    IF data->>'policy_digest'<>encode(case_policy_digest,'hex') OR
       data->>'evidence_digest'<>encode(case_evidence_digest,'hex') THEN
        RAISE EXCEPTION 'decision is bound to a different policy or evidence snapshot';
    END IF;
    IF NEW.outcome='reject' THEN
        expected_state := 'rejected';
    ELSE
        SELECT count(*) INTO required_count FROM keel_meta.supplier_case_approval_plans
        WHERE tenant_id=NEW.tenant_id AND case_id=NEW.case_id;
        SELECT count(*) INTO approved_count FROM keel_meta.supplier_case_decisions
        WHERE tenant_id=NEW.tenant_id AND case_id=NEW.case_id AND outcome='approve';
        expected_state := CASE WHEN approved_count=required_count THEN 'approved' ELSE 'submitted' END;
    END IF;
    IF data->>'resulting_state'<>expected_state THEN
        RAISE EXCEPTION 'decision result does not match frozen approval plan completion';
    END IF;
    RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER supplier_case_decision_event_guard
    AFTER INSERT ON keel_meta.supplier_case_decisions
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION keel_meta.verify_supplier_case_decision_event();

-- Replace the snapshot invariant so terminal states can only be reached by the
-- corresponding immutable decision/expiry event. Each case row remains the lock.
CREATE OR REPLACE FUNCTION keel_meta.verify_supplier_case_snapshot_event()
RETURNS trigger LANGUAGE plpgsql
SET search_path = pg_catalog, keel_meta, pg_temp
AS $$
DECLARE tail_type text; tail_hash bytea; tail_evidence_id uuid; evidence_events bigint; tail_data jsonb;
    plan_count bigint; policy_step_count integer;
BEGIN
    SELECT event_type,event_hash,evidence_id INTO tail_type,tail_hash,tail_evidence_id
    FROM keel_meta.supplier_case_events WHERE tenant_id=NEW.tenant_id AND case_id=NEW.case_id
      AND aggregate_version=NEW.aggregate_version;
    IF tail_hash IS NULL OR tail_hash<>NEW.last_event_hash OR
       (SELECT count(*) FROM keel_meta.supplier_case_events WHERE tenant_id=NEW.tenant_id AND case_id=NEW.case_id)<>NEW.aggregate_version THEN
        RAISE EXCEPTION 'supplier case snapshot must match a contiguous immutable event tail';
    END IF;
    SELECT count(*) INTO evidence_events FROM keel_meta.supplier_case_events
    WHERE tenant_id=NEW.tenant_id AND case_id=NEW.case_id AND event_type='supplier.case.evidence-added';
    IF evidence_events<>NEW.evidence_epoch THEN RAISE EXCEPTION 'supplier case evidence epoch must match event history'; END IF;
    IF NEW.case_state IN ('submitted','approved','rejected') OR
       (NEW.case_state='expired' AND EXISTS (
          SELECT 1 FROM keel_meta.supplier_case_events submitted_event
          WHERE submitted_event.tenant_id=NEW.tenant_id AND submitted_event.case_id=NEW.case_id
            AND submitted_event.event_type='supplier.case.submitted')) THEN
        SELECT count(*) INTO plan_count FROM keel_meta.supplier_case_approval_plans
        WHERE tenant_id=NEW.tenant_id AND case_id=NEW.case_id
          AND policy_version=NEW.policy_version AND policy_digest=NEW.policy_digest
          AND evidence_digest=NEW.evidence_digest;
        SELECT jsonb_array_length(policy_definition->'steps') INTO policy_step_count
        FROM keel_meta.supplier_review_policies WHERE tenant_id=NEW.tenant_id
          AND policy_id=NEW.policy_id AND version=NEW.policy_version;
        IF plan_count<>policy_step_count THEN RAISE EXCEPTION 'case approval plan must exactly match the frozen policy'; END IF;
    END IF;
    IF tail_type IN ('supplier.case.approval-decided','supplier.case.expired') THEN
        tail_data := convert_from((SELECT event_data FROM keel_meta.supplier_case_events WHERE tenant_id=NEW.tenant_id AND case_id=NEW.case_id AND aggregate_version=NEW.aggregate_version),'UTF8')::jsonb;
    END IF;
    IF NOT ((NEW.case_state='collecting' AND tail_type IN ('supplier.case.created','supplier.case.evidence-added')) OR
            (NEW.case_state='submitted' AND tail_type='supplier.case.submitted') OR
            (NEW.case_state IN ('submitted','approved','rejected') AND tail_type='supplier.case.approval-decided' AND tail_data->>'resulting_state'=NEW.case_state) OR
            (NEW.case_state='expired' AND tail_type='supplier.case.expired')) THEN
        RAISE EXCEPTION 'supplier case state must match the immutable event tail';
    END IF;
    IF (tail_type='supplier.case.evidence-added')<>(tail_evidence_id IS NOT NULL) THEN RAISE EXCEPTION 'evidence event link invalid'; END IF;
    RETURN NULL;
END $$;

ALTER TABLE keel_meta.supplier_case_approval_plans ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.supplier_case_approval_plans FORCE ROW LEVEL SECURITY;
CREATE POLICY supplier_case_approval_plans_tenant ON keel_meta.supplier_case_approval_plans
    TO keel_app USING (tenant_id=(SELECT keel_private.current_tenant_id()))
    WITH CHECK (tenant_id=(SELECT keel_private.current_tenant_id()));
ALTER TABLE keel_meta.supplier_case_reviewer_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.supplier_case_reviewer_grants FORCE ROW LEVEL SECURITY;
CREATE POLICY supplier_case_reviewer_grants_tenant ON keel_meta.supplier_case_reviewer_grants
    TO keel_app USING (tenant_id=(SELECT keel_private.current_tenant_id()))
    WITH CHECK (tenant_id=(SELECT keel_private.current_tenant_id()));
ALTER TABLE keel_meta.supplier_case_delegations ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.supplier_case_delegations FORCE ROW LEVEL SECURITY;
CREATE POLICY supplier_case_delegations_tenant ON keel_meta.supplier_case_delegations
    TO keel_app USING (tenant_id=(SELECT keel_private.current_tenant_id()))
    WITH CHECK (tenant_id=(SELECT keel_private.current_tenant_id()));
ALTER TABLE keel_meta.supplier_case_decisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.supplier_case_decisions FORCE ROW LEVEL SECURITY;
CREATE POLICY supplier_case_decisions_tenant ON keel_meta.supplier_case_decisions
    TO keel_app USING (tenant_id=(SELECT keel_private.current_tenant_id()))
    WITH CHECK (tenant_id=(SELECT keel_private.current_tenant_id()));

REVOKE ALL ON keel_meta.supplier_case_approval_plans, keel_meta.supplier_case_reviewer_grants,
    keel_meta.supplier_case_delegations, keel_meta.supplier_case_decisions FROM PUBLIC, keel_agent,
    keel_worker, keel_projector, keel_operator, keel_file_processor;
GRANT SELECT, INSERT ON keel_meta.supplier_case_approval_plans TO keel_app;
GRANT SELECT ON keel_meta.supplier_case_reviewer_grants, keel_meta.supplier_case_delegations TO keel_app;
GRANT SELECT, INSERT ON keel_meta.supplier_case_decisions TO keel_app;
GRANT EXECUTE ON FUNCTION keel_meta.guard_supplier_case_approval_plan(), keel_meta.guard_supplier_case_decision(),
    keel_meta.verify_supplier_case_decision_event(), keel_meta.verify_supplier_case_snapshot_event() TO keel_app;
