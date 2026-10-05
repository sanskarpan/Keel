-- Canceled cases, audited evidence review, and idempotent provider-neutral reminders.
ALTER TABLE keel_meta.supplier_case_events
    DROP CONSTRAINT supplier_case_events_event_type_check,
    ADD CONSTRAINT supplier_case_events_event_type_check CHECK (event_type IN (
        'supplier.case.created', 'supplier.case.evidence-added', 'supplier.case.submitted',
        'supplier.case.approval-decided', 'supplier.case.expired', 'supplier.case.canceled',
        'supplier.case.manual-review-requested', 'supplier.case.manual-review-resolved'
    )),
    ADD COLUMN cancellation_id uuid,
    ADD COLUMN manual_review_id uuid,
    ADD CONSTRAINT supplier_case_event_cancellation_shape CHECK
        ((event_type = 'supplier.case.canceled') = (cancellation_id IS NOT NULL)),
    ADD CONSTRAINT supplier_case_event_cancellation_identity UNIQUE (tenant_id,case_id,aggregate_version,cancellation_id),
    ADD CONSTRAINT supplier_case_event_manual_review_shape CHECK
        ((event_type IN ('supplier.case.manual-review-requested','supplier.case.manual-review-resolved')) = (manual_review_id IS NOT NULL)),
    ADD CONSTRAINT supplier_case_event_manual_review_identity UNIQUE (tenant_id,case_id,aggregate_version,manual_review_id);

ALTER TABLE keel_meta.supplier_workflow_intents
    DROP CONSTRAINT supplier_workflow_intents_intent_type_check,
    ADD CONSTRAINT supplier_workflow_intents_intent_type_check CHECK (intent_type IN (
        'supplier.case.created', 'supplier.case.evidence-added', 'supplier.case.submitted',
        'supplier.case.approval-decided', 'supplier.case.expired', 'supplier.case.canceled',
        'supplier.case.manual-review-requested', 'supplier.case.manual-review-resolved'
    ));

ALTER TABLE keel_meta.supplier_workflow_dispatch
    DROP CONSTRAINT supplier_workflow_dispatch_intent_type_check,
    ADD CONSTRAINT supplier_workflow_dispatch_intent_type_check CHECK (intent_type IN (
        'supplier.case.created', 'supplier.case.evidence-added', 'supplier.case.submitted',
        'supplier.case.approval-decided', 'supplier.case.expired', 'supplier.case.canceled',
        'supplier.case.manual-review-requested', 'supplier.case.manual-review-resolved'
    )),
    DROP CONSTRAINT supplier_workflow_dispatch_aggregate_version_check,
    ADD CONSTRAINT supplier_workflow_dispatch_aggregate_version_check CHECK (aggregate_version BETWEEN 1 AND 138);

ALTER TABLE keel_meta.supplier_invitations
    DROP CONSTRAINT supplier_invitations_check,
    ADD CONSTRAINT supplier_invitations_acceptance_history_check
        CHECK ((invitation_state='accepted' AND accepted_at IS NOT NULL) OR
               (invitation_state IN ('pending','expired') AND accepted_at IS NULL) OR invitation_state='revoked');

CREATE TABLE keel_meta.supplier_case_manual_reviews (
    tenant_id uuid NOT NULL,
    case_id uuid NOT NULL,
    review_id uuid NOT NULL,
    evidence_id uuid NOT NULL,
    evidence_digest bytea NOT NULL CHECK (octet_length(evidence_digest)=32),
    requested_by_ref text NOT NULL CHECK (requested_by_ref ~ '^(principal|service-principal):[A-Za-z0-9._~-]{1,120}$'),
    request_reason text NOT NULL CHECK (length(request_reason) BETWEEN 1 AND 500),
    state text NOT NULL CHECK (state IN ('open','confirmed','replacement-required')),
    requested_event_version bigint NOT NULL CHECK (requested_event_version > 0),
    resolved_event_version bigint,
    resolved_by_ref text CHECK (resolved_by_ref IS NULL OR resolved_by_ref ~ '^(principal|service-principal):[A-Za-z0-9._~-]{1,120}$'),
    resolution_reason text CHECK (resolution_reason IS NULL OR length(resolution_reason) BETWEEN 1 AND 500),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    resolved_at timestamptz,
    PRIMARY KEY (tenant_id,case_id,review_id),
    FOREIGN KEY (tenant_id,case_id) REFERENCES keel_meta.supplier_cases (tenant_id,case_id),
    FOREIGN KEY (tenant_id,case_id,evidence_id) REFERENCES keel_meta.supplier_case_evidence (tenant_id,case_id,evidence_id),
    FOREIGN KEY (tenant_id,case_id,requested_event_version) REFERENCES keel_meta.supplier_case_events (tenant_id,case_id,aggregate_version) DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (tenant_id,case_id,resolved_event_version) REFERENCES keel_meta.supplier_case_events (tenant_id,case_id,aggregate_version) DEFERRABLE INITIALLY DEFERRED,
    CHECK ((state='open' AND resolved_event_version IS NULL AND resolved_by_ref IS NULL AND resolution_reason IS NULL AND resolved_at IS NULL)
        OR (state<>'open' AND resolved_event_version IS NOT NULL AND resolved_by_ref IS NOT NULL AND resolution_reason IS NOT NULL AND resolved_at IS NOT NULL))
);
CREATE UNIQUE INDEX supplier_case_manual_review_one_open_per_evidence
    ON keel_meta.supplier_case_manual_reviews (tenant_id,case_id,evidence_id) WHERE state='open';

CREATE TABLE keel_meta.supplier_case_activity_effects (
    tenant_id uuid NOT NULL,
    effect_id uuid NOT NULL,
    case_id uuid NOT NULL,
    effect_key text NOT NULL CHECK (length(effect_key) BETWEEN 1 AND 180),
    effect_type text NOT NULL CHECK (effect_type IN ('case_reminder','case_expiry')),
    occurrence text NOT NULL CHECK (occurrence IN ('midpoint','deadline-minus-one-hour','deadline')),
    due_at timestamptz NOT NULL,
    payload jsonb NOT NULL CHECK (jsonb_typeof(payload)='object' AND payload->>'case_id'=case_id::text AND payload->>'occurrence'=occurrence),
    payload_digest bytea NOT NULL CHECK (octet_length(payload_digest)=32),
    effect_state text NOT NULL DEFAULT 'pending' CHECK (effect_state IN ('pending','leased','delivered','dead','canceled')),
    available_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count BETWEEN 0 AND 12),
    lease_owner uuid,
    lease_epoch bigint NOT NULL DEFAULT 0 CHECK (lease_epoch>=0),
    lease_expires_at timestamptz,
    delivered_at timestamptz,
    last_error_code text CHECK (last_error_code IS NULL OR last_error_code IN ('sink_unavailable','sink_timeout','permanent_rejection','unknown')),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id,effect_id),
    UNIQUE (tenant_id,effect_key),
    FOREIGN KEY (tenant_id,case_id) REFERENCES keel_meta.supplier_cases (tenant_id,case_id),
    CHECK ((effect_type='case_expiry')=(occurrence='deadline')),
    CHECK ((effect_state='leased' AND lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL)
        OR (effect_state<>'leased' AND lease_owner IS NULL AND lease_expires_at IS NULL)),
    CHECK ((effect_state='delivered')=(delivered_at IS NOT NULL)),
    CHECK (effect_state<>'dead' OR (last_error_code IS NOT NULL AND attempt_count>0))
);
CREATE INDEX supplier_case_activity_effects_due_idx
    ON keel_meta.supplier_case_activity_effects (tenant_id,available_at,due_at,effect_id)
    WHERE effect_state IN ('pending','leased');

ALTER TABLE keel_meta.supplier_case_manual_reviews ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.supplier_case_manual_reviews FORCE ROW LEVEL SECURITY;
CREATE POLICY supplier_case_manual_reviews_tenant ON keel_meta.supplier_case_manual_reviews
    TO keel_app USING (tenant_id=(SELECT keel_private.current_tenant_id()))
    WITH CHECK (tenant_id=(SELECT keel_private.current_tenant_id()));
ALTER TABLE keel_meta.supplier_case_activity_effects ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.supplier_case_activity_effects FORCE ROW LEVEL SECURITY;
CREATE POLICY supplier_case_activity_effects_app ON keel_meta.supplier_case_activity_effects
    FOR INSERT TO keel_app WITH CHECK (tenant_id=(SELECT keel_private.current_tenant_id()));
CREATE POLICY supplier_case_activity_effects_worker ON keel_meta.supplier_case_activity_effects
    FOR ALL TO keel_worker USING (tenant_id=(SELECT keel_private.current_tenant_id()))
    WITH CHECK (tenant_id=(SELECT keel_private.current_tenant_id()));
CREATE POLICY supplier_case_activity_effects_owner ON keel_meta.supplier_case_activity_effects
    FOR ALL TO keel_schema_owner USING (true) WITH CHECK (true);
CREATE POLICY supplier_case_manual_reviews_owner ON keel_meta.supplier_case_manual_reviews
    FOR ALL TO keel_schema_owner USING (true) WITH CHECK (true);

REVOKE ALL ON keel_meta.supplier_case_manual_reviews,keel_meta.supplier_case_activity_effects FROM PUBLIC,keel_agent,keel_worker,keel_projector,keel_operator,keel_file_processor;
GRANT SELECT,INSERT ON keel_meta.supplier_case_manual_reviews TO keel_app;
GRANT UPDATE (state,resolved_event_version,resolved_by_ref,resolution_reason,resolved_at)
    ON keel_meta.supplier_case_manual_reviews TO keel_app;
GRANT SELECT,UPDATE ON keel_meta.supplier_case_activity_effects TO keel_worker;

CREATE OR REPLACE FUNCTION keel_meta.verify_supplier_case_snapshot_event()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, keel_meta, pg_temp
AS $$
DECLARE tail_type text; tail_hash bytea; tail_evidence_id uuid; evidence_events bigint;
    tail_data jsonb; plan_count bigint; policy_step_count integer;
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
       (NEW.case_state IN ('expired','canceled') AND EXISTS (
          SELECT 1 FROM keel_meta.supplier_case_events se WHERE se.tenant_id=NEW.tenant_id AND se.case_id=NEW.case_id
            AND se.event_type='supplier.case.submitted')) THEN
        SELECT count(*) INTO plan_count FROM keel_meta.supplier_case_approval_plans
        WHERE tenant_id=NEW.tenant_id AND case_id=NEW.case_id AND policy_version=NEW.policy_version
          AND policy_digest=NEW.policy_digest AND evidence_digest=NEW.evidence_digest;
        SELECT jsonb_array_length(policy_definition->'steps') INTO policy_step_count
        FROM keel_meta.supplier_review_policies WHERE tenant_id=NEW.tenant_id AND policy_id=NEW.policy_id AND version=NEW.policy_version;
        IF plan_count<>policy_step_count THEN RAISE EXCEPTION 'case approval plan must exactly match the frozen policy'; END IF;
    END IF;
    IF tail_type IN ('supplier.case.approval-decided','supplier.case.expired','supplier.case.canceled',
       'supplier.case.manual-review-requested','supplier.case.manual-review-resolved') THEN
        tail_data:=convert_from((SELECT event_data FROM keel_meta.supplier_case_events WHERE tenant_id=NEW.tenant_id
          AND case_id=NEW.case_id AND aggregate_version=NEW.aggregate_version),'UTF8')::jsonb;
    END IF;
    IF NOT ((NEW.case_state='collecting' AND tail_type IN ('supplier.case.created','supplier.case.evidence-added')) OR
      (NEW.case_state='submitted' AND tail_type='supplier.case.submitted') OR
      (NEW.case_state IN ('submitted','approved','rejected') AND tail_type='supplier.case.approval-decided' AND tail_data->>'resulting_state'=NEW.case_state) OR
      (NEW.case_state='expired' AND tail_type='supplier.case.expired') OR
      (NEW.case_state='canceled' AND tail_type='supplier.case.canceled') OR
      (NEW.case_state='submitted' AND tail_type IN ('supplier.case.manual-review-requested','supplier.case.manual-review-resolved'))) THEN
      RAISE EXCEPTION 'supplier case state must match the immutable event tail';
    END IF;
    IF (tail_type='supplier.case.evidence-added')<>(tail_evidence_id IS NOT NULL) THEN RAISE EXCEPTION 'evidence event link invalid'; END IF;
    RETURN NULL;
END $$;

CREATE OR REPLACE FUNCTION keel_meta.guard_supplier_case_manual_review()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,keel_meta,pg_temp AS $$
DECLARE c keel_meta.supplier_cases%ROWTYPE; e keel_meta.supplier_case_events%ROWTYPE; data jsonb; authorized boolean;
BEGIN
    SELECT * INTO c FROM keel_meta.supplier_cases WHERE tenant_id=NEW.tenant_id AND case_id=NEW.case_id FOR UPDATE;
    IF c.case_state<>'submitted' OR c.deadline_at<=clock_timestamp() THEN
        RAISE EXCEPTION 'manual review requires a live submitted case';
    END IF;
    IF TG_OP='INSERT' THEN
        SELECT * INTO e FROM keel_meta.supplier_case_events WHERE tenant_id=NEW.tenant_id AND case_id=NEW.case_id
          AND aggregate_version=NEW.requested_event_version;
        data:=convert_from(e.event_data,'UTF8')::jsonb;
        IF e.event_type<>'supplier.case.manual-review-requested' OR e.actor_ref<>NEW.requested_by_ref OR
           data->>'review_id'<>NEW.review_id::text OR data->>'evidence_id'<>NEW.evidence_id::text OR
           data->>'reason'<>NEW.request_reason OR NOT EXISTS (
             SELECT 1 FROM keel_meta.supplier_case_evidence ce WHERE ce.tenant_id=NEW.tenant_id AND ce.case_id=NEW.case_id
              AND ce.evidence_id=NEW.evidence_id AND ce.content_sha256=NEW.evidence_digest) THEN
          RAISE EXCEPTION 'manual review request must match the immutable evidence event';
        END IF;
        SELECT EXISTS (
          SELECT 1 FROM keel_meta.supplier_case_reviewer_grants g JOIN keel_meta.supplier_case_approval_plans ap
            ON ap.tenant_id=g.tenant_id AND ap.case_id=NEW.case_id AND ap.required_role=g.role_key
          WHERE g.tenant_id=NEW.tenant_id AND g.principal_ref=NEW.requested_by_ref AND g.revoked_at IS NULL
        ) OR EXISTS (
          SELECT 1 FROM keel_meta.supplier_case_delegations d JOIN keel_meta.supplier_case_approval_plans ap
            ON ap.tenant_id=d.tenant_id AND ap.case_id=NEW.case_id AND ap.required_role=d.role_key
          JOIN keel_meta.supplier_case_reviewer_grants g ON g.tenant_id=d.tenant_id AND g.principal_ref=d.delegator_ref AND g.role_key=d.role_key
          WHERE d.tenant_id=NEW.tenant_id AND d.delegatee_ref=NEW.requested_by_ref AND d.revoked_at IS NULL
            AND d.starts_at<=clock_timestamp() AND d.expires_at>clock_timestamp() AND g.revoked_at IS NULL
        ) INTO authorized;
        IF authorized IS DISTINCT FROM true THEN RAISE EXCEPTION 'manual review requester lacks a current case review role'; END IF;
        IF EXISTS (SELECT 1 FROM keel_meta.supplier_case_events se WHERE se.tenant_id=NEW.tenant_id AND se.case_id=NEW.case_id
          AND se.event_type IN ('supplier.case.created','supplier.case.submitted') AND se.actor_ref=NEW.requested_by_ref) THEN
          RAISE EXCEPTION 'case creator and submitter cannot perform manual evidence review';
        END IF;
    ELSE
        IF NEW.tenant_id<>OLD.tenant_id OR NEW.case_id<>OLD.case_id OR NEW.review_id<>OLD.review_id OR
           NEW.evidence_id<>OLD.evidence_id OR NEW.evidence_digest<>OLD.evidence_digest OR
           NEW.requested_by_ref<>OLD.requested_by_ref OR NEW.request_reason<>OLD.request_reason OR
           NEW.requested_event_version<>OLD.requested_event_version OR NEW.created_at<>OLD.created_at OR
           OLD.state<>'open' OR NEW.state NOT IN ('confirmed','replacement-required') THEN
          RAISE EXCEPTION 'manual review is immutable after resolution';
        END IF;
        SELECT * INTO e FROM keel_meta.supplier_case_events WHERE tenant_id=NEW.tenant_id AND case_id=NEW.case_id
          AND aggregate_version=NEW.resolved_event_version;
        data:=convert_from(e.event_data,'UTF8')::jsonb;
        IF e.event_type<>'supplier.case.manual-review-resolved' OR e.actor_ref<>NEW.resolved_by_ref OR
           data->>'review_id'<>NEW.review_id::text OR data->>'evidence_id'<>NEW.evidence_id::text OR
           data->>'outcome'<>NEW.state OR data->>'reason'<>NEW.resolution_reason THEN
          RAISE EXCEPTION 'manual review resolution must match the immutable event';
        END IF;
        SELECT EXISTS (
          SELECT 1 FROM keel_meta.supplier_case_reviewer_grants g JOIN keel_meta.supplier_case_approval_plans ap
            ON ap.tenant_id=g.tenant_id AND ap.case_id=NEW.case_id AND ap.required_role=g.role_key
          WHERE g.tenant_id=NEW.tenant_id AND g.principal_ref=NEW.resolved_by_ref AND g.revoked_at IS NULL
        ) OR EXISTS (
          SELECT 1 FROM keel_meta.supplier_case_delegations d JOIN keel_meta.supplier_case_approval_plans ap
            ON ap.tenant_id=d.tenant_id AND ap.case_id=NEW.case_id AND ap.required_role=d.role_key
          JOIN keel_meta.supplier_case_reviewer_grants g ON g.tenant_id=d.tenant_id AND g.principal_ref=d.delegator_ref AND g.role_key=d.role_key
          WHERE d.tenant_id=NEW.tenant_id AND d.delegatee_ref=NEW.resolved_by_ref AND d.revoked_at IS NULL
            AND d.starts_at<=clock_timestamp() AND d.expires_at>clock_timestamp() AND g.revoked_at IS NULL
        ) INTO authorized;
        IF authorized IS DISTINCT FROM true THEN RAISE EXCEPTION 'manual review resolver lacks a current case review role'; END IF;
        IF EXISTS (SELECT 1 FROM keel_meta.supplier_case_events se WHERE se.tenant_id=NEW.tenant_id AND se.case_id=NEW.case_id
          AND se.event_type IN ('supplier.case.created','supplier.case.submitted') AND se.actor_ref=NEW.resolved_by_ref) THEN
          RAISE EXCEPTION 'case creator and submitter cannot resolve manual evidence review';
        END IF;
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER supplier_case_manual_review_guard BEFORE INSERT OR UPDATE ON keel_meta.supplier_case_manual_reviews
    FOR EACH ROW EXECUTE FUNCTION keel_meta.guard_supplier_case_manual_review();
REVOKE ALL ON FUNCTION keel_meta.guard_supplier_case_manual_review() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION keel_meta.guard_supplier_case_manual_review() TO keel_app;

CREATE FUNCTION keel_meta.guard_supplier_case_activity_effect()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,keel_meta,pg_temp AS $$
BEGIN
    IF NEW.tenant_id<>OLD.tenant_id OR NEW.effect_id<>OLD.effect_id OR NEW.case_id<>OLD.case_id OR
       NEW.effect_key<>OLD.effect_key OR NEW.effect_type<>OLD.effect_type OR NEW.occurrence<>OLD.occurrence OR
       NEW.due_at<>OLD.due_at OR NEW.payload<>OLD.payload OR NEW.payload_digest<>OLD.payload_digest OR NEW.created_at<>OLD.created_at OR
       NEW.attempt_count<OLD.attempt_count OR NEW.attempt_count>OLD.attempt_count+1 OR
       NEW.lease_epoch<OLD.lease_epoch OR NEW.lease_epoch>OLD.lease_epoch+1 OR
       (NEW.effect_state='leased' AND NEW.lease_epoch<>OLD.lease_epoch+1) OR
       (NEW.effect_state<>'leased' AND NEW.lease_epoch<>OLD.lease_epoch) THEN
        RAISE EXCEPTION 'supplier case effect identity and payload are immutable and claims are fenced';
    END IF;
    IF NOT ((OLD.effect_state='pending' AND NEW.effect_state IN ('leased','canceled','dead')) OR
      (OLD.effect_state='leased' AND NEW.effect_state IN ('leased','pending','delivered','dead','canceled')) OR
      (OLD.effect_state=NEW.effect_state)) THEN
      RAISE EXCEPTION 'invalid supplier case effect transition';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER supplier_case_activity_effect_guard BEFORE UPDATE ON keel_meta.supplier_case_activity_effects
    FOR EACH ROW EXECUTE FUNCTION keel_meta.guard_supplier_case_activity_effect();
REVOKE ALL ON FUNCTION keel_meta.guard_supplier_case_activity_effect() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION keel_meta.guard_supplier_case_activity_effect() TO keel_worker,keel_schema_owner;

CREATE OR REPLACE FUNCTION keel_meta.guard_supplier_case_update()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,keel_meta,pg_temp AS $$
BEGIN
    IF TG_OP='UPDATE' THEN
        IF NEW.tenant_id<>OLD.tenant_id OR NEW.case_id<>OLD.case_id OR NEW.supplier_id<>OLD.supplier_id OR
          NEW.policy_id<>OLD.policy_id OR NEW.policy_version<>OLD.policy_version OR NEW.policy_digest<>OLD.policy_digest OR
          NEW.deadline_at<>OLD.deadline_at OR NEW.created_at<>OLD.created_at OR NEW.aggregate_version<>OLD.aggregate_version+1 OR
          NEW.evidence_epoch<OLD.evidence_epoch OR NEW.evidence_epoch>OLD.evidence_epoch+1 THEN
          RAISE EXCEPTION 'supplier case identity and versioned policy are immutable';
        END IF;
        IF NOT ((OLD.case_state='collecting' AND NEW.case_state IN ('collecting','submitted','canceled','expired')) OR
          (OLD.case_state='submitted' AND NEW.case_state IN ('submitted','approved','rejected','canceled','expired'))) THEN
          RAISE EXCEPTION 'invalid supplier case state transition';
        END IF;
    ELSIF NEW.aggregate_version<>1 OR NEW.case_state<>'collecting' OR NEW.evidence_epoch<>0 THEN
        RAISE EXCEPTION 'supplier case must begin in collecting version one';
    END IF;
    RETURN NEW;
END $$;

REVOKE ALL ON FUNCTION keel_meta.verify_supplier_case_snapshot_event() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION keel_meta.verify_supplier_case_snapshot_event() TO keel_app;
REVOKE ALL ON FUNCTION keel_meta.guard_supplier_case_update() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION keel_meta.guard_supplier_case_update() TO keel_app;

CREATE OR REPLACE FUNCTION keel_meta.block_intake_for_canceled_case()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,keel_meta,pg_temp AS $$
DECLARE cid uuid; state text;
BEGIN
    IF TG_TABLE_NAME='supplier_invitations' THEN
      IF NEW.invitation_state IN ('revoked','expired') THEN RETURN NEW; END IF;
      cid:=NEW.case_id;
    ELSIF TG_TABLE_NAME='supplier_uploads' THEN
      IF TG_OP='UPDATE' AND NEW.upload_state IN ('rejected','expired') THEN RETURN NEW; END IF;
      SELECT case_id INTO cid FROM keel_meta.supplier_invitations WHERE tenant_id=NEW.tenant_id AND invitation_id=NEW.invitation_id;
    ELSE
      SELECT case_id INTO cid FROM keel_meta.supplier_invitations WHERE tenant_id=NEW.tenant_id AND invitation_id=NEW.invitation_id;
    END IF;
    SELECT case_state INTO state FROM keel_meta.supplier_cases WHERE tenant_id=NEW.tenant_id AND case_id=cid FOR KEY SHARE;
    IF state IS DISTINCT FROM 'collecting' THEN RAISE EXCEPTION 'supplier intake is closed for this case'; END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER supplier_invitation_live_case_guard BEFORE INSERT OR UPDATE ON keel_meta.supplier_invitations
    FOR EACH ROW EXECUTE FUNCTION keel_meta.block_intake_for_canceled_case();
CREATE TRIGGER supplier_upload_session_live_case_guard BEFORE INSERT ON keel_meta.supplier_upload_sessions
    FOR EACH ROW EXECUTE FUNCTION keel_meta.block_intake_for_canceled_case();
CREATE TRIGGER supplier_upload_live_case_guard BEFORE INSERT OR UPDATE ON keel_meta.supplier_uploads
    FOR EACH ROW EXECUTE FUNCTION keel_meta.block_intake_for_canceled_case();
REVOKE ALL ON FUNCTION keel_meta.block_intake_for_canceled_case() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION keel_meta.block_intake_for_canceled_case() TO keel_app,keel_file_processor;

CREATE FUNCTION keel_meta.schedule_supplier_case_reminders()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,keel_meta,pg_temp AS $$
DECLARE occurrence text; due timestamptz; body jsonb;
BEGIN
    FOREACH occurrence IN ARRAY ARRAY['midpoint','deadline-minus-one-hour','deadline'] LOOP
      due:=CASE occurrence WHEN 'midpoint' THEN NEW.created_at+(NEW.deadline_at-NEW.created_at)/2
           WHEN 'deadline-minus-one-hour' THEN NEW.deadline_at-interval '1 hour' ELSE NEW.deadline_at END;
      IF (occurrence<>'deadline' AND due<=NEW.created_at) OR (occurrence<>'deadline' AND due>=NEW.deadline_at) OR
         (occurrence='deadline-minus-one-hour' AND due=NEW.created_at+(NEW.deadline_at-NEW.created_at)/2) THEN CONTINUE; END IF;
      body:=jsonb_build_object('case_id',NEW.case_id::text,'occurrence',occurrence);
      INSERT INTO keel_meta.supplier_case_activity_effects
        (tenant_id,effect_id,case_id,effect_key,effect_type,occurrence,due_at,payload,payload_digest)
      VALUES (NEW.tenant_id,gen_random_uuid(),NEW.case_id,NEW.case_id::text||CASE WHEN occurrence='deadline' THEN ':case-expiry:' ELSE ':case-reminder:' END||occurrence,
        CASE WHEN occurrence='deadline' THEN 'case_expiry' ELSE 'case_reminder' END,occurrence,due,body,sha256(convert_to(body::text,'UTF8')));
    END LOOP;
    RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION keel_meta.schedule_supplier_case_reminders() FROM PUBLIC;
CREATE TRIGGER supplier_case_schedule_reminders AFTER INSERT ON keel_meta.supplier_cases
    FOR EACH ROW EXECUTE FUNCTION keel_meta.schedule_supplier_case_reminders();

CREATE FUNCTION keel_meta.cancel_supplier_case_reminders()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,keel_meta,pg_temp AS $$
BEGIN
    IF NEW.case_state IN ('approved','rejected','canceled','expired') AND OLD.case_state<>NEW.case_state THEN
      UPDATE keel_meta.supplier_case_activity_effects SET effect_state='canceled',lease_owner=NULL,
        lease_expires_at=NULL,updated_at=clock_timestamp()
      WHERE tenant_id=NEW.tenant_id AND case_id=NEW.case_id AND effect_state IN ('pending','leased');
    END IF;
    RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION keel_meta.cancel_supplier_case_reminders() FROM PUBLIC;
CREATE TRIGGER supplier_case_terminal_cancel_reminders AFTER UPDATE OF case_state ON keel_meta.supplier_cases
    FOR EACH ROW EXECUTE FUNCTION keel_meta.cancel_supplier_case_reminders();

CREATE FUNCTION keel_meta.guard_supplier_case_lifecycle_event()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,keel_meta,pg_temp AS $$
DECLARE c keel_meta.supplier_cases%ROWTYPE; data jsonb; authorized boolean; review_state text; review_evidence uuid;
BEGIN
    IF NEW.event_type NOT IN ('supplier.case.canceled','supplier.case.manual-review-requested','supplier.case.manual-review-resolved') THEN RETURN NEW; END IF;
    SELECT * INTO c FROM keel_meta.supplier_cases WHERE tenant_id=NEW.tenant_id AND case_id=NEW.case_id FOR UPDATE;
    data:=convert_from(NEW.event_data,'UTF8')::jsonb;
    IF NEW.event_type='supplier.case.canceled' THEN
      IF c.case_state NOT IN ('collecting','submitted') OR c.deadline_at<=clock_timestamp() OR
         NEW.occurred_at>=c.deadline_at OR NEW.occurred_at>clock_timestamp() OR NEW.actor_ref NOT LIKE 'principal:%' OR
         data->>'cancellation_id'<>NEW.cancellation_id::text OR length(COALESCE(data->>'reason','')) NOT BETWEEN 1 AND 500 THEN
        RAISE EXCEPTION 'cancellation event must be authorized and accepted before the persisted deadline';
      END IF;
      RETURN NEW;
    END IF;
    IF c.case_state<>'submitted' OR c.deadline_at<=clock_timestamp() OR NEW.occurred_at>=c.deadline_at OR
       NEW.occurred_at>clock_timestamp() OR NEW.actor_ref NOT LIKE 'principal:%' OR
       data->>'review_id'<>NEW.manual_review_id::text OR length(COALESCE(data->>'evidence_id',''))<>36 THEN
      RAISE EXCEPTION 'manual review event requires a live submitted case and trusted reviewer';
    END IF;
    IF NEW.event_type='supplier.case.manual-review-requested' THEN
      IF length(COALESCE(data->>'reason','')) NOT BETWEEN 1 AND 500 OR NOT EXISTS (
        SELECT 1 FROM keel_meta.supplier_case_evidence ce WHERE ce.tenant_id=NEW.tenant_id AND ce.case_id=NEW.case_id
          AND ce.evidence_id=(data->>'evidence_id')::uuid) THEN RAISE EXCEPTION 'manual review must reference current case evidence'; END IF;
    ELSE
      IF data->>'outcome' NOT IN ('confirmed','replacement-required') OR length(COALESCE(data->>'reason','')) NOT BETWEEN 1 AND 500 THEN
        RAISE EXCEPTION 'manual review resolution is invalid';
      END IF;
      SELECT state,evidence_id INTO review_state,review_evidence FROM keel_meta.supplier_case_manual_reviews
        WHERE tenant_id=NEW.tenant_id AND case_id=NEW.case_id AND review_id=NEW.manual_review_id FOR UPDATE;
      IF review_state IS DISTINCT FROM 'open' OR review_evidence<>(data->>'evidence_id')::uuid THEN
        RAISE EXCEPTION 'manual review resolution requires its open evidence review';
      END IF;
    END IF;
    SELECT EXISTS (
      SELECT 1 FROM keel_meta.supplier_case_reviewer_grants g JOIN keel_meta.supplier_case_approval_plans ap
        ON ap.tenant_id=g.tenant_id AND ap.case_id=NEW.case_id AND ap.required_role=g.role_key
      WHERE g.tenant_id=NEW.tenant_id AND g.principal_ref=NEW.actor_ref AND g.revoked_at IS NULL
    ) OR EXISTS (
      SELECT 1 FROM keel_meta.supplier_case_delegations d JOIN keel_meta.supplier_case_approval_plans ap
        ON ap.tenant_id=d.tenant_id AND ap.case_id=NEW.case_id AND ap.required_role=d.role_key
      JOIN keel_meta.supplier_case_reviewer_grants g ON g.tenant_id=d.tenant_id AND g.principal_ref=d.delegator_ref AND g.role_key=d.role_key
      WHERE d.tenant_id=NEW.tenant_id AND d.delegatee_ref=NEW.actor_ref AND d.revoked_at IS NULL
        AND d.starts_at<=clock_timestamp() AND d.expires_at>clock_timestamp() AND g.revoked_at IS NULL
    ) INTO authorized;
    IF authorized IS DISTINCT FROM true OR EXISTS (
      SELECT 1 FROM keel_meta.supplier_case_events se WHERE se.tenant_id=NEW.tenant_id AND se.case_id=NEW.case_id
        AND se.event_type IN ('supplier.case.created','supplier.case.submitted') AND se.actor_ref=NEW.actor_ref
    ) THEN RAISE EXCEPTION 'manual review actor lacks an eligible independent reviewer grant'; END IF;
    RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION keel_meta.guard_supplier_case_lifecycle_event() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION keel_meta.guard_supplier_case_lifecycle_event() TO keel_app;
CREATE TRIGGER supplier_case_lifecycle_event_guard BEFORE INSERT ON keel_meta.supplier_case_events
    FOR EACH ROW EXECUTE FUNCTION keel_meta.guard_supplier_case_lifecycle_event();

-- The worker receives only case status, deadline and currently-authorized principal refs.
-- It cannot query supplier identity, evidence content, or reviewer/delegation tables directly.
CREATE POLICY supplier_cases_reminder_context_owner ON keel_meta.supplier_cases
    FOR SELECT TO keel_schema_owner USING (true);
CREATE POLICY supplier_cases_reminder_lock_owner ON keel_meta.supplier_cases
    FOR UPDATE TO keel_schema_owner USING (true) WITH CHECK (true);
CREATE POLICY supplier_case_events_reminder_context_owner ON keel_meta.supplier_case_events
    FOR SELECT TO keel_schema_owner USING (true);
CREATE POLICY supplier_case_approval_plans_reminder_context_owner ON keel_meta.supplier_case_approval_plans
    FOR SELECT TO keel_schema_owner USING (true);
CREATE POLICY supplier_case_reviewer_grants_reminder_context_owner ON keel_meta.supplier_case_reviewer_grants
    FOR SELECT TO keel_schema_owner USING (true);
CREATE POLICY supplier_case_delegations_reminder_context_owner ON keel_meta.supplier_case_delegations
    FOR SELECT TO keel_schema_owner USING (true);
CREATE POLICY supplier_invitations_case_guard_owner ON keel_meta.supplier_invitations
    FOR SELECT TO keel_schema_owner USING (true);

CREATE FUNCTION keel_meta.load_supplier_case_reminder_context(p_tenant uuid,p_case uuid,p_effect uuid,p_owner uuid,p_epoch bigint)
RETURNS TABLE(case_state text,deadline_at timestamptz,recipient_refs text[],effect_type text)
LANGUAGE sql SECURITY DEFINER VOLATILE
SET search_path=pg_catalog,keel_meta,pg_temp
AS $$
    SELECT c.case_state,c.deadline_at,CASE WHEN fx.effect_type='case_reminder' THEN ARRAY(
      SELECT DISTINCT refs.actor_ref FROM (
        SELECT g.principal_ref AS actor_ref FROM keel_meta.supplier_case_reviewer_grants g
          JOIN keel_meta.supplier_case_approval_plans ap ON ap.tenant_id=g.tenant_id AND ap.case_id=p_case AND ap.required_role=g.role_key
          WHERE g.tenant_id=p_tenant AND g.revoked_at IS NULL
        UNION ALL
        SELECT d.delegatee_ref AS actor_ref FROM keel_meta.supplier_case_delegations d
          JOIN keel_meta.supplier_case_approval_plans ap ON ap.tenant_id=d.tenant_id AND ap.case_id=p_case AND ap.required_role=d.role_key
          WHERE d.tenant_id=p_tenant AND d.revoked_at IS NULL AND d.starts_at<=clock_timestamp() AND d.expires_at>clock_timestamp()
      ) refs
    ) ELSE ARRAY[]::text[] END,fx.effect_type
    FROM keel_meta.supplier_cases c
    JOIN keel_meta.supplier_case_activity_effects fx ON fx.tenant_id=c.tenant_id AND fx.case_id=c.case_id
    WHERE c.tenant_id=p_tenant AND c.case_id=p_case AND p_tenant=keel_private.current_tenant_id()
      AND c.case_state IN ('collecting','submitted')
      AND ((fx.effect_type='case_reminder' AND c.deadline_at>clock_timestamp()) OR
           (fx.effect_type='case_expiry' AND c.deadline_at<=clock_timestamp()))
      AND fx.effect_id=p_effect AND fx.effect_state='leased' AND fx.lease_owner=p_owner
      AND fx.lease_epoch=p_epoch AND fx.lease_expires_at>clock_timestamp()
$$;
REVOKE ALL ON FUNCTION keel_meta.load_supplier_case_reminder_context(uuid,uuid,uuid,uuid,bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION keel_meta.load_supplier_case_reminder_context(uuid,uuid,uuid,uuid,bigint) TO keel_worker;
