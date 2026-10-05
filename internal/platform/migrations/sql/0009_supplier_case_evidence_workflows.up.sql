-- Immutable review-policy versions, case/event snapshots, evidence references, and
-- transactionally-created workflow intents. Delivery leases are added by K2.3.
CREATE TABLE keel_meta.supplier_review_policies (
    tenant_id uuid NOT NULL,
    policy_id uuid NOT NULL,
    version integer NOT NULL CHECK (version > 0),
    name text NOT NULL CHECK (length(name) BETWEEN 1 AND 120),
    deadline_seconds integer NOT NULL CHECK (deadline_seconds BETWEEN 3600 AND 259200),
    required_evidence text[] NOT NULL CHECK (cardinality(required_evidence) <= 100),
    policy_definition jsonb NOT NULL CHECK (jsonb_typeof(policy_definition) = 'object'),
    policy_digest bytea NOT NULL CHECK (octet_length(policy_digest) = 32),
    published_at timestamptz NOT NULL,
    created_by_ref text NOT NULL CHECK (created_by_ref ~ '^(principal|service-principal):[A-Za-z0-9._~-]{1,120}$'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, policy_id, version)
);

CREATE TABLE keel_meta.supplier_cases (
    tenant_id uuid NOT NULL,
    case_id uuid NOT NULL,
    supplier_id uuid NOT NULL,
    policy_id uuid NOT NULL,
    policy_version integer NOT NULL,
    policy_digest bytea NOT NULL CHECK (octet_length(policy_digest) = 32),
    case_state text NOT NULL CHECK (case_state IN ('collecting', 'submitted', 'approved', 'rejected', 'canceled', 'expired')),
    aggregate_version bigint NOT NULL CHECK (aggregate_version > 0),
    evidence_epoch bigint NOT NULL DEFAULT 0 CHECK (evidence_epoch >= 0),
    evidence_digest bytea NOT NULL CHECK (octet_length(evidence_digest) = 32),
    last_event_hash bytea NOT NULL CHECK (octet_length(last_event_hash) = 32),
    deadline_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, case_id),
    FOREIGN KEY (tenant_id, policy_id, policy_version)
        REFERENCES keel_meta.supplier_review_policies (tenant_id, policy_id, version),
    CHECK (deadline_at > created_at)
);
CREATE INDEX supplier_cases_supplier_idx
    ON keel_meta.supplier_cases (tenant_id, supplier_id, created_at DESC);
CREATE INDEX supplier_cases_deadline_idx
    ON keel_meta.supplier_cases (tenant_id, deadline_at, case_id)
    WHERE case_state IN ('collecting', 'submitted');

CREATE TABLE keel_meta.supplier_case_events (
    tenant_id uuid NOT NULL,
    case_id uuid NOT NULL,
    aggregate_version bigint NOT NULL CHECK (aggregate_version > 0),
    event_type text NOT NULL CHECK (event_type IN (
        'supplier.case.created', 'supplier.case.evidence-added', 'supplier.case.submitted'
    )),
    actor_ref text NOT NULL CHECK (actor_ref ~ '^(principal|service-principal):[A-Za-z0-9._~-]{1,120}$'),
    occurred_at timestamptz NOT NULL,
    event_data bytea NOT NULL CHECK (octet_length(event_data) BETWEEN 2 AND 16384),
    evidence_id uuid,
    previous_hash bytea,
    event_hash bytea NOT NULL CHECK (octet_length(event_hash) = 32),
    PRIMARY KEY (tenant_id, case_id, aggregate_version),
    UNIQUE (tenant_id, case_id, evidence_id),
    FOREIGN KEY (tenant_id, case_id)
        REFERENCES keel_meta.supplier_cases (tenant_id, case_id),
    CHECK ((event_type = 'supplier.case.evidence-added') = (evidence_id IS NOT NULL)),
    CHECK ((aggregate_version = 1 AND previous_hash IS NULL) OR
           (aggregate_version > 1 AND octet_length(previous_hash) = 32))
);

CREATE TABLE keel_meta.supplier_case_evidence (
    tenant_id uuid NOT NULL,
    case_id uuid NOT NULL,
    evidence_id uuid NOT NULL,
    evidence_slot text NOT NULL CHECK (evidence_slot ~ '^[a-z][a-z0-9._-]{0,63}$'),
    evidence_kind text NOT NULL CHECK (evidence_kind ~ '^[a-z][a-z0-9._-]{0,63}$'),
    slot_version integer NOT NULL CHECK (slot_version > 0),
    upload_id uuid NOT NULL,
    media_type text NOT NULL CHECK (media_type IN (
        'application/pdf',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'text/plain'
    )),
    content_bytes bigint NOT NULL CHECK (content_bytes BETWEEN 1 AND 20971520),
    content_sha256 bytea NOT NULL CHECK (octet_length(content_sha256) = 32),
    added_by_ref text NOT NULL CHECK (added_by_ref ~ '^(principal|service-principal):[A-Za-z0-9._~-]{1,120}$'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, case_id, evidence_id),
    UNIQUE (tenant_id, case_id, evidence_slot, slot_version),
    UNIQUE (tenant_id, upload_id),
    FOREIGN KEY (tenant_id, case_id)
        REFERENCES keel_meta.supplier_cases (tenant_id, case_id),
    FOREIGN KEY (tenant_id, upload_id)
        REFERENCES keel_meta.supplier_uploads (tenant_id, upload_id),
    FOREIGN KEY (tenant_id, case_id, evidence_id)
        REFERENCES keel_meta.supplier_case_events (tenant_id, case_id, evidence_id)
        DEFERRABLE INITIALLY DEFERRED
);
ALTER TABLE keel_meta.supplier_case_events
    ADD CONSTRAINT supplier_case_event_evidence_fk
    FOREIGN KEY (tenant_id, case_id, evidence_id)
    REFERENCES keel_meta.supplier_case_evidence (tenant_id, case_id, evidence_id)
    DEFERRABLE INITIALLY DEFERRED;

CREATE FUNCTION keel_meta.verify_supplier_case_evidence_source()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, keel_meta, pg_temp
AS $$
DECLARE
    source_ok boolean;
    current_state text;
    current_deadline timestamptz;
    evidence_count bigint;
    evidence_bytes bigint;
BEGIN
    SELECT case_state,deadline_at INTO current_state,current_deadline
    FROM keel_meta.supplier_cases
    WHERE tenant_id = NEW.tenant_id AND case_id = NEW.case_id
    FOR UPDATE;
    IF current_state IS DISTINCT FROM 'collecting' OR current_deadline <= clock_timestamp() THEN
        RAISE EXCEPTION 'evidence can only be attached to an active collecting case';
    END IF;
    SELECT count(*),COALESCE(sum(content_bytes),0) INTO evidence_count,evidence_bytes
    FROM keel_meta.supplier_case_evidence
    WHERE tenant_id = NEW.tenant_id AND case_id = NEW.case_id;
    IF evidence_count >= 100 OR evidence_bytes + NEW.content_bytes > 104857600 THEN
        RAISE EXCEPTION 'supplier case evidence quota exceeded';
    END IF;
    SELECT true INTO source_ok
    FROM keel_meta.supplier_uploads AS u
    JOIN keel_meta.supplier_invitations AS i
      ON i.tenant_id = u.tenant_id AND i.invitation_id = u.invitation_id
    WHERE u.tenant_id = NEW.tenant_id
      AND u.upload_id = NEW.upload_id
      AND i.case_id = NEW.case_id
      AND i.invitation_state = 'accepted'
      AND i.expires_at > clock_timestamp()
      AND i.revoked_at IS NULL
      AND u.upload_state = 'extracted'
      AND u.detected_media_type = NEW.media_type
      AND u.expected_bytes = NEW.content_bytes
      AND u.expected_sha256 = NEW.content_sha256;
    IF source_ok IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'supplier evidence must reference a matching extracted upload';
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER supplier_case_evidence_source_guard
    BEFORE INSERT ON keel_meta.supplier_case_evidence
    FOR EACH ROW EXECUTE FUNCTION keel_meta.verify_supplier_case_evidence_source();

CREATE TABLE keel_meta.supplier_workflow_intents (
    tenant_id uuid NOT NULL,
    intent_id uuid NOT NULL,
    case_id uuid NOT NULL,
    aggregate_version bigint NOT NULL CHECK (aggregate_version > 0),
    intent_type text NOT NULL CHECK (intent_type IN (
        'supplier.case.created', 'supplier.case.evidence-added', 'supplier.case.submitted'
    )),
    logical_key text NOT NULL CHECK (length(logical_key) BETWEEN 1 AND 180),
    payload jsonb NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, intent_id),
    UNIQUE (tenant_id, logical_key),
    UNIQUE (tenant_id, case_id, aggregate_version),
    FOREIGN KEY (tenant_id, case_id, aggregate_version)
        REFERENCES keel_meta.supplier_case_events (tenant_id, case_id, aggregate_version)
);
CREATE INDEX supplier_workflow_intents_pending_idx
    ON keel_meta.supplier_workflow_intents (tenant_id, created_at, intent_id);

CREATE FUNCTION keel_meta.verify_supplier_case_event_intent()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, keel_meta, pg_temp
AS $$
DECLARE
    intent_count bigint;
    intent_type text;
    snapshot_version bigint;
    snapshot_hash bytea;
    event_count bigint;
BEGIN
    SELECT count(*),min(wi.intent_type) INTO intent_count,intent_type
    FROM keel_meta.supplier_workflow_intents AS wi
    WHERE wi.tenant_id = NEW.tenant_id AND wi.case_id = NEW.case_id
      AND wi.aggregate_version = NEW.aggregate_version;
    IF intent_count <> 1 OR intent_type <> NEW.event_type THEN
        RAISE EXCEPTION 'every supplier case event requires one matching durable workflow intent';
    END IF;
    SELECT aggregate_version,last_event_hash INTO snapshot_version,snapshot_hash
    FROM keel_meta.supplier_cases
    WHERE tenant_id = NEW.tenant_id AND case_id = NEW.case_id;
    SELECT count(*) INTO event_count FROM keel_meta.supplier_case_events
    WHERE tenant_id = NEW.tenant_id AND case_id = NEW.case_id;
    IF snapshot_version IS NULL OR snapshot_version <> event_count OR
       (NEW.aggregate_version = snapshot_version AND snapshot_hash <> NEW.event_hash) THEN
        RAISE EXCEPTION 'supplier case events and snapshot must commit at the same aggregate version';
    END IF;
    RETURN NULL;
END
$$;
CREATE CONSTRAINT TRIGGER supplier_case_event_intent_guard
    AFTER INSERT ON keel_meta.supplier_case_events
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION keel_meta.verify_supplier_case_event_intent();

CREATE FUNCTION keel_meta.guard_supplier_case_update()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, keel_meta, pg_temp
AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        IF NEW.tenant_id <> OLD.tenant_id OR NEW.case_id <> OLD.case_id OR
           NEW.supplier_id <> OLD.supplier_id OR NEW.policy_id <> OLD.policy_id OR
           NEW.policy_version <> OLD.policy_version OR NEW.policy_digest <> OLD.policy_digest OR
           NEW.deadline_at <> OLD.deadline_at OR NEW.created_at <> OLD.created_at OR
           NEW.aggregate_version <> OLD.aggregate_version + 1 OR
           NEW.evidence_epoch < OLD.evidence_epoch OR NEW.evidence_epoch > OLD.evidence_epoch + 1 THEN
            RAISE EXCEPTION 'supplier case identity and versioned policy are immutable';
        END IF;
        IF NOT (
            (OLD.case_state = 'collecting' AND NEW.case_state IN ('collecting','submitted','canceled','expired')) OR
            (OLD.case_state = 'submitted' AND NEW.case_state IN ('submitted','approved','rejected','canceled','expired'))
        ) THEN
            RAISE EXCEPTION 'invalid supplier case state transition';
        END IF;
    ELSIF NEW.aggregate_version <> 1 OR NEW.case_state <> 'collecting' OR NEW.evidence_epoch <> 0 THEN
        RAISE EXCEPTION 'supplier case must begin in collecting version one';
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER supplier_case_update_guard
    BEFORE INSERT OR UPDATE ON keel_meta.supplier_cases
    FOR EACH ROW EXECUTE FUNCTION keel_meta.guard_supplier_case_update();

CREATE FUNCTION keel_meta.verify_supplier_case_snapshot_event()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, keel_meta, pg_temp
AS $$
DECLARE
    tail_type text;
    tail_hash bytea;
    tail_evidence_id uuid;
    evidence_events bigint;
BEGIN
    SELECT event_type,event_hash,evidence_id INTO tail_type,tail_hash,tail_evidence_id
    FROM keel_meta.supplier_case_events
    WHERE tenant_id = NEW.tenant_id AND case_id = NEW.case_id
      AND aggregate_version = NEW.aggregate_version;
    IF tail_hash IS NULL OR tail_hash <> NEW.last_event_hash OR
       (SELECT count(*) FROM keel_meta.supplier_case_events
        WHERE tenant_id = NEW.tenant_id AND case_id = NEW.case_id) <> NEW.aggregate_version THEN
        RAISE EXCEPTION 'supplier case snapshot must match a contiguous immutable event tail';
    END IF;
    SELECT count(*) INTO evidence_events FROM keel_meta.supplier_case_events
    WHERE tenant_id = NEW.tenant_id AND case_id = NEW.case_id
      AND event_type = 'supplier.case.evidence-added';
    IF evidence_events <> NEW.evidence_epoch THEN
        RAISE EXCEPTION 'supplier case evidence epoch must match its event history';
    END IF;
    IF NOT ((NEW.case_state = 'collecting' AND tail_type IN ('supplier.case.created','supplier.case.evidence-added')) OR
            (NEW.case_state = 'submitted' AND tail_type = 'supplier.case.submitted')) THEN
        RAISE EXCEPTION 'supplier case status must match its event tail';
    END IF;
    IF (tail_type = 'supplier.case.evidence-added') <> (tail_evidence_id IS NOT NULL) THEN
        RAISE EXCEPTION 'supplier case evidence event is not linked to an evidence record';
    END IF;
    RETURN NULL;
END
$$;
CREATE CONSTRAINT TRIGGER supplier_case_snapshot_event_guard
    AFTER INSERT OR UPDATE ON keel_meta.supplier_cases
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION keel_meta.verify_supplier_case_snapshot_event();

ALTER TABLE keel_meta.supplier_review_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.supplier_review_policies FORCE ROW LEVEL SECURITY;
CREATE POLICY supplier_review_policies_tenant_isolation ON keel_meta.supplier_review_policies
    TO keel_app USING (tenant_id = (SELECT keel_private.current_tenant_id()))
    WITH CHECK (tenant_id = (SELECT keel_private.current_tenant_id()));

ALTER TABLE keel_meta.supplier_cases ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.supplier_cases FORCE ROW LEVEL SECURITY;
CREATE POLICY supplier_cases_tenant_isolation ON keel_meta.supplier_cases
    TO keel_app USING (tenant_id = (SELECT keel_private.current_tenant_id()))
    WITH CHECK (tenant_id = (SELECT keel_private.current_tenant_id()));

ALTER TABLE keel_meta.supplier_case_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.supplier_case_events FORCE ROW LEVEL SECURITY;
CREATE POLICY supplier_case_events_tenant_isolation ON keel_meta.supplier_case_events
    TO keel_app USING (tenant_id = (SELECT keel_private.current_tenant_id()))
    WITH CHECK (tenant_id = (SELECT keel_private.current_tenant_id()));

ALTER TABLE keel_meta.supplier_case_evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.supplier_case_evidence FORCE ROW LEVEL SECURITY;
CREATE POLICY supplier_case_evidence_tenant_isolation ON keel_meta.supplier_case_evidence
    TO keel_app USING (tenant_id = (SELECT keel_private.current_tenant_id()))
    WITH CHECK (tenant_id = (SELECT keel_private.current_tenant_id()));

ALTER TABLE keel_meta.supplier_workflow_intents ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.supplier_workflow_intents FORCE ROW LEVEL SECURITY;
CREATE POLICY supplier_workflow_intents_tenant_isolation ON keel_meta.supplier_workflow_intents
    TO keel_app USING (tenant_id = (SELECT keel_private.current_tenant_id()))
    WITH CHECK (tenant_id = (SELECT keel_private.current_tenant_id()));

REVOKE ALL ON keel_meta.supplier_review_policies, keel_meta.supplier_cases,
    keel_meta.supplier_case_events, keel_meta.supplier_case_evidence,
    keel_meta.supplier_workflow_intents FROM PUBLIC, keel_agent, keel_worker,
    keel_projector, keel_operator, keel_file_processor;
REVOKE ALL ON FUNCTION keel_meta.guard_supplier_case_update() FROM PUBLIC;
REVOKE ALL ON FUNCTION keel_meta.verify_supplier_case_snapshot_event() FROM PUBLIC;
REVOKE ALL ON FUNCTION keel_meta.verify_supplier_case_evidence_source() FROM PUBLIC;
REVOKE ALL ON FUNCTION keel_meta.verify_supplier_case_event_intent() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION keel_meta.guard_supplier_case_update() TO keel_app;
GRANT EXECUTE ON FUNCTION keel_meta.verify_supplier_case_snapshot_event() TO keel_app;
GRANT EXECUTE ON FUNCTION keel_meta.verify_supplier_case_evidence_source() TO keel_app;
GRANT EXECUTE ON FUNCTION keel_meta.verify_supplier_case_event_intent() TO keel_app;
GRANT SELECT, INSERT ON keel_meta.supplier_review_policies TO keel_app;
GRANT SELECT, INSERT ON keel_meta.supplier_cases TO keel_app;
GRANT UPDATE (case_state, aggregate_version, evidence_epoch, evidence_digest,
    last_event_hash, updated_at) ON keel_meta.supplier_cases TO keel_app;
GRANT SELECT, INSERT ON keel_meta.supplier_case_events TO keel_app;
GRANT SELECT, INSERT ON keel_meta.supplier_case_evidence TO keel_app;
GRANT SELECT, INSERT ON keel_meta.supplier_workflow_intents TO keel_app;
REVOKE ALL ON FUNCTION keel_meta.verify_supplier_case_evidence_source() FROM PUBLIC;
