CREATE TABLE keel_meta.context_vault_legal_holds (
    tenant_id uuid NOT NULL CHECK (tenant_id<>'00000000-0000-0000-0000-000000000000'::uuid),
    hold_id uuid NOT NULL CHECK (hold_id<>'00000000-0000-0000-0000-000000000000'::uuid),
    record_id uuid NOT NULL CHECK (record_id<>'00000000-0000-0000-0000-000000000000'::uuid),
    version bigint NOT NULL CHECK (version>0),
    revision integer NOT NULL CHECK (revision>0),
    review_due_at timestamptz NOT NULL,
    released_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id,hold_id)
);

CREATE INDEX context_vault_legal_holds_active_record_idx
    ON keel_meta.context_vault_legal_holds (tenant_id,record_id,version,review_due_at)
    WHERE released_at IS NULL;
ALTER TABLE keel_meta.context_vault_legal_holds ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.context_vault_legal_holds FORCE ROW LEVEL SECURITY;
CREATE POLICY context_vault_legal_holds_authority ON keel_meta.context_vault_legal_holds
    TO keel_context_legal_hold USING (tenant_id=(SELECT keel_private.current_tenant_id()))
    WITH CHECK (tenant_id=(SELECT keel_private.current_tenant_id()));
CREATE POLICY context_vault_legal_holds_schema_owner ON keel_meta.context_vault_legal_holds
    TO keel_schema_owner USING (true) WITH CHECK (true);
REVOKE ALL ON keel_meta.context_vault_legal_holds FROM PUBLIC,keel_app,keel_worker,keel_operator,
    keel_context_vault,keel_context_policy,keel_context_erasure,keel_context_erasure_worker,
    keel_context_legal_hold,keel_agent;

CREATE TABLE keel_meta.context_vault_legal_hold_events (
    tenant_id uuid NOT NULL,
    hold_id uuid NOT NULL,
    record_id uuid NOT NULL,
    version bigint NOT NULL CHECK (version>0),
    revision integer NOT NULL CHECK (revision>0),
    action text NOT NULL CHECK (action IN ('created','reviewed','released')),
    decision text NOT NULL CHECK (decision IN ('placed','extend','release')),
    reason_code text NOT NULL CHECK (reason_code IN ('litigation','regulatory','investigation','preservation_order','other_authorized')),
    actor_id uuid NOT NULL CHECK (actor_id<>'00000000-0000-0000-0000-000000000000'::uuid),
    review_due_at timestamptz NOT NULL,
    event_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id,hold_id,revision),
    FOREIGN KEY (tenant_id,hold_id) REFERENCES keel_meta.context_vault_legal_holds(tenant_id,hold_id)
);
ALTER TABLE keel_meta.context_vault_legal_hold_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.context_vault_legal_hold_events FORCE ROW LEVEL SECURITY;
CREATE POLICY context_vault_legal_hold_events_authority ON keel_meta.context_vault_legal_hold_events
    TO keel_context_legal_hold USING (tenant_id=(SELECT keel_private.current_tenant_id()))
    WITH CHECK (tenant_id=(SELECT keel_private.current_tenant_id()));
CREATE POLICY context_vault_legal_hold_events_schema_owner ON keel_meta.context_vault_legal_hold_events
    TO keel_schema_owner USING (true) WITH CHECK (true);
REVOKE ALL ON keel_meta.context_vault_legal_hold_events FROM PUBLIC,keel_app,keel_worker,keel_operator,
    keel_context_vault,keel_context_policy,keel_context_erasure,keel_context_erasure_worker,
    keel_context_legal_hold,keel_agent;

CREATE FUNCTION keel_meta.reject_context_vault_legal_hold_event_mutation()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    RAISE EXCEPTION 'context vault legal hold events are append-only';
END $$;
CREATE TRIGGER context_vault_legal_hold_event_immutable
    BEFORE UPDATE OR DELETE ON keel_meta.context_vault_legal_hold_events
    FOR EACH ROW EXECUTE FUNCTION keel_meta.reject_context_vault_legal_hold_event_mutation();
REVOKE ALL ON FUNCTION keel_meta.reject_context_vault_legal_hold_event_mutation() FROM PUBLIC;

CREATE FUNCTION keel_meta.guard_context_vault_legal_hold()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    IF TG_OP='INSERT' THEN
        IF NEW.revision<>1 OR NEW.released_at IS NOT NULL OR
           NOT pg_catalog.pg_has_role(session_user,'keel_context_legal_hold','MEMBER') OR current_user<>'keel_schema_owner' THEN
            RAISE EXCEPTION 'context vault legal hold authority is required';
        END IF;
        RETURN NEW;
    END IF;
    IF TG_OP='DELETE' OR NEW.tenant_id<>OLD.tenant_id OR NEW.hold_id<>OLD.hold_id OR
       NEW.record_id<>OLD.record_id OR NEW.version<>OLD.version OR NEW.created_at<>OLD.created_at OR
       NEW.revision<>OLD.revision+1 OR NEW.updated_at<=OLD.updated_at OR OLD.released_at IS NOT NULL OR
       (NEW.released_at IS NOT NULL AND NEW.released_at>clock_timestamp()) THEN
        RAISE EXCEPTION 'invalid context vault legal hold transition';
    END IF;
    IF NOT pg_catalog.pg_has_role(session_user,'keel_context_legal_hold','MEMBER') OR current_user<>'keel_schema_owner' THEN
        RAISE EXCEPTION 'context vault legal hold authority is required';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER context_vault_legal_hold_guard BEFORE INSERT OR UPDATE OR DELETE
    ON keel_meta.context_vault_legal_holds FOR EACH ROW EXECUTE FUNCTION keel_meta.guard_context_vault_legal_hold();
REVOKE ALL ON FUNCTION keel_meta.guard_context_vault_legal_hold() FROM PUBLIC;

ALTER TABLE keel_meta.context_vault_erasure_jobs DROP CONSTRAINT context_vault_erasure_jobs_state_check;
ALTER TABLE keel_meta.context_vault_erasure_jobs ADD CONSTRAINT context_vault_erasure_jobs_state_check
    CHECK (state IN ('pending','leased','held','blocked','complete'));

CREATE OR REPLACE FUNCTION keel_meta.guard_context_vault_erasure_job()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,keel_meta,pg_temp AS $$
BEGIN
    IF TG_OP='INSERT' THEN
        IF NEW.state<>'pending' OR NEW.attempt_count<>0 OR NEW.failure_count<>0 OR NEW.last_error_code IS NOT NULL OR
           NEW.lease_owner IS NOT NULL OR NEW.lease_until IS NOT NULL OR NEW.lease_epoch<>0 OR
           NEW.blocked_at IS NOT NULL OR NEW.completed_at IS NOT NULL OR NEW.available_at<>NEW.expires_at THEN
            RAISE EXCEPTION 'context erasure jobs must begin pending at their database expiry';
        END IF;
        RETURN NEW;
    END IF;
    IF TG_OP='DELETE' OR NEW.tenant_id<>OLD.tenant_id OR NEW.record_id<>OLD.record_id OR NEW.version<>OLD.version OR
       NEW.expires_at<>OLD.expires_at OR NEW.created_at<>OLD.created_at OR NEW.updated_at<=OLD.updated_at OR
       NEW.attempt_count<OLD.attempt_count OR NEW.attempt_count>OLD.attempt_count+1 OR
       NEW.failure_count<OLD.failure_count OR NEW.failure_count>OLD.failure_count+1 OR
       NEW.lease_epoch<OLD.lease_epoch OR NEW.lease_epoch>OLD.lease_epoch+1 THEN
        RAISE EXCEPTION 'context erasure job identity and counters must advance monotonically';
    END IF;
    IF OLD.state='pending' AND NEW.state='leased' AND NEW.lease_owner IS NOT NULL AND
       NEW.lease_epoch=OLD.lease_epoch+1 AND NEW.attempt_count=OLD.attempt_count+1 AND
       NEW.failure_count=OLD.failure_count AND NEW.available_at=OLD.available_at AND
       NEW.lease_until>clock_timestamp() AND NEW.lease_until<=clock_timestamp()+interval '15 minutes'+interval '1 second' AND
       NEW.last_error_code IS NULL AND NEW.blocked_at IS NULL AND NEW.completed_at IS NULL AND
       OLD.available_at<=clock_timestamp() AND OLD.failure_count<12 THEN RETURN NEW; END IF;
    IF OLD.state='leased' AND OLD.lease_until<=clock_timestamp() AND NEW.state IN ('pending','blocked') AND
       NEW.lease_owner IS NULL AND NEW.lease_until IS NULL AND NEW.lease_epoch=OLD.lease_epoch AND
       NEW.attempt_count=OLD.attempt_count AND NEW.failure_count=OLD.failure_count+1 AND
       NEW.completed_at IS NULL AND NEW.last_error_code IS NOT NULL AND
       ((NEW.state='pending' AND NEW.failure_count<12 AND NEW.blocked_at IS NULL AND NEW.available_at>=OLD.lease_until) OR
        (NEW.state='blocked' AND NEW.failure_count=12 AND NEW.blocked_at IS NOT NULL AND
         NEW.last_error_code='attempts_exhausted' AND NEW.available_at=OLD.available_at)) THEN RETURN NEW; END IF;
    IF OLD.state='leased' AND NEW.state='pending' AND OLD.lease_owner IS NOT NULL AND OLD.lease_until>clock_timestamp() AND
       NEW.lease_owner IS NULL AND NEW.lease_until IS NULL AND NEW.lease_epoch=OLD.lease_epoch AND
       NEW.attempt_count=OLD.attempt_count AND NEW.failure_count=OLD.failure_count+1 AND
       NEW.available_at>clock_timestamp() AND NEW.available_at<=clock_timestamp()+interval '24 hours'+interval '1 second' AND
       NEW.last_error_code IS NOT NULL AND NEW.blocked_at IS NULL AND NEW.completed_at IS NULL THEN RETURN NEW; END IF;
    IF OLD.state='leased' AND NEW.state='blocked' AND OLD.lease_owner IS NOT NULL AND OLD.lease_until>clock_timestamp() AND
       NEW.lease_owner IS NULL AND NEW.lease_until IS NULL AND NEW.lease_epoch=OLD.lease_epoch AND
       NEW.attempt_count=OLD.attempt_count AND NEW.failure_count=OLD.failure_count+1 AND
       NEW.available_at=OLD.available_at AND NEW.last_error_code='attempts_exhausted' AND
       NEW.blocked_at IS NOT NULL AND NEW.completed_at IS NULL THEN RETURN NEW; END IF;
    IF OLD.state='leased' AND NEW.state='complete' AND OLD.lease_owner IS NOT NULL AND OLD.lease_until>clock_timestamp() AND
       NEW.lease_owner IS NULL AND NEW.lease_until IS NULL AND NEW.lease_epoch=OLD.lease_epoch AND
       NEW.attempt_count=OLD.attempt_count AND NEW.failure_count=OLD.failure_count AND
       NEW.available_at=OLD.available_at AND NEW.last_error_code IS NULL AND
       NEW.blocked_at IS NULL AND NEW.completed_at IS NOT NULL THEN RETURN NEW; END IF;
    IF OLD.state='pending' AND NEW.state='complete' AND NEW.lease_owner IS NULL AND NEW.lease_until IS NULL AND
       NEW.lease_epoch=OLD.lease_epoch AND NEW.attempt_count=OLD.attempt_count AND NEW.failure_count=OLD.failure_count AND
       NEW.available_at=OLD.available_at AND NEW.last_error_code IS NULL AND NEW.blocked_at IS NULL AND NEW.completed_at IS NOT NULL THEN RETURN NEW; END IF;
    IF OLD.state IN ('pending','leased') AND NEW.state='held' AND NEW.lease_owner IS NULL AND NEW.lease_until IS NULL AND
       NEW.lease_epoch=OLD.lease_epoch+(CASE WHEN OLD.state='leased' THEN 1 ELSE 0 END) AND
       NEW.attempt_count=OLD.attempt_count AND NEW.failure_count=OLD.failure_count AND
       NEW.available_at=OLD.available_at AND NEW.last_error_code='legal_hold_active' AND
       NEW.blocked_at IS NULL AND NEW.completed_at IS NULL AND
       (pg_catalog.pg_has_role(session_user,'keel_context_legal_hold','MEMBER') OR
        pg_catalog.pg_has_role(session_user,'keel_context_erasure','MEMBER') OR
        pg_catalog.pg_has_role(session_user,'keel_context_erasure_worker','MEMBER')) THEN RETURN NEW; END IF;
    IF OLD.state='held' AND NEW.state='pending' AND NEW.lease_owner IS NULL AND NEW.lease_until IS NULL AND
       NEW.lease_epoch=OLD.lease_epoch AND NEW.attempt_count=OLD.attempt_count AND NEW.failure_count=OLD.failure_count AND
       NEW.available_at=OLD.expires_at AND NEW.last_error_code IS NULL AND NEW.blocked_at IS NULL AND
       NEW.completed_at IS NULL AND pg_catalog.pg_has_role(session_user,'keel_context_legal_hold','MEMBER') THEN RETURN NEW; END IF;
    RAISE EXCEPTION 'invalid context erasure job transition: % -> %',OLD.state,NEW.state;
END $$;
REVOKE ALL ON FUNCTION keel_meta.guard_context_vault_erasure_job() FROM PUBLIC;

CREATE FUNCTION keel_meta.context_vault_has_active_legal_hold(p_tenant uuid,p_record uuid,p_version bigint)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,keel_meta AS $$
    SELECT EXISTS (SELECT 1 FROM keel_meta.context_vault_legal_holds h
        WHERE h.tenant_id=p_tenant AND h.record_id=p_record AND h.version=p_version AND h.released_at IS NULL)
$$;
REVOKE ALL ON FUNCTION keel_meta.context_vault_has_active_legal_hold(uuid,uuid,bigint) FROM PUBLIC;

CREATE OR REPLACE FUNCTION keel_meta.guard_context_vault_mutation()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,keel_meta AS $$
DECLARE expected_digest text;
BEGIN
    IF TG_OP='UPDATE' THEN RAISE EXCEPTION 'context vault record versions are immutable'; END IF;
    IF TG_OP='DELETE' AND current_user='keel_schema_owner' AND
       (pg_catalog.pg_has_role(session_user,'keel_context_erasure','MEMBER') OR
        pg_catalog.pg_has_role(session_user,'keel_context_erasure_worker','MEMBER')) THEN
        IF keel_meta.context_vault_has_active_legal_hold(OLD.tenant_id,OLD.record_id,OLD.version) THEN
            RAISE EXCEPTION 'context vault record is protected by an active legal hold';
        END IF;
        expected_digest:=keel_meta.context_vault_envelope_sha256(OLD.tenant_id,OLD.record_id,OLD.version,
            OLD.policy_digest,OLD.algorithm,OLD.key_id,OLD.wrapped_dek,OLD.nonce,OLD.ciphertext);
        IF EXISTS (SELECT 1 FROM keel_meta.context_vault_erasure_receipts receipt
            WHERE receipt.tenant_id=OLD.tenant_id AND receipt.record_id=OLD.record_id AND
                  receipt.version=OLD.version AND receipt.purpose=OLD.purpose AND
                  receipt.retention_policy_version=OLD.retention_policy_version AND receipt.consent_id=OLD.consent_id AND
                  receipt.expires_at=OLD.expires_at AND receipt.envelope_sha256=expected_digest) THEN RETURN OLD; END IF;
    END IF;
    RAISE EXCEPTION 'context vault record versions are immutable';
END $$;
REVOKE ALL ON FUNCTION keel_meta.guard_context_vault_mutation() FROM PUBLIC;

CREATE FUNCTION keel_meta.create_context_vault_legal_hold(
    p_record_id uuid,p_version bigint,p_actor_id uuid,p_reason_code text,p_review_milliseconds bigint)
RETURNS TABLE(hold_id uuid,revision integer,review_due_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,keel_meta,keel_private,pg_temp AS $$
DECLARE authorized_tenant uuid; record_found boolean; new_hold uuid; due_at timestamptz;
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'keel_context_legal_hold','MEMBER') THEN
        RAISE EXCEPTION 'context legal hold capability is required';
    END IF;
    authorized_tenant:=keel_private.current_tenant_id();
    IF authorized_tenant IS NULL OR p_record_id IS NULL OR p_version IS NULL OR p_version<1 OR
       p_actor_id IS NULL OR p_actor_id='00000000-0000-0000-0000-000000000000'::uuid OR
       p_reason_code IS NULL OR p_reason_code NOT IN ('litigation','regulatory','investigation','preservation_order','other_authorized') OR
       p_review_milliseconds IS NULL OR p_review_milliseconds NOT BETWEEN 1000 AND 7776000000 THEN
        RAISE EXCEPTION 'context legal hold metadata is invalid';
    END IF;
    SELECT true INTO record_found FROM keel_meta.context_vault_records r
     WHERE r.tenant_id=authorized_tenant AND r.record_id=p_record_id AND r.version=p_version FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'context vault record is unavailable for legal hold'; END IF;
    new_hold:=pg_catalog.gen_random_uuid();
    due_at:=clock_timestamp()+p_review_milliseconds*interval '1 millisecond';
    INSERT INTO keel_meta.context_vault_legal_holds(tenant_id,hold_id,record_id,version,revision,review_due_at)
    VALUES (authorized_tenant,new_hold,p_record_id,p_version,1,due_at);
    INSERT INTO keel_meta.context_vault_legal_hold_events
        (tenant_id,hold_id,record_id,version,revision,action,decision,reason_code,actor_id,review_due_at)
    VALUES (authorized_tenant,new_hold,p_record_id,p_version,1,'created','placed',p_reason_code,p_actor_id,due_at);
    UPDATE keel_meta.context_vault_erasure_jobs SET state='held',lease_owner=NULL,lease_until=NULL,
        lease_epoch=lease_epoch+(CASE WHEN state='leased' THEN 1 ELSE 0 END),
        last_error_code='legal_hold_active',updated_at=clock_timestamp()
     WHERE tenant_id=authorized_tenant AND record_id=p_record_id AND version=p_version AND state IN ('pending','leased');
    RETURN QUERY SELECT new_hold,1,due_at;
END $$;
REVOKE ALL ON FUNCTION keel_meta.create_context_vault_legal_hold(uuid,bigint,uuid,text,bigint) FROM PUBLIC;

CREATE FUNCTION keel_meta.review_context_vault_legal_hold(
    p_hold_id uuid,p_actor_id uuid,p_decision text,p_reason_code text,p_review_milliseconds bigint)
RETURNS TABLE(revision integer,review_due_at timestamptz,released boolean)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,keel_meta,keel_private,pg_temp AS $$
DECLARE authorized_tenant uuid; target keel_meta.context_vault_legal_holds%ROWTYPE;
        next_revision integer; due_at timestamptz; release_time timestamptz;
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'keel_context_legal_hold','MEMBER') THEN
        RAISE EXCEPTION 'context legal hold capability is required';
    END IF;
    authorized_tenant:=keel_private.current_tenant_id();
    IF authorized_tenant IS NULL OR p_hold_id IS NULL OR p_actor_id IS NULL OR
       p_actor_id='00000000-0000-0000-0000-000000000000'::uuid OR
       p_decision IS NULL OR p_decision NOT IN ('extend','release') OR p_reason_code IS NULL OR
       p_reason_code NOT IN ('litigation','regulatory','investigation','preservation_order','other_authorized') OR
       (p_decision='extend' AND (p_review_milliseconds IS NULL OR p_review_milliseconds NOT BETWEEN 1000 AND 7776000000)) OR
       (p_decision='release' AND p_review_milliseconds IS NOT NULL) THEN
        RAISE EXCEPTION 'context legal hold review metadata is invalid';
    END IF;
    SELECT * INTO target FROM keel_meta.context_vault_legal_holds
     WHERE tenant_id=authorized_tenant AND hold_id=p_hold_id;
    IF NOT FOUND THEN RAISE EXCEPTION 'context legal hold is unavailable'; END IF;
    PERFORM 1 FROM keel_meta.context_vault_records r
     WHERE r.tenant_id=authorized_tenant AND r.record_id=target.record_id AND r.version=target.version FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'context vault record is unavailable for legal hold review'; END IF;
    SELECT * INTO target FROM keel_meta.context_vault_legal_holds
     WHERE tenant_id=authorized_tenant AND hold_id=p_hold_id FOR UPDATE;
    IF NOT FOUND OR target.released_at IS NOT NULL THEN RAISE EXCEPTION 'context legal hold is already released'; END IF;
    next_revision:=target.revision+1;
    due_at:=target.review_due_at;
    release_time:=NULL;
    IF p_decision='extend' THEN due_at:=clock_timestamp()+p_review_milliseconds*interval '1 millisecond';
    ELSE release_time:=clock_timestamp(); END IF;
    UPDATE keel_meta.context_vault_legal_holds SET revision=next_revision,review_due_at=due_at,
        released_at=release_time,updated_at=clock_timestamp()
     WHERE tenant_id=authorized_tenant AND hold_id=p_hold_id;
    INSERT INTO keel_meta.context_vault_legal_hold_events
        (tenant_id,hold_id,record_id,version,revision,action,decision,reason_code,actor_id,review_due_at)
    VALUES (authorized_tenant,p_hold_id,target.record_id,target.version,next_revision,'reviewed',p_decision,
        p_reason_code,p_actor_id,due_at);
    IF p_decision='release' AND NOT keel_meta.context_vault_has_active_legal_hold(
        authorized_tenant,target.record_id,target.version) THEN
        UPDATE keel_meta.context_vault_erasure_jobs SET state='pending',available_at=expires_at,
            last_error_code=NULL,updated_at=clock_timestamp()
         WHERE tenant_id=authorized_tenant AND record_id=target.record_id AND version=target.version AND state='held';
    END IF;
    RETURN QUERY SELECT next_revision,due_at,p_decision='release';
END $$;
REVOKE ALL ON FUNCTION keel_meta.review_context_vault_legal_hold(uuid,uuid,text,text,bigint) FROM PUBLIC;

CREATE FUNCTION keel_meta.release_context_vault_legal_hold(p_hold_id uuid,p_actor_id uuid,p_reason_code text)
RETURNS TABLE(revision integer,review_due_at timestamptz,released boolean)
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,keel_meta,keel_private AS $$
    SELECT * FROM keel_meta.review_context_vault_legal_hold(p_hold_id,p_actor_id,'release',p_reason_code,NULL)
$$;
REVOKE ALL ON FUNCTION keel_meta.release_context_vault_legal_hold(uuid,uuid,text) FROM PUBLIC;

CREATE FUNCTION keel_meta.extend_context_vault_legal_hold(
    p_hold_id uuid,p_actor_id uuid,p_reason_code text,p_review_milliseconds bigint)
RETURNS TABLE(revision integer,review_due_at timestamptz,released boolean)
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,keel_meta,keel_private AS $$
    SELECT * FROM keel_meta.review_context_vault_legal_hold(p_hold_id,p_actor_id,'extend',p_reason_code,p_review_milliseconds)
$$;
REVOKE ALL ON FUNCTION keel_meta.extend_context_vault_legal_hold(uuid,uuid,text,bigint) FROM PUBLIC;

GRANT USAGE ON SCHEMA keel_meta,keel_private TO keel_context_legal_hold;
GRANT EXECUTE ON FUNCTION keel_private.current_tenant_id() TO keel_context_legal_hold;
GRANT EXECUTE ON FUNCTION keel_meta.create_context_vault_legal_hold(uuid,bigint,uuid,text,bigint) TO keel_context_legal_hold;
GRANT EXECUTE ON FUNCTION keel_meta.review_context_vault_legal_hold(uuid,uuid,text,text,bigint) TO keel_context_legal_hold;
GRANT EXECUTE ON FUNCTION keel_meta.release_context_vault_legal_hold(uuid,uuid,text) TO keel_context_legal_hold;
GRANT EXECUTE ON FUNCTION keel_meta.extend_context_vault_legal_hold(uuid,uuid,text,bigint) TO keel_context_legal_hold;

REVOKE ALL ON keel_meta.context_vault_records,keel_meta.context_retention_policies,
    keel_meta.context_retention_policy_heads,keel_meta.context_vault_erasure_receipts
    FROM keel_context_legal_hold;

CREATE OR REPLACE FUNCTION keel_meta.erase_expired_context_vault(p_batch_size integer)
RETURNS integer LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,keel_meta,keel_private,pg_temp AS $$
DECLARE authorized_tenant uuid; record_row keel_meta.context_vault_records%ROWTYPE; deleted_count integer:=0;
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'keel_context_erasure','MEMBER') THEN RAISE EXCEPTION 'context erasure capability is required'; END IF;
    authorized_tenant:=keel_private.current_tenant_id();
    IF authorized_tenant IS NULL THEN RAISE EXCEPTION 'context erasure tenant scope is required'; END IF;
    IF p_batch_size IS NULL OR p_batch_size<1 OR p_batch_size>100 THEN RAISE EXCEPTION 'context erasure batch size is outside the supported bound'; END IF;
    FOR record_row IN SELECT * FROM keel_meta.context_vault_records
        WHERE tenant_id=authorized_tenant AND expires_at<=statement_timestamp()
          AND NOT keel_meta.context_vault_has_active_legal_hold(tenant_id,record_id,version)
        ORDER BY expires_at,record_id,version LIMIT p_batch_size FOR UPDATE SKIP LOCKED
    LOOP
        IF keel_meta.context_vault_has_active_legal_hold(record_row.tenant_id,record_row.record_id,record_row.version) THEN
            UPDATE keel_meta.context_vault_erasure_jobs SET state='held',lease_owner=NULL,lease_until=NULL,
                lease_epoch=lease_epoch+(CASE WHEN state='leased' THEN 1 ELSE 0 END),
                last_error_code='legal_hold_active',updated_at=clock_timestamp()
             WHERE tenant_id=record_row.tenant_id AND record_id=record_row.record_id AND version=record_row.version
               AND state IN ('pending','leased');
            CONTINUE;
        END IF;
        INSERT INTO keel_meta.context_vault_erasure_receipts
            (tenant_id,record_id,version,purpose,retention_policy_version,consent_id,expires_at,envelope_sha256)
        VALUES (record_row.tenant_id,record_row.record_id,record_row.version,record_row.purpose,
            record_row.retention_policy_version,record_row.consent_id,record_row.expires_at,
            keel_meta.context_vault_envelope_sha256(record_row.tenant_id,record_row.record_id,record_row.version,
                record_row.policy_digest,record_row.algorithm,record_row.key_id,record_row.wrapped_dek,
                record_row.nonce,record_row.ciphertext));
        DELETE FROM keel_meta.context_vault_records WHERE tenant_id=record_row.tenant_id
            AND record_id=record_row.record_id AND version=record_row.version;
        deleted_count:=deleted_count+1;
    END LOOP;
    RETURN deleted_count;
END $$;
REVOKE ALL ON FUNCTION keel_meta.erase_expired_context_vault(integer) FROM PUBLIC;

DROP FUNCTION keel_meta.process_context_vault_erasure_job(uuid,bigint,text,bigint);
CREATE FUNCTION keel_meta.process_context_vault_erasure_job(
    p_record_id uuid,p_version bigint,p_worker_id text,p_lease_epoch bigint)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,keel_meta,keel_private,pg_temp AS $$
DECLARE authorized_tenant uuid; job_row keel_meta.context_vault_erasure_jobs%ROWTYPE;
        record_row keel_meta.context_vault_records%ROWTYPE; record_found boolean; job_found boolean;
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'keel_context_erasure_worker','MEMBER') THEN RAISE EXCEPTION 'context erasure worker capability is required'; END IF;
    authorized_tenant:=keel_private.current_tenant_id();
    IF authorized_tenant IS NULL OR p_record_id IS NULL OR p_version IS NULL OR p_version<1 OR
       p_worker_id IS NULL OR p_worker_id !~ '^[a-z0-9][a-z0-9._:-]{1,63}$' OR p_lease_epoch IS NULL OR p_lease_epoch<1 THEN
        RAISE EXCEPTION 'context erasure job identity is invalid';
    END IF;
    SELECT * INTO record_row FROM keel_meta.context_vault_records r
     WHERE r.tenant_id=authorized_tenant AND r.record_id=p_record_id AND r.version=p_version
       AND r.expires_at<=statement_timestamp() FOR UPDATE;
    record_found:=FOUND;
    SELECT * INTO job_row FROM keel_meta.context_vault_erasure_jobs j
     WHERE j.tenant_id=authorized_tenant AND j.record_id=p_record_id AND j.version=p_version
       AND j.state='leased' AND j.lease_owner=p_worker_id AND j.lease_epoch=p_lease_epoch
       AND j.lease_until>clock_timestamp() FOR UPDATE;
    job_found:=FOUND;
    IF NOT job_found THEN RAISE EXCEPTION 'context erasure lease is no longer current'; END IF;
    IF NOT record_found THEN
        IF EXISTS (SELECT 1 FROM keel_meta.context_vault_erasure_receipts r
            WHERE r.tenant_id=authorized_tenant AND r.record_id=p_record_id AND r.version=p_version) THEN
            UPDATE keel_meta.context_vault_erasure_jobs SET state='complete',lease_owner=NULL,lease_until=NULL,
                last_error_code=NULL,completed_at=clock_timestamp(),updated_at=clock_timestamp()
             WHERE tenant_id=authorized_tenant AND record_id=p_record_id AND version=p_version;
            RETURN 'already_deleted';
        END IF;
        RAISE EXCEPTION 'expired context record is unavailable for erasure';
    END IF;
    IF keel_meta.context_vault_has_active_legal_hold(authorized_tenant,p_record_id,p_version) THEN
        UPDATE keel_meta.context_vault_erasure_jobs SET state='held',lease_owner=NULL,lease_until=NULL,
            lease_epoch=lease_epoch+1,last_error_code='legal_hold_active',updated_at=clock_timestamp()
         WHERE tenant_id=authorized_tenant AND record_id=p_record_id AND version=p_version;
        RETURN 'held';
    END IF;
    INSERT INTO keel_meta.context_vault_erasure_receipts
        (tenant_id,record_id,version,purpose,retention_policy_version,consent_id,expires_at,envelope_sha256)
    VALUES (record_row.tenant_id,record_row.record_id,record_row.version,record_row.purpose,
        record_row.retention_policy_version,record_row.consent_id,record_row.expires_at,
        keel_meta.context_vault_envelope_sha256(record_row.tenant_id,record_row.record_id,record_row.version,
            record_row.policy_digest,record_row.algorithm,record_row.key_id,record_row.wrapped_dek,
            record_row.nonce,record_row.ciphertext));
    DELETE FROM keel_meta.context_vault_records WHERE tenant_id=authorized_tenant AND record_id=p_record_id AND version=p_version;
    UPDATE keel_meta.context_vault_erasure_jobs SET state='complete',lease_owner=NULL,lease_until=NULL,
        last_error_code=NULL,completed_at=clock_timestamp(),updated_at=clock_timestamp()
     WHERE tenant_id=authorized_tenant AND record_id=p_record_id AND version=p_version;
    RETURN 'deleted';
END $$;
REVOKE ALL ON FUNCTION keel_meta.process_context_vault_erasure_job(uuid,bigint,text,bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION keel_meta.process_context_vault_erasure_job(uuid,bigint,text,bigint) TO keel_context_erasure_worker;
