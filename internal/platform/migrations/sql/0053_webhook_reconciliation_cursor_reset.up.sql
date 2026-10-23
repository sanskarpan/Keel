CREATE TABLE keel_meta.webhook_reconciliation_cursor_resets (
    tenant_id uuid NOT NULL CHECK (tenant_id<>'00000000-0000-0000-0000-000000000000'::uuid),
    reset_id text NOT NULL CHECK (reset_id ~ '^[A-Za-z0-9_-]{8,64}$'),
    requested_by text NOT NULL CHECK (requested_by ~ '^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}$'),
    prior_created_at timestamptz NOT NULL,
    prior_event_id uuid NOT NULL,
    new_created_at timestamptz NOT NULL,
    new_event_id uuid NOT NULL,
    reason text NOT NULL CHECK (length(reason) BETWEEN 1 AND 512 AND reason !~ '[[:cntrl:]]'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id,reset_id),
    CONSTRAINT webhook_reconciliation_cursor_resets_backward CHECK (
        (new_created_at,new_event_id)<(prior_created_at,prior_event_id))
);
ALTER TABLE keel_meta.webhook_reconciliation_cursor_resets ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.webhook_reconciliation_cursor_resets FORCE ROW LEVEL SECURITY;
CREATE POLICY webhook_reconciliation_cursor_resets_schema_owner
    ON keel_meta.webhook_reconciliation_cursor_resets TO keel_schema_owner USING (true) WITH CHECK (true);
REVOKE ALL ON keel_meta.webhook_reconciliation_cursor_resets FROM PUBLIC,keel_app,keel_worker,keel_operator,
    keel_budget_control,keel_rate_control,keel_ai_worker,keel_projector,keel_file_processor,
    keel_retrieval_indexer,keel_context_vault,keel_context_policy,keel_context_erasure,
    keel_context_erasure_worker,keel_context_legal_hold,keel_context_replay,keel_agent,
    keel_callback,keel_webhook;
CREATE TRIGGER webhook_reconciliation_cursor_reset_immutable BEFORE UPDATE OR DELETE
    ON keel_meta.webhook_reconciliation_cursor_resets FOR EACH ROW
    EXECUTE FUNCTION keel_meta.reject_webhook_reconciliation_mutation();

CREATE OR REPLACE FUNCTION keel_meta.guard_webhook_reconciliation_cursor()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    IF TG_OP='DELETE' THEN
        RAISE EXCEPTION 'webhook reconciliation cursor cannot be deleted';
    END IF;
    IF NEW.tenant_id<>OLD.tenant_id THEN
        RAISE EXCEPTION 'webhook reconciliation cursor identity is immutable';
    END IF;
    IF (NEW.last_event_created_at,NEW.last_event_id)<=(OLD.last_event_created_at,OLD.last_event_id) AND
       NOT EXISTS (
           SELECT 1 FROM keel_meta.webhook_reconciliation_cursor_resets r
            WHERE r.tenant_id=OLD.tenant_id
              AND r.prior_created_at=OLD.last_event_created_at
              AND r.prior_event_id=OLD.last_event_id
              AND r.new_created_at=NEW.last_event_created_at
              AND r.new_event_id=NEW.last_event_id) THEN
        RAISE EXCEPTION 'webhook reconciliation cursor is invalid';
    END IF;
    RETURN NEW;
END $$;

CREATE FUNCTION keel_meta.reset_webhook_reconciliation_cursor(
    p_reset_id text,p_requested_by text,p_to_created_at timestamptz,p_reason text)
RETURNS TABLE(r_reset_id text,r_prior_created_at timestamptz,r_prior_event_id uuid,
    r_new_created_at timestamptz,r_new_event_id uuid)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,keel_meta,keel_private,pg_temp AS $$
DECLARE authorized_tenant uuid;
        prior_created_at timestamptz;
        prior_event_id uuid;
        new_event_id uuid:='00000000-0000-0000-0000-000000000000'::uuid;
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'keel_operator','MEMBER') THEN
        RAISE EXCEPTION 'webhook reconciliation capability is required';
    END IF;
    authorized_tenant:=keel_private.current_tenant_id();
    IF authorized_tenant IS NULL OR
       p_reset_id IS NULL OR p_reset_id !~ '^[A-Za-z0-9_-]{8,64}$' OR
       p_requested_by IS NULL OR p_requested_by !~ '^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}$' OR
       p_to_created_at IS NULL OR p_to_created_at>clock_timestamp() OR
       p_reason IS NULL OR length(p_reason) NOT BETWEEN 1 AND 512 OR p_reason ~ '[[:cntrl:]]' THEN
        RAISE EXCEPTION 'webhook reconciliation reset request is invalid';
    END IF;

    PERFORM pg_catalog.pg_advisory_xact_lock(
        pg_catalog.hashtextextended('keel.webhook.reconciliation.reset:'||authorized_tenant::text,0));

    IF EXISTS (SELECT 1 FROM keel_meta.webhook_reconciliation_cursor_resets
                WHERE tenant_id=authorized_tenant AND reset_id=p_reset_id) THEN
        RAISE EXCEPTION 'webhook reconciliation reset already exists';
    END IF;

    SELECT c.last_event_created_at,c.last_event_id INTO prior_created_at,prior_event_id
      FROM keel_meta.webhook_reconciliation_cursors c
     WHERE c.tenant_id=authorized_tenant
       FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'webhook reconciliation cursor was not found';
    END IF;
    IF (p_to_created_at,new_event_id)>=(prior_created_at,prior_event_id) THEN
        RAISE EXCEPTION 'webhook reconciliation reset must move backward';
    END IF;

    INSERT INTO keel_meta.webhook_reconciliation_cursor_resets
        (tenant_id,reset_id,requested_by,prior_created_at,prior_event_id,new_created_at,new_event_id,reason)
    VALUES (authorized_tenant,p_reset_id,p_requested_by,prior_created_at,prior_event_id,
            p_to_created_at,new_event_id,p_reason);

    UPDATE keel_meta.webhook_reconciliation_cursors
       SET last_event_created_at=p_to_created_at,last_event_id=new_event_id,updated_at=clock_timestamp()
     WHERE tenant_id=authorized_tenant;

    RETURN QUERY SELECT p_reset_id,prior_created_at,prior_event_id,p_to_created_at,new_event_id;
END $$;
REVOKE ALL ON FUNCTION keel_meta.reset_webhook_reconciliation_cursor(text,text,timestamptz,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION keel_meta.reset_webhook_reconciliation_cursor(text,text,timestamptz,text)
    TO keel_operator;
