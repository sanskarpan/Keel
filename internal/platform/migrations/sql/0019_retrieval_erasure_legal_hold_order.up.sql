-- Destructive cleanup actions cannot even record success until the required
-- legal-hold adapter has recorded a clearance decision for this lease history.
CREATE OR REPLACE FUNCTION keel_meta.require_retrieval_erasure_hold_clear_before_action()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,keel_meta,pg_temp AS $$
BEGIN
    IF NEW.action_key<>'legal_hold_check' AND NOT EXISTS (
        SELECT 1 FROM keel_meta.retrieval_erasure_action_receipts r
        WHERE r.tenant_id=NEW.tenant_id AND r.visibility_key=NEW.visibility_key AND r.job_id=NEW.job_id
          AND r.action_key='legal_hold_check' AND r.disposition='complete' AND r.lease_epoch<=NEW.lease_epoch
    ) THEN
        RAISE EXCEPTION 'legal hold clearance receipt is required before recording a destructive erasure action';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER retrieval_erasure_hold_action_order
    BEFORE INSERT ON keel_meta.retrieval_erasure_action_receipts
    FOR EACH ROW EXECUTE FUNCTION keel_meta.require_retrieval_erasure_hold_clear_before_action();
REVOKE ALL ON FUNCTION keel_meta.require_retrieval_erasure_hold_clear_before_action() FROM PUBLIC;
