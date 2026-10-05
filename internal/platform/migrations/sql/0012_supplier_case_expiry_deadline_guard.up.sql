-- Expiry is a privileged domain transition, but its deadline is independently
-- enforced by PostgreSQL so an app caller cannot mark a live case expired.
CREATE FUNCTION keel_meta.guard_supplier_case_expiry_event()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, keel_meta, pg_temp
AS $$
DECLARE frozen_deadline timestamptz; current_state text; payload jsonb;
BEGIN
    IF NEW.event_type <> 'supplier.case.expired' THEN
        RETURN NEW;
    END IF;
    SELECT deadline_at,case_state INTO frozen_deadline,current_state
    FROM keel_meta.supplier_cases
    WHERE tenant_id=NEW.tenant_id AND case_id=NEW.case_id
    FOR UPDATE;
    payload := convert_from(NEW.event_data,'UTF8')::jsonb;
    IF frozen_deadline IS NULL OR current_state NOT IN ('collecting','submitted') OR
       NEW.actor_ref <> 'service-principal:keel-supplier-case-expirer' OR
       payload->>'deadline_at' IS NULL OR
       (payload->>'deadline_at')::timestamptz <> frozen_deadline OR
       NEW.occurred_at < frozen_deadline OR NEW.occurred_at > clock_timestamp() THEN
        RAISE EXCEPTION 'supplier case expiry must match its persisted deadline after it has passed';
    END IF;
    RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION keel_meta.guard_supplier_case_expiry_event() FROM PUBLIC;
CREATE TRIGGER supplier_case_expiry_deadline_guard
    BEFORE INSERT ON keel_meta.supplier_case_events
    FOR EACH ROW EXECUTE FUNCTION keel_meta.guard_supplier_case_expiry_event();
GRANT EXECUTE ON FUNCTION keel_meta.guard_supplier_case_expiry_event() TO keel_app;
