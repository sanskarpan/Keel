-- K8.11 repair of 0067: the throttle guard forbade the fresh-count reset.
-- 0067_identity_login_lockout allowed first_failure_at to change only by not
-- changing it, but the decay and expired-lock branches reset the count to one
-- with first_failure_at=now, so every such UPDATE aborted with
-- 'identity throttle identity is immutable' before the row changed. This
-- replaces the guard to permit exactly that transition (count reset to one,
-- unlocked, first and last moved together to now) while still refusing any
-- other rewrite of an active count. Applied files are immutable; this is the
-- forward repair per the migrations README.

CREATE OR REPLACE FUNCTION keel_meta.guard_identity_login_throttle_row()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    IF current_user<>'keel_schema_owner' OR
       NOT pg_catalog.pg_has_role(session_user,'keel_identity','MEMBER') THEN
        RAISE EXCEPTION 'identity throttle is capability-managed';
    END IF;
    IF TG_OP='DELETE' THEN
        -- success clears the count; consumed lockouts leave no residue.
        RETURN OLD;
    END IF;
    IF TG_OP='INSERT' THEN
        IF NEW.principal_id IS NULL OR NEW.consecutive_failures<0 OR
           NEW.first_failure_at IS NULL OR NEW.last_failure_at IS NULL OR
           NEW.last_failure_at<NEW.first_failure_at OR
           (NEW.locked_until IS NOT NULL AND NEW.locked_until<=NEW.last_failure_at) THEN
            RAISE EXCEPTION 'identity throttle row is invalid';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.principal_id<>OLD.principal_id THEN
        RAISE EXCEPTION 'identity throttle identity is immutable';
    END IF;
    IF NEW.first_failure_at<>OLD.first_failure_at AND NOT (
           NEW.consecutive_failures=1 AND NEW.locked_until IS NULL AND
           NEW.last_failure_at=NEW.first_failure_at) THEN
        RAISE EXCEPTION 'identity throttle identity is immutable';
    END IF;
    RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION keel_meta.guard_identity_login_throttle_row() FROM PUBLIC;
