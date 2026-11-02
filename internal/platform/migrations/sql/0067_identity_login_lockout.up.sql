-- K8.11 slice 4: bounded login lockout.
-- One throttle row per principal counts consecutive failed password logins.
-- Five consecutive failures lock the principal for 15 minutes; a success
-- deletes the row, an expired lock or a failure older than 15 minutes starts
-- a fresh count, and attempts while locked change nothing (no lockout
-- stretching). All access is through keel_identity-gated SECURITY DEFINER
-- functions; the table carries forced RLS with no direct grants.

CREATE TABLE keel_meta.identity_login_throttle (
    principal_id uuid NOT NULL PRIMARY KEY REFERENCES keel_meta.identity_principals(principal_id),
    consecutive_failures integer NOT NULL CHECK (consecutive_failures>=0),
    first_failure_at timestamptz NOT NULL,
    last_failure_at timestamptz NOT NULL,
    locked_until timestamptz,
    CONSTRAINT identity_throttle_window CHECK (last_failure_at>=first_failure_at),
    CONSTRAINT identity_throttle_lock_shape CHECK (locked_until IS NULL OR locked_until>last_failure_at)
);
ALTER TABLE keel_meta.identity_login_throttle ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_meta.identity_login_throttle FORCE ROW LEVEL SECURITY;
CREATE POLICY identity_login_throttle_schema_owner ON keel_meta.identity_login_throttle
    TO keel_schema_owner USING (true) WITH CHECK (true);
REVOKE ALL ON keel_meta.identity_login_throttle FROM PUBLIC,keel_app,keel_worker,keel_operator,
    keel_budget_control,keel_rate_control,keel_rate_status,keel_ai_worker,keel_projector,
    keel_file_processor,keel_retrieval_indexer,keel_context_vault,keel_context_policy,
    keel_context_erasure,keel_context_erasure_worker,keel_context_legal_hold,
    keel_context_replay,keel_agent,keel_callback,keel_webhook,keel_identity;

CREATE FUNCTION keel_meta.guard_identity_login_throttle_row()
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
    IF NEW.principal_id<>OLD.principal_id OR NEW.first_failure_at<>OLD.first_failure_at THEN
        RAISE EXCEPTION 'identity throttle identity is immutable';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER identity_login_throttle_guard BEFORE INSERT OR UPDATE OR DELETE
    ON keel_meta.identity_login_throttle FOR EACH ROW
    EXECUTE FUNCTION keel_meta.guard_identity_login_throttle_row();
REVOKE ALL ON FUNCTION keel_meta.guard_identity_login_throttle_row() FROM PUBLIC;

CREATE FUNCTION keel_meta.record_identity_login_failure(p_principal_id uuid)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,keel_meta,pg_temp AS $$
DECLARE
    failures integer;
    first_at timestamptz;
    last_at timestamptz;
    locked timestamptz;
    now timestamptz := clock_timestamp();
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'keel_identity','MEMBER') THEN
        RAISE EXCEPTION 'identity capability is required';
    END IF;
    IF p_principal_id IS NULL OR p_principal_id='00000000-0000-0000-0000-000000000000'::uuid THEN
        RAISE EXCEPTION 'identity throttle record is invalid';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM keel_meta.identity_principals WHERE principal_id=p_principal_id) THEN
        RETURN 'unknown_principal';
    END IF;
    SELECT consecutive_failures,first_failure_at,last_failure_at,locked_until
      INTO failures,first_at,last_at,locked
      FROM keel_meta.identity_login_throttle
      WHERE principal_id=p_principal_id FOR UPDATE;
    IF NOT FOUND THEN
        INSERT INTO keel_meta.identity_login_throttle
            (principal_id,consecutive_failures,first_failure_at,last_failure_at,locked_until)
            VALUES (p_principal_id,1,now,now,NULL);
        RETURN 'counted';
    END IF;
    IF locked IS NOT NULL AND locked>now THEN
        RETURN 'locked';
    END IF;
    IF (locked IS NOT NULL AND locked<=now) OR last_at<now-INTERVAL '15 minutes' THEN
        UPDATE keel_meta.identity_login_throttle
           SET consecutive_failures=1,first_failure_at=now,last_failure_at=now,locked_until=NULL
         WHERE principal_id=p_principal_id;
        RETURN 'counted';
    END IF;
    IF failures+1>=5 THEN
        UPDATE keel_meta.identity_login_throttle
           SET consecutive_failures=failures+1,last_failure_at=now,locked_until=now+INTERVAL '15 minutes'
         WHERE principal_id=p_principal_id;
        RETURN 'locked';
    END IF;
    UPDATE keel_meta.identity_login_throttle
       SET consecutive_failures=failures+1,last_failure_at=now
     WHERE principal_id=p_principal_id;
    RETURN 'counted';
END $$;
REVOKE ALL ON FUNCTION keel_meta.record_identity_login_failure(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION keel_meta.record_identity_login_failure(uuid) TO keel_identity;

CREATE FUNCTION keel_meta.reset_identity_login_throttle(p_principal_id uuid)
RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,keel_meta,pg_temp AS $$
DECLARE removed integer := 0;
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'keel_identity','MEMBER') THEN
        RAISE EXCEPTION 'identity capability is required';
    END IF;
    IF p_principal_id IS NULL OR p_principal_id='00000000-0000-0000-0000-000000000000'::uuid THEN
        RAISE EXCEPTION 'identity throttle reset is invalid';
    END IF;
    DELETE FROM keel_meta.identity_login_throttle WHERE principal_id=p_principal_id;
    GET DIAGNOSTICS removed = ROW_COUNT;
    RETURN removed;
END $$;
REVOKE ALL ON FUNCTION keel_meta.reset_identity_login_throttle(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION keel_meta.reset_identity_login_throttle(uuid) TO keel_identity;

CREATE FUNCTION keel_meta.identity_throttle_for(p_principal_id uuid)
RETURNS TABLE(out_consecutive integer,out_locked_until timestamptz)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,keel_meta,pg_temp AS $$
BEGIN
    IF NOT pg_catalog.pg_has_role(session_user,'keel_identity','MEMBER') THEN
        RAISE EXCEPTION 'identity capability is required';
    END IF;
    IF p_principal_id IS NULL OR p_principal_id='00000000-0000-0000-0000-000000000000'::uuid THEN
        RAISE EXCEPTION 'identity throttle lookup is invalid';
    END IF;
    RETURN QUERY
        SELECT consecutive_failures,locked_until
          FROM keel_meta.identity_login_throttle
         WHERE principal_id=p_principal_id;
END $$;
REVOKE ALL ON FUNCTION keel_meta.identity_throttle_for(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION keel_meta.identity_throttle_for(uuid) TO keel_identity;
