-- K8.11 repair of 0074: the membership guard rejects member-to-owner transfer.
-- 0074_identity_invites_transfer allowed only owner-to-admin and
-- admin-to-owner role moves, but transfer_organization_ownership seats the
-- target from either admin or member. The live transfer test failed with
-- 'membership roles change only by owner transfer' on a member target. This
-- replaces the guard to permit all three transfer shapes; every other
-- direct mutation, including deletes, stays refused. Applied files are
-- immutable; this is the forward repair per the migrations README.

CREATE OR REPLACE FUNCTION keel_meta.guard_identity_memberships_row()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    IF TG_OP='DELETE' THEN
        RAISE EXCEPTION 'identity memberships have no delete path in this slice';
    END IF;
    IF current_user<>'keel_schema_owner' OR
       NOT pg_catalog.pg_has_role(session_user,'keel_identity','MEMBER') THEN
        RAISE EXCEPTION 'identity memberships are capability-managed';
    END IF;
    IF TG_OP='INSERT' THEN
        RETURN NEW;
    END IF;
    IF NEW.org_id<>OLD.org_id OR NEW.principal_id<>OLD.principal_id OR
       NEW.created_at<>OLD.created_at THEN
        RAISE EXCEPTION 'identity membership identity is immutable';
    END IF;
    IF NOT ((OLD.role='owner' AND NEW.role='admin') OR
            (OLD.role='admin' AND NEW.role='owner') OR
            (OLD.role='member' AND NEW.role='owner')) THEN
        RAISE EXCEPTION 'membership roles change only by owner transfer';
    END IF;
    RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION keel_meta.guard_identity_memberships_row() FROM PUBLIC;
