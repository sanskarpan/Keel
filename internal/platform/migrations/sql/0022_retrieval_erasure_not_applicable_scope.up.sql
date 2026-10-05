-- The worker may acknowledge N/A only for cache/queued-work capabilities that
-- the current profile explicitly does not mount. Required source, index,
-- legal-hold and backup work must not be skipped to satisfy completion.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM keel_meta.retrieval_erasure_action_receipts
        WHERE disposition='not_applicable'
          AND action_key NOT IN ('cache_revocation','queued_work_revocation')
    ) THEN
        RAISE EXCEPTION 'required retrieval erasure actions have not-applicable receipts; reconcile before applying migration 0022';
    END IF;
END $$;

ALTER TABLE keel_meta.retrieval_erasure_action_receipts
    ADD CONSTRAINT retrieval_erasure_receipt_not_applicable_scope
    CHECK (disposition<>'not_applicable' OR action_key IN ('cache_revocation','queued_work_revocation'));
