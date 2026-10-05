-- The worker may acknowledge N/A only for cache/queued-work capabilities that
-- the current profile explicitly does not mount. Required source, index,
-- legal-hold and backup work must not be skipped to satisfy completion. This
-- constraint scan also fails closed on any pre-existing out-of-scope receipt.
ALTER TABLE keel_meta.retrieval_erasure_action_receipts
    ADD CONSTRAINT retrieval_erasure_receipt_not_applicable_scope
    CHECK (disposition<>'not_applicable' OR action_key IN ('cache_revocation','queued_work_revocation'));
