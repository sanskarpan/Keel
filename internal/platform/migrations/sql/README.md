# Keel SQL migrations

Add only forward migrations named `NNNN_description.up.sql` with unique, increasing integer
versions. Applied files are immutable: the runner records SHA-256 and stops on drift. Repair a
mistake with a new forward migration; do not edit an applied file. Each migration and its ledger
row run in one PostgreSQL transaction while the runner holds the fixed session advisory lock and
`SET ROLE keel_schema_owner` on the same connection.

Keep files compatible with transactional PostgreSQL execution. Online operations such as
`CREATE INDEX CONCURRENTLY` require an explicit future runner extension and separate acceptance;
they cannot be placed in a regular migration file. The order aggregate/idempotency schema is
introduced by migration `0001_orders_and_idempotency`; transactional outbox/state-feed tables,
event-identity constraints, and the age-bound feed retention policy are added by `0002` through
`0004`. Migration `0014_retrieval_lexical_publication` adds tenant/visibility-scoped immutable
lexical builds, posting/statistic reconciliation, and a generation-fenced active-corpus pointer.
Add later product tables with the owning domain migration and its access, retention, and recovery
contracts.
