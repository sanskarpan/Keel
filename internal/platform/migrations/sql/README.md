# Keel SQL migrations

Add only forward migrations named `NNNN_description.up.sql` with unique, increasing integer
versions. Applied files are immutable: the runner records SHA-256 and stops on drift. Repair a
mistake with a new forward migration; do not edit an applied file. Each migration and its ledger
row run in one PostgreSQL transaction while the runner holds the fixed session advisory lock and
`SET ROLE keel_schema_owner` on the same connection.

Keep files compatible with transactional PostgreSQL execution. Online operations such as
`CREATE INDEX CONCURRENTLY` require an explicit future runner extension and separate acceptance;
they cannot be placed in a regular migration file. The first domain migration will ship alongside
the first owning domain schema so Keel does not manufacture unused application tables here.
