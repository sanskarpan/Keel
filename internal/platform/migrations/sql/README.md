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
Migration `0015_retrieval_vector_publication` adds immutable model manifests, source-generation-bound
vector builds, forced-RLS vector rows, and model-specific bounded HNSW index provisioning. The pgvector
extension must be installed and enabled in the target database by the privileged database bootstrap
before running application migrations; the restricted `keel_schema_owner` role must not install extensions.
The disposable CI database explicitly enables pgvector before applying the migration chain.
Migration `0016_retrieval_source_eligibility_erasure` adds a forced-RLS cohort/source withdrawal fence,
blocks stale rebuild publication and query results, and persists idempotent fenced erasure requests.
Migration `0017_retrieval_erasure_leases` adds tenant/cohort-scoped skip-locked claims, lease epochs,
bounded retry scheduling, and durable blocked/completed outcomes for those requests. These migrations
provide query suppression and cleanup orchestration state only: source-object deletion, physical index
compaction, backup expiry, and an end-to-end cleanup processor require separately qualified adapters
and runbooks.
Migration `0028_rate_limit_degraded_fallback` adds the disabled-by-default PostgreSQL safe-read
degraded limiter: control-plane-owned policies, shared regional fleet and tenant/route buckets,
expiring idempotency receipts, a 60-second outage fence, and recovery fencing through a separately
credentialed rate-control role. It does not enable fallback on any production route or qualify
managed Redis/PostgreSQL failover.

Migration `0029_rate_limit_degraded_status` adds a function for reading one home-region window's
presence, recovery fence, admission-open state, expiry, and last recovery time. It exposes no tenant,
route, request, outage, or Redis key data and grants no direct application-role read access.

Migration `0030_rate_limit_status_role` moves execution behind a dedicated `keel_rate_status` role.
It revokes status-function execution from `keel_rate_control`, whose credential can clear the Redis
recovery fence, and grants only schema usage plus status-function execution to the status role. The
deployment must provision the no-login role before migration; local bootstrap creates the separate
`keel_local_rate_status` login. The `rate-limit-observer` runtime uses this login to refresh and export
the snapshot, but a deployment profile still needs to launch it and configure scraping.

Migration `0031_ai_provider_attempt_ledger` adds immutable, content-free provider attempt plans and
append-only outcome evidence. Queue admission can persist the plan in the same transaction as the
K4.3 reserve and K4.4 job. Outcome recording requires the current AI worker lease owner and epoch.
The ledger does not dispatch provider requests or retry a fallback.

Migration `0032_ai_attempt_settlement` adds a worker-only transaction that records an attempt outcome
and applies terminal K4.3 budget settlement/unknown retention plus the K4.4 queue transition as one
unit. A proven primary no-charge failure keeps the existing reservation and lease only while the
preplanned fallback is still eligible; otherwise the reservation settles as no-charge. Immutable
disposition receipts bind an attempt, outcome ordinal, source, worker, and epoch; a terminal receipt
also records the settled amount. This remains a database contract: no provider adapter, transport
dispatch, or production charge qualification is provided by the migration.

Migration `0033_context_vault_records` stores bounded encrypted context envelopes as immutable
tenant/record/version rows. Only the dedicated `keel_context_vault` role can insert and read
unexpired rows under forced RLS; local bootstrap provides a separate test login. It stores no
plaintext and does not add expiry deletion, legal-hold processing, replay authorization, KMS
integration, or Langfuse delivery.

Migration `0034_context_retention_policy` adds immutable tenant/purpose retention snapshots and a
monotonic current-policy pointer. Context writes require the current enabled snapshot and explicit
consent reference; PostgreSQL derives expiry from its own clock and the approved retention interval.
The separate `keel_context_policy` capability can author snapshots but cannot read vault records;
the vault role can read policy metadata but cannot author policy.

Migration `0035_context_vault_expiry_erasure` adds immutable content-free erasure receipts and a
bounded `erase_expired_context_vault` database function. The dedicated `keel_context_erasure`
capability can invoke it, but cannot read or directly delete vault rows or receipts. Each call derives
tenant scope from the authenticated database session, deletes at most 100 expired rows, and inserts a
SHA-256 receipt over a versioned, length-prefixed binary envelope serialization in the same transaction
as each deletion. Migration `0036` adds the durable worker lease and retry queue; legal holds and
backup/PITR/replica/restore erasure qualification remain separate K5.4 work.

Migration `0036_context_vault_erasure_jobs` creates one content-free durable job for each context
record, scheduled from its database-derived expiry. The `keel_context_erasure_worker` capability has
no direct table access; security-definer functions provide tenant-scoped one-at-a-time claims,
lease-epoch fencing, bounded retry/backoff and terminal blocking. Processing atomically inserts the
0035 receipt, deletes the expired envelope, and completes its current job lease. The Go polling
runtime accepts one explicitly authorized tenant and is injectable/local only; no deployable worker
profile, legal-hold lifecycle, or hosted backup/restore guarantee is provided.

Add later product tables with the owning domain migration and its access, retention, and recovery
contracts.
