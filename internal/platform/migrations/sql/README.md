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
as each deletion. Migration `0036` adds the durable worker lease and retry queue; migration `0037`
adds a dedicated legal-hold lifecycle and serializes it with every supported erasure path.
Backup/PITR/replica/restore erasure qualification remains separate K5.4 work.

Migration `0036_context_vault_erasure_jobs` creates one content-free durable job for each context
record, scheduled from its database-derived expiry. The `keel_context_erasure_worker` capability has
no direct table access; security-definer functions provide tenant-scoped one-at-a-time claims,
lease-epoch fencing, bounded retry/backoff and terminal blocking. Processing atomically inserts the
0035 receipt, deletes the expired envelope, and completes its current job lease. The Go polling
runtime accepts one explicitly authorized tenant and is injectable/local only; no deployable worker
profile or hosted backup/restore guarantee is provided.

Migration `0037_context_vault_legal_holds` stores content-free hold state and immutable lifecycle
events behind the separate `keel_context_legal_hold` capability. Holds are scoped to one exact record
version. Database time controls event timestamps; a bounded review deadline does not automatically
release a hold, so overdue unreviewed holds continue blocking erasure. The erasure batch function,
queue processor, and record mutation guard all enforce active holds. Hold placement/review/release,
queue lease takeover, and both deletion paths lock the same record first. Releasing the final active
hold makes its expiry job claimable again. The authority role cannot read ciphertext, retention
policies, hold tables, or erasure receipts directly. This is a database lifecycle only: no public
legal workflow endpoint or actor-identity provider is wired, and hosted backup/restore qualification
remains unclaimed.

Migration `0039_callback_inbox` adds the authenticated provider callback inbox: a global
provider/event identity, canonical payload digest, event type and key ID, with a database-derived
received/applied timestamp. A recorded event and its domain effect commit in one tenant
transaction; an exact redelivery is a duplicate, while a same-ID/different-digest or same-ID/other-
tenant delivery is a conflict recorded in an append-only ledger. A dedicated `keel_callback`
capability has no direct table privileges; security-definer claim/confirm functions derive the
tenant from the authorized transaction context and require capability membership. The inbox stores
no payload. Signature verification and key rotation are delivered by `internal/delivery/webhook`
(K6.2); HTTP routing, provider adapters and a callback runtime remain K6.3-K6.5 work.
Migration `0038_context_vault_replay_audit` adds a dedicated `keel_context_replay` capability and
one-use, content-free replay audit state/events. Its begin function can read only one exact,
unexpired context version and denies records with an active hold. Before plaintext delivery, a
second function rechecks expiry/hold state while holding a shared lock on the record; hold placement
and deletion take the conflicting lock. The service has no model/tool/business mutation port and
requires a five-second caller deadline. The local capability is synthetic, the public replay route
stays unmounted, and production identity/KMS/deployment qualification remains outstanding.

Migration `0040_webhook_deliveries` adds the outbound webhook delivery ledger: one row per tenant,
event, endpoint and subscription revision, with a globally unique delivery ID and a
database-derived creation time. A dedicated `keel_webhook` capability has no direct table
privileges; a security-definer claim function derives the tenant from the authorized transaction
context, requires capability membership and returns the existing delivery on a duplicate claim. Rows
are immutable. Attempts, retry state, endpoint registration and delivery execution remain
K6.3-K6.5 work.

Migration `0041_webhook_delivery_attempts` adds the durable attempt scheduler behind the delivery
ledger: one mutable state row per delivery (`pending`, `in_flight`, `delivered`, `failed`,
`exhausted`) and an append-only attempt log of outcome class, HTTP status, latency and the fenced
lease epoch. A capability-gated security-definer function leases due deliveries with
`FOR UPDATE SKIP LOCKED`, a bounded expiry and a strictly increasing lease epoch; a second fenced
function records one classified attempt and moves the state, returning an expired lease to
re-delivery while rejecting a stale epoch or attempt number. State rows cannot be deleted, terminal
states cannot change, counters are monotonic and attempts cannot be rewritten. The database owns the
fence and the state machine, not the retry delay or exhaustion policy; per-endpoint circuit
breaking, the delivery worker, endpoint registration and the capped replay UI remain K6.3-K6.5
work.

Migration `0042_webhook_endpoints` adds the versioned endpoint registry: the tenant-visible endpoint
identity, HTTPS URL, signing-key reference, subscription revision, active/inactive status and a
monotonic `version` used for optimistic concurrency. Registration and status changes require the
application capability and an expected version (zero creates, a positive value updates only on an
exact match); delivery resolves the URL and key only for an active endpoint at the requested
subscription revision under the webhook capability. Identity and creation time are immutable, rows
cannot be deleted, direct grants are revoked and forced RLS applies. The URL may embed a receiver
token, so it is returned only to the resolving capability and is never stored in an attempt row.
DNS and address vetting still happen on every delivery dial; registration enforces the static HTTPS,
fragment, character, host and length rules. No HTTP worker, secret storage, breaker persistence or
replay record is added.

Migration `0043_webhook_endpoint_breakers` persists the shared per-endpoint breaker keyed by
tenant/endpoint with a foreign key to the endpoint registry: status (`closed`, `open`, `half_open`),
consecutive failures, cooldown start and length, admitted half-open probes, and a monotonic version.
Check constraints enforce the state shape, the guard trigger refuses deletes and identity changes and
requires a single-step version, forced RLS applies and direct grants are revoked. Load and save are
security-definer functions gated on the webhook capability; save inserts at expected version zero or
updates only on an exact match, so concurrent workers produce one winner and one version conflict.
The policy stays in Go: PostgreSQL owns the compare-and-swap, not the breaker decision. The worker consults the breaker before each send; no operator reset or metric is added.

Migration `0044_webhook_replays` records manual replay requests before execution: one immutable row
per tenant/delivery with a caller-supplied replay ID, operator principal and a bounded non-control
reason, a foreign key to the delivery ledger, a unique tenant/delivery constraint, a guard trigger
that refuses update/delete, forced RLS and revoked direct grants. Operator-gated security-definer
functions record idempotently by replay ID and expose a tenant-scoped existence check; conflicting
reuse and a second replay for the same delivery are refused. No selection, authorization, state
transition or execution is added.

Migration `0045_webhook_lease_first_attempt` re-creates `lease_webhook_deliveries` because its
return type gains the delivery's `first_attempt_at`. Selection, capability gating, `SKIP LOCKED`,
the monotonic epoch and the 5-300 second fence are unchanged; the worker uses the returned time to
enforce the 24-hour retry window across re-leases. The drop/recreate is transactional and re-issues
the webhook grant.

Migration `0046_webhook_payload_source` adds the first production webhook body read: a
webhook-gated security-definer function resolves the delivery's event to the outbox `safe_envelope`
and returns canonical JSON text, bounded to 1 MiB, without exposing the URL, secret, private event
data or receiver response. It derives the tenant from the authorized context, requires a canonical
UUID event, adds the schema-owner read policy on `event_outbox`, and revokes direct grants. The
worker port now receives the trusted tenant explicitly; no body store or per-event webhook schema is
added. The producer/fanout is added by migration `0048` below.

Migration `0047_webhook_replay_requeue` adds the operator-authorized replay requeue: a forced-RLS,
append-only transition row binds the prior `failed`/`exhausted` state, attempts, finish time and lease
epoch to the recorded replay and delivery, with a guard trigger that refuses update/delete. One
operator-gated security-definer function reuses an exact replay request idempotently, records the
replay and transition, and returns the delivery to `pending` in the same transaction without changing
`attempts`, `first_attempt_at` or `lease_epoch`; the delivery-state guard accepts only that audited
transition and still refuses unaudited terminal updates, including `delivered` to `pending`. Endpoint
eligibility requires the same active registration revision and a signing-key reference. The function
grants execution to `keel_operator` only and exposes no direct transition-table access. Known-key
membership, selection and execution remain outside the database contract.

Migration `0048_webhook_delivery_fanout` adds `fanout_webhook_deliveries(event_id)`, called in the
same transaction as the outbox append. The `keel_app`-gated security-definer function derives the
tenant from context, requires the event to exist in the tenant outbox, and inserts one delivery per
active endpoint at its current subscription revision. The delivery identity constraint makes a
repeated or concurrent call a no-op, so the function returns only the inserted count. It returns no
endpoint URL or key, grants execute only to `keel_app`, and does not backfill events or filter by
event type. Endpoints registered after an event do not receive it; the current registry has no
per-event subscription filter.

Migration `0049_webhook_tenant_scheduling` adds global partial indexes for due pending and expired
in-flight state plus `list_webhook_delivery_tenants(limit)`. The `keel_webhook`-gated
security-definer function returns only tenant IDs that have a pending delivery due now or an
in-flight lease expired now, grouped per tenant, ordered by earliest due time and bounded to
1-1000 rows. It exposes no delivery, endpoint, URL, payload, attempt or state data, and grants
execute only to `keel_webhook`; the scheduler process uses it to choose tenants for the existing
tenant-scoped lease. Migration `0050_webhook_delivery_metrics` replaces that function with the same
capability and ordering plus the earliest due time and due delivery count, so the worker can expose
content-free backlog and age gauges. It adds no label values, identifiers or delivery content.

Migration `0051_webhook_reconciliation` adds the first K6.4 dry-run foundation: a tenant event
cursor, append-only run and per-event gap history, and an outbox cursor index. The
`keel_operator`-gated `plan_webhook_reconciliation(run_id,requested_by,from,limit)` serializes per
tenant, scans at most 500 outbox events above the cursor, compares current active endpoints at their
current subscription revision with the delivery ledger, records the run/gaps/cursor atomically and
returns event IDs with missing delivery counts. It creates no deliveries, exposes no endpoint,
URL, payload or receiver data, keeps cursor/run/gap tables behind forced RLS and revoked direct
grants, and refuses duplicate run IDs and un-audited cursor rewinds. Migration
`0052_webhook_reconciliation_repair` adds append-only repair-run and repair-item history plus a
`keel_operator`-gated `repair_webhook_reconciliation_run(repair_id,run_id,requested_by,limit)`
function. Repair selects a bounded set of recorded gaps, revalidates current active endpoints at
their current subscription revision, inserts only missing delivery identities with the normal
pending state, and fails closed above 10,000 candidates. It records gap-event and inserted-delivery
counts and item IDs only; it exposes no endpoint, URL, payload or receiver data, keeps all repair
tables behind forced RLS and revoked direct grants, and refuses duplicate repair IDs. Migration
`0053_webhook_reconciliation_cursor_reset` adds an append-only reset audit and a
`keel_operator`-gated `reset_webhook_reconciliation_cursor(reset_id,requested_by,to,reason)`
function. A reset must move to a non-future time strictly before the current cursor, records the
prior/new watermark, operator and bounded reason, and updates the cursor to `(to,zero UUID)` so the
next planner rescans from that time. The cursor guard accepts a backward move only when the matching
reset row exists. It creates no deliveries, does not change run/gap history, and keeps the reset
table behind forced RLS and revoked direct grants. Migration `0054_webhook_endpoint_quota`
re-creates endpoint registration and status functions with a per-tenant advisory lock and a
100-active-endpoint cap. Creating or reactivating above the cap fails; updating an existing endpoint,
deactivating, and activating an already-active endpoint remain allowed. The cap protects new growth
only: existing over-cap tenants are not rewritten or deactivated. Migration
`0056_webhook_tenant_quota_policy` adds a per-tenant policy and append-only policy history, with a
default limit of 100. `keel_operator` can create or update the limit using an expected version and
bounded reason; registration/reactivation reads the effective limit. Lowering below the current
active count does not deactivate endpoints but blocks new growth. `0055_webhook_replay_candidates` adds a
`keel_operator`-gated candidate query over failed/exhausted deliveries with attempts, replay flag,
current endpoint status at the delivery revision and key reference. It returns no URL, payload,
signature or receiver content; the unmounted HTTP API applies the existing selection cap and key
readiness before returning delivery IDs and skip reasons. Migration
`0057_webhook_tenant_delivery_quota` adds a per-tenant delivery batch policy (1-100, default 5)
and append-only policy history, with an expected-version `keel_operator`-gated setter, and
re-creates tenant discovery with the effective per-pass lease limit. The scheduler leases at most
the minimum of the process batch and the tenant limit; deliveries above the ceiling stay due for a
later pass. It drops no backlog and adds no global cap, fair-share ordering or HTTP/UI. Migration
`0058_webhook_endpoint_status_history` records one append-only status/subscription row per
endpoint version through a registry trigger (backfilling current rows), and adds an
operator-gated point-in-time query returning the latest record at or before a timestamp. It
exposes no URL, key, payload or receiver data and changes no repair semantics. Migration
`0059_webhook_historical_repair` re-creates the repair function so each gap event is revalidated
against the endpoint status recorded at the event's time: deliveries are inserted only for
endpoints active then, at their then-current subscription, while identities with no history or
an inactive-then endpoint are skipped and counted in a new audited `skipped_identities` column.
Migration `0060_webhook_historical_planner` re-creates the planner (same signature) so missing
counts are computed against the endpoint status recorded at each event's time for currently
active endpoints; inactive-then windows and pre-history events report no gap, matching exactly
what historical repair can insert. Migration `0061_webhook_reconciliation_runs_api` adds an
operator-gated recent-runs listing with per-run scanned/gap/missing/repaired/skipped counts and
cursor watermarks, bounded to 100 rows; it exposes no event, endpoint, URL, payload or receiver
content. Migration `0062_provider_callback_observations` adds an append-only provider observation
trail recorded by the `keel_callback`-gated inbox alongside each claim outcome (applied,
duplicate with redelivery delay, conflict), with forced RLS, revoked direct grants and an
immutable-history trigger; it exposes no payload or receiver content and changes no apply
semantics.

Add later product tables with the owning domain migration and its access, retention, and recovery
contracts.
