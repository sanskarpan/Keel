# Persistence, roles and data lifecycle

## 1. Conventions

All tenant-owned primary/unique keys and foreign keys include `tenant_id`. UUIDs identify business records; sequence/version numbers order records. Timestamps are UTC `timestamptz`. Monetary values use integer micro-USD for cost and minor currency units for order value. Use checked integer arithmetic; currency/rate provenance is explicit.

PostgreSQL events, inbox deduplication keys and ledgers are initially unpartitioned to preserve global uniqueness within tenant/logical-ID scopes. Time partitioning is introduced only with a separate permanent dedup registry or another proven cross-partition uniqueness design. Foreign keys/reference ownership are verified in migration tests.

## 2. Tables and constraints

| Table | Essential fields / invariants | Access |
|---|---|---|
| `tenants` | ID, home_region, residency/retention policy, status | Control plane; authenticated membership-derived lookup |
| `memberships` | `(tenant,actor)`, roles, revision, disabled_at | Tenant-scoped; changes audited |
| `supplier_cases` | `(tenant,id)`, state, deadline, evidence_digest, policy_version, workflow_id | API/workflow activities |
| `approval_requests` | `(tenant,id)`, resource_type/id, evidence_digest, policy_version, required_role, deadline | Authorized approvers |
| `approval_decisions` | ID, request_id, actor, decision/reason, accepted_at; unique logical decision; immutable | Append only |
| `workflow_intents` | stable workflow ID, start/signal type, input hash, payload reference, status, attempts, lease_epoch | Metadata claim role; scoped dispatch |
| `order_heads` | `(tenant,order)`, version, reconstructable command_snapshot, snapshot_hash | Lock before mutation |
| `order_events` | `(tenant,order,version)` PK; unique `(tenant,event_id)`; type/schema, metadata, payload reference/hash | API append; update/delete denied |
| `order_projections` | `(tenant,order)`, contiguous applied_version and status only | Projector writer; API reads watermark only; authoritative status/version stay in `order_heads`; forced RLS |
| `event_outbox` | immutable event FK, aggregate/version, schema version, allowlisted JSON envelope | App transaction inserts; app and worker can select; delivery state is stored separately |
| `outbox_delivery` | `(tenant,event_id)`, aggregate/version, pending/published/blocked state, attempt count, retry time, coarse error code | App inserts pending in command transaction; worker updates delivery outcome; corrupt head remains blocked for reviewed repair |
| `outbox_publish_heads` | `(tenant,aggregate)`, next_version, claim_owner, lease_epoch, lease expiry | One fenced publisher claim per stream; advances only after broker acknowledgement |
| `event_inbox` | `(tenant,consumer,event_id)` and `(tenant,consumer,aggregate,version)` unique; canonical envelope hash; source/state | Projector transaction; forced RLS |
| `deferred_events` | `(tenant,consumer,aggregate,version)`, expected missing version, bounded retry state and blocked reason | Projector gap repair; forced RLS |
| `event_quarantine` | tenant/consumer/event/hash/reason; no raw envelope | Projector writer; forced RLS |
| `transport_quarantine` | trusted Kafka topic/partition/offset, payload hash and bounded reason; no raw payload or tenant claim, including unmatched tenant/event claims | Projector insert plus restricted metadata read |
| `documents` | `(tenant,id)`, owner/classification/current_version/withdrawn_at | API/doc worker |
| `document_versions` | `(tenant,doc,version)`, immutable object/version ID/hash, scan/publication state | Immutable after publish |
| `document_chunks` | `(tenant,chunk)`, document_version FK, text reference/hash, tokenizer/corpus version, length | Retrieval; sensitive content encrypted where required |
| `chunk_embeddings` | `(tenant,chunk,model_id)`, `vector(384)` for initial qualified embedding model family, checksum | Model identity/dimension checked |
| `document_terms` | `(tenant,visibility_class,corpus_version,term_id,chunk_id)`, term_frequency | Inverted lexical postings; RLS |
| `corpus_statistics` | `(tenant,visibility_class,corpus_version)`, N, total_length, publication pointer | Atomic corpus switch |
| `term_statistics` | `(tenant,visibility_class,corpus_version,term_id)`, document_frequency | Hidden corpus stats never public |
| `inferences` | ID, context/prompt/policy hashes, status, accounting_status, reservation_id, final_response_ref | API/executor scoped |
| `jobs` | ID/type, inference/case FK, status, cost class, next_run, lease_epoch/expiry, attempts/checkpoint | Durable work queue |
| `job_results` | `(tenant,job,logical_effect)` unique, content_ref/hash, model identity, outcome | Fenced executor commit |
| `context_records` | encrypted object ref, prompt/query/doc/version hashes, access policy/expiry | Authorized replay only |
| `cache_entries` | tenant/access/context/model/prompt/tool scope, embedding, response ref, expires_at | Eligible complete responses only |
| `budget_accounts` | `(tenant,period,scope)` PK, hard_limit, committed, reserved, version | Row-lock admission; nonnegative checked counters |
| `budget_reservations` | `(tenant,id)`, inference unique, quote_id, amount, liability_state, expiry | Exactly one reservation per inference |
| `usage_ledger` | logical_source/attempt/type unique; signed amount, confidence, quote/provider invoice ref | Append-only accounting |
| `usage_rollups` | tenant/time/endpoint/model bounded dimensions; watermark | Rebuildable derived data |
| `webhook_endpoints` | tenant/id, URL, key reference, status, subscription version | Integration managers |
| `webhook_deliveries` | unique tenant/event/endpoint/subscription-version; state, next_attempt, lease_epoch | Scoped worker |
| `delivery_attempts` | tenant/delivery/attempt unique; timing, response classification, redacted snippets | Append only |
| `callback_inbox` | tenant/provider/provider_event_id unique, verified hash, receipt/apply state | Verified adapters |
| `reconciliation_runs` | tenant/id, adapter, cursor/watermark, diff references, result | Audited operators |
| `state_feed_counters` | `(tenant)` primary key and last committed feed sequence | App transaction locks/increments once per accepted aggregate event |
| `state_updates` | `(tenant,sequence)` primary key plus event/aggregate/version/kind and allowlisted payload; no raw PII | App inserts/selects; worker selects and RLS limits deletes to rows older than 24h; per-tenant replay feed |
| `order_heads` | `(tenant,order)` primary key; tenant-unique bytewise/case-sensitive external reference; current status/version, reconstructable snapshot and SHA-256 | API transaction; aggregate head is locked for each versioned mutation; FORCE RLS |
| `order_events` | `(tenant,order,aggregate_version)` primary key; tenant-unique event ID, event payload and SHA-256 | API append-only; event append and head update commit atomically; bounded history pages verify canonical payload digest and contiguous versions; FORCE RLS |
| `idempotency_requests` | `(tenant,normalized route,key digest)` unique; canonical request hash, protected response detail/error code, expiry | API transactional; response detail expires after 7d; worker deletes expired details in bounded tenant batches |
| `idempotency_dedup` | `(tenant,normalized route,key digest)` unique; principal-binding digest, request hash, canonical operation reference and outcome state | Compact non-sensitive tombstone retained through consequential business-effect/audit lifetime; cannot be key-reused; FORCE RLS |
| `audit_records` | tenant/id, actor/auth context, action/resource, before/after digests, request/trace ref | Append only; export immutable audit archive |

## 3. Index plan

- `order_events(tenant_id, order_id, version)` supports stream replay; event ID unique constraint deduplicates transport.
- `jobs(status,next_run_at,tenant_id)` partial index for runnable jobs, and `(tenant_id,status,created_at)` for UI/quotas. Fair scheduler tracks per-tenant virtual finish and active counts; a bounded claim procedure picks tenants before jobs to prevent a hot tenant dominating SKIP LOCKED.
- `outbox_publish_heads(tenant_id,lease_expires_at,aggregate_id)` supports expired-lease claims; `outbox_delivery(tenant_id,next_attempt_at,aggregate_id,aggregate_version)` supports due retries. A claim joins only the head's exact `next_version`, so later events cannot bypass a pending or delayed earlier event.
- `webhook_deliveries(state,next_attempt_at)` partial index; per-endpoint concurrency guard prevents retry storms.
- `document_terms(tenant_id,visibility_class,corpus_version,term_id)` postings lookup; include tf/chunk ID. Statistics use tenant/visibility/version keys.
- HNSW cosine index applies to one compatible embedding model family/version. Add tenant/model/visibility B-tree filters. Exact path for small/selective corpora. Observe actual query plans under skew; a global HNSW index is not a tenant-local index.
- `state_updates(tenant_id,sequence)` provides 24-hour replay. Cursor allocation updates a per-tenant feed-head row in the same transaction so committed stream IDs do not regress; this serializes accepted state changes within one tenant. A bounded worker prune is RLS-limited to rows older than 24 hours and never deletes/resets the cursor; readers compare the oldest retained cursor to detect when to resync. Do not use precommit BIGSERIAL allocation as proof of commit order.
- Usage and audit indexes support tenant/time pagination; no unbounded multi-column metric cardinality.

## 4. Roles and RLS resolver

`keel_migrator` owns schema and policy changes; no application runs with that role. `keel_api` has limited DML and tenant context. `keel_projector`, `keel_executor`, `keel_webhooks` and `keel_workflow` have only their necessary tables/functions. Queue metadata claims use narrowly reviewed SECURITY DEFINER functions with fixed `search_path`, qualified object names, revoked PUBLIC execution and lease ownership checks; no arbitrary SQL parameter is accepted.

Every tenant table enables and forces RLS. Policy shape:

```sql
USING (tenant_id = security.current_tenant_id())
WITH CHECK (tenant_id = security.current_tenant_id())
```

For normal trusted app sessions, `current_tenant_id()` checks the authenticated role family and returns transaction-local context. For tenant-bound agent login roles, it resolves `session_user` through a protected `agent_role_bindings` table; GUC values are ignored. No resolution yields NULL/default deny. Bindings cannot be written by agent/app credentials. The function uses qualified names and cannot be shadowed in public/temp schemas.

Agent child login roles have SELECT on approved views/tables only, no DML/DDL/CREATE/unsafe function execution, no membership in application/migration roles and no ability to change session authorization. Role/database pool limits prevent one pool per tenant exhausting connections. The typed query broker retains the credentials; the model never sees them. Credential routing and role bindings are tested with GUC/SET ROLE/search_path attacks.

RLS protects against tenant-context mistakes in trusted services. It is not a complete defense against a compromised cross-tenant application principal; reduce that exposure through scoped identities, brokered claims, audit and resource segmentation.

## 5. Leases and fencing

Claims set owner, increment `lease_epoch` and use database time for expiry. The publisher loads only the currently claimed head event, validates the complete allowlisted envelope, publishes synchronously outside the transaction, then marks delivery published and advances `next_version` in one transaction guarded by owner, epoch, expected version and an unexpired lease. Broker failure records an allowlisted coarse code, increments attempts, schedules bounded exponential retry with deterministic jitter, and releases the claim. A permanently invalid envelope is durably marked `blocked` with a coarse error code and releases its lease without advancing the head; later versions remain stopped until reviewed repair resolves the corrupt version. A stale worker cannot acknowledge or record failure after lease expiry/reclaim. A broker acknowledgement lost after acceptance can still cause duplicate delivery; stable event IDs and consumer inbox deduplication handle this at least-once boundary. Broker partition ordering is keyed by tenant/aggregate; the database head remains the source of publish order.

Claim procedures return tenant/logical IDs without raw documents. Subsequent operations use the correct tenant-scoped transaction. Do not use an unlimited BYPASSRLS service account for every background task.

## 6. Retention and erasure

Initial defaults: state updates 24h; idempotency response details 7d (compact consequential-operation dedup tombstones retained through business-effect/audit lifetime); encrypted prompt context 7d only when enabled; delivery response snippets 7d; webhook attempt metadata 90d; raw supplier documents tenant-configured 30–365d; business event/audit retention by customer policy/legal hold. Time-based purge jobs use bounded batches and a deletion manifest.

Event payloads hold typed non-PII facts, opaque references and digests. Sensitive data lives in encrypted mutable/erasable records, not immutable event JSON or Kafka headers. Erasure revokes cache eligibility, deletes object versions including noncurrent versions, expires prompt context/embeddings and produces a verification manifest. Legal hold blocks deletion and is visible to administrators. Backups age out according to a documented retention schedule; restore applies the erasure journal before reopening access.

## 7. Migrations

Additive migration first, compatible code rollout second, backfill with bounded jobs third, validated read switch fourth, contraction last. Never drop a field required by old events/workflow histories. Migration job uses a dedicated owner role and global schema advisory lock, with checksum and execution record. Application startup checks minimum compatible schema and fails readiness instead of auto-migrating.

## 8. SaaS and expanded product tables

The common SaaS table families and lifecycle constraints in shared SAAS-FOUNDATION.md are required in 1.0. Keel uses `tenants` as its organization authority rather than creating a competing organization ID. Supplier-only principals are not internal `memberships`. Subscription provider customer IDs are unique to one tenant; billing inbox uniqueness includes provider/account/event ID. Entitlement revision is monotonic and commercial roles cannot mutate procurement/AI balances.

| Version / tables | Keys and invariant |
|---|---|
| 1.0 `suppliers`, `supplier_aliases`, `supplier_contacts`, `supplier_grants` | Tenant/supplier FK; canonical merges retain original references; principal grants include resource scope/expiry |
| 1.0 `intake_form_versions`, `purchase_drafts` | Tenant/category/version; immutable published schema, draft schema reference and current revision |
| 1.0 `approval_plans`, `approval_steps`, `delegations` | Unique active plan per resource/packet; step dependencies same tenant/plan; immutable accepted decision; delegation interval/scope checked |
| 1.0 `procurement_budget_accounts`, `procurement_reservations` | Tenant/entity/project/period/currency account; one logical reservation per packet; lock/version and nonnegative counters |
| 1.0 `procurement_ledger_entries` | Unique tenant/logical-operation/kind/line; integer minor units/currency and reversal reference; append-only |
| 1.0 `resource_threads`, `thread_participants`, `comments` | Tenant/resource/thread FKs; internal versus explicit external scope; no visibility inheritance from mention alone |
| 1.5 `catalog_versions`, `catalog_items`, `repeat_buy_templates` | Supplier/contract/version; price/unit/currency/validity and authorized entity scopes |
| 1.5 `sourcing_requests`, `sourcing_invites`, `supplier_responses`, `awards` | Tenant/request/version/deadline; supplier scoped; immutable response versions and reviewed award |
| 1.5 `purchase_order_heads`, `purchase_order_events`, `po_lines`, `po_amendments` | Event/head version; immutable issued versions; permanent tenant/entity/PO-number uniqueness; amendment linked approval-order/base-PO version and unique delta allocation |
| 1.5 `receipts`, `receipt_lines`, `receipt_reversals` | PO/version/line FKs, fixed-point quantities, logical operation dedup; accepted sum/tolerance checked under line lock |
| 1.5 `invoices`, `invoice_lines`, `match_runs`, `match_exceptions` | Supplier/entity/external invoice identity, digest; frozen match policy, allocated capacity and override actor |
| 1.5 `contracts`, `contract_versions`, `obligations`, `renewal_tasks` | Document/version/owner; confirmed dates with timezone and source spans; unique logical reminder occurrence |
| 1.5 `connector_bindings`, `external_mappings`, `sync_intents`, `actual_observations` | Provider/local ID/version mapping; unique external event/effect; per-field source authority and watermark |
| 2.0 `legal_entities`, `business_units`, `scope_grants`, `fx_quotes` | Tenant scoped; explicit resource scope, quote currency/source/time/rounding provenance |
| 2.0 `policy_versions`, `simulation_runs`, `risk_assessments`, `risk_findings`, `risk_acceptances` | Published immutable policy/rubric, simulation digest/read-only result, acceptance scope/owner/expiry |

Every child uses composite tenant FKs; finer entity/thread/supplier visibility applies in API/views in addition to RLS. Agent tools expose only allowlisted authorized views, not new billing/contact/raw invoice tables by default. Add indexes for active approval steps by assignee/deadline, procurement reservations by account/state, supplier tasks, renewal due dates, PO line receipt sums and connector pending intents. Financial/billing/dedup ledgers remain unpartitioned initially or use a separately proven permanent dedup registry. No invoice/receipt index bypasses current entity permissions.

Business-unit visibility enters document/cache/context scope revisions; permission changes invalidate eligible search/cache reads. Expanded events include typed IDs/digests rather than raw contact, banking or invoice text. Retention profiles distinguish business documents, comment edit history, subscription accounting records, risk/legal holds and exports; object version purge and restore erasure journal cover every new storage family.
