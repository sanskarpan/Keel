# Behavioral and algorithmic specification

Normative keywords MUST/MUST NOT identify release-blocking behavior. Default limits are starting settings that require load qualification.

PRODUCT-SPEC.md extends this core with versioned SaaS/purchasing requirements; shared SAAS-FOUNDATION.md governs customer lifecycle. Subscription entitlement cannot grant a role or bypass a financial/safety invariant.

## 1. Request and admission lifecycle

Ingress derives tenant and actor from validated identity, never from a body-supplied tenant ID alone. It bounds header size (16 KiB), ordinary JSON body size (256 KiB), upload metadata and read/header/idle deadlines. Upload bodies travel directly to a scoped object-store URL. Each route has a concurrency/admission class. A full admission queue returns 429/503 with a bounded retry hint; it does not create an unbounded goroutine backlog.

Targets distinguish 10,000 established connections, 200 simultaneous ordinary requests and 100 active streamed inferences in a qualification profile. Pool and provider limits can yield admitted sockets but rejected expensive work. Graceful termination removes readiness, stops claims/admissions and drains already-admitted operations for at most 30 seconds; long jobs retain their durable logical IDs for recovery.

## 2. Identity and tenant transaction

OIDC tokens require exact issuer/audience, valid signature/algorithm, time checks and fresh enough key cache. Tenant membership and action permission are evaluated server-side. External supplier invitations are single-purpose, expiring, hashed at rest and scoped to a case; accepting one can establish a persistent supplier principal with only explicitly granted tenant/supplier/resource access, never an internal membership.

Every tenant database operation runs inside a transaction wrapper that sets tenant context with `SET LOCAL`, timeouts and read-only mode where appropriate. Policies enforce tenant identity for both reads and writes; composite foreign keys enforce tenant consistency. App credentials cannot own tables, bypass RLS or mutate policies.

Agent queries go through allowlisted typed tools and tenant-bound read-only DB sessions. For agent sessions, the RLS tenant resolver uses an immutable mapping from `session_user` to tenant. Setting a custom tenant variable cannot switch its identity. SQL strings from the model are never executed directly.

## 3. Order aggregate

States: `draft -> submitted -> verifying -> approved | rejected`; `draft`, `submitted` and `verifying` may transition to `canceled`. `verifying` is the API state for awaiting approval; submission accepts the requester command, then the durable verification intent moves the aggregate into that state. Terminal states are immutable except a distinct, explicitly designed future compensating aggregate; no `force status` API exists.

Each command includes expected aggregate version. The database locks the head, checks the version and validates business rules against a reconstructable command snapshot. An accepted command appends one or more events with contiguous versions and updates the snapshot/head, outbox and state feed in the same transaction. At startup/audit, replay verifies snapshot state equals event-derived state. Events are the source of truth, not the mutable snapshot.

Approving an order requires supplier eligibility, evidence/policy versions, amount threshold and separation-of-duties checks. The pure K1.1 order model checks the recorded decision is bound to the submitted evidence and that the requester cannot decide their own order; the command service must additionally authorize the approver, evaluate supplier eligibility and enforce policy/threshold rules before emitting it. AI recommendations do not count as approval. Commands use integer minor currency units plus an ISO currency; no binary floating point for amounts. V1 line quantities are positive canonical decimal strings with at most six fractional digits and are never parsed through binary floating point. Amounts are positive safe JSON integers in minor units. Currency syntax is checked in the pure model; the command service validates the supported ISO 4217 catalog before mutation. In v1 all lines on an order, the applicable approval thresholds and the selected procurement budget account must share the same ISO currency/minor-unit definition. Reject any mismatch before submission, approval, or reservation; there is no implicit FX, display-rate conversion, or threshold reinterpretation. FX requires the pinned, auditable quote path in 2.0. V1 does not execute payments.

## 4. Idempotency

Require `Idempotency-Key` for mutating commands, inference creation and replay requests. Scope keys by tenant, normalized route/action and caller principal class; reauthorize every replay. Store SHA-256 of canonical validated payload + method + route. Same key/different request returns 409. Same key/completed request returns its durable response and `Idempotent-Replayed: true`. Same key/in-progress returns 409 with retry guidance.

For short DB commands, idempotency insertion/result and command effects commit together. No reservation persists with an uncommitted business result. For async requests, the durable operation ID commits with the key; subsequent attempts return that ID. Detailed idempotency responses are retained for seven days by default, but consequential-operation deduplication is durable for at least the lifetime of the financial/business effect and its audit obligations. A compact registry preserves tenant, route, key digest, principal binding, request hash, canonical operation reference and outcome state without retaining sensitive request bodies. After detail expiry, the same key/hash resolves to the existing operation where possible, otherwise returns stable `idempotency_record_expired` (409/410) and never executes again; a changed payload returns `idempotency_conflict` (409). Key reuse is forbidden while the business effect can recur.

## 5. Supplier onboarding and approvals

Implemented case states: `collecting -> submitted -> approved | rejected | expired` (`canceled` is reserved for K2.5); `submitted` means evidence is frozen and the policy review plan is pending. Verification exhaustion/manual review remain K2.5. Technical retries never imply business approval. Deadline is persisted at creation from PostgreSQL time and capped at 72h; it cannot move on worker restart.

Workflow ID: `keel.supplier-case.v1.<sha256(tenant_uuid || NUL || case_uuid)>`; raw tenant identity is not placed in Temporal input, signal payload or workflow history. Start intent references the committed case event/policy/evidence digests in PostgreSQL. Retry-safe start/signal delivery and event identity checks are implemented. Deadline activity mounting, workflow-version rollout and continuation remain gated by K0/K0.1 and K2.5/K2.6.

Approval API locks the authoritative resource row (case or order) and active approval plan, verifies current approver/delegation, policy/evidence digest and accepts the step decision only when PostgreSQL time, captured after taking the lock, is before the effective deadline and the resource is eligible. For an order, each accepted decision appends an approval-step event; only satisfaction of every required step appends `order.approved` and atomically converts the procurement reservation to commitment. A configured rejection appends the rejected outcome and releases the reservation. For a supplier case, K2.4 freezes bounded policy steps at submission, enforces prerequisites, creator/submitter separation, and one-level active delegation; acceptance creates an immutable step decision, case event, updated snapshot and Temporal intent in one transaction. Direct case-app grants cannot mutate reviewer/delegation records. Later role revocation blocks new decisions but does not retroactively invalidate accepted decisions. Signal transport may duplicate; activities read committed plan/decision records and deduplicate IDs. Automatic timer/activity mounting and role provisioning remain unimplemented behind the K0 identity/runtime gate.

At the deadline, the expiry operation locks the case and checks the authoritative state; its event/snapshot/intent commit atomically. A completed eligible plan wins even if its final signal arrives late; partial approvals do not defeat expiry. Approval and expiry serialize on the same case row; acceptance at or after the deadline is rejected. A document/policy revision cannot rewrite the frozen plan; new evidence requires a new case. K2.5 will connect automatic Temporal timer/activity processing, cancellation and compensations; no history is deleted.

## 6. Hybrid retrieval

Chunk documents into reproducible, versioned sections with parent titles and source offsets. Bound chunk size and extraction cost. Index only successfully scanned and published versions; document withdrawal/ACL changes invalidate eligibility immediately at query time, even before asynchronous index cleanup.

BM25 score for query terms:

`sum(IDF(t) * tf(t,d)*(k1+1)/(tf(t,d)+k1*(1-b+b*len(d)/avg_len)))`

where `IDF(t)=ln(1+(N-df(t)+0.5)/(df(t)+0.5))`, `k1=1.2`, `b=0.75`; `N`, `df` and `avg_len` are maintained per tenant/corpus version. Stopwords, normalization, language support and tokenization have version IDs. V1 uses a qualified English analyzer; other languages require an evaluated analyzer/model profile. Each chunk belongs to one disjoint visibility cohort; authorized-cohort statistics can be summed without duplicate document counts. Publication/withdrawal rechecks and statistics-pointer updates must not expose diagnostic counts for hidden cohorts. Publication atomically switches a corpus version only after postings/statistics are consistent; indexes can build outside the switch transaction. Filter visibility before final result return. Document ACL classes with different visibility require statistics scoped to that effective corpus or use a documented authorized corpus; do not expose hidden term-frequency information through diagnostics.

Candidate pool: top 100 lexical + top 100 semantic by default. RRF `sum(1/(60+rank))` combines ranks, deduplicated by document chunk/version. Optional reranker sees at most 20 eligible candidates and obeys the same cost/security policy. Return citations, method, corpus/model versions and confidence/evaluation status, not an unsupported probability of correctness.

Use exact cosine scoring below 10k eligible chunks or for highly selective filters. Larger searches use HNSW, bounded iterative scans and a maximum query deadline. If underfilled, an exact fallback is permitted only within the measured scan budget; otherwise return fewer eligible results plus `retrieval_degraded=true`. No extra results bypass ACL to fill top-k. Final result authorization is checked against the current statement snapshot before response serialization; a permission revoked after that check cannot retract bytes already returned. Clients must not treat old search results as authorization for later actions. Model/dimension changes use a parallel index version and evaluated cutover, never mix vector spaces.

## 7. AI execution and semantic caching

Inference states: `queued -> running -> completed | failed | canceled | usage_pending`. Terminal response status and accounting settlement are separate fields: a response may complete while actual provider cost remains unknown. Jobs use stable operation ID, lease epoch, heartbeat and bounded attempts. Stale workers cannot commit final job effects after losing their lease. External model providers may not support fencing, so duplicate charges remain possible and must be accounted rather than hidden. Persist an attempt identity and liability before sending the provider request. A reconciliation role can append verified usage observations after a lease is lost; only the current executor epoch may commit the job result. A discarded stale result must not discard a real charge.

Budget admission locks a tenant/period account, reserves a conservative worst-case amount using a versioned price quote and provider token limits, then commits the job. Reservations include fallback allowance. If the provider cannot bound cost, that route is disabled or isolated under a separately approved spend cap. Atomically enforce `committed + reserved + requested <= hard_limit`. Unknown outcome retains a bounded liability reservation until reconciliation, not an immediate refund.

Cache eligibility is allowlisted: stable read-only FAQ/explanation operations, complete accepted responses, fixed prompt/tool policy, known provider/model and unchanged document/context version digest. No cache for commands, personalized permissions, changing order state, tool effects, sensitive one-time secrets or incomplete streams. Key scope includes environment, tenant, access class, prompt version, serving-model identity, tool-policy hash, context digest and generation settings.

Exact normalized cache lookup precedes semantic lookup. Semantic candidates are scoped before similarity search; similarity alone is insufficient. Compare protected entities, numeric values, units, dates and polarity; mismatches bypass the cache. Thresholds come from a labeled evaluation with a high precision requirement (initial target >=99.5% eligible-hit correctness), not a guessed universal cosine value. Cache hits still reauthorize documents and respect budget/rate/retention policy. Record saved *estimated incremental provider cost*, not proof that money was refunded.

Provider fallback is allowed only before any client-visible token and within one additional attempt/budget/deadline. 429/503/network failures are classified. After content starts, emit a typed interrupted terminal event; never splice another model's answer into the same stream. Retries carry provider idempotency keys where supported and record uncertainty where not supported.

## 8. Streaming

Use one SSE connection per browser view for both persisted business-state events and transient model tokens. Messages include `kind`, `logical_operation_id`, event ID where durable, token sequence where transient, payload and correlation ID. Durable state updates use a per-tenant commit-ordered sequence; the cursor counter and state row commit atomically with the accepted aggregate mutation and idempotency result. The payload is an allowlist of IDs, version, status/event kind and schema version, never order descriptions, external references, amounts, supplier details or evidence. This feed orders tenant-visible update notifications; aggregate event order remains `(aggregate_id, aggregate_version)`. Token order is per inference/attempt.

Business-state events are replayable from a tenant-scoped sequence. `Last-Event-ID` older than retention produces `resync_required`; clients fetch an authoritative snapshot and resume. Model tokens are not promised durable replay: reconnect loads the final persisted response or reports interrupted/running status. Bounded queues default to 256 messages/256 KiB per client, writes time out after 10s, heartbeats run every 20s. A slow client is disconnected with a resync hint; API memory does not grow without limit. At most five streams per user and a tenant stream quota apply.

## 9. Rate-limit and quota semantics

Lua operations use Redis server time and scoped tenant/route keys. Home-region Redis is the intended global admission authority. Replication is asynchronous; failover may lose recent admits and cannot provide a strict active-active global counter. Document and measure overshoot bounds under supported failover scenarios.

Expensive model work and sensitive write routes fail closed if the mandatory limiter/budget authority is unavailable. Safe reads may use a local fallback bucket with static fleet-wide allowance allocations and at most 60 seconds of degraded operation. No auto-expanding fallback quota is permitted as replicas increase. Financial hard limits are PostgreSQL reservations and remain independent of Redis availability.

## 10. Webhooks and reconciliation

Inbound callbacks require adapter-specific verified signatures/timestamps, a stable provider event ID and payload bounds. Persist inbox before returning 202. Apply allowed state transitions in a transaction with event-id and aggregate-version deduplication. An authentic but impossible/late callback is quarantined for reconciliation, not force-applied.

Outbound fanout creates one logical delivery for `(tenant,event_id,endpoint_id,subscription_version)`. Retries use the same logical event ID and increment attempt IDs. Success is a qualified 2xx; retry 408/429/5xx/network errors with full jitter, honor bounded Retry-After; permanent 4xx failures stop according to adapter policy. Maximum 12 automatic attempts over 24 hours; exhausted deliveries remain inspectable and replayable. Replays never change the event's original identity.

Reconciliation compares canonical order/case state with recorded integration observations using a cursor/time watermark. It proposes or queues idempotent missing deliveries, flags disagreements and records an audit trail. It cannot overwrite terminal order decisions from a remote snapshot. SSRF checks apply to registration, DNS resolution and every connect/replay attempt.

## 11. Trace context, replay and costs

Model observations include request ID, attempt ID, safe model/provider metadata, token counts, price quote, cost state, cache decision and retrieval/context record IDs. SQL telemetry contains query templates/operation names, not raw bind values. Immutable sensitive context is encrypted separately under tenant retention/consent. Replay executes read-only tools in a sandbox with external side effects disabled and is explicitly a diagnostic execution, not guaranteed provider determinism.

Usage ledger entries are immutable and deduplicated by logical source + attempt + charge type. Corrections append reversal/adjustment records; they do not overwrite history. Rollups separate confirmed, estimated and unknown spend, reserved liabilities, platform allocation and actual provider cost. Budget-threshold alerts and anomaly alerts are distinct; sparse/new tenants use conservative fixed thresholds until a minimum history exists.
