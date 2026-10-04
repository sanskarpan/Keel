# Validation strategy

Tests are release evidence for implementation, not generated assertions mirroring internal methods. Record exact artifact/config/schema versions, workload, environment and expected invariants for every suite.

## 1. Correctness properties

- Replaying an order's contiguous immutable events produces the same state as its command snapshot and projection.
- Duplicate commands/events/callbacks do not change logical effect counts; conflicting same-ID payloads are rejected/quarantined.
- A stale aggregate version cannot mutate the order. An unapproved or expired supplier cannot produce an approved purchase order.
- Approval and expiry race serializes around durable acceptance time/evidence; signal loss cannot discard an already accepted decision.
- Lease epoch loss prevents DB result commits. Worker retry preserves logical IDs/checkpoints.
- `committed + reserved <= hard_limit` at admission; unknown external spend remains a visible liability; ledger rollups reconcile.
- Stream loss does not lose the durable result; reconnect never concatenates tokens from different model attempts.

Use property/model-based state-machine tests and controlled concurrent transactions. Compare to an independently implemented simple reference model. Record counterexamples/seeds.

K1.1 implements that reference model in `internal/orders`: prove every allowed and forbidden status transition, contiguous version and aggregate-identity checks, unique event IDs, deterministic replay, stored-snapshot equality, evidence-digest binding, requester/approver separation, terminal-state immutability, stale-version conflicts, and exact decimal-quantity boundaries. The reference transition table is independent of the production reducer.

K1.2 PostgreSQL tests use the non-owner app role for order commands, a separate worker role for expiry pruning, and a test-only admin connection to move expiry timestamps forward without sleeping. They race identical create keys and distinct submit keys, assert request/principal conflicts and natural-reference uniqueness, force an event-ID constraint failure to prove the key claim and aggregate head roll back together, exercise tenant RLS, and expire then prune a successful create response before retrying it after eight days. The retry must resolve the same order's latest snapshot, leave event count unchanged, retain exactly one compact tombstone and contain no response detail. CI applies the embedded migration through the migrator before these tests. These tests cover order persistence only and do not substitute for the remaining K0 end-to-end authorization/API gate or future outbox tests.

K1.3 verifies accepted order commands commit their event, safe outbox envelope, per-tenant state sequence, snapshot, and idempotency result together. A temporary test constraint forces the final state-feed append to fail after prior writes; the transaction must leave no head/event/outbox/cursor/idempotency claim and the same key must then succeed. Tests assert exact allowlisted payload keys with PII canaries absent, concurrent state cursors increment without gaps in commit order, worker reads remain tenant-scoped, runtime roles cannot update event/outbox/feed history, the app cannot delete feed rows, and the worker cannot delete fresh feed rows but can prune expired rows in bounded batches without resetting the cursor.

K1.4 runs PostgreSQL/Kafka integration coverage with separate app, worker and test-admin credentials. It verifies head-only version claims, lease expiry/reclaim and epoch fencing, stale load/ack rejection, persisted retry delay and bounded backoff, stable event ID reuse, idempotent acknowledgement, durable poison-envelope blocking, and that version N+1 remains unavailable until N is acknowledged. A real Kafka test asserts stable identity headers, partition key and per-aggregate order. Kafka may accept a write while its acknowledgement is lost; therefore the contract is at-least-once, and K1.5 must deduplicate by event ID. A stale producer may also deliver an old duplicate after a successor version; K1.5/K1.7 must prove inbox deduplication and contiguous projection behavior for that ordering. The local target provisions an isolated test topic; CI starts a pinned single-node Kafka service and provisions the same topic before Go checks.

K1.5 uses separate app, projector and test-admin credentials against real PostgreSQL. It sends version 2 before version 1, proves the inbox defers the gap, replays both canonical outbox envelopes into a contiguous status projection, then redelivers version 1 after version 2 and confirms no state change. It also checks tenant RLS, denied canonical outbox mutation, and durable malformed-record quarantine containing only a digest. Shadow rebuild/cutover and broker offset/rebalance failure tests remain future work; a passing projector integration test does not claim those boundaries.

## 2. Integration matrix

Run real PostgreSQL/pgvector, Kafka and Redis containers plus Temporal test environment. Test DB commit/offset commit boundaries, publish acknowledgement loss, outbox relay crash, consumer rebalance, event gaps, dedupe retention (including retries after detail expiry) and provider request uncertainty. Local schema/role behavior must match production grants, including non-owner roles; testing only as a superuser is insufficient.

Temporal tests use time skipping to reach 72h and signals/worker restarts/versioned histories. At least one staging soak spans a real deadline and rollout; time skipping alone does not validate clock/network/operational behavior.

K0.6 runs migration integration tests under the dedicated non-superuser migrator login. Competing runners must serialize on the same PostgreSQL session advisory lock; an identical rerun is a no-op; changed applied content/name, a missing applied source or a pending migration ordered behind the ledger stops before mutation. A failed transactional migration leaves no object/data/ledger row from that file, and a new forward repair can subsequently apply. Health tests cover dependency-independent liveness, bounded readiness probes, nonleaking failures, build identity and low-cardinality process/HTTP metrics. CI runs these tests against PostgreSQL on every PR. The signed release workflow is tag-triggered; no published release or production signature-verification drill is implied until one is emitted and verified.

K0.5 runs `make local-rls-test` against the local PostgreSQL container using non-owner credentials. It verifies the app role sees only its transaction-bound tenant, context does not leak through the connection pool, the probe table has `FORCE ROW LEVEL SECURITY`, an agent's protected login mapping overrides a forged GUC and wrapper tenant, unmapped role escalation is unavailable, and agent writes are denied. GitHub Actions repeats this against a pinned PostgreSQL/pgvector service before unit/static/race/build checks. These checks validate the role mechanism only; they do not close the K0 end-to-end API gate or replace RLS coverage on future product tables.

## 3. Isolation and adversarial suite

Seed two tenants with identical external references, document titles/query terms and inference prompts. Attempt guessed IDs, cursor reuse, cache scope changes, stream subscriptions, signed URL reuse, callbacks, replay/context reads and role/GUC changes. Cover app role and tenant-bound agent role separately. Change permissions/document visibility after cache population and during a query.

Inject PII canaries in uploaded content/model replies/headers/error strings; scan logs, traces, metrics, DLQs, snippets and test artifacts. Test parser bombs, malformed docs, prompt injection, forbidden tool writes, SSRF redirect/rebinding, OIDC key confusion and webhook signature replay. Any tenant breach or privilege escalation is release blocking.

## 4. Search/cache evaluation

Maintain a versioned labeled query corpus with at least 1,000 representative queries overall and at least 200 cases in each high-risk stratum (numeric/date/unit, negation/polarity, rare terms and permission partitions); publish corpus composition and version. Each case has expected relevant version IDs and nonrelevant hard negatives. Two blinded reviewers label independently and a third adjudicates disagreements; report reviewer agreement, per-stratum results and confidence intervals. Compare lexical/vector/hybrid nDCG@10, recall@10, latency and cost. Use exact vector results as an oracle for ANN recall under tenant skew and restrictive filters.

Validate BM25 independently on a tiny hand-calculated corpus and against a trusted reference scorer. Test corpus statistics/version publication and access filtering. Semantic cache evaluation uses at least 600 independently labeled eligible-hit pairs per serving policy, reporting the one-sided 95% exact confidence bound for precision; require its lower bound to be >=99.5%. With zero false responses among 600, the one-sided exact lower bound is just over 99.5%; if any false response occurs, increase the sample or fail the gate. Tenant/permission leakage and numeric, entity, date, or polarity false hits are zero-tolerance regardless of aggregate score. Measure missed opportunities and cost, never only hit rate. Use adversarial near-neighbor queries that look similar but ask different questions. Regressions disable cache/reranker cutover.

## 5. Load/recovery qualification

Follow CAPACITY-AND-COST.md, including separate socket, active-request, live-stream and provider limits. Measure rejections as well as successful traffic. Soak indexing, Kafka rebalance, workflow waits and webhook outages while normal traffic runs. Confirm memory/FD/DB connections remain bounded under slow-client and reconnect storms.

Recovery suite verifies PITR restore, role/context security, event-projection rebuild, ledger uncertainty and erasure journal application. Ghostlight supplies infrastructure chaos experiments; Keel supplies business invariants and endpoint probes. An injected failure is not a pass until recovery/state/cost evidence is complete.

## 6. Release gates

Gate identity includes source/artifact/config/schema/policy digests. Required: static analysis + dependency/vulnerability policy, compatibility contracts, real-dependency integration, isolation/adversarial tests, search/cache quality, migration rollback/forward-repair proof, load profile, backup restore and operational runbooks. Reports can be pass/fail/inconclusive/canceled; incomplete observations never pass.

No report should assert a measured result until the suite has actually run. Design-time targets in these files remain marked targets.

## 7. SaaS and expanded customer release matrix

| Release | Required tests beyond technical coverage |
|---|---|
| 1.0 SaaS | Signup/resume/duplicate org, owner transfer, hostile org switch, supplier/internal thread visibility, key/member/session revocation, billing signature/reorder/current-state reconciliation, meter dedup, trial abuse, dunning/downgrade/cancel, import/export/hold/closure, notification recipient reauthorization, support grant expiry |
| 1.0 purchasing authority | Conditional form version/draft migration, supplier merge/history, serial/parallel incomplete/deny/deadline plans, current delegation/revocation, two concurrent final approvals against one budget, reservation release/expiry and ledger/counter reconciliation |
| 1.5 execution | Isolated supplier bids/deadlines, stale catalog, PO issuance/unknown dispatch, amendment approval delta, partial receipt/return fixed-point quantities, duplicate invoice/line allocation, matching tolerance/override, ERP effect/reconciliation and no double-counted actuals, renewal timezone/notice owner failures |
| 2.0 governance | Real IdP SSO/SCIM races/recovery, business-unit and field visibility, FX source/rounding/staleness, policy cycles/missing roles/simulation no writes, risk expiry/suspension/acceptance, SIEM/legal hold and dedicated-region restore |

Property/state tests compare approval plan outcomes and procurement ledger against a pure reference model. Verify currency mismatch rejects before state change and no mixed-currency threshold/account comparison is possible. Retry the same financial-operation key after response-detail expiry and prove it returns the original operation or a stable expired-record conflict without creating a second effect; changed payload must conflict. Verify currency mismatch rejects before state change and no mixed-currency threshold/account comparison is possible. Retry the same financial-operation key after response-detail expiry and prove it returns the original operation or a stable expired-record conflict without creating a second effect; changed payload must conflict. Fault-inject between final step/financial conversion/event append to prove atomicity. Run real non-owner DB roles; internal/supplier/business-unit scope tests include search/cache/streams/export/notifications, not only record reads. SaaS provider sandboxes establish webhook/reconciliation semantics; raw customer payment instructions remain impossible.

Browser end-to-end tests cover administrator->supplier->requester->approver journeys in 1.0 and buyer->partial receiver->invoice exception->accounting handoff in 1.5. Include keyboard/screen-reader/manual accessibility checks, narrow viewport, flaky network, async conflicts and notification failure. Usability studies/partner evidence are separate from automated browser tests. Measure actual full-workflow CPU/DB/AI/storage/mail/connector cost; no paid release until operating economics/support and all launch gates are documented.
