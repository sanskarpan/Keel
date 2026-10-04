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

## 2. Integration matrix

Run real PostgreSQL/pgvector, Kafka and Redis containers plus Temporal test environment. Test DB commit/offset commit boundaries, publish acknowledgement loss, outbox relay crash, consumer rebalance, event gaps, dedupe retention (including retries after detail expiry) and provider request uncertainty. Local schema/role behavior must match production grants, including non-owner roles; testing only as a superuser is insufficient.

Temporal tests use time skipping to reach 72h and signals/worker restarts/versioned histories. At least one staging soak spans a real deadline and rollout; time skipping alone does not validate clock/network/operational behavior.

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
