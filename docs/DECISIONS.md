# Architecture decision records

Status: accepted design baseline, pending implementation qualification. Amend decisions explicitly with rationale/evidence; do not silently change persistent semantics.

| ADR | Decision | Alternatives / consequences |
|---|---|---|
| K-001 | Modular Go backend, independent roles from one artifact | Service-per-entity adds deployment/contract burden without measured need; extract later at demonstrated boundaries |
| K-002 | PostgreSQL event source + transactional outbox + Kafka transport | Kafka-only history complicates tenant access and transactional command state; DB snapshots remain reconstructable |
| K-003 | At-least-once transport with transactionally idempotent effects | Kafka transactions do not include external PG/webhook/provider transactions; uncertainty and duplicate charges need explicit handling |
| K-004 | Temporal for multi-day approval workflows | A bespoke timer/cron engine repeats durable replay/versioning work; activities still need idempotency |
| K-005 | RLS everywhere; agent tenant bound to session identity | Caller-set GUC alone cannot confine a read-only agent credential; typed tools and per-tenant bindings add pool/role management |
| K-006 | Tenant-local PostgreSQL BM25 postings + pgvector initial adapter | Native ts_rank is not BM25; search extensions/dedicated engines add isolation/availability qualification; bounded corpus envelope required |
| K-007 | Exact vector path plus bounded filtered HNSW | ANN can underfill under tenant filtering; dynamic scan budgets and recall measurements are necessary |
| K-008 | Financial reservations/usage ledger in PG | Redis counters/cache cannot guarantee durable monetary caps across failover; hot budget rows need measured admission capacity |
| K-009 | Semantic cache allowlist and context/identity equivalence | Whole-platform fuzzy caching risks wrong or private answers; lower initial hit rate buys a defensible correctness bar |
| K-010 | Single home-region writer per tenant | Active-active DB/event/budget semantics are outside v1; global edge routing includes home-region latency |
| K-011 | Transient token transport; durable completed output/state feed | Persisting every token creates sensitive storage and throughput overhead; interrupted clients fetch authoritative output |
| K-012 | Sensitive replay vault separate from telemetry | Automatically recording full prompt/SQL content leaks data; encrypted opt-in replay increases operational/privacy work |
| K-013 | Preview/production immutable recipe contract | Ad hoc deploy scripts make Ghostlight unable to verify candidate generation/dependencies |
| K-014 | Append-only audit/event facts minimize PII | Immutable raw PII conflicts with erasure; opaque references and controlled encryption preserve business evidence |
| K-015 | Independent versioned SaaS beyond learning-topic coverage | Paid launch needs customer/commercial/support/UX lifecycle, not only technical proof; later discovery ideas need demand gates |
| K-016 | Procurement commitment, AI liability and subscription ledgers separate | They represent different money/authority; shared counters would double-count budgets/revenue and grant unsafe powers |
| K-017 | Frozen serial/parallel approval plans with atomic final financial transition | One accepted step is insufficient; deadline/packet/current-role and reservation checks serialize under authoritative resource locks |
| K-018 | Approved authority immutable; fulfillment uses separate PO/receipt/invoice aggregates | Extends to accounting handoff without reinterpreting historical order events or implementing payment rails |
| K-019 | Supplier portal grants separate from internal membership | Cross-buyer collaboration does not imply shared supplier data; internal threads never become external by mention |
| K-020 | Policy/risk/scenario assistance is read-only until authorized human commands | AI and what-if simulations cannot acquire approval/financial authority; proposed differentiation requires customer evidence |

## Revision template

Each amended ADR includes status/date/owner, concrete trigger, previous/new behavior, considered options, data/security/compatibility consequences, migration and rollback strategy, qualification reports and affected document sections. Changing a quota, lease, privacy or replay invariant requires the corresponding negative/failure tests.
