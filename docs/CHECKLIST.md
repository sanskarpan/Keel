# Implementation checklist and release gates

Tasks retain their individual status until acceptance evidence passes. Record owner, PR/commit, evidence path and decision revision beside completed items. A phase gate remains open until its independent evidence passes. Shared contract version: 1.1. K8 starts alongside K0/K1; phase numbering preserves the technical baseline, not chronological deferral. ROADMAP.md defines paid 1.0 through enterprise/discovery versions. Original topics are minimum scope.

## K0 — Foundation and boundaries

- [ ] K0.1 Lock supported language/dependency versions, images and provider capabilities; close Q-01; close Q-03/Q-04/Q-09 or document each as disabled/not applicable in the selected pilot profile with owner, reason and evidence. Q-01 always blocks a pilot. Local synthetic profile pinned in `docs/TECHNOLOGY-BASELINE.md`; hosted version/provider support and a named accountable owner remain open, so no pilot is enabled.
- [x] K0.2 Create Go role entry point, module boundaries, structured redacting logger and validated configuration. Owner: Keel platform (named person unassigned); PR #98; evidence: `cmd/keel`, `internal/platform`, `go test -race ./...`, `go build ./...`; decision: role bootstrap only, unimplemented roles fail closed.
- [x] K0.3 Build local real-dependency Compose profile and deterministic two-tenant seeds. Owner: Keel platform (named person unassigned); PR #99; evidence: `deploy/compose/README.md`, `deploy/compose/compose.yaml`, `make local-up`, `make local-health`, `make local-seed`; decision: loopback-only, synthetic development profile and not a pilot/production deployment.
- [x] K0.4 Define OpenAPI/event schemas and shared deployment recipe fixtures; contract CI checks. Owner: Keel platform (named person unassigned); PR #102; evidence: `contracts/openapi/openapi.yaml`, `contracts/events/order-submitted.v1.schema.json`, `contracts/deployment-recipe.schema.json`, `internal/contracts/contract_test.go`, `.github/workflows/contract.yml`; decision: initial health/order contract only, later domain routes ship with their implementation issues.
- [x] K0.5 Create schema owner/app/worker/agent roles and FORCE RLS transaction wrapper. Owner: Keel platform (named person unassigned); PR #103; evidence: `deploy/compose/init/20-keel-tenant-roles.sql`, `internal/platform/tenancy`, `make local-rls-test`, GitHub Actions real-PostgreSQL integration/race/build; decision: role/context mechanism proven; every future tenant table still requires FORCE RLS; K0 API/agent isolation evidence is recorded in `docs/K0-GATE-EVIDENCE.md`, while production identity-provider and runtime wiring remain open.
- [x] K0.6 Implement migration locking/checksums, health/version/metrics and signed artifact/SBOM pipeline. Owner: Keel platform (named person unassigned); PR #104; evidence: `internal/platform/migrations`, `internal/platform/health`, release workflow, real-PostgreSQL CI migration/RLS and contract run #6; decision: migration/health/release mechanisms are implemented; runtime health wiring, domain schema, first emitted release, required release-environment reviewers and protected-tag ruleset remain pending.
- [x] K0 gate: two-tenant API and session-bound agent isolation proven with real non-owner DB roles. Owner: sanskarpan (repository owner; local synthetic profile only); PR #117 (closes #8); evidence: `docs/K0-GATE-EVIDENCE.md`, `TestPostgreSQLTwoTenantOrderAPIIsolation` exercises both tenants through the real HTTP handler and `keel_local_app` role, verifies forged tenant headers do not change trusted context, and checks reciprocal cross-tenant reads return non-enumerating 404; `TestPostgreSQLTenantIsolation` asserts the real agent `session_user` and read-only role, then proves it remains pinned to its mapped tenant despite forged GUC/scope and cannot write or inherit `keel_app`. Security review and deployment limits are recorded in the evidence document. No migration or deployment is introduced; revert the merge commit to roll back, and CI destroys its disposable PostgreSQL service and seeded synthetic rows after test cleanup. Contract CI run #63 passed. Production IdP/API runtime wiring is not claimed; K0.1 and K8 identity requirements still block customer traffic.

## K1 — Event-sourced order vertical slice

- [x] K1.1 Implement order state machine, command snapshot and pure event replay reference model. Owner: Keel platform (named person unassigned); PR #105; evidence: `internal/orders`, independent transition/replay tests, contract quantity tests, CI contract run #9; decision: pure model/replay only; persistence, transactional idempotency/outbox, HTTP API, approver authorization/policy evaluation and the K0 end-to-end isolation gate remain open.
- [x] K1.2 Add aggregate lock/version, stable natural references and transactional idempotency plus a compact dedup registry that prevents financial-effect re-execution after response detail expiry; include >7-day retry proof. Owner: Keel platform (named person unassigned); PR #106; evidence: `internal/orders/postgres`, migration `0001_orders_and_idempotency`, same-key create race, distinct-key aggregate lock/version race, natural-reference and request/principal conflict cases, transaction rollback proof, tenant RLS, eight-day response-detail expiry/prune/retry resolving the same latest order without extra events; `make local-orders-test`, `make local-migration-test`, `make local-rls-test`, `make check`, `go test -race ./...`, `go build ./...`; CI contract run #12 passed. Decision: seven-day detail is pruned under the least-privilege worker role while a digest-only tombstone preserves no-reexecution; expired successful retries resolve current operation state and expired rejected retries return the stable expired-record error. K0 end-to-end API authorization, approver policy checks and K1 outbox/HTTP work remain open.
- [x] K1.3 Append events/outbox/state-feed/result in one transaction; DB append-only grants. Owner: Keel platform (named person unassigned); PR #107; evidence: migrations `0002_order_outbox_state_feed`, `0003_order_effect_identity_constraints` and `0004_state_feed_retention`, accepted create/submit writes atomically append event, privacy-safe outbox envelope, per-tenant commit-ordered state update, snapshot and idempotency result; concurrent cursor writes remain contiguous; exact allowlisted payload tests exclude private order fields; app roles cannot change event/outbox/feed history, worker reads are tenant-scoped and RLS restricts feed deletion to 24-hour-expired rows; bounded prune preserves the cursor; injected final state-feed insert failure rolls back all earlier side effects and permits same-key retry. `make local-orders-test`, `make local-migration-test`, `make local-rls-test`, `make check`, `go test -race ./...`, `go build ./...`; CI contract run #20 passed. Decision: per-tenant cursor locking provides commit ordering and is an explicit write-contention tradeoff; outbox relay claims/ack/retries remain K1.4.
- [x] K1.4 Implement publish-head claims, broker acknowledgement/retry/fencing and stable event IDs. Owner: Keel platform (named person unassigned); PR #110; evidence: migration `0005_outbox_delivery_and_publish_heads`, pending delivery metadata inserted atomically with event/outbox, head-only `FOR UPDATE SKIP LOCKED` claims, DB-clock leases with epoch fencing, strict allowlisted envelope validation, synchronous Kafka `RequireAll` publication using stable event ID headers and tenant/aggregate partition keys, transactional acknowledge/head advance, bounded deterministic backoff persisted in PostgreSQL, durable corrupt-envelope block without head skip, and stale-worker/retry/poison coverage; local PostgreSQL/Kafka integration, migration and tenant RLS suites passed; CI contract run #23 passed. Follow-ups for audited repair and production TLS transport remain tracked in #108 and #109.
- [x] K1.4-OPS Add an audited, tenant-scoped operator repair path for blocked outbox streams without changing immutable event history or skipping versions. Owner: Keel platform (named person unassigned); PR #114 (closes #108); evidence: migration `0007_audited_outbox_repair`, non-login `keel_operator` role and tenant RLS, context-bound operator authorization, payload-free blocked diagnostics, stale-state guards, canonical event/envelope hash validation plus complete event replay, ordered-only retry reset, transactionally coupled audit, and a DB trigger that rejects unaudited blocked-to-pending changes; attempt count, event ID, claim epoch and publish head version are preserved. Unit/integration tests prove denied authorization, wrong-tenant isolation, stale/corrupt-source refusal, audit rollback on failed repair, and same-ID resume before version 2. Local `go test -p 1 ./...`, `go vet -p 1 ./...`, `go test -race -p 1 ./...`, `go build -p 1 ./...`, and fresh PostgreSQL/Kafka integration passed; CI contract run #45 passed. The operator service is not runtime-wired; K0 authentication/runtime gates still apply.
- [x] K1.4-SEC Qualify authenticated TLS Kafka transport and fail closed for non-local plaintext configuration before production wiring. Owner: Keel platform (named person unassigned); PR #115 (closes #109); evidence: explicit non-empty CA trust pool, TLS 1.2+ verification and hostname checks, SCRAM-SHA-512, remote plaintext refusal, isolated local-synthetic constructors, credential redaction, serialized producer/consumer trust and credential rotation; ephemeral real Kafka integration rejects untrusted CA, wrong hostname and invalid credentials, then proves reconnect with a second principal. `go test ./...`, `go test -race ./...`, `go vet ./...`, `go build ./...`, and pinned-broker `scripts/test-kafka-secure.sh` passed; final PR-head CI contract run #57 passed. Cloud runtime secret injection and managed Kafka service qualification remain outside the enabled local-synthetic profile; K0 runtime gates still apply.
- [x] K1.5 Add durable inbox, contiguous projection apply, conflict quarantine and gap replay. Owner: Keel platform (named person unassigned); PR #111 (closes #13); evidence: migration `0006_order_inbox_projection_and_gap_replay`, forced-RLS inbox/deferred/quarantine tables and restricted projector role, `order-projection-v1` consumer pin, strict seven-field order envelope plus unique Kafka identity headers, canonical-source verification, atomic idempotent inbox/projection writes, bounded contiguous gap replay, tenantless quarantine for claims without canonical source identity, durable blocked state for corrupt canonical events, and non-owner multi-tenant PostgreSQL integration coverage. Also rejects duplicate JSON keys and duplicate/unknown identity headers; retries of malformed transport quarantine are digest-idempotent. Local fresh-PostgreSQL/Kafka integration and `go test -p 1 ./...`, `go vet -p 1 ./...`, `go test -race -p 1 ./...`, `go build -p 1 ./...` passed; CI contract run #26 passed. Decision: this vertical slice intentionally supports one pinned projection consumer; concrete Kafka offset, commit, and rebalance handling remains K1.7. K1.4 publisher numeric-seconds retry persistence fix is included after K1.5 integration uncovered PostgreSQL rejecting sub-millisecond duration strings.
- [x] K1.6 Add order UI/history, projection watermark and authoritative command reads. Owner: Keel platform (named person unassigned); PR #112 (closes #14); evidence: command snapshot remains authoritative and is read with the independent projection watermark in a repeatable-read transaction (missing projection is watermark 0); first history page is read from the same snapshot; bounded descending immutable event pages verify event hashes, identity, metadata, and contiguous versions; AES-256-GCM cursors bind tenant/order/page size with expiry and key rotation; authorized HTTP handlers derive tenant/principal only from trusted context, hide denied resources as 404, expose allowlisted JSON/history fields, and set private/no-store/security headers; strong GET ETags include command version and projection watermark, with `X-Order-Version` carrying command version; accessible server-rendered order detail distinguishes command status from projection lag. PostgreSQL integration covers lag/absent/current projection, paging, integrity failures, cross-tenant RLS, and a concurrent submit/projector/read race that checks snapshot, watermark, and history coherence; cursor and HTTP/UI tests cover tampering/scope/expiry, authorization, redaction, headers, parsing, and rendering. Local `go test -p 1 ./...`, `go vet -p 1 ./...`, `go test -race -p 1 ./...`, `go build -p 1 ./...`, fresh isolated PostgreSQL integration, and CI contract run #33 passed. K0 production identity-provider and API-runtime wiring remains a separate gate.
- [x] K1.7 Exercise command/relay/consumer crash and rebalance boundaries. Owner: Keel platform (named person unassigned); PR #113 (closes #15); evidence: existing command transaction fault injection proves rollback and same-idempotency-key retry; real Kafka relay fault injection loses PostgreSQL publish acknowledgement after broker acceptance, lease reclaim republishes the same stable event ID, and the projector inbox yields one logical effect. The consumer group adapter disables automatic commits, preserves repeated Kafka headers, serializes one message at a time, and commits only durable applied/duplicate/deferred/quarantined outcomes; processor/database/quarantine failures and non-durable dispositions leave the offset unadvanced. PostgreSQL/Kafka integration exercises both ambiguous offset-commit outcomes: rejected commit causes group rejoin and duplicate suppression; accepted commit with a lost response resumes after that offset and applies the next aggregate version. Producer and consumer share canonical order-topic validation. Dedicated K1.7 topics are provisioned locally and in CI, with stable consumer-group IDs. Local `go test -p 1 ./...`, `go vet -p 1 ./...`, `go test -race -p 1 ./...`, `go build -p 1 ./...`, full isolated PostgreSQL/Kafka integration, and CI contract run #42 passed. Delivery remains at-least-once; this does not claim exactly-once Kafka semantics. K0 runtime assembly and generation-scoped shadow projection rebuild remain separate gates.
- [x] K1 gate: duplicates/reorder/replay never duplicate effects; event-derived state equals snapshot/projection. Owner: sanskarpan (repository owner; local synthetic profile only); PR #116 (closes #16); evidence: `docs/K1-GATE-EVIDENCE.md`, pure replay/reference tests, PostgreSQL event-hash/snapshot reconciliation, version-2-before-version-1 gap repair and late-duplicate integration test with exactly one applied inbox row per canonical event, Kafka acknowledgement/offset-loss rebalance tests, and projection watermark/status reconciliation against the replayed command snapshot. Security/privacy review found no new payload fields or production authorization claim; details and residual K0/runtime limits are recorded in the evidence document. No migration or production deployment is introduced; revert the PR merge commit to roll back, and disposable CI dependencies/test data are closed or removed by the job/test cleanup hooks. CI contract run #57 passed. At-least-once delivery is retained; exactly-once broker semantics are not claimed.

## K2 — Durable supplier onboarding

- [ ] K2.1 Implement supplier invitations, validated upload flow and sandbox scan/extraction.
- [ ] K2.2 Add case/evidence/policy/deadline model and durable workflow intents.
- [ ] K2.3 Implement deterministic Temporal workflow IDs, retry-safe start and deduplicated signals.
- [ ] K2.4 Add human approval/separation-of-duties checks and deadline race serialization.
- [ ] K2.5 Add reminders, cancellation, manual review and idempotent activity effects.
- [ ] K2.6 Qualify workflow history/versioned rollout and 72h restart behavior.
- [ ] K2 gate: accepted pre-deadline decision survives signal loss; late decisions cannot approve; real-duration staging evidence recorded.

## K3 — Tenant-safe hybrid retrieval

- [ ] K3.1 Define tokenization/chunk/model/corpus versioning and labeled evaluation corpus.
- [ ] K3.2 Implement tenant/visibility-local BM25 postings/statistics and atomic publication.
- [ ] K3.3 Implement embeddings/model identity, exact search and bounded filtered HNSW.
- [ ] K3.4 Add rank fusion, optional capped reranker, immutable citations and degraded-results flags.
- [ ] K3.5 Enforce withdrawal/ACL changes at query time and erasure/index cleanup.
- [ ] K3.6 Measure SQL plans, posting budgets, skewed tenant recall/latency and reference BM25 correctness.
- [ ] K3 gate: isolation and agreed relevance target pass within the documented capacity envelope.

## K4 — AI gateway, budget and policy

- [ ] K4.1 Build typed read-only agent query broker with protected session-role mapping.
- [ ] K4.2 Implement versioned prompt/provider/tool policy and PII scrubbing before provider/logging.
- [ ] K4.3 Implement durable reserve/settle/unknown-liability ledger and safe price quoting.
- [ ] K4.4 Add fair DB job claims, lease epochs, provider concurrency/token/time caps.
- [ ] K4.5 Implement exact and scoped semantic cache, entity/polarity checks and labeled precision gate with >=600 independent eligible pairs per serving policy and one-sided 95% lower confidence bound >=99.5%.
- [ ] K4.6 Add at most one pre-token fallback, provider idempotency capability and charged-attempt records.
- [ ] K4.7 Add global home-region Redis rate limiting and bounded degradation policies.
- [ ] K4 gate: budget races and provider uncertainty remain bounded; no tool writes; cache near-neighbor/privacy failures rejected.

## K5 — Live operations and correlated diagnostics

- [ ] K5.1 Build multiplexed SSE state/token transport, durable cursors and transient token sequencing.
- [ ] K5.2 Add per-client queue/write-timeout limits, reconnect snapshots and interrupted-result handling.
- [ ] K5.3 Trace HTTP/query/event/workflow/model/delivery boundaries with links and safe attributes.
- [ ] K5.4 Add encrypted context-vault retention, authorized read-only replay and Langfuse adapter.
- [ ] K5.5 Implement tenant cost dashboard, confirmed/estimated/unknown breakdowns and rollup watermarks.
- [ ] K5.6 Add threshold/budget alerts and history-qualified spend anomalies.
- [ ] K5 gate: slow clients do not exhaust memory; telemetry PII scan passes; every attempt is attributable.

## K6 — Reliable external effects

- [ ] K6.1 Implement authenticated callback inbox and provider event/payload conflict handling.
- [ ] K6.2 Add logical delivery uniqueness, signing/key rotation and SSRF-safe egress.
- [ ] K6.3 Implement jitter retry, per-endpoint circuit breaker, exhaustion and capped replay UI.
- [ ] K6.4 Implement dry-run reconciliation, cursor accounting and idempotent repairs.
- [ ] K6.5 Exercise late/duplicate callbacks, receiver failure and replay after secret/DNS changes.
- [ ] K6 gate: no replay causes unauthorized/duplicate domain transitions or bypasses egress policy.

## K7 — Production qualification and handoff

- [ ] K7.1 Package immutable recipe/Helm role profiles for Ghostlight; bounded migration/test contracts.
- [ ] K7.2 Run capacity profile, 10k socket and separate active-stream tests; publish raw reports.
- [ ] K7.3 Run 6h+ soak and production-scale 24h qualification; CPU/RSS/FD/DB limits documented.
- [ ] K7.4 Qualify PITR/region recovery, erasure journal, workflow continuity and external reconciliation.
- [ ] K7.5 Install SLO/burn dashboards, alerts, kill switches and operator runbooks.
- [ ] K7.6 Run Ghostlight faults with Keel's independent invariants; record recovery and cost.
- [ ] K7.7 Publish two Keel architecture articles with ADRs, diagrams and measured tradeoffs.
- [ ] K7 technical gate: signed candidate/config/schema evidence; critical security/correctness gates pass; operational owner assigned. Paid launch also requires K8.

## K8 — Complete 1.0 SaaS and customer workflows

- [ ] K8.1 Implement organization/trial/region/terms onboarding, sample mode, setup checklist and bounded abuse protection; K-F01/K-F04.
- [ ] K8.2 Implement members/invites/owner transfer/service principals, persistent supplier identity/grants and session/key revocation; K-F02/K-F07.
- [ ] K8.3 Build versioned category intake/drafts, supplier master/duplicate review and auditable merge; K-F05/K-F06.
- [ ] K8.4 Implement serial/parallel frozen approval plans, delegation, packet supersession and final-step deadline arbitration; K-F09/K-F11.
- [ ] K8.5 Implement separate procurement ledger/accounts/reservations/commitments/overrides; reference-model concurrency and reconciliation; K-F10.
- [ ] K8.6 Implement hosted subscription checkout/portal, verified billing inbox/reconciliation, versioned entitlements/meters, grace/cancel/downgrade and invoice observations; K-F03/K-F16.
- [ ] K8.7 Build role-specific task inbox and supplier console, explicitly internal/external collaboration, deduplicated notifications/preferences/digests; K-F04/K-F07/K-F14.
- [ ] K8.8 Implement CSV dry-run/commit/per-row jobs, checksummed safe exports, legal-hold/privacy/organization closure and time-bound support access; K-F17/K-F18.
- [ ] K8.9 Complete accessible responsive journeys, help/integration health/status incident communications and privacy-safe analytics; K-F04/K-F15/K-F18.
- [ ] K8.10 Qualify real billing/email sandboxes, trial economics/pricing, design-partner activation, SaaS workload/load/recovery and all shared foundation negative cases; K-F01–K-F18.
- [ ] K8.11 Ship first-party identity bootstrap/sign-in, verified email, session lifecycle/revocation, owner MFA, recovery and lockout protections; test account recovery and takeover boundaries.
- [ ] K8.12 Complete jurisdiction-scoped privacy/legal launch review: terms, privacy notice, DPA/subprocessor disclosures, breach response, rights-request and retention workflows; document accountable operational owners before real customer data.
- [ ] K8 paid 1.0 gate: K0–K7 critical gates plus signup->supplier->request->human approval->budget->billing/export/offboarding pass; no unchecked commercial/UX/security blocker.

## K9 — 1.5 purchasing execution and contract lifecycle

- [ ] K9.1 Implement catalog versions, eligibility/price revalidation and repeat-buy drafts; K-F19.
- [ ] K9.2 Implement RFQ/RFP invitations, isolated versioned bids/deadlines/criteria and reviewed award; K-F20.
- [ ] K9.3 Implement PO aggregates/permanent IDs, issuance/dispatch/acknowledgment and unknown-send observation; K-F21.
- [ ] K9.4 Implement material amendments, fresh approval/budget deltas and exact supplier version handling; K-F21.
- [ ] K9.5 Implement partial fixed-point receipts/service milestones/returns/reversals and line locks; K-F22.
- [ ] K9.6 Implement invoice dedup, two/three-way allocation/tolerance matching, audited exception resolution and no payment path; K-F23.
- [ ] K9.7 Qualify one ERP/accounting adapter, field authority/mappings/cursors, idempotent handoff and commitment-to-actual reconciliation; K-F25.
- [ ] K9.8 Build contract/obligation metadata confirmation, durable notice/renewal tasks and owner/timezone fallback; K-F24.
- [ ] K9.9 Build scoped spend/cycle analytics and qualified chat notification/intake integrations; K-F26/K-F27.
- [ ] K9 1.5 gate: sourcing->approved amended PO->partial receipt->invoice exception->reconciled accounting handoff plus renewal proof; financial/privacy/capacity qualification passes.

## K10 — 2.0 enterprise identity, governance and tenancy

- [ ] K10.1 Qualify enterprise SSO/SCIM/group grants/offboarding and tested recovery; K-F28.
- [ ] K10.2 Add legal entities/business scopes/resource-field visibility and provenance-safe multi-currency quotes; K-F29.
- [ ] K10.3 Build immutable policy schema/builder, bounded historical simulation and publication approval; K-F30.
- [ ] K10.4 Add rubric/questionnaire/evidence findings and accountable expiring risk acceptance; K-F31.
- [ ] K10.5 Implement evidence expiry/reassessment/supplier suspension and impact workbench; K-F32.
- [ ] K10.6 Implement SIEM/audit export, advanced retention/legal hold and private evidence access; K-F33.
- [ ] K10.7 Qualify dedicated/regional deployment, key/restore/residency profile and contractual support responsibility; K-F34.
- [ ] K10.8 Publish scoped API/SDK/migration/connector administration with compatibility/security fixtures; K-F35.
- [ ] K10 enterprise gate: actual IdP, scope/FX/simulation/risk/retention/dedicated profile evidence and support readiness; no architecture-only compliance claims.

## K11 — 3.0 discovery, not automatic delivery

- [ ] K11.1 Interview/prototype renewal negotiation and supplier performance insights; licensed data, provenance/disputes and bounded economics; K-F36/K-F37.
- [ ] K11.2 Qualify e-signature provider and multilingual analyzer/model/interface before committing feature scope; K-F38.
- [ ] K11.3 Prototype read-only synthetic scenario lab and purchasing-opportunity recommendations; no live effects; K-F39/K-F40.
- [ ] K11.4 Select at most two demand-validated bets, write implementation acceptance and rerun privacy/quality/cost qualification before release.
- [ ] K11 discovery gate: explicit go/no-go decision per idea, user value evidence and safe operating profile; rejected/deferred ideas remain documented rather than claimed delivered.
