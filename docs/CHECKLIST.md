# Implementation checklist and release gates

All tasks are pending. Record owner, PR/commit, evidence path and decision revision beside completed items. A phase gate remains open until its independent evidence passes. Shared contract version: 1.1. K8 starts alongside K0/K1; phase numbering preserves the technical baseline, not chronological deferral. ROADMAP.md defines paid 1.0 through enterprise/discovery versions. Original topics are minimum scope.

## K0 — Foundation and boundaries

- [ ] K0.1 Lock supported language/dependency versions, images and provider capabilities; close Q-01; close Q-03/Q-04/Q-09 or document each as disabled/not applicable in the selected pilot profile with owner, reason and evidence. Q-01 always blocks a pilot.
- [ ] K0.2 Create Go role entry point, module boundaries, structured redacting logger and validated configuration.
- [ ] K0.3 Build local real-dependency Compose profile and deterministic two-tenant seeds.
- [ ] K0.4 Define OpenAPI/event schemas and shared deployment recipe fixtures; contract CI checks.
- [ ] K0.5 Create schema owner/app/worker/agent roles and FORCE RLS transaction wrapper.
- [ ] K0.6 Implement migration locking/checksums, health/version/metrics and signed artifact/SBOM pipeline.
- [ ] K0 gate: two-tenant API and session-bound agent isolation proven with real non-owner DB roles.

## K1 — Event-sourced order vertical slice

- [ ] K1.1 Implement order state machine, command snapshot and pure event replay reference model.
- [ ] K1.2 Add aggregate lock/version, stable natural references and transactional idempotency plus a compact dedup registry that prevents financial-effect re-execution after response detail expiry; include >7-day retry proof.
- [ ] K1.3 Append events/outbox/state-feed/result in one transaction; DB append-only grants.
- [ ] K1.4 Implement publish-head claims, broker acknowledgement/retry/fencing and stable event IDs.
- [ ] K1.5 Add durable inbox, contiguous projection apply, conflict quarantine and gap replay.
- [ ] K1.6 Add order UI/history, projection watermark and authoritative command reads.
- [ ] K1.7 Exercise command/relay/consumer crash and rebalance boundaries.
- [ ] K1 gate: duplicates/reorder/replay never duplicate effects; event-derived state equals snapshot/projection.

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
