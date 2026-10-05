# Keel checklist issue index

This index maps every unchecked item in [`CHECKLIST.md`](CHECKLIST.md) to its GitHub issue. It contains 95 issues, including phase gates. Issues are sequenced by phase; no milestone has a due date, and phase order is not a delivery-date promise.

## K0 — Foundation and boundaries

| Checklist ID | Type | Checklist item | GitHub issue |
|---|---|---|---|
| `K0.1` | task | K0.1 Lock supported language/dependency versions, images and provider capabilities; close Q-01; close Q-03/Q-04/Q-09 or document each as disabled/not applicable in the selected pilot profile with owner, reason and evidence. Q-01 always blocks a pilot. | [Open issue](https://github.com/sanskarpan/Keel/issues/2) |

| `K0.2` | task | K0.2 Create Go role entry point, module boundaries, structured redacting logger and validated configuration. | [Open issue](https://github.com/sanskarpan/Keel/issues/3) |

| `K0.3` | task | K0.3 Build local real-dependency Compose profile and deterministic two-tenant seeds. | [Open issue](https://github.com/sanskarpan/Keel/issues/4) |

| `K0.4` | task | K0.4 Define OpenAPI/event schemas and shared deployment recipe fixtures; contract CI checks. | [Open issue](https://github.com/sanskarpan/Keel/issues/5) |

| `K0.5` | task | K0.5 Create schema owner/app/worker/agent roles and FORCE RLS transaction wrapper. | [Open issue](https://github.com/sanskarpan/Keel/issues/6) |

| `K0.6` | task | K0.6 Implement migration locking/checksums, health/version/metrics and signed artifact/SBOM pipeline. | [Open issue](https://github.com/sanskarpan/Keel/issues/7) |

| `K0-GATE` | gate | K0 gate: two-tenant API and session-bound agent isolation proven with real non-owner DB roles. | [PR #117 (closes issue #8)](https://github.com/sanskarpan/Keel/pull/117) |


## K1 — Event-sourced order vertical slice

| Checklist ID | Type | Checklist item | GitHub issue |
|---|---|---|---|
| `K1.1` | task | K1.1 Implement order state machine, command snapshot and pure event replay reference model. | [Open issue](https://github.com/sanskarpan/Keel/issues/9) |

| `K1.2` | task | K1.2 Add aggregate lock/version, stable natural references and transactional idempotency plus a compact dedup registry that prevents financial-effect re-execution after response detail expiry; include >7-day retry proof. | [Open issue](https://github.com/sanskarpan/Keel/issues/10) |

| `K1.3` | task | K1.3 Append events/outbox/state-feed/result in one transaction; DB append-only grants. | [Open issue](https://github.com/sanskarpan/Keel/issues/11) |

| `K1.4` | task | K1.4 Implement publish-head claims, broker acknowledgement/retry/fencing and stable event IDs. | [PR #110 (closes issue #12)](https://github.com/sanskarpan/Keel/pull/110) |
| `K1.4-OPS` | task | Add an audited, tenant-scoped operator repair path for blocked outbox streams. | [PR #114 (closes issue #108)](https://github.com/sanskarpan/Keel/pull/114) |
| `K1.4-SEC` | task | Qualify authenticated TLS Kafka transport and fail closed for non-local plaintext configuration. | [PR #115 (closes issue #109)](https://github.com/sanskarpan/Keel/pull/115) |

| `K1.5` | task | K1.5 Add durable inbox, contiguous projection apply, conflict quarantine and gap replay. | [PR #111 (closes issue #13)](https://github.com/sanskarpan/Keel/pull/111) |

| `K1.6` | task | K1.6 Add order UI/history, projection watermark and authoritative command reads. | [PR #112 (closes issue #14)](https://github.com/sanskarpan/Keel/pull/112) |

| `K1.7` | task | K1.7 Exercise command/relay/consumer crash and rebalance boundaries. | [PR #113 (closes issue #15)](https://github.com/sanskarpan/Keel/pull/113) |

| `K1-GATE` | gate | K1 gate: duplicates/reorder/replay never duplicate effects; event-derived state equals snapshot/projection. | [PR #116 (closes issue #16)](https://github.com/sanskarpan/Keel/pull/116) |


## K2 — Durable supplier onboarding

| Checklist ID | Type | Checklist item | GitHub issue |
|---|---|---|---|
| `K2.1` | task | K2.1 Implement supplier invitations, validated upload flow and sandbox scan/extraction. | [Open issue](https://github.com/sanskarpan/Keel/issues/17) |

| `K2.2` | task | K2.2 Add case/evidence/policy/deadline model and durable workflow intents. | [Open issue](https://github.com/sanskarpan/Keel/issues/18) |

| `K2.3` | task | K2.3 Implement deterministic Temporal workflow IDs, retry-safe start and deduplicated signals. | [Open issue](https://github.com/sanskarpan/Keel/issues/19) |

| `K2.4` | task | K2.4 Add human approval/separation-of-duties checks and deadline race serialization. | [Open issue](https://github.com/sanskarpan/Keel/issues/20) |

| `K2.5` | task | K2.5 Add reminders, cancellation, manual review and idempotent activity effects. | [Open issue](https://github.com/sanskarpan/Keel/issues/21) |

| `K2.6` | task | K2.6 Qualify workflow history/versioned rollout and 72h restart behavior. | [Open issue](https://github.com/sanskarpan/Keel/issues/22) |

| `K2-GATE` | gate | K2 gate: accepted pre-deadline decision survives signal loss; late decisions cannot approve; real-duration staging evidence recorded. | [Open issue](https://github.com/sanskarpan/Keel/issues/23) |


## K3 — Tenant-safe hybrid retrieval

| Checklist ID | Type | Checklist item | GitHub issue |
|---|---|---|---|
| `K3.1` | task | K3.1 Define tokenization/chunk/model/corpus versioning and labeled evaluation corpus. | [Open issue](https://github.com/sanskarpan/Keel/issues/24) |

| `K3.2` | task | K3.2 Implement tenant/visibility-local BM25 postings/statistics and atomic publication. | [Open issue](https://github.com/sanskarpan/Keel/issues/25) |

| `K3.3` | task | K3.3 Implement embeddings/model identity, exact search and bounded filtered HNSW. | [Open issue](https://github.com/sanskarpan/Keel/issues/26) |

| `K3.4` | task | K3.4 Add rank fusion, optional capped reranker, immutable citations and degraded-results flags. | [Open issue](https://github.com/sanskarpan/Keel/issues/27) |

| `K3.5` | task | K3.5 Enforce withdrawal/ACL changes at query time and erasure/index cleanup. | [Open issue](https://github.com/sanskarpan/Keel/issues/28) |

| `K3.6` | task | K3.6 Measure SQL plans, posting budgets, skewed tenant recall/latency and reference BM25 correctness. | [Open issue](https://github.com/sanskarpan/Keel/issues/29) |

| `K3-GATE` | gate | K3 gate: isolation and agreed relevance target pass within the documented capacity envelope. | [Open issue](https://github.com/sanskarpan/Keel/issues/30) |


## K4 — AI gateway, budget and policy

| Checklist ID | Type | Checklist item | GitHub issue |
|---|---|---|---|
| `K4.1` | task | K4.1 Build typed read-only agent query broker with protected session-role mapping. Initial internal slice: [issue #184](https://github.com/sanskarpan/Keel/issues/184), [PR #185](https://github.com/sanskarpan/Keel/pull/185); parent remains open. | [Open parent issue](https://github.com/sanskarpan/Keel/issues/31) |

| `K4.2` | task | K4.2 Implement versioned prompt/provider/tool policy and PII scrubbing before provider/logging. Offline slice: [issue #182](https://github.com/sanskarpan/Keel/issues/182), [merged PR #183](https://github.com/sanskarpan/Keel/pull/183); parent remains open. | [Open parent issue](https://github.com/sanskarpan/Keel/issues/32) |

| `K4.3` | task | K4.3 Implement durable reserve/settle/unknown-liability ledger and safe price quoting. | [Open issue](https://github.com/sanskarpan/Keel/issues/33) |

| `K4.3-follow-up` | bug | Route active budget-period row locking through a tenant-checked SECURITY DEFINER function without granting app UPDATE privileges. | [Open issue](https://github.com/sanskarpan/Keel/issues/189) |

| `K4.4` | task | K4.4 Add fair DB job claims, lease epochs, provider concurrency/token/time caps. | [Open issue](https://github.com/sanskarpan/Keel/issues/34) |

| `K4.4-outcomes` | task | Reconcile expired AI attempts with K4.3 liability; terminalize confirmed/no-charge outcomes safely and never replay an ambiguous billable attempt. | [Open issue](https://github.com/sanskarpan/Keel/issues/190) |

| `K4.5` | task | K4.5 Implement exact and scoped semantic cache, entity/polarity checks and labeled precision gate with >=600 independent eligible pairs per serving policy and one-sided 95% lower confidence bound >=99.5%. | [Open issue](https://github.com/sanskarpan/Keel/issues/35) |

| `K4.6` | task | K4.6 Add at most one pre-token fallback, provider idempotency capability and charged-attempt records. | [Open issue](https://github.com/sanskarpan/Keel/issues/36) |

| `K4.7` | task | K4.7 Add global home-region Redis rate limiting and bounded degradation policies. | [Open issue](https://github.com/sanskarpan/Keel/issues/37) |

| `K4-GATE` | gate | K4 gate: budget races and provider uncertainty remain bounded; no tool writes; cache near-neighbor/privacy failures rejected. | [Open issue](https://github.com/sanskarpan/Keel/issues/38) |


## K5 — Live operations and correlated diagnostics

| Checklist ID | Type | Checklist item | GitHub issue |
|---|---|---|---|
| `K5.1` | task | K5.1 Build multiplexed SSE state/token transport, durable cursors and transient token sequencing. | [Open issue](https://github.com/sanskarpan/Keel/issues/39) |

| `K5.2` | task | K5.2 Add per-client queue/write-timeout limits, reconnect snapshots and interrupted-result handling. | [Open issue](https://github.com/sanskarpan/Keel/issues/40) |

| `K5.3` | task | K5.3 Trace HTTP/query/event/workflow/model/delivery boundaries with links and safe attributes. | [Open issue](https://github.com/sanskarpan/Keel/issues/41) |

| `K5.4` | task | K5.4 Add encrypted context-vault retention, authorized read-only replay and Langfuse adapter. | [Open issue](https://github.com/sanskarpan/Keel/issues/42) |

| `K5.5` | task | K5.5 Implement tenant cost dashboard, confirmed/estimated/unknown breakdowns and rollup watermarks. | [Open issue](https://github.com/sanskarpan/Keel/issues/43) |

| `K5.6` | task | K5.6 Add threshold/budget alerts and history-qualified spend anomalies. | [Open issue](https://github.com/sanskarpan/Keel/issues/44) |

| `K5-GATE` | gate | K5 gate: slow clients do not exhaust memory; telemetry PII scan passes; every attempt is attributable. | [Open issue](https://github.com/sanskarpan/Keel/issues/45) |


## K6 — Reliable external effects

| Checklist ID | Type | Checklist item | GitHub issue |
|---|---|---|---|
| `K6.1` | task | K6.1 Implement authenticated callback inbox and provider event/payload conflict handling. | [Open issue](https://github.com/sanskarpan/Keel/issues/46) |

| `K6.2` | task | K6.2 Add logical delivery uniqueness, signing/key rotation and SSRF-safe egress. | [Open issue](https://github.com/sanskarpan/Keel/issues/47) |

| `K6.3` | task | K6.3 Implement jitter retry, per-endpoint circuit breaker, exhaustion and capped replay UI. | [Open issue](https://github.com/sanskarpan/Keel/issues/48) |

| `K6.4` | task | K6.4 Implement dry-run reconciliation, cursor accounting and idempotent repairs. | [Open issue](https://github.com/sanskarpan/Keel/issues/49) |

| `K6.5` | task | K6.5 Exercise late/duplicate callbacks, receiver failure and replay after secret/DNS changes. | [Open issue](https://github.com/sanskarpan/Keel/issues/50) |

| `K6-GATE` | gate | K6 gate: no replay causes unauthorized/duplicate domain transitions or bypasses egress policy. | [Open issue](https://github.com/sanskarpan/Keel/issues/51) |


## K7 — Production qualification and handoff

| Checklist ID | Type | Checklist item | GitHub issue |
|---|---|---|---|
| `K7.1` | task | K7.1 Package immutable recipe/Helm role profiles for Ghostlight; bounded migration/test contracts. | [Open issue](https://github.com/sanskarpan/Keel/issues/52) |

| `K7.2` | task | K7.2 Run capacity profile, 10k socket and separate active-stream tests; publish raw reports. | [Open issue](https://github.com/sanskarpan/Keel/issues/53) |

| `K7.3` | task | K7.3 Run 6h+ soak and production-scale 24h qualification; CPU/RSS/FD/DB limits documented. | [Open issue](https://github.com/sanskarpan/Keel/issues/54) |

| `K7.4` | task | K7.4 Qualify PITR/region recovery, erasure journal, workflow continuity and external reconciliation. | [Open issue](https://github.com/sanskarpan/Keel/issues/55) |

| `K7.5` | task | K7.5 Install SLO/burn dashboards, alerts, kill switches and operator runbooks. | [Open issue](https://github.com/sanskarpan/Keel/issues/56) |

| `K7.6` | task | K7.6 Run Ghostlight faults with Keel's independent invariants; record recovery and cost. | [Open issue](https://github.com/sanskarpan/Keel/issues/57) |

| `K7.7` | task | K7.7 Publish two Keel architecture articles with ADRs, diagrams and measured tradeoffs. | [Open issue](https://github.com/sanskarpan/Keel/issues/58) |

| `K7-GATE` | gate | K7 technical gate: signed candidate/config/schema evidence; critical security/correctness gates pass; operational owner assigned. Paid launch also requires K8. | [Open issue](https://github.com/sanskarpan/Keel/issues/59) |


## K8 — Complete 1.0 SaaS and customer workflows

| Checklist ID | Type | Checklist item | GitHub issue |
|---|---|---|---|
| `K8.1` | task | K8.1 Implement organization/trial/region/terms onboarding, sample mode, setup checklist and bounded abuse protection; K-F01/K-F04. | [Open issue](https://github.com/sanskarpan/Keel/issues/60) |

| `K8.2` | task | K8.2 Implement members/invites/owner transfer/service principals, persistent supplier identity/grants and session/key revocation; K-F02/K-F07. | [Open issue](https://github.com/sanskarpan/Keel/issues/61) |

| `K8.3` | task | K8.3 Build versioned category intake/drafts, supplier master/duplicate review and auditable merge; K-F05/K-F06. | [Open issue](https://github.com/sanskarpan/Keel/issues/62) |

| `K8.4` | task | K8.4 Implement serial/parallel frozen approval plans, delegation, packet supersession and final-step deadline arbitration; K-F09/K-F11. | [Open issue](https://github.com/sanskarpan/Keel/issues/63) |

| `K8.5` | task | K8.5 Implement separate procurement ledger/accounts/reservations/commitments/overrides; reference-model concurrency and reconciliation; K-F10. | [Open issue](https://github.com/sanskarpan/Keel/issues/64) |

| `K8.6` | task | K8.6 Implement hosted subscription checkout/portal, verified billing inbox/reconciliation, versioned entitlements/meters, grace/cancel/downgrade and invoice observations; K-F03/K-F16. | [Open issue](https://github.com/sanskarpan/Keel/issues/65) |

| `K8.7` | task | K8.7 Build role-specific task inbox and supplier console, explicitly internal/external collaboration, deduplicated notifications/preferences/digests; K-F04/K-F07/K-F14. | [Open issue](https://github.com/sanskarpan/Keel/issues/66) |

| `K8.8` | task | K8.8 Implement CSV dry-run/commit/per-row jobs, checksummed safe exports, legal-hold/privacy/organization closure and time-bound support access; K-F17/K-F18. | [Open issue](https://github.com/sanskarpan/Keel/issues/67) |

| `K8.9` | task | K8.9 Complete accessible responsive journeys, help/integration health/status incident communications and privacy-safe analytics; K-F04/K-F15/K-F18. | [Open issue](https://github.com/sanskarpan/Keel/issues/68) |

| `K8.10` | task | K8.10 Qualify real billing/email sandboxes, trial economics/pricing, design-partner activation, SaaS workload/load/recovery and all shared foundation negative cases; K-F01–K-F18. | [Open issue](https://github.com/sanskarpan/Keel/issues/69) |

| `K8.11` | task | K8.11 Ship first-party identity bootstrap/sign-in, verified email, session lifecycle/revocation, owner MFA, recovery and lockout protections; test account recovery and takeover boundaries. | [Open issue](https://github.com/sanskarpan/Keel/issues/70) |

| `K8.12` | task | K8.12 Complete jurisdiction-scoped privacy/legal launch review: terms, privacy notice, DPA/subprocessor disclosures, breach response, rights-request and retention workflows; document accountable operational owners before real customer data. | [Open issue](https://github.com/sanskarpan/Keel/issues/71) |

| `K8-GATE` | gate | K8 paid 1.0 gate: K0–K7 critical gates plus signup->supplier->request->human approval->budget->billing/export/offboarding pass; no unchecked commercial/UX/security blocker. | [Open issue](https://github.com/sanskarpan/Keel/issues/72) |


## K9 — 1.5 purchasing execution and contract lifecycle

| Checklist ID | Type | Checklist item | GitHub issue |
|---|---|---|---|
| `K9.1` | task | K9.1 Implement catalog versions, eligibility/price revalidation and repeat-buy drafts; K-F19. | [Open issue](https://github.com/sanskarpan/Keel/issues/73) |

| `K9.2` | task | K9.2 Implement RFQ/RFP invitations, isolated versioned bids/deadlines/criteria and reviewed award; K-F20. | [Open issue](https://github.com/sanskarpan/Keel/issues/74) |

| `K9.3` | task | K9.3 Implement PO aggregates/permanent IDs, issuance/dispatch/acknowledgment and unknown-send observation; K-F21. | [Open issue](https://github.com/sanskarpan/Keel/issues/75) |

| `K9.4` | task | K9.4 Implement material amendments, fresh approval/budget deltas and exact supplier version handling; K-F21. | [Open issue](https://github.com/sanskarpan/Keel/issues/76) |

| `K9.5` | task | K9.5 Implement partial fixed-point receipts/service milestones/returns/reversals and line locks; K-F22. | [Open issue](https://github.com/sanskarpan/Keel/issues/77) |

| `K9.6` | task | K9.6 Implement invoice dedup, two/three-way allocation/tolerance matching, audited exception resolution and no payment path; K-F23. | [Open issue](https://github.com/sanskarpan/Keel/issues/78) |

| `K9.7` | task | K9.7 Qualify one ERP/accounting adapter, field authority/mappings/cursors, idempotent handoff and commitment-to-actual reconciliation; K-F25. | [Open issue](https://github.com/sanskarpan/Keel/issues/79) |

| `K9.8` | task | K9.8 Build contract/obligation metadata confirmation, durable notice/renewal tasks and owner/timezone fallback; K-F24. | [Open issue](https://github.com/sanskarpan/Keel/issues/80) |

| `K9.9` | task | K9.9 Build scoped spend/cycle analytics and qualified chat notification/intake integrations; K-F26/K-F27. | [Open issue](https://github.com/sanskarpan/Keel/issues/81) |

| `K9-GATE` | gate | K9 1.5 gate: sourcing->approved amended PO->partial receipt->invoice exception->reconciled accounting handoff plus renewal proof; financial/privacy/capacity qualification passes. | [Open issue](https://github.com/sanskarpan/Keel/issues/82) |


## K10 — 2.0 enterprise identity, governance and tenancy

| Checklist ID | Type | Checklist item | GitHub issue |
|---|---|---|---|
| `K10.1` | task | K10.1 Qualify enterprise SSO/SCIM/group grants/offboarding and tested recovery; K-F28. | [Open issue](https://github.com/sanskarpan/Keel/issues/83) |

| `K10.2` | task | K10.2 Add legal entities/business scopes/resource-field visibility and provenance-safe multi-currency quotes; K-F29. | [Open issue](https://github.com/sanskarpan/Keel/issues/84) |

| `K10.3` | task | K10.3 Build immutable policy schema/builder, bounded historical simulation and publication approval; K-F30. | [Open issue](https://github.com/sanskarpan/Keel/issues/85) |

| `K10.4` | task | K10.4 Add rubric/questionnaire/evidence findings and accountable expiring risk acceptance; K-F31. | [Open issue](https://github.com/sanskarpan/Keel/issues/86) |

| `K10.5` | task | K10.5 Implement evidence expiry/reassessment/supplier suspension and impact workbench; K-F32. | [Open issue](https://github.com/sanskarpan/Keel/issues/87) |

| `K10.6` | task | K10.6 Implement SIEM/audit export, advanced retention/legal hold and private evidence access; K-F33. | [Open issue](https://github.com/sanskarpan/Keel/issues/88) |

| `K10.7` | task | K10.7 Qualify dedicated/regional deployment, key/restore/residency profile and contractual support responsibility; K-F34. | [Open issue](https://github.com/sanskarpan/Keel/issues/89) |

| `K10.8` | task | K10.8 Publish scoped API/SDK/migration/connector administration with compatibility/security fixtures; K-F35. | [Open issue](https://github.com/sanskarpan/Keel/issues/90) |

| `K10-GATE` | gate | K10 enterprise gate: actual IdP, scope/FX/simulation/risk/retention/dedicated profile evidence and support readiness; no architecture-only compliance claims. | [Open issue](https://github.com/sanskarpan/Keel/issues/91) |


## K11 — 3.0 discovery, not automatic delivery

| Checklist ID | Type | Checklist item | GitHub issue |
|---|---|---|---|
| `K11.1` | task | K11.1 Interview/prototype renewal negotiation and supplier performance insights; licensed data, provenance/disputes and bounded economics; K-F36/K-F37. | [Open issue](https://github.com/sanskarpan/Keel/issues/92) |

| `K11.2` | task | K11.2 Qualify e-signature provider and multilingual analyzer/model/interface before committing feature scope; K-F38. | [Open issue](https://github.com/sanskarpan/Keel/issues/93) |

| `K11.3` | task | K11.3 Prototype read-only synthetic scenario lab and purchasing-opportunity recommendations; no live effects; K-F39/K-F40. | [Open issue](https://github.com/sanskarpan/Keel/issues/94) |

| `K11.4` | task | K11.4 Select at most two demand-validated bets, write implementation acceptance and rerun privacy/quality/cost qualification before release. | [Open issue](https://github.com/sanskarpan/Keel/issues/95) |

| `K11-GATE` | gate | K11 discovery gate: explicit go/no-go decision per idea, user value evidence and safe operating profile; rejected/deferred ideas remain documented rather than claimed delivered. | [Open issue](https://github.com/sanskarpan/Keel/issues/96) |
