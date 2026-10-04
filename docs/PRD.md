# Product requirements

Revision 2: this PRD defines the 1.0 technical/product core. PRODUCT-STRATEGY.md, FEATURE-CATALOG.md, JOURNEYS.md, PRODUCT-SPEC.md and ROADMAP.md extend it into a versioned independent SaaS. The original topics are minimum coverage. Organization/commercial lifecycle and launch readiness follow shared SAAS-FOUNDATION.md.

## 1. Problem and users

A procurement team must decide whether a supplier is acceptable, which policies or contracts apply, and whether a purchase should proceed. Documents and callbacks arrive over days. Duplicate messages and system outages must not create duplicate orders or bypass approval. AI assistance must preserve the organization's access boundaries and spending limits.

Primary users are requesters, procurement approvers, supplier coordinators and tenant administrators. Platform operators handle system health and integration recovery through separately authorized administrative actions. An external supplier has access only to its invitation/upload surface, not the tenant's internal search or orders.

## 2. Core journey

1. A tenant administrator configures OIDC, roles, budgets, approval policy and webhook endpoints.
2. A coordinator opens supplier onboarding. The supplier receives a narrowly scoped, expiring invitation and uploads supporting documents.
3. A durable 72-hour workflow validates uploads, runs policy/extraction checks and waits for authorized human approval. Reminders and deadline behavior survive service restarts.
4. An employee searches approved contracts/policies and submits a purchase order with an external reference. AI can explain evidence and suggest fields; the human chooses the order command.
5. Order transitions append durable events. Projections update the dashboard, which streams model output and state updates as separate typed messages.
6. Downstream systems receive signed webhooks. Callback delivery is deduplicated and reconciled against the order's current state. Administrators inspect failures and request audited replay.
7. Administrators inspect workload latency, integration status and attributed model/compute spend.

## 3. Product boundary

Paid 1.0 scope ends at approved/rejected/canceled order authority and supplier onboarding decisions, with guided intake, supplier portal, procurement budgets, collaboration and complete SaaS lifecycle. Purchasing 1.5 extends through separate PO, receipt and invoice-exception aggregates, contracts/renewals and accounting handoff. Payment movement, tax/GL posting and autonomous purchasing remain external/out of scope. Keel stores value/commitments but never debits customer money or instructs a bank. Its own hosted subscription billing is a separate administrative module.

AI has read-only access to approved retrieval tools. It cannot approve suppliers, change orders, accept policy exceptions, edit budgets or emit external business events. These actions require authenticated typed commands and permission checks. The UI displays extraction confidence/evidence and marks generated suggestions as suggestions.

Initial external integrations are a generic signed webhook and one reference procurement-system adapter with a sandbox. Add real provider adapters only after their signature, idempotency and reconciliation contracts are qualified.

Product release requires organization onboarding/membership, paid plan/entitlement handling, accessible customer console, notification/help/support, integration health, bulk import/export and auditable offboarding. These are 1.0 requirements, not optional follow-ups to technical qualification. Expanded features are versioned in FEATURE-CATALOG.md.

## 4. Required capabilities

| Capability | User-visible behavior |
|---|---|
| Organization isolation | Users cannot enumerate, retrieve or cache-hit another tenant's records |
| Supplier onboarding | State, outstanding approvals, deadline, evidence and history remain visible across outages |
| Search | Lexical/vector/hybrid results cite document/version, access classification and retrieval score explanation |
| Orders | Repeated submission with the same key yields the same logical order; decisions carry actor, reason and policy version |
| AI assistance | Live response, citations, selected serving model, fallback disclosure and estimated/confirmed usage |
| Operations | Replayable state stream plus an authoritative paginated API when the stream has gaps |
| Webhooks | Attempt history, signed test-fire, exhausted delivery filters and capped replay |
| Cost controls | Per-tenant budget, endpoint/model breakdown, uncertainty flag, threshold alerts and hard AI admission cap |
| Privacy | Documents and sensitive replay context have configurable retention and auditable access |

## 5. Success criteria

- A full onboarding/order flow can be completed after API, worker and workflow-service restart without losing an accepted approval or duplicating a transition.
- At least 95% of reference evaluation queries retrieve a relevant result in top 10 for the curated v1 corpus; report lexical/vector/hybrid scores separately and stratify rare/numeric/negated queries.
- No cross-tenant result appears in any authorization, retrieval, cache, stream, replay or artifact test. Any detected leakage blocks release regardless of aggregate metrics.
- A tenant can account for every model attempt and distinguish confirmed provider charges from estimates or unknown charges.
- Integration failures are recoverable through product APIs rather than manual database updates.
- Target SLOs in SRE.md hold under the documented capacity envelope; external provider failures are shown separately from internal gateway reliability.

## 6. Product limits

Default upload limit is 20 MiB per file, 100 files per onboarding case and a per-tenant storage quota. Supported v1 formats: PDF without encrypted content, UTF-8 text and DOCX, processed in a sandbox. Large scanned-document OCR is an explicitly metered async capability, not an unbounded upload side effect.

Default model context is 32k tokens, output reservation up to 2k tokens and one selected provider attempt plus at most one pre-stream fallback. Default job runtime is 5 minutes; longer work must declare checkpoints and a separate profile. Search queries are limited to 2 KiB/20 lexical terms and top 100 combined results. Custom limits are bounded by platform capacity configuration.

Roles: tenant-admin, coordinator, requester, approver, integration-manager and auditor. Approval policy supports amount thresholds and separation of duties; policy changes affect new cases unless an authorized migration explicitly updates existing cases. Support access is time-bound, customer-visible where contractually required and audited.

## 7. Acceptance scenarios

The reference demo includes two tenants with overlapping document titles, a supplier with missing evidence, a human approval close to its deadline, a repeated order command, an order event gap, an AI provider failure before streaming, a slow dashboard client and a webhook receiver outage. Demonstrate correct isolation, explicit error states and recoverable progress in each scenario.

## 8. Deferred choices requiring customer input

Residency region, document retention/legal hold, identity provider, model-provider terms and approval-policy defaults are deployment configuration decisions. Unsupported residency or compliance claims must not appear in product language. Self-hosting is supported by a local/reference deployment profile; production support commits only to the qualified infrastructure matrix.
