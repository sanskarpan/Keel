# Keel versions, dependencies and release gates

The 15 topics are a floor. K0–K7 deliver the technical foundations; K8–K10 turn them into a complete SaaS and purchasing product; K11 explores later differentiated capabilities. K8 begins alongside K0/K1 rather than waiting until technical qualification finishes. No calendar date or team-size estimate is presented as a commitment.

## 0.1 — Controlled pilot

Scope: K0/K1/K2 foundations and onboarding/order journey; bounded K3/K4 retrieval/AI; K8 organization/membership/setup basics and supplier context. Real customer data requires approved retention/provider terms and isolation evidence. Pilot can remain synthetic if those are unresolved.

Gate: two-tenant and external-supplier isolation, duplicate-command/event correctness, durable approvals, basic unknown-cost accounting, bounded upload and real-dependency restore smoke. Demonstrate one administrator/requester/approver/supplier journey. Publish support limitations and restrict admission to supported use cases. This is not a paid generally available service.

## 1.0 — Complete intake and approval SaaS

Scope: K-F01–K-F18; K0–K8 technical/product delivery including serial/parallel approval, procurement commitment budgets, supplier portal, collaboration, commercial lifecycle and customer recovery. Procurement v1 ends at approved orders; fulfillment features are the next deliberate product release.

Critical path: supplier/role isolation -> authoritative order/evidence model -> approval packets -> procurement reservations -> customer console -> safe AI -> integrations -> paid entitlements/metering -> combined load/recovery/security/customer-journey evidence. Signup, billing and notifications start early with stub/sandbox providers; they cannot be bolted on after the release candidate.

Gate: all K0–K7 critical technical gates and K8 SaaS gates; member/role changes during pending approval; budget races; supplier portal leakage; checkout event reorder; dunning/cancel/downgrade; import/export; accessible primary journeys; invitation/email deliverability; support access and deletion/hold drills. Obtain design-partner evidence, measured cost envelope and pricing decision before accepting live paid subscriptions. No “GA” badge from unchecked tasks.

## 1.5 — Purchasing execution and contract lifecycle

Scope: K-F19–K-F27, K9. Dependency order:

1. Catalog/sourcing and master-data mapping enrich intake without replacing prior records.
2. Versioned PO issuance and amendments extend approved authority; qualify reapproval/commitment delta logic.
3. Receipts/service milestones enable matching.
4. Invoice review/exception aggregates and one ERP connector reconcile actuals against commitments.
5. Contract obligations/renewals, spend/cycle analytics and qualified chat channels complete routine customer work.

Gate: one full request->approved PO->supplier acknowledgment->partial receipt->invoice exception->corrected accounting handoff journey; quantity/currency/tolerance invariants; supplier response isolation; material amendment races; no duplicate spend; renewal timezone/notice cases; callback unknown outcome recovery. Re-run capacity with these new workload components before preserving the 1.0 envelope. Payments/GL postings remain outside Keel.

## 2.0 — Governed enterprise deployment

Scope: K-F28–K-F35, K10. Enterprise identity, scoped legal entities/projects, policy builder/simulation, explainable risk governance, reassessment, SIEM/legal hold, public integration tooling and qualified dedicated/regional tenancy.

Gate: actual SSO/SCIM offboarding and break-glass; business-unit and row/document-field scope tests; multi-currency conversion provenance; simulation correctness/limits; no policy cycle/unresolvable role; risk acceptance expiry; native residency/key/restore evidence; deployment support/contract ownership. Dedicated infrastructure capacity and price have their own measured profile; the initial shared PostgreSQL envelope is not automatically an enterprise claim.

## 3.0 — Discovery backlog

Scope: K-F36–K-F40, K11. Interview and prototype negotiation insights, supplier performance, e-signature/multilingual interfaces, policy/scenario sandbox and purchasing opportunity recommendations. Prioritize at most one or two validated bets per release. “All” here is a considered roadmap, not a promise to build every idea regardless of demand.

Go/no-go criteria: identifiable user, repeated pain, authorized data availability, acceptable legal/provider terms, measurable improvement and bounded operating cost. Recommendation-only mode first. Signatures/languages get independent contract/quality tests; an AI insight cannot become a purchasing command by changing a feature flag.

## Rollout and scope safety

New capabilities use per-org entitlement and server-owned release flags; a flag cannot disable core authorization/accounting. Migrate additively, backfill boundedly and run domain shadow comparisons before enabling new financial projections. Historical approvals, evidence, event schemas and workflow policy versions remain interpretable. Canary with design partners, then gradually expand after cost/error/support evidence. Downgrade/cancellation behavior ships with the feature, not afterward.

For each release capture build/config/schema/policy/entitlement versions, tests, load profile, support/trust/UX evidence and unresolved qualification items. Owners: product/domain, search/AI, SaaS platform, integrations, security and SRE; actual people assigned at implementation. Release criteria scale with feature risk; a high-risk financial/permission change cannot be treated as a UI-only release.
