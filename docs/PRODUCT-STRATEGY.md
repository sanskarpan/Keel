# Keel as a SaaS product

## 1. Product promise and customer

Keel helps a growing organization buy from the right supplier, with the right evidence, approvals and budget, while keeping the whole decision auditable. A requester gets a clear next step; procurement/security get a prioritized exception queue; suppliers get a usable collaboration portal; finance sees commitments and accounting handoff. The 15-topic portfolio is a technical minimum. Product planning continues through multiple commercial releases.

Initial customer hypothesis: organizations with 50–500 employees, a small procurement/finance function, recurring software/services purchases and supplier/security evidence spread across email, spreadsheets and storage. These segment limits are discovery hypotheses, not enforced tenant limits. Buyer: finance/procurement lead. Champions: procurement coordinator and security reviewer. Daily participants: employee requesters, approvers, supplier contacts and auditors.

Keel is independently useful and saleable without Ghostlight; Ghostlight supplies the delivery/reliability evidence for its engineering team. Product branding, customer organizations and subscriptions remain separate.

## 2. Jobs and value chain

| User job | Product outcome | Measure |
|---|---|---|
| Request a purchase without knowing every policy | Guided intake recommends approved suppliers/contracts and shows missing evidence | Time to valid submission; abandonment and resubmission rate |
| Decide whether a supplier is acceptable | Evidence checklist, risk findings, specialist tasks and explicit accountable acceptance | Time to eligible supplier; reopened reviews; overdue evidence |
| Approve with confidence | Exact request/evidence/policy/budget packet and understandable decision history | Review time and decisions reversed for missing context |
| Keep delivery and commitments visible | Versioned PO dispatch, acknowledgment, partial receipts and invoice exceptions | Unacknowledged POs; unresolved matching exceptions |
| Avoid a missed renewal or hidden commitment | Contract obligations, notice deadlines and renewal decision tasks | Notice deadlines met; stale renewal decisions |
| Operate without spreadsheet recovery | Integration health, retries, audit/export and accountable reconciliation | Manual DB interventions; unresolved integration age |

## 3. Differentiated bets

**Evidence timeline:** a purchase page connects supplier eligibility, immutable source versions, policy, budget reservation, approvals, PO changes and accounting references. Readers can explain the decision as it was made and see what has since changed. This is more useful than a chat answer detached from business state.

**Policy rehearsal:** before publishing approval/risk rules, run bounded historical scenarios with outcomes, added reviewers and expected bottlenecks. Simulation cannot mutate orders or rewrite prior approvals. Show data completeness and unresolved role mappings. Validate whether operators understand the output and catch a deliberately dangerous rule before publishing.

**Exception workbench:** group the work needing humans—missing supplier evidence, budget conflicts, stalled approvals, delivery issues, invoice discrepancies and renewal notices—with owners, deadlines and reasons. AI may draft a contextual decision brief with citations; humans own every risk acceptance, budget override and purchasing command.

These are hypotheses inspired by [comparable products](../research/PRODUCT-RESEARCH.md), not claims of market uniqueness. Ship a coherent workflow before investing in agent novelty.

## 4. Versions and commercial shape

| Version | Customer promise | Commercial readiness |
|---|---|---|
| 0.1 private pilot | Supplier-to-approved-order journey with two-tenant isolation, evidence and safe AI | Synthetic demo plus controlled design-partner onboarding; no public SLA |
| 1.0 paid launch | Complete intake/onboarding/approval SaaS with procurement budgets, supplier portal, collaboration, billing, support and portability | One Team plan is sufficient; pricing and limits validated; launch safety/recovery gates pass |
| 1.5 purchasing lifecycle | Sourcing/catalogs, issued PO changes, receiving, invoice exception review, contracts/renewals and one qualified accounting adapter | Add-ons only after economics and workflow value measured |
| 2.0 enterprise | Business-unit/legal-entity governance, SSO/SCIM, advanced approval rules, risk governance and qualified residency/dedicated deployment | Contracted support/SLA only after evidence; no implied compliance certification |
| 3.0 discovery horizon | Negotiation briefs, richer supplier performance, multilingual retrieval, qualified e-signature and sandbox scenarios | Separate experiments and go/no-go gates; not committed launch features |

Starter proposes smaller internal-seat/storage/AI allowance; Team adds higher workflow/connector capacity; Enterprise adds administration and qualified deployment options. Supplier contacts remain free collaboration participants by default. Price dollars, tax jurisdictions and trial eligibility need discovery. Every plan includes isolation, safe approvals, export/privacy controls and operational recovery. Product unit economics separate SaaS price, procurement value, external AI charges and storage/notification/connector cost.

## 5. Activation, retention and discovery

Activation event: an administrator configures one policy and invites another internal participant, one supplier submits evidence, and an authorized human completes an evidence-backed request decision. A separate sample-mode activation uses synthetic data; do not count it as customer production usage. A target of <=60 minutes administrator hands-on setup is tested excluding time waiting for real supplier responses.

North-star candidate: weekly evidence-backed purchase decisions completed by customer organizations. Guardrails: tenant leakage zero tolerance; budget/approval invariant failures zero tolerance; user-reported wrong evidence; approval reopening; backlog age; active customer teams; cost per successful workflow and retention. Do not reward artificially split requests or automated sample decisions. Track p50/p90 actual cycle times against each design partner's baseline rather than copying vendor “faster approval” claims.

Discovery: interview finance/procurement/security participants, map their real exceptions, test a request/approval prototype and run three design-partner pilots. Test evidence timeline comprehension, draft AI acceptance without authority confusion, import effort, supplier invitation completion and willingness to pay. A successful usability gate requires at least four of five representative participants to complete each core task without operator intervention; accessibility defects can still block launch. Small tests inform design, not statistical ROI claims.

## 6. Product boundaries and expansion rules

Keel 1.0 concludes purchasing authority at approved/rejected/canceled orders. In 1.5, an approved order remains immutable authority while separate PO, receipt and invoice-review aggregates extend execution. Customer payment movement, tax posting, general ledger and warehouse inventory remain external systems. Keel's own SaaS subscription billing is a separate administrative module.

AI reads authorized information and proposes drafts; it cannot approve, issue a PO, alter budgets, accept risk or send supplier/business integration commands on its own. Human-confirmed drafts enter normal authenticated command paths. A connector is supported only when source-of-truth, callback signatures, idempotency, reconciliation and customer recovery are specified. Add a feature only with a user journey, ownership, limits and release evidence.
