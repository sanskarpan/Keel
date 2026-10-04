# Keel journeys, screens and failure states

These are product experience specifications, not rendered UI designs or completed usability tests. Every journey uses current server authorization and the shared SaaS foundation. Product labels distinguish requested/approved/committed/received/accounting actuals and estimated/confirmed AI charges.

## 1. Administrator: signup to first useful workflow — 1.0

Entry: public product/pricing/docs, then verified identity, organization/region/terms and trial. The setup workspace guides members, one purchase category/form, one approval route, procurement budget, supplier evidence checklist, provider/privacy policy and optional webhook. Safe defaults use a sample supplier and stubbed AI until production credentials/consent are configured. Import is optional; a customer can start with one manual supplier.

Screens: organization overview, setup checklist, members/roles, settings, category/form builder, approval policy preview, budget setup and integration health. Setup progress persists with validated configuration revisions. A second administrator can continue without overwriting newer changes. Changing region after customer content exists starts an explicit migration review, not an instant dropdown switch.

Success: invite another participant, complete one supplier review, submit/decide one real request, then optionally activate a paid plan. Provider/card setup failure exposes safe operation status and manual recovery. Never claim onboarding is complete because a checkout redirect was visited. A plan restriction offers billing repair/export and safe existing-work closure.

## 2. Supplier: invited collaboration — 1.0

Entry: purpose-scoped expiring invitation. Supplier establishes/reuses a verified identity, explicitly selects the buyer collaboration context, sees company/contact data and evidence tasks, uploads documents and submits a frozen packet. A persistent portal can show multiple buyer contexts only after separate invitations; a context never shares evidence with another buyer automatically.

Screens: buyer-branded portal home, checklist with why each file is requested, upload progress/quarantine errors, external-only questions, submission receipt and requested revisions. Supplier sees its own published PO/invoice interactions in 1.5. Internal risk comments, other suppliers and employee search are inaccessible; even hidden-record counts are suppressed.

Failure: expired/revoked invitation offers a reissue request without disclosing internal case status; interrupted upload resumes under a current grant; malware/type/size failure explains remediation; rejected packet shows permitted reasons and next steps. Evidence replacement creates a new version and approval packet; it cannot overwrite a version an approver relied on. Notifications link to authenticated tasks.

## 3. Requester: need to decision — 1.0

Entry: personal home, “Request a purchase,” category templates, preferred supplier search and policy snippets. Draft captures legal/business unit, project/cost center, supplier, line items, currency, estimated amount, need-by date and evidence. Plain-language/quote assistance proposes fields; user confirms each material value and submission. Suggested supplier/contract is reauthorized and rechecked on submit.

Screens: category intake, saved draft, guided evidence, budget impact, review-before-submit and request timeline. Before submit show required reviewers, budget warning and missing prerequisites. A stale form/policy change presents a migration/diff, preserving the draft without silently interpreting fields under another policy.

Success: durable request ID and status URL; timeline shows current tasks, estimates and actual state. Repeated click/network retry uses the same idempotency key. Budget race yields a specific conflict and next action, not lost draft. Search/index/provider failure can permit manual submission when policy allows; approval/evidence checks remain mandatory. Amend/cancel actions explicitly disclose budget/reapproval impact.

## 4. Approver/security: evidence to accountable decision — 1.0/2.0

Entry: personal inbox or authenticated notification. Approval page shows request summary, exact supplier evidence, risk findings, relevant policy clauses, current procurement budget/reservation, conflicts and remaining steps. Evidence timeline distinguishes historical snapshot from current withdrawn/changed evidence. AI brief cites the packet and clearly marks uncertainty.

Screens: inbox filters by due date/role, decision packet, external/internal discussion panes, delegated assignment and approve/reject/request-revision dialog. Users cannot approve their own request or inherit authority by being mentioned. Delegation requires scope/interval, cannot broaden role/currency/amount limits and is visible in audit.

Failure: policy/evidence revision invalidates the packet; show precise changed fields and require fresh decision. Deadline/role revocation races return authoritative outcome. Parallel route progress is visible without pretending one approval completes every required step. Enterprise risk acceptance requires a named owner, expiry and rationale. Policy simulator highlights missing reviewers/cycles before publication.

## 5. Buyer/finance: approved request to accounting handoff — 1.5

Entry: approved queue. Buyer converts approval authority into an issued PO, reviews legal entity/addresses/tax metadata/line terms and dispatches through portal/email or qualified adapter. Supplier acknowledgment is a separate event. A supplier's requested price/date change is a proposal; buyer submits an amendment and obtains needed reapproval.

Screens: PO workspace, delivery/acknowledgment history, line receipts/service milestones, invoice capture/matching, exception queue and ERP sync detail. Authorized receiving users record partial deliveries/returns with evidence. Invoice matching shows PO/receipt/invoice line comparisons and tolerance policy; a human resolves discrepancies. Keel prepares an accounting handoff but never marks a payment sent from local inference.

Failure: unknown outbound response observes/deduplicates remote PO identity before resending; a material amendment preserves the old issued version until the new one is approved; over-receipt/over-invoice is rejected or separately overridden; stale ERP actuals show a watermark. Finance can identify provisional commitments versus confirmed accounting actuals without double counting both.

## 6. Contract owner: signed agreement to renewal decision — 1.5/2.0

Contract repository holds immutable document references, responsible owner, effective/end dates, notice windows, value/currency and obligations. Extraction proposes metadata; an owner confirms dates and source text. Calendar shows notice deadlines, not just expiration. Renewal opens a new request/decision pack with actual spend and supplier eligibility; no auto-renewal command is inferred from an AI recommendation.

Failure: unknown or conflicting dates are explicit tasks; timezone/date-only semantics are fixed per legal entity; missing owner escalates to an authorized group; provider/e-signature status is unverified until qualified signed events or reconciliation. Policy/risk changes create reassessment tasks and do not rewrite past contracts.

## 7. Operator/admin: maintain, migrate and leave — all versions

Admin navigation includes integration health, authorized audit/search, usage/billing, imports/exports, support access and privacy. Integration detail shows last sync, cursor lag, conflicts, credentials nearing expiry and safe replay. Bounded bulk jobs show per-row result and resumable operation IDs. Support receives only a time-bound grant for the named issue.

Offboarding shows subscription effective end, pending workflows/commitments, export preparation, revoked external credentials and deletion/legal-hold state. Closing an organization does not hide unpaid accounting obligations or delete evidence under hold. Product export includes a manifest and authorized attachment versions. Trial/demo data can be reset independently.

## 8. Console behavior and accessibility gates

Primary navigation: Home/Tasks, Requests/Orders, Suppliers, Search/Documents, Budgets, Integrations, Usage, Settings; 1.5 adds Sourcing, POs/Receiving, Invoices and Contracts. Permissions remove actions and explain restricted views; the backend still denies forbidden calls. Enterprise scopes filter both listings and summaries.

All main tables support bounded pagination, saved filters, stable sorting and accessible details; exports use async jobs rather than download of unlimited results. Live changes announce discreetly and preserve focus/unsaved drafts. Chart data has a table alternative; danger/risk is not color alone. Validate empty/loading/partial/expired/permission/offline states and narrow-screen requester/approver/supplier use. Success requires task completion evidence, not just screenshots of populated dashboards.
