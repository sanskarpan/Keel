# Versioned Keel feature catalog

Committed design scope is 1.0–2.0, subject to phase gates. 3.0 is a discovery horizon. Every entry is planned, not implemented. Core correctness remains governed by SPEC.md; expanded behavior by PRODUCT-SPEC.md and shared SAAS-FOUNDATION.md. Version dependencies and gates are in ROADMAP.md; delivery tasks map to K0–K11.

| ID | Version | Feature / end-to-end result | Minimum acceptance / dependency |
|---|---|---|---|
| K-F01 | 1.0 | Organization signup, trial, region and guided setup | Resumable setup; sample/real data separate; no duplicate org on retry; K8 |
| K-F02 | 1.0 | Invites, memberships, roles, service principals and org switching | Revocation and hostile switch tests; no ownerless org; K0/K8 |
| K-F03 | 1.0 | Plans, hosted checkout, subscriptions, invoices and entitlements | Reordered billing events cannot upgrade another org; grace/downgrade tests; K8 |
| K-F04 | 1.0 | Accessible responsive console, global navigation and personal work queue | Core requester/admin/supplier tasks pass keyboard and narrow-screen tests; K8 |
| K-F05 | 1.0 | Guided category intake with conditional fields and saved drafts | Versioned form snapshot; obsolete draft migrations explicit; K1/K8 |
| K-F06 | 1.0 | Supplier master and reviewed duplicate detection | Tenant/entity-scoped matching; audited merge preserves aliases/history; K2/K8 |
| K-F07 | 1.0 | Persistent supplier portal, invitations and evidence checklist | Supplier cannot enumerate internal records or other buyer orgs; invitation expiry/resume; K2/K8 |
| K-F08 | 1.0 | Scanned documents, extraction, classification and evidence versions | Malware/oversize quarantine; human-confirmed extracted fields; K2/K3 |
| K-F09 | 1.0 | Approval inbox, serial/parallel rules, delegation and reminders | Every required step satisfied by current eligible actors; evidence changes supersede decisions; K2/K8 |
| K-F10 | 1.0 | Procurement budgets and commitment reservations | Concurrent approvals cannot exceed hard cap without separately authorized override; K8 |
| K-F11 | 1.0 | Immutable order history and evidence timeline | Explain exact policy/evidence/actor at decision; reconstruct from events; K1/K5 |
| K-F12 | 1.0 | Tenant-safe hybrid policy/contract search with citations | Current visibility and qualified recall; version not guessed by AI; K3 |
| K-F13 | 1.0 | AI request drafting and evidence-backed explanations | Generated fields remain uncommitted drafts until user command; quality/cost gates; K4 |
| K-F14 | 1.0 | Personal notifications, mentions, comments and shared supplier threads | No internal-thread or recipient-visibility leakage; delivery outage does not stall decisions; K8 |
| K-F15 | 1.0 | Integration hub, signed webhooks and failure/replay console | Auth health, cursor/watermark, audited retry and secret rotation; K6 |
| K-F16 | 1.0 | AI/storage/workflow usage and budget dashboard | Confirmed/estimated/unknown costs separate; no subscription/procurement confusion; K4/K5/K8 |
| K-F17 | 1.0 | Bounded CSV onboarding, exports and privacy/offboarding | Dry-run and per-row errors; safe spreadsheet export; erasure/hold and restore tests; K8 |
| K-F18 | 1.0 | Support, audit log, status/incident communications and help | Time-limited support access; current task/help links; sanitized external status; K7/K8 |
| K-F19 | 1.5 | Approved supplier/item catalogs and repeat-buy templates | Versioned price/terms; expiry or supplier suspension blocks new buy; K9 |
| K-F20 | 1.5 | RFQ/RFP requests, supplier responses and human award | Supplier isolation; immutable deadline/criteria; audited late-response handling; K9 |
| K-F21 | 1.5 | PO issuance, supplier acknowledgment and change orders | Approved authority required; change delta reapproved; no duplicate issue on retry; K9 |
| K-F22 | 1.5 | Partial goods receipts, service milestones and returns | Bounded line quantities, actor/evidence and reversal ledger; K9 |
| K-F23 | 1.5 | Invoice capture, two/three-way matching and exception workbench | Duplicate detection, tolerances and override audit; no payment execution; K9 |
| K-F24 | 1.5 | Contract repository, obligations and renewal notice calendar | Confirmed extracted dates; durable reminders and cancellation notice tasks; K9 |
| K-F25 | 1.5 | Accounting/ERP connector with reconciliation and master-data mapping | One sandbox-qualified adapter; ownership/conflict rules; no duplicate actual spend; K6/K9 |
| K-F26 | 1.5 | Spend, cycle-time and bottleneck analytics with scheduled reports | Currencies/timezone/watermark explicit; authorized export; K9 |
| K-F27 | 1.5 | Slack/Teams notices and scoped interactive intake | Signed requests and mapped identity; sensitive approval stays authenticated; K9 |
| K-F28 | 2.0 | Enterprise SSO, SCIM, group grants and recovery | Real IdP lifecycle, disable/re-enable ordering and break-glass drill; K10 |
| K-F29 | 2.0 | Legal entities, business units, project scopes and multi-currency policy | Scope-negative tests; FX provenance; org RLS alone insufficient; K10 |
| K-F30 | 2.0 | Versioned policy builder, simulation and publication approvals | Historical what-if read-only; no cyclic routes or missing reviewers; K10 |
| K-F31 | 2.0 | Risk assessments, questionnaires, findings and accountable risk acceptance | Published rubric/evidence; reevaluation on material change; no AI final score authority; K10 |
| K-F32 | 2.0 | Evidence expiry, recurring reassessment and supplier suspension | Durable schedules; pending requests recheck eligibility; existing PO impact reviewed; K10 |
| K-F33 | 2.0 | SIEM/audit export, legal hold and configurable retention | Export authorization; erasure/hold conflicts disclosed; K10 |
| K-F34 | 2.0 | Qualified regional/dedicated tenancy and administrative keys | Actual IAM/restore/residency evidence; no silent region migration; K10 |
| K-F35 | 2.0 | Scoped public API/SDK, migration tooling and connector administration | Permission/version/rate contracts; replay cannot grant broader rights; K10 |
| K-F36 | 3.0 | Renewal/negotiation decision briefs with cited alternatives | Licensed/authorized data and user decision; recommendation benchmark; K11 |
| K-F37 | 3.0 | Supplier performance scorecards and corrective-action plans | Transparent source/freshness; dispute/correction path; no unqualified global risk feed; K11 |
| K-F38 | 3.0 | E-signature integration and multilingual retrieval/interfaces | Qualified provider event proof; evaluated analyzer/model per language; K11 |
| K-F39 | 3.0 | Scenario sandbox for policies, supplier outages and purchasing plans | Synthetic/anonymized qualified data; no live webhooks/financial effects; K11 |
| K-F40 | 3.0 | Cross-team opportunity insights for duplicate purchases/unused commitments | Same-tenant scope and provenance; savings estimates not cash realization; K11 |

No feature is completed by having its menu item exist. Acceptance includes authorization, resource bounds, progress/failure states, operator recovery, observability and customer lifecycle. All external supplier and internal-user journeys must remain usable under plan restriction where needed for safe closure.
