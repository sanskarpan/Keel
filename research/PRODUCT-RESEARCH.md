# Comparable-product research and product decisions

Research date: 4 October 2026. Method: retrieve official product pages and documentation, inspect their visible text, compare recurring customer journeys, and derive requirements for these two products. This is desk research; there were no product trials, interviews, private roadmap access or independent performance measurements. Vendor outcomes and savings claims are not adopted as our results. [Retrieval evidence](PRODUCT-RESEARCH-EVIDENCE.json) records successful URLs, redirects, extraction hashes and unsuccessful requests.

## 1. Procurement and supplier lifecycle

| Reference and observed positioning | Relevant visible capability | Decision for Keel |
|---|---|---|
| [Zip intake-to-procure](https://zip.com/products/intake-to-procure) | Guided intake, cross-functional routing, preferred suppliers and centralized activity | Give requesters one front door; make request forms and policy simulation product features, not backend configuration alone |
| [Zip supplier onboarding](https://zip.com/products/supplier-onboarding) | Guided supplier portal, assessment, centralized evidence and ERP supplier creation | Persistent supplier profile and supplier-specific portal; duplicate review and explicit ERP synchronization states |
| [Zip budgets](https://zip.com/products/budgets) | Budget/project views in approvals; alerts and ERP actuals | Add real procurement commitment accounting, distinct from AI-cost budgets; do not double-count a PO and its invoice |
| [Procurify platform](https://www.procurify.com/platform/) | Intake-to-approve, purchase-to-receive, invoice-to-pay and ERP connections | Close Keel's workflow through dispatch, receipt and invoice exception/accounting handoff in 1.5; payment execution stays with ERP/provider |
| [Precoro supplier management](https://precoro.com/solutions/supplier-management) | Portal for documents, catalogs, proposals, POs and invoices; common supplier view | One supplier workspace with deliberately separate internal/external threads and scoped business-unit access |
| [Precoro purchase orders](https://precoro.com/to/purchase-order-software) | Request-to-PO conversion, multilevel routing, catalogs, matching and supplier communication | Versioned PO changes, partial receipt and matching tolerance rules; avoid adding a full inventory warehouse product |
| [Ramp procurement](https://ramp.com/procurement) | Plain-language intake, cross-functional checks, renewals, PO budget tracking and matching | Human-confirmed draft assistance, renewal decision packs and exception inbox; no claim that model confidence authorizes purchasing |
| [Ironclad CLM](https://ironcladapp.com/product/ai-based-contract-management) | Contract repository, routing, collaboration, insights, drafting/review | Build metadata, citations, obligations and renewal scheduling; integrate e-signature later instead of building a full legal redlining/signing engine |
| [Vanta third-party risk](https://www.vanta.com/products/third-party-risk-management) | Questionnaires, evidence extraction, risk rubrics, remediation and monitoring | Explainable risk findings, reviewed risk register, reassessment and expiry; AI drafts findings, qualified humans own risk acceptance |

Short source excerpts used to anchor interpretation: Zip describes an intake path that can “route them for approval automatically”; Precoro describes vendors able to “receive RFPs and purchase orders”; Procurify labels one workflow “Purchase-to-Receive.” These establish product scope patterns; they do not establish the correctness, exact tier availability or quality of those competitors.

The category expectation is a continuous purchasing workflow. The earlier architecture already supported strong technical foundations but did not completely specify request discovery, day-to-day buyer/supplier collaboration, commercial SaaS lifecycle, post-approval fulfillment or contract renewals. The expansion makes those first-class product areas.

Keel's proposed focus is evidence-backed buying for smaller procurement/security teams: every significant decision links to the exact supplier evidence, policy, approver and resulting commitment. The differentiated bet is an **evidence timeline plus policy-change simulator**, not a large list of generic agents. Competitor evidence does not prove this is unique or customers will pay; discovery tests must validate that bet.

## 2. Developer platform and reliability lifecycle

| Reference | Observed visible capability | Decision for Ghostlight |
|---|---|---|
| [Bunnyshell ephemeral environments](https://www.bunnyshell.com/ephemeral-environments/) | Full-stack PR environments, shareable QA URLs, self-service templates, sleep/wake scheduling | Add reviewer workspaces, controlled sharing, schedule-aware suspension and template onboarding; preserve truthful residual-cost reporting |
| [Qovery ephemeral environments](https://www.qovery.com/solutions/ephemeral-environments) | Per-PR apps/dependencies, blueprint cloning, fixture/snapshot seeding, TTL and budgets | Versioned synthetic fixture packs and topology-aware templates; prohibit importing raw production snapshots despite competitor support |
| [Qovery platform](https://www.qovery.com/) | BYOC, policy tokens, approvals/quotas and reusable templates | Hosted preview first, qualified customer-account connector in enterprise; scoped command API/CLI without raw cloud credentials |
| [env zero](https://www.envzero.com/) | Reusable templates, RBAC, approvals, cost controls, drift and discovered-resource ownership | Policy simulator, native inventory drift, change approval and safe reconciliation; do not automatically remediate unknown destructive drift |
| [Port documentation](https://docs.port.io/) | Catalog entities, self-service actions, workflows, approvals and scorecards | Model projects/services/owners as a product catalog with approved actions and visible policy checks |
| [Harness IDP](https://www.harness.io/products/internal-developer-portal) | Catalog, golden paths, workflow orchestration and scorecards | Repository installation wizard and reusable golden paths; service ownership and evidence coverage matter more than dashboard decoration |
| [Gremlin reliability management](https://www.gremlin.com/product/reliability-management) and [score explanation](https://www.gremlin.com/blog/how-gremlins-reliability-score-works) | Dependency tests, detected risks, suite-based scoring and recovery exercises | Reliability coverage by service/dependency with freshness and confidence, scheduled game days and remediation tracking |

Source anchors: Bunnyshell explicitly names “Auto-sleep schedules”; Qovery lists “Cost caps & TTL”; Harness describes “Self-service golden paths”; Gremlin bases its score on suites of tests. Ghostlight must define its own score methodology rather than claiming a green summary proves production reliability.

The category expectation is an operational product for platform teams and reviewers, not just a PR webhook that starts Terraform. The missing product depth was organization onboarding, catalog management, project permissions, review feedback, self-service control, scheduled operation, repeatable fixtures, governance and longitudinal evidence.

Ghostlight's differentiated bet is an **independent release evidence passport**: the precise candidate, dependency/policy versions, measured invariants, failure recovery, cost and cleanup. Add reproducible failure recipes and comparable-run diffs. It remains useful as a standalone product for reviewed workloads; Keel is its first reference customer, not a mandatory dependency for every customer.

## 3. SaaS administration sources

[Stripe subscription webhooks](https://docs.stripe.com/billing/subscriptions/webhooks) establish that subscription activity and payment failures are asynchronous; durable event ingestion and reconciliation must drive entitlements, not the browser checkout redirect. This reference does not select Stripe commercially or imply country/currency availability has been qualified.

[WorkOS Directory Sync](https://workos.com/docs/directory-sync) describes organization directory provisioning and deprovisioning. Identity offboarding, directory mapping, inactive-user handling and ordering/reconciliation need explicit acceptance cases. WorkOS is a candidate abstraction, not a mandated vendor. Direct SCIM/OIDC alternatives can satisfy the same contracts.

## 4. Adopt, differentiate, defer

Adopt category necessities: onboarding, RBAC, subscriptions, usable notifications, integration health, import/export, accessible consoles, auditable collaboration and support. These are 1.0 paid-launch gates, not optional features after the learning topics.

Differentiate Keel with immutable evidence provenance, understandable policy decisions, safe simulations and an exception-first workbench. Differentiate Ghostlight with independently signed evidence, honest fault/coverage reporting, bounded spend and verified cleanup. Each bet has a measurable user test in PRODUCT-STRATEGY.md.

Defer Keel payment rails, general-purpose legal CLM, warehouse inventory, autonomous approval and externally sourced universal supplier risk scores. Defer Ghostlight arbitrary cloud-admin workflows, production chaos by default, unreviewed template marketplaces and automatic production remediation. Later versions broaden workflow coverage through bounded capabilities without weakening trust boundaries.

## 5. Uncertainty and further discovery

- Public pages can change, market claims can be optimistic, and feature availability can differ by contract/tier. Do not turn this matrix into a competitor sales claim.
- Several guessed URLs returned 404/503 or a soft “Page Not Found”; replace them with verified official pages. Uffizzi was unavailable and is not evidence for a capability claim here. Port is referenced from its accessible documentation index, not the failed action path. Old env0 and ziphq domains redirected; the matrix uses final domains.
- Product discovery next: 6–10 procurement operators and 6–10 platform/reviewer users, then at least three design partners per product. Those are proposed research sample sizes, not completed interviews.
- Validate willingness to pay, actual process exceptions, customer infrastructure and migration burden. Product releases have evidence gates rather than fabricated delivery dates.
- Add an implementation research gate for billing country/tax/currency, IdP/SCIM behavior, connector APIs/limits, delivery costs, preview suspension compatibility and dataset provenance. Public product comparisons alone cannot resolve those choices.
