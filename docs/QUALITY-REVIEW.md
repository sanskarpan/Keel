# Independent architecture review disposition

This document records corrections made after an independent cross-document audit of the design package. It is not evidence that any product control has been implemented or tested.

| Finding | Disposition | Durable contract / verification |
|---|---|---|
| V1 currencies could be mixed across an order, approval threshold and procurement budget. | Accepted. V1 rejects incompatible currencies before submission, approval or reservation; no implicit FX. | `PRODUCT-SPEC.md`, `SPEC.md`, `API.md`; `TESTING.md` requires no-side-effect mismatch tests. FX stays in the pinned 2.0 quote flow. |
| Seven-day API idempotency detail expiry could permit a delayed retry to re-create a financial operation. | Accepted. Compact, non-sensitive dedup tombstones persist through the consequential effect/audit lifetime; expired keys resolve to the original operation or stable conflict and never execute again. | `DATA-MODEL.md`, `SPEC.md`, `API.md`, `TESTING.md`; retry-after-expiry and changed-payload cases are release evidence. |
| Pilot research tasks were inconsistent with a deliberately restricted synthetic/stub profile. | Accepted. Q-01 is mandatory; other named questions may be closed or explicitly disabled/not applicable with evidence for the selected profile. | `CHECKLIST.md` K0.1; all pilot feature flags must match the selected profile. |
| Sign-in/session/recovery and legal/privacy readiness were described but not independently tracked as 1.0 launch tasks. | Accepted. Separate identity and jurisdiction-scoped privacy/legal tasks are required before live data. | `CHECKLIST.md` K8.11–K8.12 and `../shared/SAAS-FOUNDATION.md`. |
| Trial abuse signals needed clearer limits, minimization, retention and appeals. | Accepted. Use only proportionate documented signals, delete raw signals within 30 days absent a documented hold, and provide human review and reversible appeal. | `../shared/SAAS-FOUNDATION.md`. The 30-day period is a proposed product policy to qualify with counsel and customer commitments. |
| Measurement claims needed a reproducible review/sample protocol. | Accepted. Search evaluation specifies versioned strata and blinded adjudication; semantic cache requires at least 600 independently reviewed eligible pairs per policy and a one-sided 95% lower precision bound of at least 99.5%, with privacy/scope errors zero-tolerance. | `TESTING.md`; numbers are release qualification thresholds, not measured product results. |

The audit found no release-blocking unsupported market-research claims. Comparative-product observations are expressly limited to public materials and remain hypotheses pending customer research.
