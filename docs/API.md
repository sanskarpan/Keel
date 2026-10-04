# HTTP and streaming contract

The canonical initial HTTP shape is [`contracts/openapi/openapi.yaml`](../contracts/openapi/openapi.yaml), validated in CI. It covers health/version and the first order vertical slice; later supplier, SaaS, retrieval and AI routes remain design scope until their implementation issues ship. The OpenAPI contract is not a claim that those handlers exist. Examples specify shape, not real identifiers/secrets.

## 1. Common rules

Version prefix `/v1`. Authentication: Bearer OIDC access token or explicitly scoped integration API key. Tenant identity derives from validated membership/key; an optional tenant-selection header must be authorized before use. All data endpoints run tenant-scoped DB transactions. Public liveness contains no application data.

Mutations require `Idempotency-Key`; aggregate changes require `If-Match: "<version>"`. Cursor pagination defaults 25, max 100, opaque authenticated cursors scoped to tenant/filter/order. Responses include request ID, trace reference and authoritative operation/version IDs. Cache-Control is `private,no-store` for personal/order/context content.

Problem response: `{type,title,status,code,detail,request_id,retry_after_seconds}`. Stable codes distinguish `not_authorized`, `resource_not_found`, `version_conflict`, `idempotency_conflict`, `idempotency_record_expired`, `currency_mismatch`, `budget_exceeded`, `dependency_unavailable`, `resync_required`. Cross-tenant IDs return 404; unauthenticated callers get 401. Errors never include raw SQL, provider keys, document text or unredacted URLs.

## 2. Resource endpoints

| Method and path | Permission / behavior |
|---|---|
| `POST /v1/supplier-cases` | coordinator; 202 with case/workflow operation IDs |
| `GET /v1/supplier-cases/{id}` | case reader; state/deadline/evidence/approval summary |
| `POST /v1/supplier-cases/{id}/invitations` | coordinator; expiring purpose-scoped invitation |
| `POST /v1/supplier-cases/{id}/submit` | coordinator/invited supplier according to policy; freeze evidence digest, enter verifying, signal durable workflow |
| `POST /v1/supplier-cases/{id}/cancel` | coordinator/admin; durable cancellation intent |
| `POST /v1/documents/uploads` | authorized case/document writer; metadata and scoped presigned URL |
| `POST /v1/documents/uploads/{id}/complete` | owner of upload; verify size/hash/type/object version, enqueue scan; 202 |
| `GET /v1/documents/{id}/versions/{version}` | document reader; immutable cited version metadata |
| `POST /v1/search` | reader; query/mode/filters/top_k; references, ranks, degraded flag and index versions |
| `POST /v1/orders` | requester; draft order, external reference, supported currency/minor amount, positive decimal quantities; every line shares order currency |
| `POST /v1/orders/{id}/submit` | requester; expected version and evidence references |
| `POST /v1/orders/{id}/cancel` | permitted actor; nonterminal state only |
| `GET /v1/orders/{id}` | reader; command snapshot/version plus projection watermark |
| `GET /v1/orders/{id}/events` | auditor/authorized reader; paginated redacted event history |
| `POST /v1/approvals/{id}/decisions` | current approver; decision/reason/evidence digest; durable acknowledgement |
| `POST /v1/inferences` | reader + AI entitlement; operation/context/prompt refs and max output; 202 |
| `GET /v1/inferences/{id}` | inference owner/authorized reader; result and accounting state |
| `POST /v1/inferences/{id}/cancel` | owner/admin; best-effort external cancellation, costs still reconciled |
| `GET /v1/stream` | user; multiplex tenant-authorized state and selected inference tokens |
| `GET /v1/usage` | admin/billing reader; attributed confirmed/estimated/unknown totals and watermark |
| `GET /v1/usage/timeseries` | billing reader; bounded time range/grouping |
| `PUT /v1/budgets/{scope}` | tenant-admin; audited cap/threshold policy; optimistic version |
| `POST /v1/webhook-endpoints` | integration-manager; SSRF-safe registration, secret shown once |
| `POST /v1/webhook-endpoints/{id}/test` | integration-manager; signed synthetic delivery; capped |
| `GET /v1/webhook-deliveries` | integration-manager/auditor; filter state/event/endpoint/time |
| `POST /v1/webhook-deliveries/{id}/replay` | integration-manager; same logical event; audit + async operation |
| `POST /v1/reconciliation-runs` | integration-manager; adapter/cursor/dry-run; capped async run |
| `GET /v1/reconciliation-runs/{id}` | authorized operator; diffs and effect references |
| `POST /v1/integrations/{adapter}/callbacks` | verified provider signature; no browser token; durable inbox + 202 |
| `POST /v1/context-records/{id}/replay` | separately granted diagnostic role; sandbox/retention policy |
| `POST /v1/erasures` | authorized privacy-admin; legal-hold checks, deletion manifest operation |

Admin/operator APIs are separately routed, strongly authenticated and never accessed by ordinary model tools. Bulk replay/erasure have explicit maximum batch sizes and progress IDs.

## 3. Order and inference examples

```json
{
  "external_reference": "erp-po-2026-0182",
  "supplier_id": "<uuid>",
  "currency": "INR",
  "amount_minor": 250000,
  "line_items": [{"description": "Office equipment", "quantity": "2"}],
  "evidence": [{"document_id": "<uuid>", "version": 3}]
}
```

An inference references allowed operation `policy.explain`, prompt version, immutable context refs and output bound. The API computes model policy and tenant scope; clients cannot submit arbitrary tool manifests, privileged SQL or policy overrides.

Response to accepted async work is `{operation_id,status_url,stream_subscription,result_state:"queued"}`. Return a durable operation before the client attaches SSE; execution is not dependent on the connection staying open.

## 4. SSE messages

```text
event: state
id: state:<tenant-sequence>
data: {"kind":"order.updated","aggregate_id":"<uuid>","version":4,"request_id":"..."}

event: model.token
data: {"inference_id":"<uuid>","attempt":1,"sequence":18,"text":"..."}

event: model.completed
data: {"inference_id":"<uuid>","result_url":"...","usage_status":"confirmed"}
```

Token messages do not assign durable SSE event IDs. A durable state cursor survives mixed token messages. Clients deduplicate aggregate versions and token `(inference,attempt,sequence)`. Heartbeats are SSE comments. CORS/origin checks use an explicit allowlist. Authentication uses cookies with CSRF/origin protections or a fetch streaming client with Bearer header; tokens must not appear in query strings.

If replay retention is exceeded, emit `resync_required` and close. If provider content is interrupted, emit `model.interrupted` with result status and retry policy; a fresh generation requires a new logical request or an explicitly bounded recovery action. Slow consumers close without abandoning the durable job.

## 5. Rate, timeout and compatibility contracts

Search request deadline 2s, ordinary commands 3s, inference admission 2s, provider first-token timeout 10s, whole generation 90s default, webhook connect 3s/total 10s. Each timeout produces an explicit outcome; a timed-out API command may have committed, so retry the same key rather than create a new order.

Additive API fields are compatible; enums require unknown-value handling in clients. Breaking schema/actions move to a new API version. Never reassign an old event/operation meaning. HTTP status alone does not identify a business outcome; clients inspect the documented code and durable status URL.

## 6. SaaS and product API families

All families below inherit authorization, idempotency, version preconditions and bounded pagination. Organization creation uses authenticated bootstrap authority; after creation every request resolves current tenant membership or supplier grant. Entitlements are checked server-side for new work. Product version 1.5/2.0 is a release feature level, not a reason to change the compatible `/v1` HTTP prefix.

| Version / family | Typed actions and permission boundary |
|---|---|
| 1.0 `/v1/organizations`, `/members`, `/invitations`, `/service-principals` | Create/inspect organization; owner/admin member lifecycle; explicit scope and revocation; no client-supplied tenant authority |
| 1.0 `/v1/billing/checkout`, `/portal`, `/subscription`, `/entitlements`, `/meters` | Billing-admin hosted operations and scoped reads; processor redirect cannot activate entitlement |
| 1.0 `/v1/billing/provider-events` | Exact-byte provider signature/inbox; provider/account-to-tenant mapping, no user-token write path |
| 1.0 `/v1/intake-forms`, `/purchase-drafts` | Published schema versions, requester draft/save/submit; material field confirmation |
| 1.0 `/v1/suppliers`, `/supplier-merge-proposals` | Coordinator master-data review; audited canonical merge preserving aliases/history |
| 1.0 `/v1/supplier-portal/tasks`, `/submissions`, `/threads` | External principal scoped to tenant/supplier/resource; no internal search/order-list access |
| 1.0 `/v1/approval-plans`, `/delegations` | Authorized plan/step read and bounded delegate command; decision endpoint requires `step_id` and packet digest |
| 1.0 `/v1/procurement-budgets`, `/commitments`, `/budget-overrides` | Finance/budget-owner read, scoped account changes and separately authorized bounded override; distinct from AI budgets |
| 1.0 `/v1/threads/{id}/comments`, `/notifications`, `/notification-preferences` | Current resource/thread participants only; comment cannot approve |
| 1.0 `/v1/imports`, `/exports`, `/organization-closure` | Dry-run/commit/status; owner/privacy grants, checksum artifacts and legal-hold checks |
| 1.5 `/v1/catalogs`, `/sourcing-requests`, `/supplier-responses`, `/awards` | Buyer published versions, isolated supplier bid and human award; no approval bypass |
| 1.5 `/v1/purchase-orders`, `/{id}/issue`, `/{id}/amendments`, `/{id}/acknowledgments` | Buyer approved-authority/version checks; supplier acknowledgment for exact issued version; stable dispatch operation |
| 1.5 `/v1/receipts`, `/receipt-reversals`, `/invoices`, `/match-runs`, `/match-exceptions` | Receiver/finance scoped commands, line/currency tolerance and audited override; no customer payment endpoint |
| 1.5 `/v1/contracts`, `/obligations`, `/renewal-tasks`, `/connector-sync-runs` | Confirmed owner/date metadata, durable scheduling and integration-manager reconciliation |
| 2.0 `/v1/business-scopes`, `/policy-versions`, `/policy-simulations`, `/risk-assessments`, `/risk-acceptances` | Scope-aware admin/security permissions; read-only simulation; risk acceptance reason/owner/expiry |

An approval decision request names plan/step, packet digest, decision, reason and expected resource version. Response includes accepted decision, plan progress, authoritative order/case state and financial transition reference if final. Partial approval is not reported as an approved order. Budget conflict uses `procurement_budget_exceeded`, distinct from `ai_budget_exceeded` and `subscription_restricted`; denied suppliers receive non-enumerating errors. PO amendment/receipt/match APIs return durable operation/version and financial adjustment refs, not a misleading boolean “success.”

For financial commands, order lines, approval thresholds and the selected budget account must have the same ISO currency/minor-unit definition in v1; mismatch fails before acceptance/reservation with `currency_mismatch` and no side effect. FX is a 2.0 pinned-quote feature. Idempotency keeps response detail for seven days and a compact, non-sensitive deduplication tombstone through the consequential operation/audit lifetime; expired keys return the canonical operation or `idempotency_record_expired` and are never re-executed. Bulk imports default <=500 rows/commit batch and bounded job profile; export/simulation are asynchronous. SDK schemas cover decimal quantity encoding, ISO currency/minor units, timezone/date-only fields and unknown enums. Provider contracts are qualified independently. Before paid release OpenAPI includes every 1.0 family with permission/error fixtures; later families ship with migration/compatibility and negative-scope fixtures.
