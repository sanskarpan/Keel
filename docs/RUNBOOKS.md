# Operator runbooks

Procedures below define required administrative tooling. They are not claims that a CLI already exists. Every mutation runs through an authorized API/tool with audit; direct ad hoc production SQL is a break-glass action.

## KB-01: Outbox lag or broker outage

Inspect broker health, outbox oldest age/bytes, publish-head leases and disk forecast. Confirm accepted commands remain durable. Reduce nonessential admissions before reaching the buffer cap. Restore broker/credentials/network and let normal relay retry with original event IDs. Repair a stranded lease only after its worker is terminated/expiry confirmed; never mark rows published to clear a graph. Verify contiguous projection versions, deduplication and declining backlog. Exit when age is normal and no gap/conflicting digest remains.

## KB-02: Missing or duplicated order projection

Compare canonical order event versions/digests to applied projection watermark and inbox. Duplicates with identical IDs/digests are normal transport behavior. A digest mismatch is an incident: quarantine affected stream and preserve evidence. Run dry-run projection rebuild into an isolated table, compare state/hash, then authorized switch/repair. Suppress external effects during diagnostic replay. Exit when derived state matches authoritative history and delivery uniqueness remains unchanged.

## KB-03: Workflow stuck or approval near deadline

Inspect case deadline/evidence/policy, durable approval decisions and pending start/signal intents. Inspect Temporal history/activity retries and worker version/task queue. Never start a replacement workflow with a new ID simply because the UI looks stuck. Redeliver stable intent IDs; reload pre-deadline decision records before expiry. Quarantine conflicting evidence/policy and request a new approval. Exit when canonical case and workflow state agree with recorded decisions.

## KB-04: Provider failure or runaway spend

Disable affected provider/operation policy without deleting liabilities. Inspect per-attempt request IDs, quote/token bounds, reservations and confirmed/estimated/unknown usage. Stop new expensive admissions for the affected scope. Reconcile provider usage/invoice export before releasing uncertain reservations. Model retries after streamed content require explicit new bounded requests. Exit when spending is bounded and ledger/account totals reconcile; any unreconciled liability stays visible.

## KB-05: Suspected cache wrong answer or tenant leakage

Disable semantic cache globally or for affected scope; revoke/invalidate entries by context/policy version. Preserve redacted diagnostic IDs and access logs in restricted incident storage. Verify retrieval ACLs, session tenant binding, cache scope and document revocation timing. Do not copy customer prompts to ordinary tickets/logs. Tenant leakage blocks release/re-enablement until the root cause and negative suite pass. Rebuild eligible entries rather than manually rescope old ones.

## KB-06: Slow streams or token transport loss

Inspect per-client buffer usage, API RSS, Redis notification/token transport and write-timeout disconnect rates. Increase replicas within DB/global limiter budgets if qualification permits. Prefer disconnect/resync/coalescing to larger unbounded queues. Clients retrieve durable inference result after gaps. Exit when memory is bounded, recovery works and completed jobs do not depend on the browser staying connected.

## KB-07: Webhook failures and replay

Inspect endpoint health, verified DNS/IP/egress policy, response classifications, retry schedule and secret rotation. Run signed test-fire under rate limit after endpoint repair. Preview selected exhausted deliveries in dry-run; replay capped batches preserving event IDs. Verify receiver deduplication and reconciliation watermark. Never disable SSRF or signature checks to make a replay succeed. Exit when backlog drains without duplicate business effects.

## KB-08: Database failover/recovery

Stop write admission and confirm single-writer fencing. Establish the backup/recovery cut and restore point; preserve pre-failure external effect IDs. Verify schema checksums, event/inbox/idempotency data, budget reservations, role bindings, erasure journal and Temporal consistency. Run invariant probes and read-only smoke. Resume writes gradually, then projections, then external effects after reconciliation. Record actual RPO/RTO and unrecoverable/unknown effects.

## KB-09: Tenant erasure or legal hold

Verify privacy authority and hold status. Disable new context/index/cache publication for records being erased. Execute bounded deletion manifest across objects/all versions, chunks/embeddings, prompt contexts, reversible PII records and applicable external provider records. Preserve non-PII event facts/audit required by policy. Verify with independent lookup and storage-version probes; note backup ageing/restore-journal policy. Do not claim immediate deletion from already-retained backups.

## KB-10: Subscription, entitlement or meter discrepancy

Verify tenant/provider mapping and signature/inbox identity. Freeze new costly admissions if entitlement is uncertain; retain billing repair/export and safe workflow closure. Fetch current provider subscription/invoice state, replay deduplicated observations and reconcile meter sources. Never upgrade via a checkout redirect or edit old invoice ledger rows. Apply explicit adjustment/credit with provenance, notify billing owner using safe summary and record customer impact. Recheck grace/downgrade/period timing before removing restrictions.

## KB-11: Procurement budget, PO or accounting mismatch

Stop affected financial transitions and preserve pending authority/line/effect IDs. Compare immutable procurement ledger with counters, reservation/commitment/actual mappings and ERP source versions. Check whether an external export succeeded despite timeout before retry. Correct with reviewed reversal/adjustment; do not zero counters or reissue a PO. Verify approval packet, amendment delta, accepted receipt allocations and no duplicate invoice coverage. Resume only after reference invariants and tenant/entity permissions pass.

## KB-12: Supplier/member offboarding or missed renewal task

Verify actor/scope, revoke grants/sessions/invitations and personal keys, then inspect active approvals/delegations/supplier status. Reassign tasks through an audited command; do not impersonate a departed approver. Stop new supplier approvals/PO issuance when eligibility is withdrawn, and surface existing obligation impact. For a missed notice inspect confirmed date/timezone/source version, durable occurrence and delivery state; create an accountable recovery task and preserve the original missed history.
