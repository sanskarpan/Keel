# Operator runbooks

Procedures below define administrative tooling and operational controls. Every business mutation runs through an authorized API/tool with audit; the K0.6 migration CLI is the only normal schema-change path. Direct ad hoc production SQL is a break-glass action.

## KB-00: Verify and apply a Keel release

Download the release archive, SPDX SBOM and `SHA256SUMS` from the Keel GitHub Release. Verify file checksums with `sha256sum -c SHA256SUMS`, then run `gh attestation verify keel-vX.Y.Z-linux-amd64.tar.gz --repo sanskarpan/Keel`. Extract the binary and verify its subject-bound SBOM attestation with `gh attestation verify keel-linux-amd64 --repo sanskarpan/Keel --predicate-type https://spdx.dev/Document/v2.3`. Reject artifacts with missing/invalid checksum or attestation; attestations identify the producing workflow/source but do not prove the release is safe or production-qualified. See [`RELEASES.md`](RELEASES.md) for the full release contract.

Before first use, provision a dedicated login that may `SET ROLE keel_schema_owner`, but is not a superuser, database owner, app, worker or agent login. Configure `KEEL_MIGRATION_DATABASE_URL` in a one-shot migration job secret store. Run the tagged binary's `migrate` command before compatible runtime rollout; never pass this DSN to product-facing workers or the model. The session advisory lock serializes concurrent migration jobs. The command creates `keel_meta.schema_migrations` if absent, verifies every recorded filename and SHA-256 against the binary, then commits one migration and its ledger row atomically.

If a migration fails, stop rollout and preserve logs/checksums. Its transaction is rolled back and the advisory lock is released when the process exits or its DB session is terminated. Transaction-control statements are rejected before execution so a migration cannot commit outside runner ownership. Fix the cause and retry only after confirming the same immutable file is still correct. Once a migration is applied, do not edit it or delete/alter ledger rows; publish a new forward repair. Online/nontransactional DDL is not supported by this runner. Roll application code back only when its schema compatibility allows it; otherwise deploy a forward-compatible repair.

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

## KB-13: Blocked outbox stream repair

Alert on any `outbox_delivery.delivery_state='blocked'`, oldest blocked age, and aggregate head lag. First inspect the tenant-scoped diagnostic summary (aggregate/event/version, allowlisted error code and attempt count); diagnostics never return the event payload. Confirm the incident/change reference, identify the serializer or storage correction, and preserve relevant deployment and database evidence in the restricted incident system. A distinct operator identity must pass the repair authorization check. Submit the observed event ID, version, prior error code and attempt count as stale-state guards, plus an allowlisted reason and `INC-`, `CHG-` or `OPS-` reference.

The repair transaction locks the blocked delivery and verifies the current aggregate head, immutable event hashes and contiguous event replay, matches the safe envelope to the canonical event, confirms no earlier version is unpublished or later version already published, and records the actor/reason/evidence before setting only that delivery back to pending. It preserves the event ID, attempt count, last error classification and head version; no event, envelope or claim epoch is rewritten, and the relay still publishes strictly in order. Verify the audit row, then observe the normal relay retry and confirm the same event ID publishes before later versions. If validation fails or the request is stale, stop and escalate; never edit immutable rows, mark an event published, reset a head, or skip a version. Roll back an application deployment only if it remains compatible with the stored schema; correct storage damage through a reviewed forward recovery from verified backup evidence, then retry the guarded repair. Break-glass SQL requires incident approval, a second reviewer and post-action reconciliation.

## KB-14: Supplier case Temporal dispatch backlog or conflict

K2.3 is not runtime-mounted and has no customer traffic. Until an authenticated worker role, a hosted Temporal profile and an accountable on-call owner pass K0/K0.1, use only the pinned synthetic local profile. The intended low-cardinality alerts are: any dead dispatch row, oldest pending/leased intent beyond five minutes, expired lease count above zero for more than two poll intervals, and sustained Temporal delivery errors. Never label metrics with tenant, case, intent, supplier, or evidence identifiers; metric export and paging are not wired yet.

On a local/test failure, stop the dispatcher process while leaving immutable intents and dispatch state intact. Inspect the worker-scoped minimal dispatch row, then compare its case/version/type/hash with the immutable case event and the Temporal workflow's opaque tenant/case-derived ID and history. Confirm that an accepted Temporal signal's event hash/version matches the database before retrying. Transient failures retry with deterministic bounded backoff; expired leases are reclaimed with a higher epoch, and old workers must not acknowledge them. A dead earlier version intentionally blocks later versions. Preserve that block and escalate to K2.5's audited manual-review/repair path; no general-purpose requeue or SQL state reset is permitted in K2.3.

For code rollback, stop dispatch and keep migration `0010_supplier_workflow_dispatch` applied; never drop dispatch rows, immutable intents, or Temporal histories. The V1 workflow type/task queue and minimal signal contract are persisted compatibility surfaces. Roll forward with a versioned workflow and replay qualification if history semantics change. Resume only after the backlog is ordered, event identities reconcile with workflow state, alerting/ownership exists, and a restart/duplicate-signal test passes. These steps do not establish production recovery or an SLO.

## KB-15: Supplier approval deadline or reviewer dispute

K2.4's case/decision boundary remains unmounted and has no customer approvals or automatic expiry worker. For a local/test case, compare the current case version/hash to its immutable event chain, then compare policy version/digest, frozen plan/evidence digest, accepted decision IDs and minimal Temporal event identities. Do not place decision reasons, supplier evidence, actor identifiers or raw event payloads in metrics, general logs or tickets.

An approval is eligible only when the case lock is held, PostgreSQL acceptance time is strictly before the persisted deadline, the exact plan step's direct role grant or one active delegation exists, required prerequisite steps are approved, and the actor is neither creator nor submitter. Rejection is terminal. A completed pre-deadline plan remains approved if the workflow signal arrives late; partial decisions do not prevent expiry. Retry the same decision ID only with identical actor/action/reason; any difference is a conflict. New authorization applies to new decisions only; never rewrite accepted decisions after a role change.

Expiry uses the same case-row lock and is idempotent after any terminal state. A decision/expiry conflict must be resolved from the committed database acceptance timestamp and event chain; do not infer the winner from Temporal arrival time. Missing or contradictory plan rows, digests, events or intents are a correctness incident: stop the affected synthetic worker, preserve the rows and escalate. There is no repair/reset command and direct SQL edits are prohibited. Reviewer/delegation provisioning, timer/activity delivery, paging and an accountable owner remain K0/K0.1 or K2.5 work.

Keep additive migration `0011_supplier_case_approval_arbitration` and all accepted decision/event/intent history on rollback. The earlier K2.3 worker does not understand approval event types or the expanded event bound; pause dispatch rather than deploying that worker against K2.4 data. Roll forward with a compatible workflow/worker and replay qualification; there is no destructive down migration.
