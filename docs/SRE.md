# Reliability and operations

## 1. Initial SLOs

Targets are for the qualified production-small envelope, measured in the tenant home region. These are release goals, not observed commitments.

| Surface | Target / denominator |
|---|---|
| Ordinary API | 99.9% successful valid eligible requests over 30 days; expected auth/validation/quota rejections tracked separately; internal 5xx/timeouts count bad |
| Commands | p95 <=250ms and p99 <=750ms server-side for ordinary short transactions; queue/admission time included |
| Hybrid search | p95 <=500ms, p99 <=1.5s within capacity/corpus envelope; complete eligibility checks required |
| AI admission | p95 <=250ms excluding authentication network setup; provider generation reported separately |
| Streaming | Gateway-added TTFT p95 <=250ms; provider-inclusive TTFT/error rate reported by model/region without hiding vendor outages |
| Outbox/projections | p99 <=5s from accepted command to applied projection; oldest pending age <30s normally |
| Workflow intent | p99 <=30s to durable Temporal start/signal acknowledgement |
| Webhook scheduling | 99% eligible deliveries first attempted within 30s; receiver success/retry is a separate integration SLI |
| Usage | Confirmed ledger writes accompany completion; rollup freshness <=5m; unknown provider charges explicitly visible |

Use operation templates/status classifications, not arbitrary URLs as metric labels. Report excluded requests and queue rejection rates to avoid gaming availability.

## 2. Health and observability

`internal/platform/health` supplies `/health/live`, `/health/startup`, `/health/ready`, `/version` and `/metrics` handlers plus a graceful HTTP server runner. Liveness never probes dependencies. Startup returns unavailable until the role marks initialization complete. Readiness executes caller-supplied role-specific probes with a two-second context budget and returns generic failure text; it fails closed when no probes are registered, permits outbox buffering within its safe backlog and does not require every webhook destination to be healthy. Keep the management listener private and apply network policy/authentication before deployment; these endpoints are not wired into the still-fail-closed role dispatcher. The initial metrics are process/build identity and bounded HTTP request count/duration labels; service-specific DB, queue, budget and stream measurements are added with their owning runtime features. Never put tenant, user, document, raw URL or query values into shared metric labels.

Prometheus metrics: request latency/inflight/admission rejection, stream queues/disconnects, limiter failures, DB pool/lock/statement latency, outbox age, Kafka lag/gap/deadletter counts, runnable-job age/lease expiry, provider latency/tokens/attempt outcomes, budget reservation liabilities, webhook attempt status/retry age and workflow intent lag. Avoid tenant/document/user IDs in shared metric labels.

OTel spans and links correlate commands, SQL operations, event IDs, workflows/activities, retrieval/context IDs, model attempts and deliveries. Pin semantic-convention schema version. Prompt/database values are not ordinary trace attributes. Langfuse receives safe model metadata and controlled context references via an adapter; sensitive replay content uses the separate vault.

SSE state replay comes from PostgreSQL; Redis notification hints wake local readers. Model-token frames use environment/tenant/inference-scoped transient Redis Pub/Sub with per-attempt sequence numbers and bounded executor batching. Lost frames/Redis interruptions produce a gap/interrupted transport indication and fetch of durable final output, not silent token concatenation. Do not place raw model tokens in Kafka or generic logs. Generation can finish without a connected browser.

## 3. Alert policy

Page on sustained high API error-budget burn (e.g. burn >14.4 in both 5m and 1h windows for a 99.9% availability SLO), unexplained event digest/version conflict, isolation alarm, severe outbox growth, budget-ledger invariant violation or inability to drain required work. Ticket on long-term low burn, growing uncertain charges, cache precision drift and storage forecast. Require adequate traffic before ratio alerts; zero traffic is unknown, not healthy.

Dashboards separate internal API, provider, webhook receiver and queue SLIs. Tenant-specific cost/security details live behind authorized product/API access. New anomaly models require history and a calibrated false-positive policy; use deterministic budget/threshold alerts first.

## 4. Deployments

The tag-triggered release workflow builds an immutable Linux/amd64 binary, emits an SPDX SBOM and checksum list, and obtains GitHub OIDC-backed provenance for the archive plus an SBOM attestation for the binary. Verify checksums and attestations before use. Run migrations under the dedicated migration login, then roll runtime roles using readiness/startup and backward compatibility. API PDB/zone spreading protects baseline availability; worker interruption policies reflect lease-based recovery. Canary compares errors/latency/gaps and invariant metrics, not just HTTP health. This is a release pipeline definition; no Keel release artifact has yet been published or qualified for production.

Config/secrets are validated at startup. Provider, OIDC and webhook keys rotate with overlap. Disabling a provider, semantic cache, document indexing or integration is a documented kill switch. Kill switches never bypass budget/authorization controls. Rollback code only when schema/event/workflow compatibility remains valid; use forward repair for irreversible data changes.

## 5. Failure posture

| Failure | Behavior |
|---|---|
| PostgreSQL unavailable | Reject new commands/admissions; no blind cached authorization of writes; preserve in-flight unknown outcomes for retry by same key |
| Kafka unavailable | Commit to outbox within bounded backlog; projections lag visibly; reduce/stop nonessential writes when safe buffer budget is reached |
| Redis unavailable | Model/budgeted/sensitive admission fails closed; streams degrade to durable status/final result. Approved safe reads may use the optional PostgreSQL fallback only when separately enabled and provisioned. It is shared across replicas, has fleet and tenant/route caps, and rejects new admissions after 60 seconds until a separately credentialed observer verifies home-region Redis health for five consecutive seconds. Redis failover ambiguity can add bounded fallback admissions; the two authorities are not atomic. No production route currently enables this fallback. |
| Temporal unavailable | Case/approval intents persist; UI shows pending synchronization; deadline decision records remain authoritative |
| Provider unavailable | Bounded pre-stream fallback; reservations/accounting per attempt; interrupted streams show explicit state |
| Webhook outage | Per-endpoint circuit breaker, jitter retry and durable exhaustion; no core order outage |
| Extraction sandbox failure | Quarantine document and retry safely; never publish unscanned content |
| Worker loss | Lease expires/reclaim; stale commit rejected; external unknown charges reconciled |

### Safe-read degraded admission runbook status

K4.7.2 provides shared PostgreSQL admission and recovery-fence primitives, fixed-label admission counters/durations, and a dedicated read-only `keel_rate_status` identity for the window-status query. The `rate-limit-observer` process role refreshes the snapshot with per-query deadlines and exposes unlabeled gauges and refresh errors on its management endpoint. The deployment profile does not yet launch this role or configure a scraper, so deployed alerts remain incomplete. This procedure is a code-level operational contract, not production qualification. Keep all fleet and tenant policies disabled and the application fallback switch off until issues #198 and #199 pass.

#### Before any future pilot

1. Confirm the exact home-region Redis endpoint, DNS/TLS identity, PostgreSQL single-writer region, and the approved API/runtime version. Do not enable during active Redis failover or a PostgreSQL role/region transition.
2. Require an approved control-plane implementation of `PolicyAuthorizer`, an isolated rate-control workload identity, and an audited policy change. Do not use direct SQL or an operator shell to edit policy tables; PostgreSQL can validate the role and policy constraints but cannot prove the service authorization ran.
3. Record the fleet cap/refill, each tenant/route cap/refill, safe-read classification owner, fixed one-unit request cost, rollback owner, and incident contact. Verify model/write routes have no enabled fallback policy.
4. Confirm the runtime scrape path exports the `keel_rate_limit_degraded_*` series and alert delivery works. Do not enable if telemetry is absent. Source-controlled candidate Prometheus rules are in `deploy/monitoring/prometheus/keel-rate-limit-alerts.yaml`: page when `db_error`, `window_expired`, or primary `redis_failure` occurs in a five-minute window; warn on any allowed fallback; do not page on `limited` alone. PR #235 implements the primary Redis series. The `rate-limit-observer` role attaches degraded status and refresh metrics to its management endpoint, but no deployment profile yet launches it or configures the live scrape. The rule file is not a deployed alert configuration, and the expressions must be reviewed against the selected monitoring stack and traffic before a paid pilot.
5. Enable the application fallback switch and explicitly approved policy as a coordinated change. Observe the pilot at the approved traffic ceiling; rollback immediately on unexpected routes, DB pool pressure, error growth, or missing metrics.

#### During a Redis outage

- Keep model, budgeted, sensitive-write, and unclassified routes fail-closed. Do not raise policy caps to compensate for a Redis incident.
- The shared PostgreSQL fleet and tenant/route buckets bound admitted requests. An outage window admits new safe reads for at most 60 seconds; requests after expiry fail closed. Redis and PostgreSQL cannot coordinate ambiguous Redis responses atomically, so bounded additive admission is possible and is not exactly-once across both authorities.
- If PostgreSQL is unavailable, policy state cannot be read, or the app connection pool is exhausted, fallback rejects. Treat fallback `db_error` and `window_expired` as incidents; do not bypass with process-local counters.
- Disable fallback first through the application kill switch. Then use the authorized control plane to disable fleet and tenant policies. Do not share `keel_rate_control` credentials with API, workers, or human shells.

#### Recovery and rollback

- Do not clear the regional outage window manually. Elapsed time, restarting pods, or a Redis health flap cannot reopen it.
- The isolated recovery observer must use the configured primary home-region limiter and `keel_rate_control` connection. It records recovery only after five consecutive seconds of successful PINGs; any failed probe restarts that interval. Verify recovered Redis health and DB writer identity before restoring the application switch and policy.
- If the window has expired, new safe-read admissions remain denied until the observer records recovery. Exact request replays may return their stored decision for up to ten minutes; they do not consume another token.
- Keep the additive migration in place during application rollback. It is not safe to remove admission state while any app instance may still call the fallback function.

No production traffic is authorized by this procedure. Deployment-specific dashboards, tested role-recovery exercises, production-small load/lock results and named on-call ownership remain prerequisites tracked by #198 and #199.

## 6. Backup and disaster recovery

PostgreSQL PITR/WAL backups and tested full restores; Temporal persistence backups according to qualified deployment; object-store versioning/lifecycle with erasure controls; infrastructure and schema/catalog definitions versioned. Kafka is transport, not the only copy of business history. Restoring PostgreSQL includes event histories, inbox/delivery dedupe and cost liabilities.

Initial goals: in-region failover protects acknowledged DB commits under synchronous managed HA; regional disaster RPO <=5m and RTO <=60m are drill targets, not guaranteed by merely enabling backups. Fence the original writer/egress before promoting a recovery region. Fail closed if single-writer ownership cannot be established. Restore erasure journal and legal holds before access. Rebuild projections from authoritative events and compare hashes/counts before resuming webhooks.

Provider effects may have occurred after the backup cut. Reconcile external operation IDs before retrying them, and preserve uncertain liabilities. Resume Temporal only after workflow history/database dependency consistency is verified; do not recreate a new workflow for every existing case.

## 7. Lifecycle and ownership

Named owners: product/domain for approval semantics; platform for database/broker/workflow operations; security for tenant/context boundaries; AI/search for retrieval/cache quality; integration for callback/reconciliation behavior. Each release includes on-call runbooks, evidence paths, dependency support windows and recovery contacts. Optional customer SLAs follow observed data, not this design's aspirational targets.

## 8. SaaS and expanded product operations

Add SLIs for setup operations, current entitlement reconciliation age, billing inbox backlog, meter discrepancy, membership/grant revocation delay, notification attempt age, import/export age and customer-visible UI failures. Starting goals to qualify: access disable <=60s, entitlement reconciliation <=5m normally, p99 first eligible notification attempt <=60s; provider email delivery/card authorization are separate observed outcomes. Periodic provider-current-state reconciliation handles missed webhooks. No critical safety action depends on successful subscription-provider calls.

Purchasing 1.5 adds PO dispatch unknown-age/acknowledgment lag, line receipt/allocation conflicts, invoice exceptions, procurement-ledger imbalance, ERP watermark lag and missed renewal notices. Page on invariant violation, not every pending business approval. Escalate expired high-priority evidence/notice tasks to customer owners through configured channels; avoid leaking document content in external alerts.

Restore includes procurement/commercial ledgers, active approval plans, provider mappings, notification dedup, directory disable state and exports/privacy jobs. Reconcile SaaS subscription provider and ERP external effects before resuming expensive work; never restore a stale plan into free paid entitlements or duplicate accounting actuals. All new workers share the global DB pool budget with explicitly assigned quotas. Paid launch requires status/incident communication, support ticket/JIT process and a demonstrated full customer closure/export path.
