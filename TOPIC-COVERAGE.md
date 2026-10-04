# Coverage and proof obligations

Source: https://x.com/suraj_sharma14/status/2105628804492263576. Repository review established adjacent implementations; these two projects intentionally revisit the topics through coherent production workflows.

These 15 topics are minimum technical coverage, not product scope limits. The versioned feature catalogs define 40 Keel and 36 Ghostlight capabilities; the common SaaS foundation and customer roadmaps are additional paid-launch requirements. Technical-topic completion alone does not mean either product is commercially ready.

| # | Topic | Owner | Implementation location | Evidence required |
|---|---|---|---|---|
| 1 | High-concurrency HTTP server | Keel | API ingress, admission control and stream hub | 10,000 live connections; separately measured active request and stream workload; bounded memory; drained shutdown |
| 2 | Multi-tenant hybrid search | Keel | PostgreSQL RLS, pgvector and tenant-local BM25 postings | Exact/vector/lexical/hybrid retrieval evaluation; negative isolation tests; filtered ANN recall and latency |
| 3 | Event-sourced order pipeline | Keel | Order event store, transactional outbox, Kafka, projections | Reconstruct order from events; duplicate/reorder/crash tests; DLQ replay with unchanged logical event IDs |
| 4 | Durable onboarding workflow | Keel | Temporal workflow and durable approval intents | 72-hour timer, human approval, retry/versioning/restart evidence; time-skipping tests plus one real-duration staging run |
| 5 | AI gateway and semantic cache | Keel | Model router, budget reservations, cache eligibility | Equivalent-query cache precision; tenant/context isolation; budget races; pre-stream provider failure and fallback |
| 6 | PII-redacting auth middleware | Keel | OIDC, redacting logging, typed agent query broker | PII canary scans; read-only privileges; session-bound tenant identity resisting custom-GUC tampering |
| 7 | Real-time streaming dashboard | Keel | SSE for model output and persisted state events | Mixed-source ordering contract; replay; slow-client backpressure; TTFT reported including gateway overhead |
| 8 | Correlated tracing pipeline | Keel | OTel, Langfuse adapter and protected context vault | Request/model/query/event links; authorized context replay; telemetry content and retention audit |
| 9 | Ephemeral environment provisioner | Ghostlight | Controller, trusted Terraform runner and recipes | PR open/update/close/expiry lifecycle; isolation and cleanup after partial failure |
| 10 | Queue-based autoscaler | Ghostlight | KEDA Kafka lag, runnable-work metrics and Karpenter | Lag-to-pod and pending-pod-to-node evidence; Spot interruption/on-demand fallback; cost caps |
| 11 | Globally distributed rate limiter | Keel | Home-region Redis authority plus edge policies | Two-region clients; known consistency limits; Redis failover/partition behavior; no unbounded fail-open |
| 12 | Chaos engineering suite | Ghostlight | Scoped experiments, abort monitor and SLO dashboards | Latency, replica loss and partitions; invariant checks; error-budget burn and recovery measurements |
| 13 | Webhook reconciliation engine | Keel | Inbound inbox, outbound deliveries and audit/replay UI | Duplicates, late callbacks, retries, exhausted delivery replay and reconciliation against source state |
| 14 | Cost-per-request FinOps | Keel; preview infra in Ghostlight | Usage ledger, attribution rollups and alerts | Tenant/endpoint/model-call attribution; unknown spend states; cash-versus-estimated savings reconciliation |
| 15 | Public architecture teardown | Both | ADRs, benchmark reports and three articles | Published URLs, diagrams, measured latency/cost tables, reproducible commands and limitations |

## Completion rules

1. A capability present in another repository is learning context, not evidence for the new system.
2. Local test results, integration results and production observations are distinct evidence classes.
3. No claim of 10k active LLM generations follows from 10k idle sockets. Connection, active request and inference concurrency are separate targets.
4. Native PostgreSQL `ts_rank`/`ts_rank_cd` is not BM25. Keel's lexical scorer uses documented BM25 term statistics; extension substitution must preserve that contract.
5. Kafka consumer lag is unconsumed work, not the total retained log size. A fast durable-inbox consumer can transfer backlog into PostgreSQL; autoscaling must observe that second queue too.
6. Redis replication/failover can lose recently admitted tokens. Strict financial budgets remain in PostgreSQL. The global rate limiter states its consistency model and degraded limits.
7. Exactly-once business effects require uniqueness, transactional state and idempotent protocols; transport may redeliver.
8. Fault experiments are complete only when they prove recovery and business invariants, not merely that a component can be killed.
