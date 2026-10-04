# Research basis and qualification register

Baseline date: 4 October 2026. These references explain design choices; they do not certify the planned implementation. The earlier portfolio review examined public repository metadata, available README content and likely-match code. Keel/Ghostlight are new designs, not assumed extensions already running in those repositories.

Revision 2 adds [comparable-product research](PRODUCT-RESEARCH.md) and [retrieval evidence](PRODUCT-RESEARCH-EVIDENCE.json), covering procurement/supplier/contract/risk products and preview/portal/fleet-reliability products. Public-page observations inform requirements; they do not substitute for interviews, trials or benchmark evidence.

## Authoritative sources

| Source | Design implication |
|---|---|
| [PostgreSQL row security](https://www.postgresql.org/docs/current/ddl-rowsecurity.html) | Policies default to deny when enabled without a matching policy; owners/superusers/BYPASSRLS require care. Force RLS and separate migration/app/agent roles. |
| [pgvector — hybrid search and filtering](https://github.com/pgvector/pgvector#hybrid-search) | Combine vector and lexical result ranks; qualify ANN filtering/iterative scans and exact fallback. Native PostgreSQL text ranking must not be mislabeled BM25. |
| [Temporal workflows](https://docs.temporal.io/workflows) | Durable history replay requires deterministic workflow code and explicit compatibility/versioning. Activities and external effects still require idempotency. |
| [Kafka documentation](https://kafka.apache.org/documentation/) | Ordered partitions and idempotent/transactional producers do not atomically commit an external database effect. DB inbox/outbox and effect deduplication remain necessary. Pin the deployed Kafka version's semantics during implementation. |
| [KEDA Kafka scaler](https://keda.sh/docs/latest/scalers/apache-kafka/) | Scale from consumer lag; account for partitions, offset initialization, activation thresholds and scale-to-zero behavior. |
| [Karpenter NodePools](https://karpenter.sh/docs/concepts/nodepools/) | Node provisioner controls capacity classes and disruption. Spot/on-demand fallback needs compatible pod placement and capacity limits. |
| [Chaos Mesh network faults](https://chaos-mesh.org/docs/simulate-network-chaos-on-kubernetes/) | Latency/partition experiments require narrowly scoped selectors and independent abort/cleanup. |
| [OpenTelemetry GenAI conventions](https://opentelemetry.io/docs/specs/semconv/gen-ai/) | Use model-call attributes and trace links, pin the convention version, and gate sensitive-content capture. The entry page can redirect as conventions evolve. |
| [Langfuse OpenTelemetry integration](https://langfuse.com/docs/opentelemetry/get-started) | Implement a prompt-context adapter and correlate model observations without relying on telemetry as the sensitive-data source of truth. Verify API/schema compatibility before locking a release. |
| [GitHub deployment environments](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments) | Environment protections and secrets must be separate from untrusted PR builds. |
| [GitHub Actions security](https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions) | Do not execute fork/PR code with trusted workflow credentials; restrict cloud OIDC trust and token permissions. |
| [Terraform state](https://developer.hashicorp.com/terraform/language/state) | State is sensitive; isolate, encrypt, lock and preserve it during incomplete cleanup. |
| [Kubernetes multi-tenancy](https://kubernetes.io/docs/concepts/security/multi-tenancy/) | Isolation spans namespace controls, sandboxing and dedicated cluster/hardware; validate resource-sharing tradeoffs against threat tier. |
| [gVisor documentation](https://gvisor.dev/docs/) | Sandboxed runtime provides an additional syscall/kernel boundary with compatibility/performance tradeoffs that must be measured. |
| [Temporal server security](https://docs.temporal.io/self-hosted-guide/security) | mTLS and custom authorizers can control authenticated API access; they are not by themselves an active-workflow or noisy-tenant quota. |

## Architecture corrections adopted

- "10k concurrency" is specified separately for sockets, active ordinary requests and active model streams.
- BM25 is implemented as tenant-scoped document-term statistics in PostgreSQL for the initial supported capacity. A search extension is a future performance option after proving RLS, filter correctness and compatible deployment.
- Redis coordinates best-effort global admission in a tenant's home region. Strong spend reservations stay in PostgreSQL.
- KEDA scales pods; Karpenter scales nodes. Kafka lag and PostgreSQL runnable job backlog are separate signals.
- Approval acceptance lives in a durable database record before Temporal signaling. Signal delivery is retryable.
- Event publication and projection may duplicate/reorder during failover. Consumers check logical IDs and aggregate versions rather than assuming broker order solves every boundary.
- A generic read-only role plus a caller-set tenant variable is not a safe autonomous-agent boundary. Session-bound tenant identities and a typed query broker are required.
- Preview isolation includes identities, databases, topics, buckets, encryption and outbound access. Namespace labels alone do not constitute isolation.

## Qualification items before implementation commits

| ID | Question | Owner | Exit evidence |
|---|---|---|---|
| Q-01 | Supported exact Go/PG/pgvector/Kafka/Temporal versions and managed-service availability | Keel platform | Version lock + compatibility CI |
| Q-02 | BM25 postings cost and HNSW recall at chosen tenant distribution | Keel search | Reproducible benchmark; exact oracle; tenant leakage suite |
| Q-03 | Required OIDC provider, regional residency and customer retention commitments | Keel product/security | Configuration decision + data-lifecycle tests |
| Q-04 | Provider token accounting, retention terms and idempotency support | Keel AI | Provider capability registry + billing/retry qualification |
| Q-05 | GitHub App/cloud accounts, organization policies and spending limits | Ghostlight platform | Least-privilege access proof + configured quotas |
| Q-06 | Preview DB, Kafka ACL, Temporal namespace and Redis isolation feasibility | Ghostlight platform | Two concurrent malicious previews cannot access one another |
| Q-07 | Chaos Mesh privileges and cluster boundary | Ghostlight security | Separate experiment cluster/node pool; audited platform-only controller permissions |
| Q-08 | KEDA offset behavior and Spot availability in selected regions | Ghostlight capacity | Cold activation, partition rebalance and interruption tests |
| Q-09 | Sensitive-context storage and Langfuse mode/API contract | Keel observability | Disabled-by-default prompt content; encrypted replay + access audit |
| Q-10 | Billing provider country/currency/tax/proration/event semantics | SaaS product/platform | Qualified sandbox/current-state reconciliation; contractual billing and cancellation policy |
| Q-11 | Mail/chat/issue-provider delivery, identity/privacy and cost | SaaS integrations | Sender/recipient authorization, signed callbacks, revocation/quiet-hours and deliverability evidence |
| Q-12 | ERP/accounting field authority, line matching and actuals reconciliation | Keel procurement/integrations | Real adapter sandbox, unknown effects and no double-counted commitments/actuals |
| Q-13 | Commercial packaging, unit economics and willingness to pay | Product/cost | Interviews/design partners plus measured full-journey cost and approved price/limits |
| Q-14 | Enterprise IdP/SCIM, business scopes and owner recovery | Security/identity | Actual provisioning/offboarding/order/conflict and scope-negative evidence |
| Q-15 | Fixture/suspension compatibility, retained costs and schedule semantics | Ghostlight platform | Synthetic provenance, reset/expire/resume races, unchanged TTL and measured residual costs |
| Q-16 | Customer connector identity/native permissions/offline safety | Ghostlight security/platform | Wrong-account/replay/disconnect, local abort/TTL/inventory and recovery drills |
| Q-17 | Core journey usability/accessibility and differentiated customer value | Product/design | Representative participant tasks, WCAG evidence and go/no-go for later product bets |
| Q-18 | Kubernetes runtime class (Kata/gVisor/equivalent), node-pool and EKS/provider support/cost | Ghostlight platform/security | Version-pinned sandbox escape/noisy-workload prototype; no candidate on control nodes or node identity; fail-closed unsupported runtimes |
| Q-19 | Temporal server auth/authorizer, worker API permissions, quota gateway/server limits and hosted-service support | Ghostlight platform | Adversarial direct-connect/worker credential tests; start/payload/rate/active-count caps measured at service boundary |
| Q-20 | Customer-connector/native fault TTL, watchdog failure domains and recovery during target/provider outage | Ghostlight platform/security | Killed connector/cluster, API outage, clock-skew drills; unsupported fault types denied; unclear removal remains unresolved |

No marketing claim depends on an unqualified item. Exact vendor/version choices can change via ADR if the behavior and security contracts remain satisfied.
