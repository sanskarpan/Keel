# Keel / Ghostlight contract v1.1

Status: design contract. Revision 1.1 adds reviewed optional SaaS/product role capabilities while preserving core 1.0 semantics. Receivers explicitly validate the supported minor version/capability set; they reject unknown roles rather than granting implicit permissions. Breaking changes increment the major version. Both repositories check the same canonical JSON fixtures and schema digest in CI.

## 1. Environment identity

`environment_id` is a random immutable UUID. `environment_slug` is a platform-generated DNS-safe string such as `pr-142-a7d32c`; it never comes directly from a branch name. `generation` increases on every requested artifact/config change. `source_sha`, `artifact_digest`, `configuration_digest` and `recipe_digest` identify the exact candidate.

Resources carry `ghostlight.environment_id`, `ghostlight.generation`, `ghostlight.owner`, `ghostlight.expires_at` and platform ownership tags where supported. Permissions and cleanup use immutable IDs, not display names. A replacement environment gets a new ID; a closed PR cannot resurrect its old environment.

Keel receives trusted, platform-injected `KEEL_ENVIRONMENT_ID` and `KEEL_CONFIG_DIGEST`. User requests cannot override environment identity. Tenant and environment are different dimensions; every preview has at least two synthetic tenants to exercise isolation.

## 2. Signed deployment recipe

```json
{
  "schema_version": "1.1",
  "product": "keel",
  "source_sha": "<40-or-64-character-git-object-id>",
  "images": {
    "backend": "registry.example/keel@sha256:<digest>",
    "web": "registry.example/keel-web@sha256:<digest>"
  },
  "migration_bundle": "sha256:<digest>",
  "event_schema_bundle": "sha256:<digest>",
  "configuration_schema": "sha256:<digest>",
  "health_contract": "1",
  "roles": ["api", "relay", "projector", "ai-executor", "temporal-worker", "webhook-worker", "billing-worker", "notification-worker"],
  "dependencies": ["postgres", "pgvector", "kafka", "temporal", "redis", "s3", "oidc"],
  "test_profiles": ["smoke", "isolation", "replay", "load", "chaos"],
  "resource_profile": "preview-small",
  "signature": "<external-attestation-reference>"
}
```

Digest strings above are explanatory placeholders. Implemented fixtures use valid digests. Recipe signatures/provenance bind the artifact to the source SHA and trusted build workflow. An untrusted artifact may run only in preview after scanning and sandbox checks; a signature demonstrates provenance, not that its code is safe.

Recipes select platform-owned modules and bounded resource profiles. They cannot introduce arbitrary Terraform providers/modules, Helm hooks, cluster roles, host mounts, privileged containers, external destinations or cloud IAM policies. Optional capabilities require a reviewed contract revision.

The 1.1 role catalog includes scoped `billing-worker` and `notification-worker`, and a separately qualified `procurement-worker` for Keel 1.5. Ghostlight owns its SaaS worker and preview gateway in its protected control-plane deployment; a candidate recipe cannot request their credentials. Per-role permissions/egress and resource consumption are part of reviewed profiles. Billing/email/chat/ERP in previews use controlled stubs and synthetic customers by default; real commercial credentials are never injected into candidate code.

## 3. Runtime endpoints

| Endpoint | Contract |
|---|---|
| `GET /health/live` | Process/event-loop liveness; does not probe dependencies |
| `GET /health/ready` | Role-specific ability to accept its assigned work; structured dependency states; no secrets |
| `GET /health/startup` | Configuration/schema/role setup finished; no automatic schema mutation |
| `GET /version` | Build SHA, artifact/config/schema versions and environment ID |
| `GET /metrics` | Private network/authenticated Prometheus exposition; no tenant IDs, prompts or raw URLs as labels |

API readiness depends on PostgreSQL and the ability to enforce mandatory policy. Kafka can be degraded because commands write a durable outbox; excessive outbox age/backlog can deliberately disable new writes. Redis loss disables costly AI admission but allows configured bounded safe-read fallback. Temporal API loss does not undo an accepted workflow intent. Worker readiness reflects its own executor dependencies, not every external integration.

## 4. Test and synthetic-data contract

Keel exports platform-owned test profiles with declarative workload parameters. Test code from the candidate executes only inside the preview sandbox with preview credentials. The independent platform harness supplies authoritative isolation, mutation and load probes so candidate code cannot simply attest itself healthy.

Seed fixtures include two tenants, ordinary and approver users, a supplier onboarding case, multiple document versions, orders/events, a webhook receiver, and controlled LLM responses. Fixed fixture version and random seed are recorded. Real customer data is prohibited in preview. LLM calls default to a stub; an authorized live-provider experiment receives a separate capped preview account, never production credentials.

SaaS/customer test profiles add synthetic trial/entitlement states, membership revocation, supplier/external versus internal threads, parallel approvals, procurement budgets and subscription webhook order/conflict fixtures. Keel 1.5 adds PO amendment/partial receipt/invoice/renewal scenarios. Changes to fixture/template/configuration are candidate identity changes and invalidate affected evidence. Domain tests and customer journey tests both run; one cannot substitute for the other.

## 5. Telemetry and result schema

Traces use W3C `traceparent`; Kafka/Temporal boundaries may use span links instead of a days-long parent span. Resource attributes include `service.name`, `service.version`, `deployment.environment.name` and environment ID. Metrics use bounded labels. Access-controlled logs/usage records can carry tenant IDs; shared metrics cannot.

Each test report records environment ID/generation, exact digests, source/base SHA, schema versions, workload, seed, hardware shape, start/end time, fault schedule, observation completeness, invariants, latency/error/lag recovery, spend and cleanup status. Missing samples produce `inconclusive`, not `pass`.

Gate result states: `pass`, `fail`, `inconclusive`, `canceled`. A gate is signed and valid only for its recorded candidate and policy digest. New source/config/schema changes invalidate earlier passes. Ghostlight emits a GitHub check/deployment status; it does not merge code automatically.

## 6. Scaling and disruption

Keel role profiles expose safe concurrency bounds, graceful termination budgets and resumable work semantics. Kafka projector/receiver replicas cannot exceed useful partitions without an explicit idle-consumer policy. AI executors expose PostgreSQL runnable backlog, lease count and oldest job age. KEDA does not infer executor backlog solely from Kafka once jobs have been durably received.

Pod shutdown first stops new admissions/claims, drains bounded active work, persists resumable progress and releases only leases it owns. Interrupted work is retried under the same logical ID. Karpenter supplies worker nodes; KEDA supplies desired pod counts. Stateful dependencies, ingress baseline and Temporal service are not scaled to zero.

## 7. Dependency and migration compatibility

Dependency families: supported PostgreSQL 17+ with pgvector 0.8+ iterative scans, Kafka KRaft, supported Temporal server/Go SDK, Redis-compatible service supporting atomic Lua and server time, Kubernetes/EKS, KEDA and Karpenter. Exact versions and provider images are locked before implementation and qualified as a compatibility matrix; `latest` tags are forbidden in reproducible releases.

Use expand/contract schema migrations. A dedicated migration role/job serializes migration under an advisory lock and records checksum. Old and new app versions coexist during rollout. Destructive contraction waits until old binaries, long-running workflows, replay jobs and relevant event schemas no longer depend on the old shape. Automated rollback never assumes data migrations are reversible.

## 8. Local versus hosted profiles

Local Compose runs PostgreSQL/pgvector, Kafka KRaft, Redis, Temporal, an S3-compatible store, OIDC, telemetry and stub providers. Hosted previews use isolated allocations in a shared preview cluster/account. Production uses managed durable services and separate IAM/KMS boundaries. Local profiles validate semantics; cloud qualification validates network policy, storage durability, identity and autoscaling behavior.
