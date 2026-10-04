# Keel

AI-assisted supplier onboarding and purchase-order orchestration with tenant-isolated retrieval, durable approvals and auditable external effects.

This repository combines the reviewed product/system design with its early platform implementation. The K0 foundation now includes real dependency fixtures, contract checks, tenant-role/RLS infrastructure, migration tooling and a signed release workflow. Product features, hosted provider compatibility, production qualification and load evidence remain incomplete; see `docs/CHECKLIST.md` for exact status.

## Document map

| File | Contents |
|---|---|
| [PRODUCT-STRATEGY.md](docs/PRODUCT-STRATEGY.md) | Customer segment, value, differentiation, commercial versions and discovery |
| [FEATURE-CATALOG.md](docs/FEATURE-CATALOG.md) | 40 versioned capabilities with acceptance and dependencies |
| [JOURNEYS.md](docs/JOURNEYS.md) | Complete admin, requester, approver, supplier and finance journeys |
| [PRODUCT-SPEC.md](docs/PRODUCT-SPEC.md) | SaaS, procurement budgets, approvals, sourcing, fulfillment and enterprise semantics |
| [ROADMAP.md](docs/ROADMAP.md) | Pilot, paid 1.0, purchasing 1.5, enterprise 2.0 and discovery 3.0 gates |
| [PRD.md](docs/PRD.md) | Users, journeys, scope, success criteria and product boundaries |
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | Components, data flows, regional deployment and tradeoffs |
| [SPEC.md](docs/SPEC.md) | State machines, algorithms, consistency, idempotency and failure behavior |
| [DATA-MODEL.md](docs/DATA-MODEL.md) | Tables, roles, constraints, indexes, migrations and retention |
| [API.md](docs/API.md) | HTTP, SSE, error and permission contracts |
| [EVENTS.md](docs/EVENTS.md) | Kafka, inbox/outbox, schema evolution, replay and webhook protocols |
| [SECURITY.md](docs/SECURITY.md) | Threat model, identity, tenant/agent isolation, PII and audit |
| [CAPACITY-AND-COST.md](docs/CAPACITY-AND-COST.md) | Initial scale envelope, budgets, capacity equations and benchmark workload |
| [SRE.md](docs/SRE.md) | Deployment, SLOs, telemetry, backup, disaster recovery and lifecycle |
| [RUNBOOKS.md](docs/RUNBOOKS.md) | Operator procedures for common failures |
| [RELEASES.md](docs/RELEASES.md) | Signed release/SBOM verification and migration rollout |
| [TESTING.md](docs/TESTING.md) | Correctness, security, recovery and load qualification |
| [QUALITY-REVIEW.md](docs/QUALITY-REVIEW.md) | Independent audit findings, dispositions and verification links |
| [CHECKLIST.md](docs/CHECKLIST.md) | Dependency-ordered implementation tasks and release gates |
| [ISSUE-TRACKING.md](docs/ISSUE-TRACKING.md) | Direct links from every checklist item and gate to its phase-tracked issue |
| [DECISIONS.md](docs/DECISIONS.md) | Architecture decisions with alternatives and consequences |

The [shared contract](shared/CONTRACTS.md) governs deployment by Ghostlight. The [topic map](TOPIC-COVERAGE.md) defines portfolio completion.

The [SaaS foundation](shared/SAAS-FOUNDATION.md) and [comparable-product research](research/PRODUCT-RESEARCH.md) extend this into an independently useful commercial product. Topics are a minimum, not a feature cap. Start with the strategy, journeys and roadmap before implementing checklist phases.

## Implementation shape

One Go module owns domain logic and backend process roles; a React/TypeScript application owns the operator UI. Use pgx/sqlc for database access, a Kafka client with explicit group/offset management, and the Temporal Go SDK. All infrastructure versions are qualified and locked before the first production release.

Suggested layout:

```text
cmd/keel/                 role-selecting process entry point
internal/{auth,tenancy,orders,onboarding,search,ai,usage,webhooks}/
internal/{organizations,commercial,collaboration,intake,procurement,contracts}/
internal/{db,events,telemetry,streaming,admission}/
api/{openapi,schemas}/
events/{schemas,fixtures}/
migrations/              additive schema and role changes
web/                     dashboard and API client
deploy/{compose,helm}/
test/{contract,integration,isolation,recovery,load}/
docs/{adr,reports,runbooks}/
```

Begin with one vertical slice: authenticate into a tenant, submit a purchase request, append its event, publish it, update a read model and inspect the trace. Add supplier onboarding and approvals, then documents/AI, then hardened external delivery and cost controls. Ghostlight deploys signed build recipes after this local flow is stable.

## Implementation bootstrap

The backend remains one Go module with separate process roles and bounded domain packages. Domain packages own their invariants; platform adapters assemble them, and one domain must not write another domain's tables. See [`internal/README.md`](internal/README.md) for current boundaries and dependency direction.

The pinned toolchain is Go 1.27.1. Run `make check` for unit/integration tests and `go vet`; use `make local-migration-test` for forced real-PostgreSQL locking/checksum/rollback tests, and `make local-migrate` to invoke the embedded migration bundle with the dedicated synthetic migrator role. The management HTTP handler provides liveness/readiness, build identity and bounded-cardinality metrics for runtime wiring. The role dispatcher intentionally fails closed until a role implementation is registered; configuration validation alone does not imply that an API or worker is serving traffic. Tagged releases currently build only Linux/amd64; verify the release checksum and GitHub attestations before use.
