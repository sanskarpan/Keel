# Backend module boundaries

Keel is one Go module and one release artifact with separately selectable runtime roles. It is not a network service per business entity. Runtime roles give different identities and scaling/failure budgets to API, relay, projection, AI, Temporal, webhook, billing, and notification work while sharing domain libraries.

## Bounded contexts

| Package boundary | Owns | Must not own |
|---|---|---|
| `auth`, `tenancy`, `organizations` | Principal authentication, memberships, organization lifecycle and tenant context | Procurement decisions or provider billing state |
| `orders` | Pure order command rules, canonical snapshots and deterministic event replay | Persistence, HTTP identity verification, approval policy evaluation or external effects |
| `orders/httpapi` | Trusted-context, authorized order reads; safe timeline DTOs; read-only server-rendered detail view | Resolving credentials, accepting tenant selectors, or issuing order mutations |
| `suppliers`, `onboarding` | Supplier identity, intake cases, evidence and eligibility episodes | Internal membership or purchase authorization |
| `intake`, `orders`, `approvals`, `procurement`, `contracts` | Purchase request/order authority, frozen approval plans, procurement commitments and supplier contract obligations | AI safety budgets, subscription invoices or payment execution |
| `documents`, `search` | Versioned document intake, visibility-filtered retrieval and citations | Authorization decisions or tenant-wide corpus statistics |
| `ai`, `usage` | Read-only tool policy, inference state and model-cost observations | Business command authority or unbounded provider spend |
| `commercial` | Hosted subscription observations, entitlement snapshots and SaaS metering | Procurement commitments or supplier payment workflows |
| `collaboration`, `webhooks` | Visibility-scoped communication and authorized external delivery | Reinterpreting an approved business decision |

These are source/package ownership boundaries, not independent deployment promises. Create a domain package when its first invariant or public application port is implemented; do not add empty placeholder packages.

## Dependency direction

- Domain packages own business types, invariants and ports. They do not import platform adapters or access infrastructure directly.
- A domain must not write another domain's tables or import another domain's storage implementation. Cross-domain behavior calls an explicit application command/query port; asynchronous integration uses versioned events and idempotent handlers.
- `internal/platform` owns process assembly, configuration, logging, database/event/telemetry adapters and admission mechanisms. It may wire domain ports, but must not duplicate domain rules.
- `cmd/keel` selects a runtime role, loads validated configuration, establishes cancellation and invokes the platform runtime. Secrets and tenant/customer payloads are never emitted in startup logs.

Changes to these boundaries require an ADR and tests for transaction, authorization and event ownership before cross-domain writes are introduced.
