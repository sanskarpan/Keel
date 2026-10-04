# K0 tenant/API isolation gate evidence

**Decision:** PASS for the local-synthetic order read profile; final PR-head contract CI run #63 passed. The evidence proves the database/API tenant boundary under real non-owner PostgreSQL roles; it does not enable production traffic or claim a production identity-provider integration.

## Two-tenant order API

`TestPostgreSQLTwoTenantOrderAPIIsolation` in `internal/orders/postgres/httpapi_integration_test.go` provisions distinct synthetic orders for two tenant IDs through the real order repository and HTTP handler. The test confirms its database session is `keel_local_app`, a member of the constrained `keel_app` role. It then checks:

- Each trusted tenant identity reads its own order through `GET /v1/orders/{order_id}`.
- Each tenant receives the same non-enumerating 404 when it requests the other tenant's order.
- Forged `X-Tenant-ID` headers do not change the tenant passed from trusted request identity into the repository.
- The response cannot reveal the other tenant's external reference.

The test injects identity with `httpapi.WithIdentity` as the output of a trusted authentication layer. There is no production authentication middleware or IdP integration yet. The API authorizer in this test is a deliberately minimal fixture; resource-authorization policy and identity-provider wiring remain separate K0/K8 work. Existing HTTP unit tests cover missing identity, denied access, query/header scope confusion, non-enumerating responses, and field redaction.

## Session-bound agent database role

`TestPostgreSQLTenantIsolation` in `internal/platform/tenancy/postgres_integration_test.go` connects as `keel_local_agent_alpha` using the actual non-owner login and asserts both `session_user` and membership in the `keel_agent` capability role. The database maps `session_user` to the alpha tenant, ignores a forged beta tenant GUC and a beta tenant passed to `WithTenantTx`, exposes only alpha's seeded probe row, rejects writes, and verifies the agent login is not a member of `keel_app`. The K0 fixture provisions separate alpha/beta agent logins and protected mappings in `deploy/compose/init/20-keel-tenant-roles.sql`.

## Security, privacy, operations, and rollback

The authorization context is trusted server-side data; tenant identifiers from headers, query strings, and bodies are not trusted. App/worker roles still use a transaction-local GUC, which is caller-settable by a compromised app credential, so database role isolation, narrow service credentials, and workload access remain necessary. Agent access uses the separate `session_user` mapping and a SELECT-only inherited capability. Responses use the established allowlist and denied resources are non-enumerating. All gate fixtures and created orders are synthetic.

Accountable owner: **sanskarpan (repository owner)** for the code and local synthetic profile. This is not production on-call ownership. The API and DB roles are not wired into an externally reachable service, and K0.1 hosted-provider qualification plus K8 identity bootstrap remain open; do not enable customer traffic on the strength of this test alone.

This PR adds no schema migration and performs no deployment. A merge can be rolled back by reverting its merge commit. Contract CI uses a disposable PostgreSQL service and closes database handles through test cleanup hooks; the service and all seeded synthetic records are destroyed with the job. No production data or credentials are used.
