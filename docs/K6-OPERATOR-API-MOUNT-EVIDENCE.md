# K6 slice: mounted operator API with bearer auth

Issue #453 (parent #51, checklist item K6). PR #454 merged as
`2e6973593591dfa8e5055807cbb366a9a390bf4c`; contract CI #719 passed on reviewed head
`40ae45c7a2ce0abbed63b8fc12c3f25929d688a4`. This slice mounts the operator API as a new
`operator-api` role guarded by per-tenant bearer tokens. No migration was needed and no
handler behavior changes.

## Contract

- `httpapi.BearerAuth` implements both `PrincipalResolver` and `Authorizer` from configured
  `tenant:name:token[:scopes]` grants: constant-time token comparison, canonical `Bearer`
  spacing, scoped replay/policy permissions defaulting to both, and audit actor references
  naming the grant (`bearer:<name>`) instead of the token. Duplicate names/tokens, unknown
  scopes and malformed entries are rejected; tokens never appear in logs, errors or
  responses.
- The `operator-api` role holds only the operator-capability database pool, serves the
  existing handler plus health/readiness endpoints on one listener, and requires loopback
  unless `KEEL_OPERATOR_API_ALLOW_NON_LOOPBACK=true` is set explicitly. Key readiness for
  candidate listing comes from an optional key file; without it every candidate reports
  not-ready rather than guessing.
- `config.RoleOperatorAPI` is registered in the dispatcher; `make local-operator-api` runs
  the role on `127.0.0.1:18083` with a local-only token.
- Coverage includes grant parsing, authentication matrix, per-grant scope enforcement,
  cross-tenant rejection, settings validation without credential leaks, loopback gating,
  role registration, and a live serving test (401s, empty runs list, policy write plus
  conflict, clean shutdown) against an isolated database.

## Limits

No OIDC/mTLS, per-endpoint keys, or production deployment. Non-loopback serving is an
explicit, documented opt-out for private-network platforms.

## Verification

- `go test -count=1 ./internal/delivery/webhook/... ./internal/platform/runtime/ ./internal/platform/config/`.
- Live serving test on an isolated database provisioned with tenant roles, `vector` and the
  full migration bundle (max applied 62).
- `go vet` on the touched packages; Linux CI covers the race detector.
