# Modal deployment scaffold (UNQUALIFIED)

This directory defines the Keel roles as Modal functions. Nothing here has been deployed or
run against Modal; the local Compose profile remains the only qualified runtime. The recorded
owner direction (Modal first, DigitalOcean as the cheaper alternative, no AWS lock-in) lives
in `docs/TECHNOLOGY-BASELINE.md`.

## Prerequisites (all operator-provided, none committed)

- An external managed PostgreSQL database with pgvector (Modal has no stateful Compose
  equivalent; Kafka/Redis/Temporal-backed roles are out of scope for this scaffold).
  Designated staging host is recorded in `docs/TECHNOLOGY-BASELINE.md`; it must be
  reachable from both this machine (for migrate/roles bootstrap) and Modal's network
  before proceeding.
- Tenant roles bootstrapped and migrations applied, equivalent to the local
  `20-keel-tenant-roles.sql` plus `keel migrate` against the managed database.
- A Modal account with `modal` CLI authenticated (verified with CLI 1.5.5; definitions
  authored against Python SDK 1.6.3).

## Secrets (create; values never enter the repository)

```powershell
# Operator API: bearer grants are tenant:name:token[:scopes]; generate each token fresh,
# e.g. [Convert]::ToBase64String((1..24 | ForEach-Object { Get-Random -Maximum 256 }))
modal secret create keel-operator `
  KEEL_ENVIRONMENT=staging `
  KEEL_OPERATOR_DATABASE_URL='postgres://keel_operator:<password>@<host>:5432/keel?sslmode=verify-full' `
  KEEL_OPERATOR_API_TOKENS='<tenant-uuid>:ops:<generated-token>' `
  KEEL_OPERATOR_API_ALLOW_NON_LOOPBACK=true

# Webhook worker: key material must be generated fresh, never the local-only constants.
modal secret create keel-webhook `
  KEEL_ENVIRONMENT=staging `
  KEEL_WEBHOOK_DATABASE_URL='postgres://keel_webhook:<password>@<host>:5432/keel?sslmode=verify-full' `
  KEEL_WEBHOOK_ACTIVE_KEY_ID=key_2026 `
  KEEL_WEBHOOK_ACTIVE_KEY_SECRET_B64='<base64 of 32+ random bytes>'
```

`KEEL_OPERATOR_API_ALLOW_NON_LOOPBACK=true` is required because Modal does not serve
loopback; every operator route still requires a bearer grant. Staging and production
database URLs must use `sslmode=verify-full` (enforced by the role settings loader).

## Deploy and migrate

```powershell
modal deploy keel.py          # registers serve_operator_api + run_webhook_worker
modal run keel.py::migrate_db # one-shot migration against the managed database (roles first)
```

The worker loop is persistent, not scheduled: `min_containers=1` keeps one container warm and
the 12-hour function timeout only sets the restart cadence. Lease epochs and the epoch fence
make restarts safe by design.

## Image

The builder is `golang:1.27-bookworm` pinned by index digest (recorded 2026-11-01 in
`keel.py`); the repo builds `go build -o /keel ./cmd/keel` with `GOTOOLCHAIN=local`,
matching the Makefile. Re-check the digest with Go security windows before production use.
No container images are built or published by this repository today.
