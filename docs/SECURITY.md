# Security and privacy design

## 1. Trust boundaries

Untrusted inputs include users, suppliers, uploaded files, document text, model output, provider responses and incoming callbacks. A model does not acquire authority because its output names a valid API command. Trusted policy is supplied by authenticated server configuration and signed deployment provenance, not user prompt text.

Public ingress, application workloads, extraction sandbox, database, event bus, identity provider, context vault and external integration egress are distinct boundaries. Each has separate credentials, network policy and audit. Tenant isolation is enforced at API authorization, storage, retrieval, cache, stream and database layers.

## 2. Threat and control matrix

| Threat | Required control | Verification |
|---|---|---|
| Cross-tenant record/cache/stream exposure | Auth-derived tenant, FORCE RLS, composite FKs, query-time ACLs, scoped keys/cursors | Malicious two-tenant suite across every surface |
| Agent changes custom tenant GUC or requests SQL writes | Session-user binding, SELECT-only roles, typed query tools, credentials withheld from model | GUC/SET ROLE/DDL/DML/function abuse tests |
| Prompt injection in supplier documents | Treat documents as quoted data, allowlisted read tools, independent command approval | Adversarial corpus; no approval/order mutations |
| Semantic cache wrong/unauthorized hit | Scope before search, context/version/access digests, entity/numeric/polarity checks | Labeled equivalence and permission-revocation suite |
| PII in logs/telemetry/errors | Structured allowlists, pre-emission redaction, no prompt content by default | Canary PII scans of logs/traces/metrics/error stores |
| Malicious PDF/DOCX/extraction payload | Quotas, type/magic checks, malware scan, sandbox/no network/resource limits | Bomb/recursive/archive/parser failure corpus |
| Webhook SSRF/DNS rebinding | Safe resolver/egress proxy, IP-range policy, connect-time recheck, redirect policy | Metadata/private/IPv6/rebinding integration cases |
| Replay bypasses approvals or causes duplicate effects | Separate permission, sandbox read-only replay, same event/effect IDs | Replay and revocation tests |
| Model spends after budget/connection loss | Durable bounded reservation, token ceilings, liability state, provider reconciliation | Concurrent admission and unknown-usage cases |
| Forged callback or key confusion | Exact-byte HMAC, timestamp tolerance, provider ID dedupe, key rotation | Signature/key-ID/timing/body-tamper tests |
| Compromised workload reads all secrets | Per-role workload identity, minimum IAM/DB grants, separate key providers | Runtime effective-access audit |
| Operator abuse | JIT break-glass, separate admin routes, immutable audit and approval policy | Administrative-action negative tests |

## 3. Database agent boundary

The model invokes reviewed typed tools such as `search_policies`, `get_supplier_summary` and `get_order_summary`; it never receives a DSN, database credential, raw SQL tool or arbitrary database session. A query broker maps the authenticated principal to a per-tenant read-only PostgreSQL login. A protected `session_user -> tenant_id` mapping and fixed-path `SECURITY DEFINER` function bind each agent login to one tenant; RLS ignores caller-set tenant GUCs for those logins. Agent logins inherit only the SELECT-only `keel_agent` capability role and cannot become app, worker or migration roles. Provisioning creates the login and protected mapping together; revocation removes both under a controlled operation.

Read-only transaction mode is defense in depth, not the privilege boundary; a role may otherwise try to turn it off. Revoke INSERT/UPDATE/DELETE/TRUNCATE/CREATE and unsafe function execution. Use fixed search paths and qualified SECURITY DEFINER function names. Revoke PUBLIC schema-create privileges. Do not expose database introspection or unrestricted network/file functions through tools.

Trusted API and worker roles use `WithTenantTx` to set a transaction-local `keel.tenant_id` only after server-side authorization. PostgreSQL custom GUCs are caller-settable, so this protects against omitted tenant predicates and routine application mistakes; it does not make a compromised cross-tenant app/worker credential tenant-bound. Agent identities are separately bound by `session_user`. Scope service roles, audit context changes, enforce network separation, and offer a dedicated tenant database tier for customers requiring a stronger physical boundary.

Order read handlers accept tenant and principal identity only from trusted middleware context and require a resource authorization decision before querying. They return non-enumerating 404s for denied resources. Public timeline rows use a reviewed allowlist of event ID, version, type and occurrence time; private event payloads, actor references, evidence digests and trace/correlation IDs are excluded. History cursors use AES-256-GCM with a key ID, associated-data domain and seven-day expiry; the encrypted claims bind tenant, order and page size. Cursor key material is injected into the handler, never accepted from a request, and old keys remain available for the full token lifetime after rotation.

## 4. PII handling and context retention

Central Go logging and extraction/model adapters accept structured allowlisted fields. PII scrubbing runs before emission; raw request bodies, SQL parameters, document text, provider headers and tokens are not log fields. Unknown text is dropped or hashed when safe redaction cannot be established. Redaction is best effort for content supplied to a model; publishing a recall claim requires an evaluated entity corpus.

Encrypted prompt/context retention is opt-in per tenant, with purpose, retention and provider consent recorded. Use envelope encryption with KMS keys scoped by account/region and tenant encryption context; object permissions verify tenant/context independently. Langfuse/OTel carries safe metadata and protected record references. Full-text prompt telemetry is disabled unless an explicit reviewed configuration enables an isolated, access-controlled deployment.

Context read/replay requires a diagnostic grant, current resource access, audit and expiry/legal-hold checks. Model replay is not authorized to issue writes, payment/order changes or outbound webhooks. Deletion invalidates lookup/cache/index references and removes all object versions; encrypted key destruction follows documented legal/backup commitments.

## 5. File and invitation security

Presigned URLs bind key, content length/type constraints, checksum and expiry; server-side completion validates actual stored object/version and authoritative type detection. A guessed upload ID is insufficient. Invitation tokens are purpose-scoped, short-lived, hashed and revocable. Supplier upload roles cannot read all case attachments or tenant search.

Extraction jobs run with no cloud admin credentials, restricted object access, no external network, CPU/memory/time/output-size bounds and isolated temporary files. Never pass an uploaded filename into a shell command. Virus scanning and content classification precede publication/index eligibility.

K2.1 enforces these boundaries in `internal/supplier/intake`: 256-bit purpose-separated invitation/session tokens are stored only as digests; recipient addresses are peppered HMAC digests; upload capabilities bind tenant, invitation, upload ID, declared size/hash, purpose and a <=15-minute expiry. The ingress validates the actual body before storing it and never persists the supplier filename. The local filesystem adapter is synthetic-only (0700 directory, 0600 UUID-named files, atomic create-if-absent). The separately granted `keel_file_processor` role has tenant RLS and only upload-row read/update access; lease epochs fence expired workers. Tika connects directly to the fixed internal endpoint, ignores proxy environment variables and rejects redirects. The CI sandbox runs ClamAV/Tika with no egress and bounded resources. Its bundled ClamAV signatures prove a deterministic contract only; production signature freshness/update ownership and encrypted/versioned cloud object storage are not yet qualified.

## 6. Identity and keys

OIDC exact issuer/audience and asymmetric algorithm allowlist; reject algorithm confusion and missing expiry. Key cache has bounded stale use only for already-known signing keys; unknown keys fail closed during issuer outage. API keys are high-entropy secrets hashed at rest, scoped, rate-limited and rotated/revoked; display once.

History-cursor encryption keys are separate from OIDC, API-key and database credentials. Keep a versioned key ring in the deployment secret provider; do not log tokens or claims. Removing an old key before its seven-day token expiry intentionally invalidates those cursors and should be treated as a user-visible pagination reset.

Cloud access uses workload identity, not static environment credentials shared across roles. DB/API/provider secrets rotate with overlap and short cache lifetimes; rotation does not require image rebuild. TLS is required to every remote dependency; private networking does not justify disabled verification.

## Kafka broker transport

Only the named `NewLocalSyntheticBroker` and `NewLocalSyntheticConsumer` constructors permit plaintext, and they accept only loopback endpoints or the fixed `kafka` alias used by the local Compose network. Runtime/remote callers must use `NewSecure` and `NewSecureConsumer`; those constructors require an explicit non-empty CA pool, TLS 1.2 or newer, normal Go hostname verification, and SCRAM-SHA-512 credentials. The client does not fall back to system roots or plaintext. Client certificate overrides, custom verification callbacks, and TLS key logging are rejected so application callbacks cannot weaken broker identity checks or expose session secrets. Client TLS session caches are cleared for each generation so trust rotation requires a fresh certificate handshake.

Production deployments must load the CA bundle and SCRAM username/password from the secret/configuration provider. Keep the broker DNS name in the address (or set the exact expected `TLS.ServerName` when connecting through a proxy); the certificate SAN must cover that name. Trust is limited to the configured CA pool. Roll CA trust with an overlap pool containing both old and new roots, deploy/reload clients, then remove the old root after brokers have rotated certificates. Rotate SCRAM credentials with a second valid principal: call the relay's `RotateSecurity` after provisioning it, then revoke the old principal only after all clients have reconnected. Rotation validates the next config before swapping generations; publishes and consumer runs serialize with the swap, close old connections, and use the new TLS/SASL config on reconnect. Consumer offsets not committed before rotation are replayed through the idempotent projector inbox.

Kafka transport errors are redacted for the active username and password before returning to callers. Do not log `SecurityConfig`, TLS config dumps, secret-provider payloads, or raw authentication handshake data. The CI contract generates ephemeral broker/CA keys and tests valid SASL-over-TLS, untrusted CA, hostname mismatch, rejected credentials, and producer/consumer reconnection using rotated credentials. These fixtures do not qualify any managed Kafka service or replace runtime secret injection and deployment-specific broker trust configuration.

## 7. Security release requirements

Release fails on tenant leakage, agent privilege escalation, plaintext credential/PII canary leakage, unbounded parser resource use, unsigned/unverifiable artifacts or an unresolved exploitable critical dependency issue. Lower findings require a named owner, exploitability assessment and bounded exception expiry. Threat-model changes accompany new tools, endpoints, external providers or tenant-scope changes.

## 8. Expanded SaaS and purchasing boundaries

Organization/customer billing mapping is server-owned; signed subscription metadata does not replace verified tenant mapping. Billing role can reconcile entitlements/invoices but cannot approve orders or transfer procurement/AI balances. Subscription restriction blocks costly admissions while preserving safe closure/export and established workflow authority. Hosted processor handles subscription cards; supplier banking/card/payment instructions are outside product scope.

Supplier principals have tenant/supplier/resource grants, no internal membership. Internal/external threads, exports, notifications, search diagnostics and counts enforce current visibility. Business-unit scope adds permission filtering beyond tenant RLS; its revision participates in retrieval/cache/context eligibility. Owner/group/delegation changes revoke new authority; accepted decisions remain historical until an audited invalidation/supersession command. Final plan completion and budget conversion remain atomic.

Scoped workers keep distinct billing, email/chat, ERP and context/provider secrets. All new provider inputs use signature/inbox/dedup and bounded egress; notification templates and exports prevent header/HTML/spreadsheet injection. Risk questionnaires/contracts/invoices are untrusted documents, not model system instructions. Simulations/analytics are read-only, bounded and authorized; an AI suggestion cannot become an approval/override/PO issue by sharing a backend library.

Enterprise federation/SCIM/domain claims are verified and cannot hijack organizations; directory disable defeats stale JIT events. Support access is JIT/purpose scoped and audited. New product releases must pass malicious supplier, member-revocation, billing/order-decision races, form/rule cycles, entity leakage and connector scope tests before expanding availability.
