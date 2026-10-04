# Technology baseline and provider qualification

**Decision status:** local synthetic development profile pinned; hosted pilot and production profiles are not qualified. This document records reproducible engineering inputs, not vendor approval, an SLA, or a commitment to customer-data processing. Evidence checked 2026-10-04 UTC.

## Local profile lock

| Component | Locked input | Evidence and scope |
|---|---|---|
| Go toolchain | `1.27.1` (`linux/amd64` archive SHA-256 `63d339f0da5ab53635a56f2490a7984dfe12dfcff22ad749f63edaf590168445`) | go.dev download archive checksum; module directive and `.go-version` in repository. Contract CI and tag release use this pin; only Linux/amd64 is emitted. |
| PostgreSQL + pgvector | `pgvector/pgvector:0.8.7-pg18-bookworm`, OCI index `sha256:2358fcba361ed2233a5ed81b5fe4ca779ccb304120ce531a3bf51c0ed7e2bc11`; server PostgreSQL 18.6 | pgvector upstream image manifest; PostgreSQL 18.6 is the current 18.x minor in PostgreSQL's versions feed. Local development, not a managed-provider qualification. |
| Kafka | `apache/kafka:4.3.1`, OCI index `sha256:77e3df9054047a88b520d0cc46e16696d3b22022e1d580aeccd2632df6532837` | Apache Kafka release and official container. Single combined KRaft broker/controller only. No managed-service compatibility asserted. |
| Redis | `redis:8.2.3`, OCI index `sha256:0908d9af26bf9b985e984a40a5eb82eed229b07a3317eee6843832c3cc3a9619` | Official Docker image and immutable manifest. Local cache/rate-limit development only. |
| Temporal | `temporalio/auto-setup:1.29.7`, OCI index `sha256:f14912b699cf73015ad5c4fc18d522d4b014db90e794039214dfb7c022c2644f` | Official local auto-setup image. 1.29.7 is not the current Temporal server release; chosen to match an available, documented local bootstrap image. Not Temporal Cloud or production compatibility evidence. |
| Compose | Docker Compose `2.40.3` verified in this workspace | `docker compose version`; supported contributor baseline is Compose v2. |

Every image in `deploy/compose/compose.yaml` uses an immutable OCI index digest. A changed digest is an explicit reviewed baseline change. The repository now defines a tagged Linux/amd64 Go-binary release workflow with an SPDX SBOM, checksum list, GitHub artifact provenance and SBOM attestation. It does not build container images, verify local Compose image signatures, provide a CVE policy, qualify a platform matrix, or define an upgrade cadence; none of those are implied by digest pinning or artifact attestations.

## Provider capability decision

The only enabled profile is `local-synthetic`. PostgreSQL/pgvector, Kafka, Redis and Temporal run as single local containers on an internal-only Compose network. Host ports bind to loopback. There is no externally hosted pilot profile, production region, backup/restore commitment, or customer-data path. AWS MSK's published supported-version list checked for this decision did not list Kafka 4.3.1; therefore MSK compatibility is explicitly unqualified. No other managed service is selected by inference from a compatible local image.

| Open research question | Local profile disposition | Accountable workstream | Evidence/exit condition |
|---|---|---|---|
| Q-01 versions and managed capabilities | Versions above lock local reproducibility only. Hosted-provider availability, version compatibility, limits, region, SLA, restore and price remain **open**; hosted pilots are blocked. | Platform/SRE; named delivery owner unassigned | `research/SOURCES.md`; local image manifests; provider-specific support matrix and tested managed compatibility PR required before hosted pilot. |
| Q-03 OIDC, residency and customer retention | Disabled/not applicable to synthetic local-only fixtures; no identity provider, region or customer content is configured. | Identity/Security; named delivery owner unassigned | `docs/SECURITY.md`; provider/region, data-flow and retention decision plus negative/access/erasure tests required before customer data. |
| Q-04 model usage, retention and idempotency | Disabled; no model provider credentials, model calls, token accounting, cache or generated customer output in this profile. | AI Platform; named delivery owner unassigned | `docs/SECURITY.md`, `docs/CAPACITY-AND-COST.md`; provider terms/capabilities, ledger semantics, budget/retry tests and reviewed provider registry required before enablement. |
| Q-09 sensitive context and Langfuse | Disabled; no prompt/replay content or Langfuse exporter is configured. | Observability/Security; named delivery owner unassigned | `docs/SECURITY.md`; documented content policy, encryption/access/retention controls and telemetry canary scan plus adapter contract tests required before enablement. |

Workstream accountability is not an assigned person. No customer/pilot owner or provider commitment was available in repository evidence, so none is fabricated. Q-01 is a hard gate for any pilot; K0.1 remains open until the hosted profile and these owner/decision requirements have evidence and review.

## Primary source references

- Go downloads and archive checksums: <https://go.dev/dl/>
- PostgreSQL current versions feed: <https://www.postgresql.org/versions.json>
- pgvector tags: <https://hub.docker.com/r/pgvector/pgvector/tags>
- Kafka release and Docker docs: <https://kafka.apache.org/community/downloads/> and <https://hub.docker.com/r/apache/kafka>
- Redis tags: <https://hub.docker.com/_/redis/tags>
- Temporal Docker builds and auto-setup: <https://github.com/temporalio/docker-builds/blob/main/docker/auto-setup.sh> and <https://github.com/temporalio/docker-builds/blob/main/docker-compose.yml>
- AWS MSK supported versions: <https://docs.aws.amazon.com/msk/latest/developerguide/supported-kafka-versions.html>

Digest evidence is tied to OCI image manifests returned by the registry on the decision date. It should be rechecked together with upstream security support windows before a production/hosted profile is selected.

The release workflow pins GitHub `actions/attest` v4.1.0 at `59d89421af93a897026c735860bf21b6eb4f7b26`, Anchore `sbom-action` v0.24.3 at `66cbf4bc1f1c0d2edc94016e65bc221b6bb0ad6c`, and Syft v1.54.0. Public release evidence is stored through GitHub's artifact attestation API and the tag-created GitHub Release. This configuration has not yet run for a Keel version tag.
