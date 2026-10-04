# Release and migration operations

## Release contents and trust

Pushing a valid `vMAJOR.MINOR.PATCH` tag runs `.github/workflows/release.yml`. It checks tests, vet and race behavior, builds a Linux/amd64 Go binary with the tagged version, source revision and build timestamp embedded, creates a gzip archive, generates an SPDX JSON SBOM for that binary, and publishes SHA-256 checksums for the downloadable archive and SBOM. GitHub's OIDC-backed artifact provenance attests the archive; a GitHub SBOM attestation binds the SPDX document to the binary subject. The release attaches the archive, SBOM and checksums. GitHub's `actions/attest` v4.1.0, Anchore SBOM Action v0.24.3 and Syft v1.54.0 are pinned to reviewed commits/versions rather than floating action tags.

After downloading assets, verify checksums with `sha256sum -c SHA256SUMS`. Verify provenance and SBOM using GitHub CLI:

```sh
gh attestation verify keel-v1.2.3-linux-amd64.tar.gz --repo sanskarpan/Keel
tar -xzf keel-v1.2.3-linux-amd64.tar.gz
gh attestation verify keel-linux-amd64 --repo sanskarpan/Keel --predicate-type https://spdx.dev/Document/v2.3
```

The SBOM attestation is bound to the uncompressed binary. The archive provenance describes the workflow/source identity. Review the attestation's source revision, workflow and signer identity before deployment. A valid signature establishes artifact provenance and integrity; it is not a vulnerability clearance, approval, or claim that production qualification passed. No artifact is released automatically from a pull request. Before the first customer deployment, configure repository rules to restrict `v*` tag creation and document the accountable release approvers.

The `release` GitHub Environment must have required human reviewers configured, and a repository ruleset must restrict `v*` tag creation to accountable release maintainers before any release tag is pushed. The workflow validates strict `vMAJOR.MINOR.PATCH` syntax and targets that protected environment. These controls are GitHub repository settings and are not created by the workflow file; verify them before the first tag. Without the environment protection, the review gate is absent.

The current release is one Linux/amd64 binary, not an OCI image. There is no multi-architecture qualification, container signing, CVE policy, deployment automation, or production release yet. Expand only alongside platform-specific tests, dependency policy and recovery evidence.

## Migration contract

Run `keel migrate` as a one-shot deployment job before compatible runtime rollout. Supply `KEEL_MIGRATION_DATABASE_URL` from a secret manager to a dedicated non-superuser login with permission to `SET ROLE keel_schema_owner`. Do not add credentials to flags, logs, model/tool context or normal worker environments. A one-time database bootstrap must create the `keel_schema_owner`, migration login, and a `keel_meta` schema owned by `keel_schema_owner`; the checked-in role SQL performs this only for the local synthetic profile. The command uses a global fixed PostgreSQL session advisory lock, sets the schema-owner role on the same dedicated connection, creates the ledger table if needed, validates the complete source/ledger history, then applies one versioned SQL file and its SHA-256 ledger row in a single transaction.

Migration filenames are `NNNN_description.up.sql` with unique ascending versions. Applied files are immutable and edits, removals or backfills fail closed. Publish a new forward repair when needed. The runner supports transactional DDL/DML only; do not include transaction-control statements or `CREATE INDEX CONCURRENTLY`. No destructive down migration is offered. An interrupted process releases its lock when the database session closes. Re-run only after checking the ledger and affected schema; a committed migration is skipped by identical checksum on retry.

The first domain migration should ship with its owning feature and have review for lock duration, table rewrite, backfill progress, mixed-version app compatibility, RLS/grants and forward repair. The runner mechanics are implemented and integration-tested; no domain schema migration is bundled yet.
