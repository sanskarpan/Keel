# Keel local dependency profile

This profile starts real PostgreSQL with pgvector, Kafka, Redis and Temporal for local engineering. It uses synthetic fixture identities only. It is not a pilot or production deployment: credentials are intentionally public development constants, services use plaintext protocols, there is one broker/database instance, no provider credentials, no customer data and no external network egress from the Compose network.

## Requirements and commands

Install Docker Engine with Compose v2. The checked-in image references pin both upstream versions and immutable multi-platform index digests. Start with `make local-up`, inspect with `make local-health`, and stop with `make local-down`. `make local-seed` reapplies the idempotent synthetic tenant fixture to the local `postgres` database. It does not delete data. The named volumes persist between restarts; remove them manually only when you intend to destroy local state.

Host ports bind to loopback only: PostgreSQL `127.0.0.1:54329`, Kafka `127.0.0.1:19092`, Redis `127.0.0.1:16379`, Temporal frontend `127.0.0.1:7233`. From containers use `postgres:5432`, `kafka:9092`, `redis:6379`, and `temporal:7233`. Kafka auto-topic creation is disabled; the three default partitions and replication factor one are local development settings, not production topology.

The two stable tenant fixture IDs are `11111111-1111-4111-8111-111111111111` (`synthetic-alpha`) and `22222222-2222-4222-8222-222222222222` (`synthetic-beta`). They live under `local_fixtures`, separate from application-owned schemas. This profile does not establish RLS, least-privilege application roles, migrations, or tenant-isolation evidence; those remain K0.5 and later acceptance work.

## Limitations and qualification

Temporal runs the upstream `auto-setup` development image against its own PostgreSQL databases, with default visibility storage. Pinning this image is for reproducible local work only; it does not qualify a managed Temporal service. No cloud provider, region, residency, retention, OIDC, model, email, or billing capability is selected here. Do not use this profile for public/customer pilots. The production profile remains unsupported pending K0.1 provider/version qualification and the later security, privacy, operational, capacity and recovery gates.

Image versions, platform manifests and upstream source references are recorded in [`../../docs/TECHNOLOGY-BASELINE.md`](../../docs/TECHNOLOGY-BASELINE.md). Compose initialization runs only for an empty Postgres data directory; use `make local-seed` to replay fixture rows after initial startup.
