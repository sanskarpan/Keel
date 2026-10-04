# K1 event-sourced order gate evidence

**Decision:** PASS for the local-synthetic K1 order profile, based on contract CI run #57 for PR #115 and the K1.5/K1.6/K1.7 contract suites. This decision does not enable a production or customer-data deployment; K0 and K7 gates remain prerequisites.

## Invariants and evidence

| Invariant | Evidence |
| --- | --- |
| An accepted command appends its event, immutable outbox envelope, snapshot, idempotency result, and state-feed row atomically. | `TestPostgreSQLLateStateFeedFailureRollsBackCommandAndCanRetry` and `TestPostgreSQLCommandOutboxAndStateFeedAreAtomicAndPrivate` in `internal/orders/postgres/repository_integration_test.go`; K1.2/K1.3 checklist evidence. |
| Replay is deterministic, contiguous, and rejects duplicate IDs, gaps, cross-aggregate history, malformed payloads, and illegal transitions. | `TestReplayRejectsGapsDuplicatesCrossAggregateAndMalformedPayload`, `TestOrderLifecycleReplaysToTheCommandSnapshot`, and the independent transition reference model in `internal/orders/model_test.go`. |
| Persisted event hashes/index metadata and the authoritative snapshot agree with a complete replay. | `Repository.Events` validates each event digest and indexed identity/version/type/time, replays the full history, and verifies it against the stored snapshot; exercised in PostgreSQL repository and history integration tests. |
| Reordering and duplicate delivery cause one logical effect per canonical event. | `TestPostgreSQLProjectorDefersReplaysAndDeduplicates` delivers version 2 before version 1, replays the missing canonical range, then delivers late version 1 and conflicting records. The integration test now compares event replay, command snapshot, and projection watermark/status, and requires exactly one applied inbox row per canonical event. |
| A lost relay acknowledgement or Kafka offset-commit response cannot repeat a durable domain effect. | `TestPostgreSQLKafkaConsumerReplaysUncommittedDBEffectAcrossGroupRebalance` exercises broker acceptance followed by DB-ack loss, rejected offset commit/redelivery, and accepted offset commit/response loss. The stable event identity and inbox deduplicate repeated delivery. |
| Projector lag is explicit and does not replace command authority. | `TestPostgreSQLAuthoritativeReadWatermarkAndBoundedHistory` and `TestPostgreSQLConcurrentCommandAndProjectorReadsShareOneSnapshot` check the command snapshot and projection watermark together, including lag, current state, concurrent reads, and corruption refusal. |

Kafka delivery is **at least once**. These tests establish idempotent logical projection effects for the exercised failures; they do not claim exactly-once broker delivery or cover every broker/provider implementation.

Security/privacy review: command authorization and tenant scope are enforced before repository operations; forced RLS and non-owner integration roles cover persisted event/projection access; event envelopes are allowlisted and contain no line items or evidence content; quarantines retain bounded reason codes and digests rather than untrusted payloads; remote Kafka uses verified TLS/SCRAM and redacts active credentials. No new personal or supplier evidence fields are added by the gate. Residual risks are the explicitly disabled production identity/runtime wiring and the lack of a generation-scoped production projection rebuild, both tracked by later gates.

## Security, privacy, and operational scope

The persisted order event history is the canonical source. Kafka carries the allowlisted metadata-only envelope; it does not carry order line items or private evidence. Unknown or conflicting source claims are quarantined by digest and bounded reason. K1.4-SEC additionally requires verified TLS and SCRAM for remote broker clients and keeps plaintext constructors constrained to the local synthetic network. CI run #57 passed the pinned real-broker TLS/authentication and rotation contract plus PostgreSQL, static, race, and build checks.

Accountable implementation and local-profile operations owner: **sanskarpan (repository owner)**. This assigns responsibility for the current repository and synthetic profile only; it is not an on-call rota or production service ownership. The service remains disabled for customer data until K0 authentication/runtime wiring, K0/K7 operational gates, and a production owner/on-call arrangement are completed.

## Rollback and cleanup

This gate introduces no schema migration or production deployment. The merged code change can be rolled back with a revert of its PR merge commit. CI uses disposable PostgreSQL/Kafka services; test database handles are closed with test cleanup hooks, and the secure-broker contract uses an ephemeral broker and generated certificate material. The dedicated K1.7 topic/group names are test-only and provisioned in the local/CI profiles. No customer data or durable production broker state is created by this evidence run.

Production projection rebuild/cutover is not claimed here: the current projector identity is pinned, and generation-scoped shadow rebuild remains a separate release gate. Until that work and K0 runtime authorization are qualified, keep the local-synthetic profile as the only enabled profile.
