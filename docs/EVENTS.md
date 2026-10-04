# Events, transport and external effects

## 1. Event envelope

```json
{
  "event_id": "<uuid>",
  "event_type": "order.submitted",
  "schema_version": 1,
  "tenant_id": "<uuid>",
  "aggregate_type": "order",
  "aggregate_id": "<uuid>",
  "aggregate_version": 2,
  "occurred_at": "2026-10-04T12:00:00Z",
  "actor_ref": "<opaque-reference>",
  "causation_id": "<command-id>",
  "correlation_id": "<operation-id>",
  "traceparent": "<validated-w3c-context>",
  "payload": {"supplier_id": "<uuid>", "evidence_digest": "sha256:<digest>"}
}
```

No raw PII, prompts or credentials in envelopes/headers. Event schema registration checks compatibility. Only opaque references and approved typed business facts are public to the bus. Protected context lives behind authorized retrieval.

## 2. Topics

| Topic | Key | Group / purpose |
|---|---|---|
| `keel.<env>.orders.v1` | tenant + order ID | projections and integration fanout; contiguous aggregate versions |
| `keel.<env>.suppliers.v1` | tenant + case ID | workflow/status projections and onboarding integration |
| `keel.<env>.jobs.v1` | tenant + logical job ID | durable-inbox receivers insert DB jobs; no lengthy work on poll loop |
| `keel.<env>.usage.v1` | tenant + inference ID | safe usage observations; PG ledger remains authoritative |
| `keel.<env>.deadletters.v1` | original topic/key | quarantine metadata/payload references, cause and replay status |

Initial order/job topics use 12 partitions in a production-small profile, three replicas, `min.insync.replicas=2`, producers `acks=all`. Preview topics can use smaller partition counts but must test rebalance separately. Schema/catalog and Kafka administrative permissions are platform-only. Retention defaults seven days for transport; authoritative order history lives in PostgreSQL. Quarantine references expire under privacy policy.

## 3. Outbox publication

Command appends business event and outbox atomically. Relay claims an aggregate publish-head lease, fetches next unpublished version, publishes with stable event ID and waits for broker acknowledgement. It advances the head only with valid owner/epoch. A crash after broker acknowledgement but before DB update republishes the same logical event.

Do not mark published before acknowledgement. Do not claim unrelated outbox rows with SKIP LOCKED and assume per-aggregate order survives concurrent producers. Intended per-stream sequencing plus consumer gap detection is required. A stale publisher may still have an external send in flight after lease loss; DB fencing cannot retract it. Duplicate/version checks make that harmless for business effects.

## 4. Consumer transaction and gaps

Consumer validates size/schema, identifies trusted transport environment and tenant, and performs an inbox insert and projection mutation in one tenant transaction. For aggregate event version `v`: if applied version >=v, verify matching logical event/payload digest and treat as duplicate; if applied version=v-1, apply and advance; if applied version<v-1, persist deferred gap and schedule bounded source-of-truth replay. Conflicting same-version payloads quarantine and page operators.

Commit Kafka offset only after DB commit. DB commit with a lost offset commit redelivers; inbox uniqueness suppresses effects. Invalid schema/poison records are durably quarantined before advancing the transport offset; an aggregate requiring the missing event remains explicitly blocked/degraded. No silent gap skip.

Job receivers commit after durable inbox/job insertion. They do not process a five-minute model generation inside a Kafka consumer poll loop. Executors claim the DB queue with fair tenant scheduling and fenced leases. KEDA therefore observes both receiver lag and durable runnable backlog. Consumer and executor throughput/age are reported separately.

## 5. Replay and schema evolution

Replay retains original event IDs and aggregate versions. A new consumer identity rebuilds an isolated projection, validates counts/hashes/invariants against canonical event streams, then switches its read pointer. Replaying into a live projection reuses inbox/effect uniqueness; it must not create new webhook deliveries or model calls unintentionally.

Event schemas are additive by default. Historical payload interpretation uses the recorded schema version and a deterministic upcaster. Consumer compatibility is tested against all retained historical fixtures. Breaking semantics introduce a new event type/major topic and controlled migration. Removing fields requires archive/replay/workflow compatibility review, not merely green current-code tests.

## 6. Webhook wire contract

Headers include event ID, delivery ID, attempt ID, timestamp and signature key ID. Sign `timestamp + "." + exact_body_bytes` using HMAC-SHA256; rotate keys with an overlap window. Accept receivers' retry behavior only under explicit adapter policy. Replay preserves event ID but emits a fresh attempt ID/timestamp/signature. Receivers are instructed to deduplicate by event ID and verify timestamp tolerance.

Persist attempt classification, latency, redacted response snippet and next retry. Never persist Authorization/Set-Cookie headers or unrestricted external response bodies. SSRF protection denies metadata/private/loopback/reserved destinations, redirects to disallowed networks, ambiguous IP forms and DNS rebinding; approved private endpoints require a separate reviewed network connector.

Retry full jitter uses `min(6h, 5s * 2^attempt)` within maximum 12 attempts/24h. A bounded endpoint circuit breaker and tenant delivery quota prevent outages causing storms. DLQ/exhaustion state is durable. Manual replay is capped (500 selected deliveries), audited and rechecks endpoint policy/signature configuration.

## 7. Reconciliation contract

Inbound callbacks persist a provider event ID and hash before application. Duplicate same ID/different hash is a security/data-integrity conflict. Adapter reconciliation fetches remote status under rate and spend limits, compares to canonical state and records missing/late/conflicting observations. Cursors advance only when pages and effects are durably accounted. External reads happen outside DB transactions; state is revalidated inside the effect transaction.

Repair actions carry stable logical repair IDs. They may redeliver a missing notification or quarantine a mismatch; they cannot rewrite an approved/rejected order or manufacture a supplier approval. A report links source cursor, observed version, intended repair and final effect.

## 8. Versioned SaaS and fulfillment events

1.0 adds explicit order approval-step progress and plan supersession; `order.approved` remains the final all-required-step outcome. Procurement reservation/commitment ledger entries reference command/event IDs and commit atomically with the relevant outcome. Notification intents consume the same stable event without reapproving the order. Commercial billing inbox/entitlement updates are a separate provider/domain event family and cannot manufacture purchasing events.

1.5 introduces distinct PO/sourcing/receipt/invoice/contract aggregates and additive versioned event schemas, with own contiguous stream versions and permanent logical effect IDs. Where Kafka transport is needed, reviewed topic catalog adds `keel.<env>.procurement.v1` and `keel.<env>.contracts.v1`; key = tenant + aggregate type + ID, with schema-compatible envelopes. Critical financial transitions remain in PostgreSQL, not separate Kafka transactions. Topic allocation/retention/partition and producer permissions remain platform-owned; qualification revises event-volume/storage forecasts.

New event facts carry immutable version/line/packet IDs, minor units/currency and source refs, never raw supplier contacts, invoice text or secret payment credentials. ERP handoff uses stable external document/version keys and observe-before-retry; incoming actuals transition ledger once by provider effect uniqueness. Replay rebuilds projections without reissuing POs, reposting invoices, emailing customers or altering SaaS entitlements unless an explicit audited effect repair is authorized.
