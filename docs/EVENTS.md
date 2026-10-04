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

This is the future domain-event model, not the current `keel.<env>.orders.v1` Kafka wire format. K1.4 emits only the seven identity/status metadata fields documented in §4; actor, causation, correlation and payload fields shown above are not currently serialized to Kafka. No raw PII, prompts or credentials belong in envelopes/headers. Schema registration checks compatibility before a future contract exposes approved typed business facts.

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

The order projector accepts only the bounded metadata envelope (`tenant_id`, `aggregate_id`, `aggregate_version`, `event_id`, `event_type`, `schema_version`, `occurred_at`). It resolves the exact tuple from retained immutable `event_outbox.safe_envelope`, verifies the canonical digest and metadata, then projects only order status/version; private order facts never enter Kafka or the read model. `event_outbox` is the versioned replay source and remains FK-linked to immutable order history. A future event schema requiring protected facts needs a separately authorized projection source.

For aggregate version `v`, the projector serializes on the tenant/order projection row. It records an inbox row unique by consumer/event ID and consumer/order/version. K1.5 pins the live projection to `order-projection-v1`; a second identity cannot share this projection until generation-scoped storage is added. A matching previously applied identity is a duplicate; a conflicting event identity or digest is quarantined and never advances the projection. A structurally valid tenant/event claim with no matching canonical outbox row is not trusted as tenant identity and goes to tenantless transport quarantine. Only a canonical row that proves tenant and event identity may produce tenant-scoped conflict metadata. Version `applied+1` applies only a legal status transition. A higher version is durably deferred; bounded replay loads missing canonical envelopes from PostgreSQL and applies only a contiguous chain. Missing or corrupt source rows move the deferred head to a durable blocked state and leave the aggregate behind rather than skipping a version. K1.5 implements live projection and per-aggregate gap repair; shadow projection generations and atomic read-pointer cutover remain a later rebuild phase.

`internal/platform/kafkarelay.Consumer` fetches records using a Kafka consumer group with automatic commits disabled. It preserves header occurrences, calls the projector once for the fetched record, and synchronously commits the offset only after the database transaction or digest-only quarantine has committed. Processing errors, invalid/non-durable dispositions and failed offset commits stop the loop without advancing the offset. A database commit followed by lost offset-commit acknowledgement intentionally redelivers; inbox uniqueness makes the repeat a no-op. Invalid schema/poison records with no trustworthy tenant identity are recorded in tenantless quarantine by trusted topic/partition/offset plus payload digest and bounded reason, without raw bytes. A transport quarantine persistence failure also leaves the offset uncommitted. K1.7 tests process/commit ordering, relay publish/ack loss, and group restart/rebalance with redelivery; no silent gap skip is allowed.

The decoder rejects duplicate JSON object keys and duplicate or unknown identity headers. Kafka adapters must preserve header occurrences as an ordered list until validation; converting headers to a map first loses duplicate evidence.

Job receivers commit after durable inbox/job insertion. They do not process a five-minute model generation inside a Kafka consumer poll loop. Executors claim the DB queue with fair tenant scheduling and fenced leases. KEDA therefore observes both receiver lag and durable runnable backlog. Consumer and executor throughput/age are reported separately.

## 5. Replay and schema evolution

Replay retains original event IDs and aggregate versions. K1.5 pins the live status projection to one consumer identity because its projection key has no generation dimension. A second consumer identity must not be started against this table. A future rebuild must add generation-scoped inbox/projection state, replay-boundary validation and an atomic read-pointer switch before it can use a new identity. Replaying into a live projection reuses inbox/effect uniqueness; it must not create new webhook deliveries or model calls unintentionally.

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
