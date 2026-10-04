# Capacity and cost model

All numbers below are planning assumptions and qualification targets. They are not results. Capture actual hardware, index shape, provider policy and costs in signed benchmark reports before making public claims.

## 1. Initial production envelope

| Dimension | Initial envelope |
|---|---|
| Active tenants | 100; skewed distribution included in tests |
| Corpus | <=200k eligible chunks per tenant; <=2m shared chunks total |
| Ingress connections | 10k established across API replicas; 200 active ordinary requests; separate 100-stream test |
| Sustained commands | 100/sec combined; bursts 500/sec for 60s with admission control |
| Search | 50/sec sustained; top-100 candidates per retrieval branch |
| Model work | 20 actual provider generations concurrently initially; max 100 active streams via cache/queued/running states |
| Domain events | 200/sec sustained; 2k/sec burst; seven-day Kafka transport retention |
| Documents | 20 MiB/file; bounded extraction budget and tenant quota |
| Workflow cases | 10k waiting cases; low active-activity concurrency; no goroutine per case |

Larger tenants require a qualified storage/index tier or dedicated database. Lower resource profiles advertise lower limits. Do not fit every customer into one unchecked global ANN index.

## 2. Compute and connection budgets

Start with API 3x2 vCPU/4 GiB, executor 2x4 vCPU/8 GiB, and modest relay/projector/webhook/Temporal-worker replicas. These are benchmark starting shapes, not mandated final sizing. Extraction workers can have a separate sandbox profile.

Database example: a 300-connection safe limit reserves 60 for administration/maintenance, 60 for workers and at most 180 for API/search/brokers. Cap deployment maximums so `sum(replicas * pool_max)` plus overhead remains below the safe limit. PgBouncer transaction pooling can help ordinary traffic, but per-tenant agent sessions/session_user must preserve identity semantics; do not multiplex bound roles through one login.

SSE memory upper bound at 10k clients and a 256 KiB per-client cap is ~2.44 GiB before socket/runtime overhead. Therefore cap state queues lower for ordinary clients, coalesce updates, distribute streams across replicas and measure actual retained memory. The 10k qualification includes idle sockets separately from 100 simultaneous content streams. Backpressure is preferable to increasing queues without bound.

## 3. Work capacity

Little's law: active work approximately equals arrival rate times service time. For 2 model jobs/sec with 8s mean service time, expect 16 active generations before burst/failure headroom. Provider token/rate limits may be the bottleneck before CPU. Queue capacity is not a license to accept unlimited financial liability.

Fair claims enforce per-tenant active-job caps; profile starts at 4 active expensive jobs per tenant, global provider concurrency 20 and bounded queued job count. Age and wait-time percentiles guide admission/backpressure. Receivers persist jobs quickly; autoscaling executors from Kafka lag alone would miss the resulting database queue.

## 4. Search resource model

Raw float vector bytes at 384 dimensions are 1,536 bytes/vector, excluding row/index overhead. Two million vectors require about 3.1 GB raw vector values; HNSW and tuple overhead, lexical postings and duplicated versions can multiply that. Benchmark storage, cache working set and index build memory instead of assuming vectors are the entire footprint.

BM25 postings cost grows with distinct `(term,chunk)` pairs. Cap terms/query, postings examined, candidate count, lexical statement runtime and document publish batch size. Highly frequent terms and tenant skew are required benchmarks. Exact vector search is economical for small corpora but scales linearly; measure the crossover rather than choosing HNSW for every query.

## 5. Event/storage model

At 200 events/sec and 1 KiB average envelope, seven days is roughly 124 GB decimal (115 GiB) logical data before compression/replication/index overhead. Kafka three-way replication alone increases the storage footprint. PostgreSQL event history, indexes, usage and audit add separate storage. This illustrates why the initial throughput is a capacity envelope, not a claim that every installation is inexpensive.

Track retained bytes, event count, consumer lag, outbox age, WAL/archive volume and disk headroom. Disk pressure triggers admission reduction before logs/DB reach exhaustion. Outbox age >15 minutes or a configured 70%-of-budget backlog threshold disables new nonessential writes until recovery; choose absolute row/byte thresholds from qualification.

## 6. Spend model

`provider_cost = input_tokens * quoted_input_rate + output_tokens * quoted_output_rate + qualified_extra_fees` per attempt. Normalize quote units explicitly to micro-USD/token or per-million tokens. Distinguish cached-input pricing, reasoning tokens, tool fees and unknown-provider accounting capabilities.

`operation_cost = confirmed_provider_cost + estimated_compute_allocation + measured_storage/egress_allocation`. A user-facing billable price is a separate policy. Never present an allocation estimate as a provider invoice. Semantic cache savings use a counterfactual quote tagged estimated; actual cache-hit processing/embedding costs still count.

Cost rollups by tenant/endpoint/model require durable ledger records rather than high-cardinality Prometheus labels. Reserve for every possible charged attempt; unknown charges remain a liability until provider reconciliation. Model pricing changes version the quote used at admission.

## 7. Qualification workload

Report single-region and remote-region clients separately. Include 80/20 tenant skew, 10k idle keep-alives, ordinary read/write mix, 100 concurrent SSE clients producing realistic token rates, malformed/slow clients, document indexing, queue bursts and dependency failures. Report throughput, p50/p95/p99, rejection/error rates, RSS, CPU, GC, DB saturation, ANN recall, provider TTFT and cost.

Run long-enough soak tests to expose leak/rebalance/reconnect behavior (minimum 6h staging qualification; 24h before a production scale claim). Publish raw data and exact commands/artifact/config digests. A fast parser microbenchmark is not proof of end-to-end capacity.

## 8. Expanded SaaS/product workload economics

The preceding envelope is the technical starting profile, not a free capacity allowance for every later feature. Include billing/notification jobs, signup/trial abuse, bulk imports/exports, supplier portal, serial/parallel approval contention and procurement ledger locks in paid 1.0 qualification. K8 assigns finite shares of the same DB connection budget; the new role list does not increase pool totals automatically. Bulk jobs have per-org concurrency/storage caps and lower-priority worker classes so they cannot starve short commands.

Purchasing 1.5 benchmarks PO/amendment/receipt/invoice/contract events, ERP bursts, matching/allocation locks, scheduler load and retained artifacts. Revise Kafka topic/event storage, object/export lifecycle and posting-index forecasts from measured workload. Enterprise business-scope/risk/simulation/FX/dedicated tiers have distinct profiles. Per-region/customer tier scale is only advertised after actual measurement.

Unit economics model separates SaaS revenue from customer procurement value and provider/infra liability: subscription net revenue minus attributable platform/AI/OCR/storage/mail/connector/support/payment-processing cost. Shared durable foundation cost is allocated consistently with published policy. Margin targets and price require product/cost approval; no speculative amount is sold as proven profitability. Trial caps, prepaid/contracted allowances and opt-in overage policies bound exposure before invoice finality.
