# Keel contracts

These are interface and compatibility contracts, not proof that a runtime route or event producer is implemented. Order endpoints are design contracts for K1; SaaS, supplier and AI routes are added with their implementation issues. This keeps the initial wire surface reviewable while making clear where the broader product docs describe later work.

`openapi/openapi.yaml` defines the initial health/version and order vertical slice. It derives tenant identity only from authorization, requires idempotency for mutations and optimistic concurrency for order submission. `events/order-submitted.v1.schema.json` is the strict immutable event envelope for the first event type. Future event types receive distinct versioned schemas; unknown payload fields do not silently pass.

`deployment-recipe.schema.json` implements the shared v1.1 recipe shape from `shared/CONTRACTS.md`. The fixtures are conformance examples only: `example.invalid` image and attestation references do not identify deployable or signed artifacts. No preview or production is enabled by these fixtures. Product role/dependency allowlists are explicit; additions require contract review.

`go test ./...` loads and validates the OpenAPI document, compiles the JSON Schemas, accepts positive fixtures and rejects deliberately malformed negative fixtures. The same command runs on every pull request in `.github/workflows/contract.yml`. Canonical cross-repository recipe changes must be coordinated with Ghostlight before either consumer adopts a new major/minor contract.

Breaking HTTP semantics require a new API major version. Event meaning is immutable: breaking event meaning or required payload uses a new event type/version and controlled upcast/replay. New optional recipe fields are additive only if every consumer has an explicit compatibility rule; unknown roles and dependencies are always rejected.
