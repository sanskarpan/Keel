# K6 slice: read-only operator web UI

Issue #459 (parent #51, checklist item K6). PR #460 merged as
`5ade46d094164eb7db46d062dbf0ae64c2f7bd7a`; contract CI #728 passed on reviewed head
`6c20260da466f82dee3d5f8dfcc12454bb3b542a`. This slice adds a minimal read-only dashboard
to the operator API. No migration was needed and no JSON API behavior changes.

## Contract

- `GET /ui` renders server-side HTML (auto-escaped templates, no JavaScript) with recent
  reconciliation runs, selected replay candidates and skip reasons: identities, counts and
  timestamps only, never URLs, payloads, keys, secrets or receiver content.
- The UI requires the same bearer principal with the replay scope; tokens stay in the
  `Authorization` header and never appear in URLs. Mutations stay on the JSON API.
- Template output renders into a buffer first, so a rendering failure returns a clean
  problem response instead of a half-written page.
- Coverage includes content assertions, leak checks (key IDs, URLs, secrets), auth matrix
  (401/403) and the buffered-failure path indirectly through strict template execution.

## Limits

No mutations from the UI, no OIDC, no production deployment. Browsers need header
injection since tokens are header-only by design.

## Verification

- `go test -count=1 ./internal/delivery/webhook/httpapi/`.
- `go vet` on the touched package; Linux CI covers the race detector.
