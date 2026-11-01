# K6 gate audit

Parent gate: issue #51. This audit reviews the implemented K6.1-K6.5 evidence against the gate
criterion:

> no replay causes unauthorized/duplicate domain transitions or bypasses egress policy.

The gate remains **open**. The code/evidence supports the criterion at the reviewed boundaries, but
production identity, provider-adapter, deployment and operational qualifications are not complete.

## Criterion breakdown

| Criterion | Evidence | Status |
| --- | --- | --- |
| Replay requires operator authorization | `authorize_webhook_replay_requeue` is `keel_operator`-gated; direct transition access is revoked; `TestAuthorizeReplayRequiresOperatorCapability`; unmounted HTTP handler requires injected principal + `CanReplayWebhooks`; `TestListCandidatesAuthorizationAndAuthentication`, `TestReplayMapsDomainErrors` | Met at code/DB level; production identity/mount open |
| Replay cannot duplicate a domain transition | Replay transitions only a failed/exhausted delivery to pending; it does not touch order/case state; one replay per delivery and append-only transition guard; `TestAuthorizeReplayRequeuesWithoutFreshBudget`, `TestAuthorizeReplayConcurrentSingleWinner`, callback-inbox exactly-once tests | Met |
| Replay cannot bypass endpoint revision/key checks | Candidate selection requires active endpoint at the exact revision and a ready key; requeue rechecks the exact revision; executor refuses mismatched revisions/keys; `TestAuthorizeReplayRequiresEligibleEndpoint`, `TestQualificationReplayAfterKeyRotationFailsClosed` | Met |
| Replay cannot bypass egress policy | Executor uses the K6.2 HTTPS/port/TLS/DNS-vetted client; every dial re-resolves and pins; `TestQualificationReplayAfterDNSChangeFailsClosed`; egress mixed-answer/re-resolution/pinning tests | Met |
| Duplicate/late callbacks do not double-apply | Callback inbox apply-once, exact redelivery duplicate, payload/tenant conflict, rollback and concurrent delivery tests | Met for the inbox boundary; provider-specific late policy open |
| Receiver failure/retry/exhaustion is bounded | Worker retry/exhaustion/breaker/lease/fencing tests; `TestQualificationReceiverFailureThenRecovery` | Met |
| Replay after secret/DNS change fails closed | `TestQualificationReplayAfterKeyRotationFailsClosed`, `TestQualificationReplayAfterDNSChangeFailsClosed` | Met for the tested boundaries |

## Verification run

Against an isolated PostgreSQL database with migrations through `0062`:

```text
go test -count=1 ./internal/delivery/...
ok  github.com/sanskarpan/keel/internal/delivery/callbackinbox
ok  github.com/sanskarpan/keel/internal/delivery/webhook
ok  github.com/sanskarpan/keel/internal/delivery/webhook/httpapi
ok  github.com/sanskarpan/keel/internal/delivery/webhook/metrics
ok  github.com/sanskarpan/keel/internal/delivery/webhook/postgres
ok  github.com/sanskarpan/keel/internal/delivery/webhook/scheduler
ok  github.com/sanskarpan/keel/internal/delivery/webhook/worker
```

`go vet ./internal/delivery/...` and `go build ./...` also pass. Local `go test -race` is unavailable
on this Windows toolchain; Linux contract CI runs the race suite. `promtool` validates the local
alert/config files and `docker compose --profile monitoring config --quiet` passes.

## Blockers

1. **Production operator identity: bearer-token mounting landed.** The `operator-api` role serves the operator handler on its own listener with per-tenant bearer tokens (constant-time compare, scoped grants), loopback-only by default with an explicit non-loopback opt-out, and DB readiness probes. OIDC/mTLS and production deployment remain open.
2. **No real provider adapter or late/impossible callback policy.** A code-owned synthetic HMAC
   verifier covers local development and tests, generalized into a configured multi-provider
   registry with per-provider secrets and tenant isolation; every claim outcome is recorded in an
   append-only provider observation trail with redelivery delays; the callback inbox proves the
   dedup/conflict boundary. Owner direction 2026-11-01 confirms generic HMAC as the provider
   direction, so vendor-specific schemes are out of scope unless a vendor is named. A provider-owned adapter with vendor-specific signature, rotation
   and tenant rules, the late-event business policy and remote-state reconciliation remain open.
3. **Reconciliation is not production-complete.** Provider/callback observation reconciliation
   is open; plan and repair both revalidate against endpoint state at each event's time, recent runs with repair totals are
   readable through the operator API and a read-only web UI, and plan/repair counters exist in the local
   metrics recorder behind a nil-safe store hook. The scheduler accepts an opt-in dry-run scan hook, but no runtime wires it yet
   because planning requires the operator capability.
4. **Quotas are partial.** A configurable active-endpoint policy (default 100) and a per-tenant per-pass delivery lease policy (default 5, at most 100) exist; the scheduler leases at most the minimum of the process batch and the tenant limit and leaves the remainder due. Global due-backlog caps, attempt quotas, fair-share ordering and over-cap remediation do not.
5. **Operational qualification is partial.** Source-controlled local alert rules for delivery
   and reconciliation, SLO burn alerts, a dashboard contract and an alert response runbook exist, with local Alertmanager routing to a working local alert sink (PagerDuty removed per owner direction; any free incoming-webhook URL can replace the two receiver URLs); there is no escalation or on-call ownership,
   hosted dashboard, production scrape or production SLO qualification.
6. **Key management is process-global with file sourcing.** The worker keyring holds one active plus at most one
   previous key, sourced from base64 environment secrets or a JSON key file; there is no per-endpoint key provider/KMS integration.
7. **Repair semantics are operator-explicit.** Plan and repair revalidate each event against
   the endpoint status recorded at the event's time; inactive-then or history-less identities
   never become gaps, and stale gap rows repair to audited skips instead of inserts.
8. **Logging is aggregate-only and not operationally qualified.** The worker logs fixed pass counts and no tenant/endpoint/delivery IDs, URLs, payloads, keys or raw errors, but log shipping, retention, sampling and production logging qualification are absent.

## Residual risks

- Any process holding the `keel_operator` database credential can authorize replay; credential
  isolation and workload identity remain release gates.
- The unmounted API is safe only while it stays unmounted; mounting it without the injected
  identity/authorization adapters would be a serious regression.
- The endpoint policy protects new growth only; lowering a limit does not deactivate legacy over-cap endpoints.
- Candidate listing is capped at 5,000 rows; operators must narrow with delivery filters/limits.

## Recommendation

Keep the K6 gate and issue #51 open. The next release-gating work is K0 identity/session and network
qualification, a provider adapter/late-callback policy, production key management, and deployed
monitoring/on-call ownership. The reviewed code path itself has no known unauthorized or
duplicate-domain-transition path in the tested boundaries.
