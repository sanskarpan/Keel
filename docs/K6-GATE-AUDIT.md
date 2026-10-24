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

Against an isolated PostgreSQL database with migrations through `0055`:

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

1. **No production operator identity or mounted replay route.** The API is unmounted and requires
   injected authentication/authorization. K0 identity and network policy must qualify before the
   gate can claim end-to-end authorization.
2. **No real provider adapter or late/impossible callback policy.** The callback inbox proves the
   dedup/conflict boundary, not a provider's late-event behavior or remote-state reconciliation.
3. **Reconciliation is not production-complete.** Historical endpoint status, provider/callback
   observation reconciliation, scheduler integration, an operator reconciliation UI and metrics are
   open.
4. **Quotas are partial.** A configurable active-endpoint policy exists (default 100), but due-delivery/attempt quotas and over-cap remediation do not.
5. **Operational qualification is partial.** Source-controlled local alert rules and a dashboard
   contract exist; there is no Alertmanager, paging owner, hosted dashboard, production scrape or
   SLO qualification.
6. **Key management is process-global.** The worker keyring holds one active plus at most one
   previous key; there is no per-endpoint key provider/KMS integration.
7. **Repair semantics are operator-explicit.** Current-active repair can backfill an old event to an
   endpoint active now; historical endpoint status reconstruction is absent.
8. **No content-free production logging contract.** Delivery IDs may be safe, but URLs and
   transport errors must not be logged; observability currently relies on metrics and local alerts.

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
