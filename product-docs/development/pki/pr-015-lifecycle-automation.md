# PR-015 — Certificate Lifecycle Automation and Fleet Operations

Implemented by the PR-015 delivery branch.

## Objective

Make certificate expiry visible and actionable before it becomes an outage, and
give operators the fleet-level operations a certificate platform is expected to
have.

Short certificate lifetimes are the platform's primary revocation control. That
strategy is only safe if renewal is driven rather than hoped for, which makes this
PR a prerequisite for the ephemeral tier rather than a convenience.

## Dependencies

PR-007 for renewal, PR-008 for revocation. PR-014 if enrollment lands first.

## Scope

- **Expiry visibility.** A sweeper that identifies certificates entering their
  renewal window and those approaching expiry, and emits `certificate.expiring`
  domain events through the existing outbox. Idempotent per certificate per
  window, so a restart does not re-notify.
- **Expiry queries.** List certificates by expiry window, issuer, tenant, and
  status, with authorization filtering applied in SQL like every other Atom
  listing.
- **Fleet operations.** Bulk revocation by tenant, by issuer, and by principal
  group, executed in bounded batches with per-item outcome reporting. Bulk
  issuance is explicitly *not* included — see non-goals.
- **Authority expiry.** The same visibility for CA certificates. A tenant
  intermediate that expires without a prepared successor is a tenant-wide outage,
  and it must be surfaced far enough ahead to run the rotation procedure in
  PR-003.
- **Metrics.** Issuance, renewal, revocation, and enrollment rates and failure
  counts; certificate counts bucketed by time-to-expiry; CRL size and generation
  time; authority time-to-expiry. All non-secret.

## Non-goals

Bulk issuance, device onboarding workflows, notification delivery (email, webhook,
chat), and any consumer-specific automation. Atom emits events; delivery and
presentation belong to whoever consumes them.

## Design constraints

- The sweeper is a background job in a service that may run as multiple replicas.
  It must not double-emit; coordinate the same way existing periodic work does.
- Batch operations must not hold a transaction across an unbounded row set, and
  must not open a second pool connection while a transaction is held.
- Every emitted event carries issuer, credential, entity, and tenant identifiers
  and no secret material.
- Renewal thresholds come from the certificate's profile, not from a global
  constant.

## Acceptance criteria

- A certificate entering its renewal window produces exactly one event per window,
  across restarts and replicas.
- Expiry listings are authorization-filtered and paginate over large fleets.
- Bulk revocation reports per-item outcomes and is safely resumable after failure.
- An authority approaching expiry is surfaced with enough lead time to complete
  rotation.
- Metrics expose the lifecycle state of the fleet without exposing key material or
  subject secrets.
- Disabling automation degrades to current behaviour rather than failing issuance.

## Mandatory tests

Sweeper idempotency across restart and concurrent replicas, event content and
outbox transactionality, expiry-window boundary conditions, authorization
filtering on listings, bulk revoke partial failure and resumption, authority
expiry surfacing, and metric emission without secrets.

## AI execution prompt

Implement expiry visibility, fleet queries, bulk revocation, and metrics. Emit
events; do not deliver notifications. Do not add bulk issuance. Follow the
repository's existing outbox, transaction, and background-job conventions rather
than inventing a scheduler.
