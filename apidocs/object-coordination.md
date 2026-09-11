# Object coordination through GraphQL

The additive coordination API lets a trusted application keep related metadata in
Atom without giving up conditional writes or cross-worker reservations. Existing
identity/resource APIs remain available and automatically advance object revisions.

- `Entity.revision` and `Resource.revision` are returned from the same SQL snapshot
  as their attributes.
- `commitObjectChanges(requestId, changes, guards)` accepts 1–100 operations. Each
  target appears once. Operations are `create`, `update`, `delete`, or `check`.
  Existing targets require `expectedRevision`; any conflict rolls back the batch.
- Creates take an explicit UUID, kind, optional tenant, name, alias, and attributes.
  Updates replace attributes. They cannot move a tenant, attach a profile, change
  identity kind, or modify credentials. Entity writes support unprofiled
  `application` entities; credential-bearing applications use identity lifecycle
  APIs for deletion. Resources use their existing arbitrary kind vocabulary.
- Creates use Atom's existing tenant/platform capability gate. Existing targets
  use the canonical PDP, including deny precedence and the caller's token ceiling.
  Configuration-managed objects cannot be edited/deleted. Active tenants are
  locked through commit. Application status/grant cache barriers cover writes.
- Optional guards must match a live lease's object, authenticated actor, holder
  UUID, and fence. They are checked after locking and immediately before commit.
- `acquireObjectLease` accepts a holder UUID, operation, and TTL of 1–600 seconds.
  An expired lease can be taken over; its fence increases. Repeating a live
  acquisition with the same actor/holder/operation returns that lease. Renew and
  release require the exact live guard. Old holders cannot renew or release a
  successor. `validateObjectLease` checks a guard without extending it.
- Reusing a request UUID with identical changes returns the recorded result.
  Reusing it with another body is `IDEMPOTENCY_CONFLICT`. Receipts are retained for
  seven days and expire during subsequent writes by that actor. Receipts are
  bound to the authenticated actor and contain only object IDs/revisions. They
  remain replayable after deletion; replay performs no new object mutation.
- Database uniqueness applies to each create/update, including live aliases.
  Callers can reserve application-specific keys as resources in the same batch.
- Domain events are enqueued inside the transaction. Per-object compliance audit
  rows are written after commit; request bodies and application attributes are
  not copied to audit details. The existing `entity.update.external_id` detail
  contract is preserved.

`objectCoordinationVersion` currently returns `1` to authenticated clients.
Conflicts expose `REVISION_CONFLICT`, `LEASE_HELD`, `LEASE_LOST`,
`IDEMPOTENCY_CONFLICT`, or `CONFIG_MANAGED` error codes. Existing APIs remain
unconditional unless a client uses this batch API.

Leases guard Atom transactions. Filesystem changes, subprocesses, and another
Atom instance cannot participate in that PostgreSQL transaction. Clients must use
isolated working directories and resumable/idempotent external operations.

Run the real database suite:

```sh
DATABASE_URL=postgres://... cargo test --test object_coordination -- --ignored
```
