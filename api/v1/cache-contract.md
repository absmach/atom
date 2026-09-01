# Atom v1 Redis cache contract

This file freezes the cross-release Redis interoperability surface for Atom
v1. It is a deployment contract, not a public request API.

- Physical keys are `<ATOM_CACHE_NAMESPACE>:<logical-key>`.
- Logical key patterns are frozen as:
  - `atom:v1:session:<session-uuid>`
  - `atom:v1:entity_status:<entity-uuid>`
  - `atom:v1:tenant_status:<tenant-uuid>`
  - `atom:v1:credential:<credential-uuid>`
  - `atom:v1:cred_ceiling:<credential-uuid>`
  - `atom:v1:grants:<subject-uuid>`
- The persistent namespace incarnation key is
  `<ATOM_CACHE_NAMESPACE>:atom:v1:incarnation`. It contains one random opaque
  marker created for the lifetime of that Redis namespace. Every process
  remembers the marker it observed at startup, and every lookup, populate,
  BEGIN, END, and corrupt-payload discard verifies it atomically. A missing or
  different marker permanently disables cache reads and protected mutations in
  that process until restart.
- The persistent namespace epoch key is
  `<ATOM_CACHE_NAMESPACE>:atom:v1:mutation_epoch`. BEGIN and END increment it.
- Initialization requires both the incarnation and epoch keys to be absent. A
  missing/invalid marker with a surviving epoch is a damaged or fenced
  generation and is rejected even when
  `ATOM_CACHE_INITIALIZE_NAMESPACE=true`; operators must complete the full
  drain and empty the namespace explicitly.
- Entries are Redis hashes. `i` is the incarnation that owns the hash, `v` is
  the integer local mutation version, `dirty` is the integer count of live
  tokens, `p` is the MessagePack payload, and every mutation owns one
  `lease:<uuid>` field until exact-token END succeeds. An entry whose `i` does
  not match the namespace marker is a cold miss and its old contents are never
  served.
  Dirty hashes never expire; clean hashes use their category TTL. A populate
  must match both the captured local version and namespace epoch, preventing
  version ABA after a clean hash expires.
- Payloads use `rmp_serde::to_vec`, so Rust structs encode as positional
  MessagePack arrays. Their frozen field order is:
  - session: `[entity_id, revoked_at, expires_at]`
  - entity status: `[status, tenant_id]`
  - tenant status: `[status]`
  - credential: `[entity_id, status, secret_hash, secret_lookup_hash,
    expires_at, scoped]`
  - credential ceiling: `[entries]`, where every entry has the effective-grant
    order below
  - grants: an array of effective-grant entries
  - effective grant: `[assignment_id, block_id, role_id, role_name, via,
    tenant_boundary, scope_kind, scope_ref, capability_id, effect, conditions]`
- UUIDs and UTC timestamps use their serde MessagePack representations;
  optionals use nil/value, byte vectors use the serde sequence representation,
  JSON conditions retain JSON value semantics, and enum values use their
  existing lowercase or snake_case serde strings.
- Changing any key shape, field order/meaning, enum wire spelling, nested
  shape, or serialization format requires a new logical key version and a
  rollout plan.
- `ATOM_CACHE_MODE=disabled|prepare|enabled`. `prepare` executes writer
  barriers but never reads payloads. The deprecated `ATOM_CACHE_ENABLED`
  alias applies only when mode is absent; conflicting values fail startup.
- `ATOM_CACHE_NAMESPACE` is mandatory in prepare/enabled mode and must be
  unique to one Atom deployment/database.
- A new or deliberately emptied namespace has no incarnation and is rejected
  by default. After a complete traffic stop and full drain/termination of every
  Atom process and in-flight request, start exactly one process with
  `ATOM_CACHE_INITIALIZE_NAMESPACE=true`; it atomically creates a fresh random
  incarnation and epoch. Once ready, unset the flag before starting the rest of
  the fleet. Never leave the initializer enabled in steady state: a restarting
  process must not silently initialize a flushed namespace while old processes
  may still be alive.
- A stopped-writer v0.50 upgrade using a fresh/empty namespace may use enabled
  mode directly: initialize the namespace with one enabled v1 replica as
  described above, then start the remaining enabled replicas. For rolling
  transitions or any overlap, deploy every writer in prepare mode before any
  reader enters enabled mode. Disable in reverse order. Never mix enabled
  readers with v0.50 or disabled writers.
- Mutation tokens are persistent and exact-identity. END consumes only its own
  token. Cancellation, crash, or failed END leaves a permanent dirty barrier
  and forces Postgres fallback. Atom requires one dedicated, standalone,
  non-replicated Redis primary with `maxmemory-policy=noeviction`, RDB disabled
  (`save ""`), AOF disabled (`appendonly no`), Redis Cluster disabled, and no
  Sentinel/automatic promotion. Atom verifies this using `CONFIG GET` and
  `INFO replication` at startup and readiness. The application ACL must permit
  those read commands and the cache data-plane commands, but should not permit
  `CONFIG SET`, `FLUSHALL`, `FLUSHDB`, `MIGRATE`, `RESTORE`, or replication
  reconfiguration.
- The supported Redis topology is intentionally ephemeral. Every Redis process
  restart, flush, replacement, failover attempt, epoch/incarnation reset, or
  abandoned-token repair requires a full maintenance stop: stop traffic,
  terminate/drain every Atom process and in-flight request, empty the
  namespace, initialize one fresh incarnation explicitly, unset the
  initializer, then start the remaining fleet. An old in-flight reader cannot
  populate the new incarnation because its atomic populate presents the marker
  remembered before the drain.
- Observing an unsafe eviction policy/topology globally poisons the namespace
  marker. END does the same when any exact lease is missing. Every peer's next
  atomic operation then fails closed. If writing the reserved poison marker
  fails, Atom deletes the marker; the surviving epoch still prevents an
  initializer from repairing the generation in place.
- Any direct SQL, backfill, or migration that changes a cached input must
  either use the same BEGIN/transaction/END barrier protocol for every affected
  logical key, or run under the full-drain/fresh-namespace procedure above.
- Exact v1 MessagePack payload bytes are frozen in
  `api/v1/cache-wire-v1.json`; the file is checked against runtime serializers.
