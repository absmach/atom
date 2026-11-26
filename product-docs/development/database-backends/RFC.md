# RFC: Internal Database Backend Boundary and SQLite Semantics

| Field | Value |
|---|---|
| Status | Draft |
| Decision owner | `@arvindh123` (proposed) |
| Reviewers | Database, security, and operations reviewers TBD |
| Related PRD | `product-docs/development/database-backends/PRD.md` |
| Requirement IDs | FR-1 through FR-10; NFR-1 through NFR-10 |

## Context and current state

`AppState` contains `sqlx::PgPool`; startup embeds `migrations/`; repository and
service signatures expose `PgPool`, `PgConnection`, `Postgres`, and PostgreSQL
transactions. Authorization depends on `subject_effective_grants`,
`grant_scope_matches`, recursive views, arrays, and JSONB. Mutations coordinate
audit, cache invalidation, and transactional outbox insertion around concrete
PostgreSQL transactions. Purge, hierarchy changes, outbox delivery, and PKI use
row or advisory locks.

SQLx `AnyPool` is unsuitable because its portable value model covers primitive
SQL values, while Atom relies heavily on UUID, timestamp, JSON, enum, and array
encoding. A common-query rewrite would also discard PostgreSQL's optimized
functions and locking behavior.

## Decision

Introduce a closed internal façade with concrete backend variants:

- `DatabaseKind::{Postgres, Sqlite}` identifies semantics and observability.
- cloneable `Database::{Postgres(PgPool), Sqlite(SqlitePool)}` owns connections,
  backend migration selection, health checks, and transaction creation.
- `DbTransaction::{Postgres, Sqlite}` owns exactly one backend transaction and
  provides read, immediate-write, nested-savepoint, commit, and rollback paths.
- backend-neutral `DatabaseErrorKind` classifies not-found, unique, foreign-key,
  check, busy/unavailable, and internal failures before transport mapping.
- domain repository façades accept `&Database` or `&mut DbTransaction` and
  dispatch to `storage/postgres` or `storage/sqlite`; raw SQL and SQLx backend
  types cannot escape those adapters.

This is an internal, rebuild-required extension point. Adding another backend
adds enum variants, connection/migration policy, adapter implementations, and
the parity suite. It does not add a public plugin ABI.

## System design and data flow

```text
HTTP / GraphQL / gRPC / workers
              |
       domain services and PDP
              |
       repository façades
         /             \
PostgreSQL adapter   SQLite adapter
         |              |
  PostgreSQL pool    SQLite pool/file
```

Read flows use repository-returned domain models. Mutation flows open one
backend transaction, run all validation and mutation queries on it, enqueue the
event in that transaction when enabled, hand ownership to the existing commit
helper, and perform non-transactional audit storage only after commit where the
current contract requires it. No adapter may acquire a second pool connection
while a transaction is live.

The transition may expose a temporary PostgreSQL accessor inside `storage` while
domains move one PR at a time. DB-006 removes it and activates a CI guard before
SQLite is advertised or selected outside tests.

## Interfaces and data contracts

There is no HTTP, GraphQL, gRPC, event-envelope, bootstrap-YAML, action, scope,
credential, or certificate contract change.

`DATABASE_URL` accepts:

- `postgres://...` and `postgresql://...`;
- `sqlite://<local-path>` for a durable file, created if absent only when its
  parent directory exists;
- `sqlite::memory:` for ephemeral use with one connection.

Unsupported schemes fail startup before listeners serve. PostgreSQL keeps its
current default maximum pool size of 20. File SQLite defaults to 5 connections;
memory mode forces 1. Explicit existing pool configuration continues to control
file pools. SQLite adds a 30-second busy timeout and does not make journal or
synchronous durability operator-selectable in this release.

SQLite storage encodings are backend-internal:

- UUID: canonical lowercase RFC-4122 text;
- UTC time: RFC-3339 text;
- boolean: checked integer;
- project enum: checked text matching the public serialized value;
- JSON: UTF-8 text guarded by `json_valid` and shape checks where required;
- PostgreSQL text array: validated JSON array with backend row conversion.

IDs are generated in Rust for new portable mutation paths. Adapter row types
convert SQLite storage values into the existing domain models.

## Compatibility and migration

The existing `migrations/001` through `025` remain in place, unchanged, as the
PostgreSQL history. SQLite begins with
`migrations/sqlite/025_baseline.sql`, representing the current logical schema
and seed state. It is the first released SQLite storage contract.

After the baseline, every logical schema change receives the same migration
version in both trees. CI rejects an unpaired post-025 migration. Contents may
differ by dialect, but resulting domain constraints and behavior must have
paired tests.

There is no cross-backend backfill or cutover. An existing PostgreSQL deployment
continues using PostgreSQL. A SQLite deployment starts fresh or restores a
SQLite backup. Released migration files remain immutable under the existing v1
policy.

## SQLite concurrency and canonical behavior

File connections enable `foreign_keys`, `recursive_triggers`, WAL,
`synchronous=FULL`, and the busy timeout. Mutation transactions use
`BEGIN IMMEDIATE`; row-level `FOR UPDATE` clauses are omitted because the SQLite
write reservation serializes writers. Nested collision retries use savepoints.

A process-lifetime sibling lock file prevents two Atom processes from owning one
database. SQLite paths on network/shared storage are unsupported even when a
filesystem appears to honor the lock.

PostgreSQL retains its parameterized canonical grant function and scope matcher.
SQLite implements one reusable parameterized recursive grant CTE and one scope
matching fragment. The PDP, explain, gates, authorized listers, tenant/audit
visibility, and access-token ceiling filtering must all call the same repository
contract. Reverse assignment guardrails remain a separate reverse expansion.

The SQLite outbox worker must not hold a write transaction while waiting for the
broker. Because only one Atom process is supported, it can read a bounded batch,
publish, then record results in a short immediate transaction. A crash between
publish and marking delivered may duplicate an event, which is already permitted
by the at-least-once contract; it must never mark an unpublished event delivered.

## Security and privacy

- Authentication, online authorization, deny-overrides, ABAC fail-closed, and
  access-token ceiling semantics are invariant across backends.
- Database constraint/trigger parity covers tenant boundaries, soft-delete,
  policy cleanup, credential-kind restrictions, PKI authority/profile/issuer
  rules, immutable revocation evidence, and cascaded purge behavior.
- When SQLite cannot express an invariant safely in a trigger, the adapter
  validates it under the same immediate transaction and proves race behavior.
- Recoverable signing and credential secrets retain Atom's AES-256-GCM field
  encryption. The SQLite file itself is not SQLCipher-encrypted; production docs
  require appropriate OS/disk encryption and file permissions.
- Error messages, tracing, events, and debug output must not expose SQL, secrets,
  key material, database credentials, or the database path beyond operator-safe
  startup diagnostics.

## Failure modes and recovery

| Failure | Detection | User/system effect | Recovery | Owner |
|---|---|---|---|---|
| Unsupported URL | Startup validation | Atom does not serve | Correct `DATABASE_URL` | Operator |
| SQLite parent/path unavailable | Connection setup | Atom does not serve | Fix mount/permissions/path | Operator |
| Second Atom process | Sibling lock acquisition | Second process does not serve | Stop owner or use another file | Operator |
| Migration mismatch/failure | Backend migrator | Atom does not serve | Restore backup, fix binary/migration | Operator + database reviewer |
| Busy beyond 30 seconds | SQLite extended error classification | Request fails closed as unavailable | Retry with backoff; diagnose long writer | Operator |
| Process crash during mutation | Transaction rollback/recovery | No partial mutation or orphan event | Restart; SQLite recovery runs | Database adapter |
| Crash after event publish | Delivered marker absent | Possible duplicate publication | Consumer idempotency; next poll retries | Event owner |
| Corrupt SQLite file | Integrity/startup/read error | Atom stops or returns internal/unavailable | Restore verified backup | Operator |
| Semantic dialect drift | Differential CI | Release blocked | Correct adapter/query and add regression test | Engineering |

## Observability, capacity, and cost

Startup logs include selected backend, sanitized location category (network
address versus file/memory), migration completion, SQLite durability mode, and
file-lock ownership. Existing health/readiness behavior uses the façade.

Metrics add low-cardinality backend labels to database operation latency/error
counters and record SQLite busy timeouts, migration failures, and background-job
failures. Database URLs, file paths, SQL, subject IDs, and tenant IDs are not
metric labels.

SQLite is documented for one process and moderate embedded workloads, not
multi-replica or high-write scaling. PostgreSQL remains the recommended backend
when horizontal availability, independent database operations, or high write
concurrency is required. No external database service is required for SQLite;
the operational cost moves to local durable storage, backup, and process
ownership.

## Test strategy

- Preserve and run the entire current PostgreSQL suite after every abstraction PR.
- Parameterize fixtures and run each DB-relevant integration binary against a
  fresh PostgreSQL database and fresh SQLite file, single-threaded within the
  binary as current shared seeds require.
- Differentially compare normalized PDP decisions/explanations, gates, listings,
  errors, lifecycle transitions, audit/outbox, purge, and PKI artifacts.
- Test one-connection operation, immediate-write contention, nested savepoints,
  second-process rejection, restart persistence, migration idempotency, rollback,
  crash windows, invariant rejection, and backup/restore.
- Capture a fixed PostgreSQL authz benchmark before the repository refactor and
  enforce the approved p95 regression budget.
- Run `cargo fmt --check`, `cargo clippy --locked -- -D warnings`,
  `cargo test --no-run --locked`, unit tests, both DB suites, and
  `scripts/check-v1-contracts.sh`.

## Rollout and rollback

1. Merge DB-001 through DB-006 as PostgreSQL-only behavior-preserving changes.
2. Merge the SQLite driver, schema, and adapters without documenting SQLite as
   production-supported; selection may remain test-only until parity is complete.
3. Enable the dual-backend CI and release matrix. Stop if PostgreSQL performance,
   contracts, authz parity, transaction semantics, or PKI invariants fail.
4. Publish SQLite operator documentation and support only after reviewer approval
   and release evidence.

PostgreSQL rollback uses the current binary rollback policy because its released
migrations are unchanged. Before a SQLite database is used externally, rollback
is removal of the unreleased SQLite path. After release, roll back only to an
earlier SQLite-capable binary whose migration compatibility is documented, or
restore the pre-upgrade SQLite backup. Rollback never converts SQLite data into
PostgreSQL.

## Alternatives considered

| Alternative | Advantages | Rejection reason |
|---|---|---|
| SQLx `AnyPool` | One pool/transaction type | Supports only a primitive portable type subset and obscures backend errors/semantics Atom needs |
| One portable SQL set | Less duplicated SQL | Sacrifices PostgreSQL functions/locks and still cannot express all SQLite differences safely |
| ORM rewrite | Advertised multi-database mapping | Large unrelated rewrite, poor fit for recursive authorization and lock-sensitive transactions |
| Compile-time backend features | Simpler monomorphic types | Produces separate binaries and violates runtime URL selection |
| Public backend plugin API | External extensibility | Requires a stable ABI/security boundary not needed for Atom-owned backends |
| SQLite dev-only mode | Smaller initial port | Does not satisfy the production embedded deployment goal |

## Consequences and follow-ups

The repository will contain intentional dialect-specific SQL and schema code,
but that complexity becomes bounded and testable. Every new persistence feature
must update both backends or explicitly change the support contract before merge.
SQLite operational limits become a product constraint. Cross-backend transfer,
SQLCipher, replicas, and a public backend API remain separately scoped future
initiatives.
