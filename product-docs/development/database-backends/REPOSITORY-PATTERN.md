# Repository-per-domain pattern

Status: pilot delivered (the `resources` domain — see below); the rest of the
codebase is being ported domain by domain as tracked follow-up work, not in
one pass. This document is the contract this and every future port must
follow, written up front per review request on PR #119.

## Why this replaces the general-purpose translator

The first cut of SQLite support (still present for every domain not yet
ported) routed all SQL through one query layer, `crate::db::{query, query_as,
query_scalar}`, executing PostgreSQL-dialect SQL unchanged on PostgreSQL and a
mechanically translated (`crate::db::translate`) form on SQLite. That
approach avoided hand-writing ~700 PostgreSQL-specific constructs twice, and
is fully tested (both backends, every DB-gated suite) — but a generic
compatibility layer is exactly that: generic. It found real gaps only when a
construct's translation was subtly wrong for one specific shape of query (a
`json_each`-scoped correlation, a `generate_series`-in-SELECT-list
expansion), and it is not something a reader can audit a query's SQLite
behavior from without also reading the translator.

Per review, storage is moving to explicit per-backend implementations behind
small domain-shaped contracts instead: each backend owns its native SQL for a
domain's operations, so what runs against SQLite is source code, not a
transformation of PostgreSQL source code.

## The contract shape

A domain repository is **the public functions of a module**, not a `trait`.
Callers import the domain module and call its operations with domain
input/result types (`CreateResource`, `Resource`, `ListResources`,
`ResourceList`, …) — never a driver row, a bind parameter, or a SQL string.
Concretely:

```text
src/authz/resources/
    mod.rs       # the contract: create_resource_with_audit, get_resource,
                 # list_resources, list_resources_by_ids — plus validation
                 # and dispatch shared by both backends
    postgres.rs  # native PostgreSQL SQL for the same operations (private)
    sqlite.rs    # native SQLite SQL for the same operations (private)
```

`postgres.rs`/`sqlite.rs` are declared `mod`, not `pub mod` — Rust's own
privacy rules keep them reachable only from their own `mod.rs`, so nothing
outside the domain can reach into a specific backend's implementation.
`scripts/check-db-boundary.sh` enforces the wider rule this is part of: no
`sqlx::query*` or driver type outside `src/db/` or a domain's own
`postgres.rs`/`sqlite.rs`, and no domain's adapter files widened to `pub mod`.

This is deliberately **not** one trait per domain with two `impl` blocks. A
trait would need `Send + Sync` object-safety concessions or generic
monomorphization for no real benefit here: the dispatch is a single `match`
on the already-connected [`Database`]/[`DbTransaction`] enum (see below),
resolved once per call, not a pluggable strategy chosen at a boundary far
from the call site. Matching AGENTS.md's existing convention (exhaustive
`match` over enums, not `dyn` dispatch, used throughout the codebase already
for `Database`/`DbConn`/`DbTransaction`/`AuditOutcome`/…), a domain module's
public function is the whole contract:

```rust
pub async fn get_resource(pool: &Database, id: Uuid) -> Result<Resource, AppError> {
    match pool {
        Database::Postgres(pg_pool) => postgres::get(pg_pool, id).await,
        Database::Sqlite(db) => sqlite::get(&db.pool, id).await,
    }
}
```

`Database` (`enum { Postgres(PgPool), Sqlite(SqliteDb) }`) is already the
backend selector the whole codebase uses — built at startup from
`DATABASE_URL`'s scheme (`Database::connect`) and threaded through
`AppState`/`state.pool()`. No second selector type is introduced.

## The transaction / unit-of-work boundary

Unchanged from the existing facade, because it already provides exactly what
a repository-per-domain design needs, and per review request preserving it
is the point:

- `Database::begin()` returns a `DbTransaction<'static>`
  (`enum { Postgres(Transaction<'_, Postgres>), Sqlite(Transaction<'_, Sqlite>) }`),
  one transaction for every write an operation makes.
- `DbTransaction::begin()` opens a nested savepoint from an existing
  transaction (PKI issuance's serial-collision retry uses this) — untouched.
- The transactional outbox helpers in `crate::audit`
  (`commit_with_audit`, `commit_with_observation`, `observe_in_tx`) are
  backend-neutral already (they operate on `DbTransaction`, not a concrete
  driver type) and are the single place a mutation's outbox row and its
  commit happen together. A repository's write function takes the open
  transaction, inserts through its own backend's native SQL, and hands
  control back to the caller, which calls the audit commit helper — the
  repository itself never calls `.commit()`.
- No repository method opens and commits its own transaction. A multi-step
  mutation (lock a tenant, then insert, then commit-with-outbox) shares the
  one transaction end to end, exactly as `create_resource_with_audit`
  demonstrates below.
- Cross-domain locking helpers (`tenants::repo::lock_optional_active_tenant`,
  `lock_tenant_rows_in_order`, …) stay shared infrastructure, called by any
  domain's write path before it opens its own backend match — the review
  comment's "shared internal helpers... are fine" explicitly allows this,
  and duplicating tenant-locking SQL per domain would be exactly the kind of
  helper-per-SQL-statement interface the review is against.
- The canonical grant expansion (`subject_effective_grants`,
  `grant_scope_matches`) is unaffected by this migration: it is consumed by
  the PDP/control-plane/listing readers as one shared SQL view/function per
  backend already (SQL view on PostgreSQL, SQL view + inline expansion on
  SQLite — see the SQLite baseline migration), not duplicated per domain.

## The pilot: `resources`

`src/authz/resources/` implements `create_resource_with_audit`,
`create_resource`, `get_resource`, `list_resources_by_ids`, and
`list_resources` — a read (`get_resource`, a point lookup), a harder read
(`list_resources`: a recursive CTE over group hierarchy, `jsonb`/JSON
containment, case-insensitive search, pagination) and the atomic multi-write
mutation the review asked to see proven (`create_resource_with_audit`: lock
the owning tenant, insert the row, then commit with its `resource.create`
outbox event in the same transaction — verified by
`tests/m26_audit_event_publishing.rs`'s
`outbox_failure_rolls_back_the_domain_mutation`, which fails the outbox
insert deliberately and asserts the resource insert rolled back with it, on
both backends).

Backend-specific points this pilot had to resolve natively (documented here
so later ports do not have to rediscover them):

| Construct | PostgreSQL | SQLite |
| --- | --- | --- |
| Recursive group-hierarchy CTE | `WITH RECURSIVE ... $n::uuid` | same, drop the cast — SQLite's `WITH RECURSIVE` is unchanged from PostgreSQL's |
| Case-insensitive search | `ILIKE` | `LIKE` (ASCII case-insensitive by default in SQLite) |
| jsonb containment (`@>`) | native operator | `atom_json_contains(col, $n)`, one of the SQL functions already registered per connection (`crate::db::sqlite_functions`) for the whole SQLite backend, not new for this pilot |
| `id = ANY($1::uuid[])`, ordered by input order | native array operators + `array_position` | `id IN (SELECT unhex(value) FROM json_each($1))`, ordered by `NULLIF(instr($1, lower(hex(id))), 0)` — position in the JSON text is monotonic with array index because every element is the same fixed width; `crate::db::native::uuid_array_json` encodes the parameter |
| `NULLS LAST` | native | unchanged — SQLite has supported it natively since 3.30 (2019), below the bundled 3.46/3.47 |
| JSON parameter binding | bind `serde_json::Value` directly | bind `value.to_string()` (SQLite JSON columns are `TEXT`) |

`crate::db::native` is the one shared low-level helper this pilot needed
(encoding a `&[Uuid]` as the same JSON-array-of-hex-strings format the rest
of the SQLite backend already uses for UUID arrays) — infrastructure, not a
query-building API, in line with the review's allowance for "shared internal
helpers... where they are useful."

## Porting the rest

Not attempted in one pass — the storage code this eventually touches is
~34,000 lines across ~24 files. Tracked as a follow-up, one domain at a time,
each repeating exactly the pilot's shape (contract in `mod.rs`, native SQL in
`postgres.rs`/`sqlite.rs`, tests run unchanged against both backends). Until a
domain is ported, it continues to run on the general-purpose query
layer/translator described in `IMPLEMENTATION-NOTES.md` — both approaches
coexist during the migration, and `scripts/check-db-boundary.sh` accepts
either. The translator itself is only removed once every domain has moved
off it.
