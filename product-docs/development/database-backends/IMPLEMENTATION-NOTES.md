# Implementation notes: what was built, and where it departs from the RFC

Status: delivered in the single implementation PR (`codex/database-backend-facade`).
This note is the decision record for the places where implementation diverged
from `RFC.md`. Where this note and the RFC disagree, this note describes the
code.

## 1. One query layer instead of per-domain adapters

**RFC:** a `Repository` trait per domain with a PostgreSQL adapter and a
hand-written SQLite adapter (DB-003 … DB-006 for Postgres, DB-009 … DB-014 for
SQLite).

**Built:** one query layer, `crate::db::{query, query_as, query_scalar,
QueryBuilder}`, that every repository and service calls. A statement executes
against a `Target` — a `Database`, a `DbTransaction`, or a pooled `DbConn` — and
runs on either backend.

Why the change:

- The application carries roughly 700 PostgreSQL-specific constructs across ~30
  files (`ANY($n)`, `jsonb` operators, `LATERAL`, array aggregates, interval
  arithmetic, table-valued schema functions, data-modifying CTEs). Porting them
  once per backend by hand would have duplicated every query and left two
  copies to keep in step for every future change.
- SQL is now **written once, in the PostgreSQL dialect**. PostgreSQL runs it
  unchanged (zero behaviour change). SQLite runs a cached, mechanical
  translation (`src/db/translate.rs`), or an explicit override where a rewrite
  is not mechanical.
- The existing DB-gated integration suites become the parity suite: the same
  test bodies run on both backends (`ATOM_TEST_BACKEND=sqlite`).

Consequences for the phase plan: DB-003 … DB-006 (Postgres adapters) collapse into
the "route all SQL through the query layer" step, and DB-009 … DB-014 (SQLite
adapters) collapse into translator rules, overrides, and the SQLite schema.
The acceptance criteria of those phases are met by the shared parity suite
rather than by per-adapter tests.

### Translation and overrides

| Construct | SQLite form |
| --- | --- |
| `= ANY($n)` / `<> ALL($n)` over a bound array | `IN (SELECT value FROM json_each($n))` (UUID arrays decode via `unhex`) |
| `x = ANY(column)` over a JSON-array column | `IN (… UNION ALL … atom_uuid(value) …)` |
| `array_agg`, `ARRAY[..]`, `'{}'::uuid[]`, `unnest`, `array_position`, `array_to_string` | JSON arrays / `json_group_array` / `json_each` |
| jsonb `@>`, `\|\|`, `- 'k'`, `jsonb_set`, `to_jsonb`, `jsonb_typeof` | `atom_json_contains`, `atom_json_merge`, `atom_json_remove`, `json_set`, `json_quote`, `json_type` |
| `now() ± interval '…'`, `± ($n * interval '…')`, `± ($n::text::interval)` | `atom_ts_add(ts, seconds)` |
| `EXTRACT(epoch FROM …)`, `to_timestamp(floor(…))` | `atom_ts_diff` / `atom_ts_epoch` / `atom_ts_floor` |
| `LEFT JOIN LATERAL (single column)` | correlated scalar subquery |
| `DELETE … USING`, `UPDATE t alias`, `RETURNING alias.col` | `EXISTS` / `AS alias` / bare column |
| `FOR UPDATE` / `FOR SHARE` / advisory locks / `LOCK TABLE` | stripped; a pool statement that asked for a row lock runs under `BEGIN IMMEDIATE` |
| `subject_effective_grants($1)` | expanded in place (inline recursive query); `effective_*()` are views |
| `TRUNCATE` | `DELETE FROM` |
| data-modifying CTEs (`WITH x AS (UPDATE …)`) | `Query::sqlite_all([...])`: independent statements run in order |
| anything else | `Query::sqlite("…")` explicit override |

## 2. Value encodings (departs from RFC §"SQLite representation")

| Type | PostgreSQL | SQLite |
| --- | --- | --- |
| UUID | `uuid` | **16-byte BLOB** (the RFC proposed text) |
| timestamp | `timestamptz` | fixed-width RFC 3339 text, microseconds, `Z` (`2026-09-21T12:00:00.123456Z`) |
| JSON | `jsonb` | `TEXT` guarded by `json_valid` |
| arrays | `text[]`, `uuid[]` | JSON text (UUID elements as strings) |
| boolean | `boolean` | `INTEGER` 0/1 |

BLOB UUIDs are compact, index well, and are sqlx's native encoding; the cost is
that a UUID rendered as text needs `atom_text()` (a built-in expression inside
views/triggers). Fixed-width timestamps make lexicographic order equal
chronological order, so ordinary indexes and comparisons work.

## 3. SQLite schema

- `migrations/sqlite/` mirrors `migrations/` one-to-one (migration pairing is
  checked by `scripts/check-db-boundary.sh`). The PostgreSQL baseline
  `001_initial.sql` stays byte-frozen.
- Tables, indexes, views and CHECK constraints use **only SQLite built-ins**, so
  any SQLite tool can open and copy the database (`VACUUM INTO`, backups).
  Constraints that were regexes or array containment are rewritten with `GLOB`,
  `json_*` and `replace`. The one CHECK that cannot be expressed
  (`crl_sha256 = sha256(crl_der)`) keeps its format check in SQL and is computed
  by the application.
- Invariant triggers (protected-object registry, PKI parentage, certificate
  ceilings, revocation immutability, shared-key rules) are re-expressed as
  SQLite triggers using `RAISE(ABORT, …)`. They call a few `atom_*` functions
  that Atom registers on every connection (`src/db/sqlite_functions.rs`), plus
  `grant_scope_matches`, `md5`, `now()`, `gen_random_uuid()`.
- The `sqlite` feature of sqlx bundles SQLite 3.46; scalar functions are
  registered through `libsqlite3-sys` in `after_connect` (sqlx has no scalar
  function API).

## 4. Runtime policy (as specified)

WAL, `synchronous=FULL`, `foreign_keys=ON`, `recursive_triggers=ON`, 30 s busy
timeout, `BEGIN IMMEDIATE` for every transaction, one connection for
`sqlite::memory:`, default pool of 5 for a file, and a sibling `.atom-lock`
file lock so a second Atom process cannot open the same database. Busy/locked
errors map to HTTP 503 / gRPC `UNAVAILABLE`.

## 5. Error classification

`crate::error` classifies both backends' failures into
`NotFound | Unique | ForeignKey | Check | Busy | Internal`. SQLite extended
codes: 2067/1555 unique, 787 (and 1811 with a "FOREIGN KEY" message) foreign
key, 275 and trigger aborts (1811) check, 5/6 busy. Callers use
`is_unique_violation` / `is_foreign_key_violation` / `is_check_violation`
instead of comparing SQLSTATEs. Entity `external_id`/email conflicts are
attributed on SQLite from the violated index name in the message.

## 6. Test strategy and the intentional exceptions

Every DB-gated suite runs unchanged on both backends. CI runs each test binary
against a fresh PostgreSQL database and again against a fresh SQLite file.
Test fixtures that were PostgreSQL-only were made backend-neutral
(`atom::db::testing::{database, single_connection_database,
install_rejecting_trigger}`). Four places are intentionally different on SQLite:

| Test | Why |
| --- | --- |
| `m32` serial-collision retry proof | injects the collision with a non-transactional PostgreSQL sequence; SQLite has none |
| `m50` concurrent tenant freeze / tenant move | observed through `pg_stat_activity` row-lock waits; SQLite serializes writers at `BEGIN IMMEDIATE` |
| `m31` index-plan assertion | uses `EXPLAIN QUERY PLAN` on SQLite instead of `EXPLAIN` |
| lock-order tests in `m25`, `m48` | pass on SQLite, but assert ordering that the single write lock already guarantees |

`tests/sqlite_operations.rs` covers what has no PostgreSQL analogue: fixed
PRAGMAs, restart persistence, single-owner lock, rollback atomicity, busy
mapping, and backup/restore by file copy.

## 7. Gates added

- `scripts/check-db-boundary.sh`: no driver types or raw `sqlx::query*` outside
  `src/db/` (test modules excepted), and table/view/index parity between the two
  baselines.
- CI runs the SQLite lane after the PostgreSQL lane.

## 8. Status of the phases

| Phase | Delivered as |
| --- | --- |
| DB-001, DB-002 | façade, transactions, error classification |
| DB-003 … DB-006 | query layer routing every statement (one step) |
| DB-007 | `src/db/sqlite.rs`, `migrations/sqlite/`, runtime policy |
| DB-008 | value encodings, `sqlite_functions.rs`, built-in-only constraints |
| DB-009 … DB-014 | translator rules, overrides, SQLite triggers/views/seeds; parity suite green |
| DB-015 | dual-backend CI lane, boundary/parity script, operational tests |
| DB-016 | `docs/content/docs/operations/sqlite.mdx` |
