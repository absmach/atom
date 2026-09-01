# DB-001 — Add the database façade and PostgreSQL benchmark baseline

## Objective

Introduce backend-neutral database identity, URL classification, pool ownership,
migration dispatch, and a fixed PostgreSQL authz benchmark without changing
runtime behavior.

## Product and design context

- PRD: `product-docs/development/database-backends/PRD.md`
- RFC: `product-docs/development/database-backends/RFC.md`
- Requirements: FR-1, FR-2, FR-4, FR-10; NFR-1, NFR-2, NFR-10
- Parent capability: Isolate persistence without PostgreSQL regression

## Ownership and AI execution contract

- Accountable human: `@arvindh123` (proposed)
- Human reviewer: Product/API plus database reviewer TBD
- AI executor: Any approved coding agent
- Expected PR: One focused PR
- Stop and escalate when: a change would edit/reorder a released migration, alter a public contract, or choose a benchmark budget different from the RFC.

## Scope

**In scope**

- `DatabaseKind`, a cloneable database façade, URL scheme validation, PostgreSQL
  pool construction, backend migration dispatch, and sanitized startup logging.
- Replace `AppState`'s public `PgPool` field with the façade while providing a
  storage-internal transitional PostgreSQL accessor for later leaf issues.
- Add a deterministic seeded authz benchmark and capture the main-branch baseline.

**Out of scope**

- Connecting to SQLite, changing repository SQL, or changing pool/health behavior from issue #42.

## Verified repository context

- Relevant paths/symbols: `src/db.rs`, `src/config.rs`, `src/main.rs`, `src/state.rs`, `src/authz/engine.rs`, `Cargo.toml`, `migrations/`
- Existing conventions/contracts: `DATABASE_URL` is required; `sqlx::migrate!("./migrations")` runs at startup; PostgreSQL pool settings are explicit; v1 migrations are immutable.
- Change boundaries: startup and state ownership only; storage callers may temporarily use the internal PostgreSQL accessor.

## Inputs, outputs, and interfaces

- Inputs/preconditions: Valid PostgreSQL URL and current `DbPoolConfig`.
- Outputs/postconditions: PostgreSQL startup is unchanged; unsupported schemes fail before serving; benchmark results are reproducible.
- API/schema/event contract: No public contract change.
- Compatibility requirement: Existing PostgreSQL URLs and databases work unchanged.

## Dependencies and sequencing

- Blocked by: None
- Blocks: DB-002
- External dependency: None

## Failure modes and edge cases

- Malformed/unsupported URL -> actionable startup failure without credentials in logs.
- PostgreSQL connection/migration timeout -> existing failure behavior retained.
- Benchmark variance -> document fixture, warm-up, sample count, and comparison method.

## Acceptance criteria

- Given a PostgreSQL URL, when Atom starts, then it connects and migrates through the façade with existing configuration.
- Given an unsupported or malformed scheme, when configuration loads, then startup fails before any listener serves.
- Given the fixed authz fixture, when the benchmark runs repeatedly, then it produces a baseline suitable for enforcing NFR-2.
- Existing PostgreSQL tests and v1 contract artifacts remain unchanged.

## Verification

- Tests to add/update: URL classification, migration selection, sanitized errors, `AppState` construction, authz benchmark fixture.
- Commands: `cargo fmt --check`; `cargo clippy --locked -- -D warnings`; `cargo test --no-run --locked`; `cargo test`; `scripts/check-v1-contracts.sh`.
- Manual/operational evidence: Attach benchmark baseline and environment description to the PR.

## Definition of done

- [ ] Acceptance criteria pass with evidence in the PR.
- [ ] Required checks pass and released migrations are untouched.
- [ ] Transitional PostgreSQL accessor is storage-internal and tagged for removal in DB-006.
- [ ] PR description includes `Closes #<leaf-issue-number>` after publication.
