# DB-007 — Add SQLite runtime policy and migration baseline

## Objective

Add bundled SQLite connection support, durable file and memory modes, single-owner
enforcement, backend migration selection, and the version-025 SQLite baseline.

## Product and design context

- PRD: `product-docs/development/database-backends/PRD.md`
- RFC: `product-docs/development/database-backends/RFC.md`
- Requirements: FR-1, FR-4, FR-7, FR-8; NFR-3, NFR-4, NFR-8
- Parent capability: Implement full SQLite behavior

## Ownership and AI execution contract

- Accountable human: `@arvindh123` (proposed)
- Human reviewer: Database and operations reviewers TBD
- AI executor: Any approved coding agent
- Expected PR: One focused PR
- Stop and escalate when: SQLite cannot enforce the selected durability/topology or the baseline cannot represent the current logical schema without changing a public meaning.

## Scope

**In scope**

- SQLx bundled SQLite driver, URL parsing, file creation rules, memory pool rules,
  process-lifetime sibling lock, connection PRAGMAs, immediate-write support.
- `migrations/sqlite/025_baseline.sql` with current tables, seeds, indexes, views,
  foreign keys, and expressible triggers.
- Migration selection and paired-post-025 migration validation foundation.

**Out of scope**

- Domain query implementations, cross-backend transfer, SQLCipher, or production support announcement.

## Verified repository context

- Relevant paths/symbols: `Cargo.toml`, `src/db.rs`, `src/config.rs`, `src/main.rs`, `migrations/001_initial.sql` through `025_case_insensitive_entity_email_unique.sql`, `product-docs/14-v1-compatibility.md`.
- Existing conventions/contracts: migrations are embedded and automatic; current released PostgreSQL migrations are immutable; UUIDs and JSONB dominate the schema.
- Change boundaries: SQLite startup/schema only, with placeholder repository support sufficient for migration tests.

## Inputs, outputs, and interfaces

- Inputs/preconditions: Milestone A boundary complete; `sqlite://` or `sqlite::memory:` URL.
- Outputs/postconditions: Correct SQLite database opens/migrates with required durability; second owner fails.
- API/schema/event contract: No public contract change; SQLite storage encoding follows RFC.
- Compatibility requirement: PostgreSQL migration selection remains unchanged.

## Dependencies and sequencing

- Blocked by: DB-006/Milestone A
- Blocks: DB-008
- External dependency: Bundled SQLite compile support verified in CI

## Failure modes and edge cases

- Missing parent or unwritable path -> startup failure before serving.
- Second Atom owner -> clear startup failure.
- Memory pool greater than one -> force one connection.
- WAL/PRAGMA failure or incompatible SQLite -> startup failure, never silent downgrade.
- Partial migration -> migrator reports failure and Atom does not serve.

## Acceptance criteria

- File and memory URLs create a migrated database and report the selected backend without leaking sensitive paths.
- File connections prove `foreign_keys`, `recursive_triggers`, WAL, `synchronous=FULL`, and 30-second busy timeout; write transactions reserve immediately.
- A second Atom lock attempt fails; restart after releasing the lock preserves file data.
- PostgreSQL still uses only its existing migration history.

## Verification

- Tests to add/update: URL/path matrix, pool defaults, PRAGMAs, file lock, restart, migration idempotency/checksum, memory isolation, malformed baseline.
- Commands: `cargo fmt --check`; `cargo clippy --locked -- -D warnings`; `cargo test`; startup integration tests for PostgreSQL and SQLite.
- Manual/operational evidence: Inspect `_sqlx_migrations` and PRAGMAs in a fresh file.

## Definition of done

- [ ] Acceptance criteria pass on Linux and Windows CI-supported behavior.
- [ ] SQLite remains unadvertised as supported.
- [ ] PostgreSQL migration checks remain green.
- [ ] PR description includes `Closes #<leaf-issue-number>` after publication.
