# DB-002 — Generalize transactions, commit helpers, and database errors

## Objective

Make transaction ownership, nested savepoints, mutation commits, and database
error classification backend-neutral while proving PostgreSQL semantics remain
identical.

## Product and design context

- PRD: `product-docs/development/database-backends/PRD.md`
- RFC: `product-docs/development/database-backends/RFC.md`
- Requirements: FR-5, FR-8, FR-10; NFR-4, NFR-6, NFR-7, NFR-10
- Parent capability: Isolate persistence without PostgreSQL regression

## Ownership and AI execution contract

- Accountable human: `@arvindh123` (proposed)
- Human reviewer: Database reviewer TBD
- AI executor: Any approved coding agent
- Expected PR: One focused PR
- Stop and escalate when: commit ordering, audit asymmetry, cache barriers, or outbox atomicity would change.

## Scope

**In scope**

- `DbTransaction`, read/write transaction modes, nested savepoint support, and ownership-based commit/rollback.
- Adapt audit/event commit helpers and error mapping to backend-neutral interfaces.
- Introduce `DatabaseErrorKind` and preserve repository-specific restore/entity conflict attribution.

**Out of scope**

- SQLite error codes or SQL; domain repository migration.

## Verified repository context

- Relevant paths/symbols: `src/audit.rs`, `src/events/mod.rs`, `src/error.rs`, `src/cache/invalidate.rs`, transaction-taking service functions.
- Existing conventions/contracts: outbox insertion is atomic with mutation; DB audit is post-commit/fire-and-forget; commit helpers take transactions by value; nested PKI retries use savepoints.
- Change boundaries: shared transaction and commit infrastructure, not domain behavior.

## Inputs, outputs, and interfaces

- Inputs/preconditions: Database façade from DB-001.
- Outputs/postconditions: Callers use `DbTransaction`; transport errors remain stable.
- API/schema/event contract: No contract change.
- Compatibility requirement: Preserve current unique/FK/check/not-found mappings and event/audit order.

## Dependencies and sequencing

- Blocked by: DB-001
- Blocks: DB-003, DB-004, DB-005, DB-006
- External dependency: None

## Failure modes and edge cases

- Commit succeeds but later read fails -> forbidden; required return rows must be read inside the transaction.
- Audit insert fails after commit -> caller still succeeds and failure is logged.
- Nested savepoint collision -> outer transaction remains usable.
- Pool size one -> no path attempts a second connection.

## Acceptance criteria

- Given any audited or observed mutation, when it succeeds or fails, then PostgreSQL event, audit, cache, and return behavior matches the current implementation.
- Given a unique, foreign-key, check, or missing-row error, then existing HTTP and gRPC semantics remain unchanged.
- Given a one-connection pool and nested savepoint tests, then no deadlock or poisoned outer transaction occurs.

## Verification

- Tests to add/update: commit ordering, rollback/no-outbox, audit failure tolerance, cache barriers, nested savepoints, single-connection execution, error classification.
- Commands: `cargo fmt --check`; `cargo clippy --locked -- -D warnings`; `cargo test`; PostgreSQL ignored tests with `--include-ignored --test-threads=1`.
- Manual/operational evidence: Transaction-sequence review in PR description.

## Definition of done

- [ ] Acceptance criteria and failure-injection tests pass.
- [ ] No commit helper accepts a concrete PostgreSQL transaction publicly.
- [ ] No unrelated repository domain is migrated in this PR.
- [ ] PR description includes `Closes #<leaf-issue-number>` after publication.
