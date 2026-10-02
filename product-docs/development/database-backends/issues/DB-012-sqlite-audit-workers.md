# DB-012 — Implement SQLite audit, outbox, purge, and worker semantics

## Objective

Implement SQLite audit retention, transactional event outbox, delivery, purge,
and background lifecycle coordination without holding a SQLite write lock across
external I/O or losing committed events.

## Product and design context

- PRD: `product-docs/development/database-backends/PRD.md`
- RFC: `product-docs/development/database-backends/RFC.md`
- Requirements: FR-3, FR-5, FR-7, FR-8; NFR-3, NFR-4, NFR-6, NFR-7, NFR-9
- Parent capability: Implement full SQLite behavior

## Ownership and AI execution contract

- Accountable human: `@arvindh123` (proposed)
- Human reviewer: Database and operations reviewers TBD
- AI executor: Any approved coding agent
- Expected PR: One focused PR
- Stop and escalate when: an outbox design could mark unpublished work delivered, hold a write lock during broker I/O, or weaken purge/audit retention semantics.

## Scope

**In scope:** SQLite implementations for audit write/cleanup, transactional
outbox enqueue, single-process batch publish/result marking, outbox retention,
soft-delete purge, and non-PKI worker coordination/observability.

**Out of scope:** Broker contract changes, exactly-once delivery, multi-process worker leases, and PKI-specific lifecycle.

## Verified repository context

- Relevant paths/symbols: `src/audit.rs`, `src/events/mod.rs`, `src/purge.rs`, `src/state.rs`, event publisher contract.
- Existing conventions/contracts: outbox atomic with mutation; audit insert may fail after commit; at-least-once delivery; publish timeout; PostgreSQL advisory locks prevent replica overlap; SQLite supports one process.
- Change boundaries: SQLite worker adapter and shared dispatch only.

## Inputs, outputs, and interfaces

- Inputs/preconditions: DB-007 single-owner guarantee and domain transactions from DB-009/011.
- Outputs/postconditions: Equivalent audit/outbox/purge results and safe recovery.
- API/schema/event contract: Event payload and audit API unchanged; duplicates remain allowed.
- Compatibility requirement: A committed enabled event is durable; an unpublished event is never marked delivered.

## Dependencies and sequencing

- Blocked by: DB-008, DB-009, DB-011
- Blocks: DB-015
- External dependency: Existing AMQP integration infrastructure for live publish proof

## Failure modes and edge cases

- Broker timeout/failure -> row remains retryable and writers are not blocked during network wait.
- Crash after publish before mark -> duplicate on retry, never loss.
- Unparseable payload -> attempts/error/exhaustion remain visible and never marked delivered.
- Purge overlaps request -> immediate transactions serialize and canonical authz references are cleaned.

## Acceptance criteria

- Audit success/failure asymmetry, hot-path policy, outbox enqueue/delivery/error, retention, and purge suites pass on SQLite.
- Instrumented test proves no SQLite write transaction is held while `publisher.publish` awaits.
- Crash-window tests prove at-least-once behavior and no false delivered state.
- Busy/purge/contention tests rollback completely and return required errors.

## Verification

- Tests to add/update: mock publisher timing/locking, crash windows, malformed payload, retention, purge, one-connection, restart, optional live AMQP.
- Commands: `cargo fmt --check`; `cargo clippy --locked -- -D warnings`; `cargo test`; SQLite audit/event/purge suites; existing live AMQP test where infrastructure exists.
- Manual/operational evidence: State-transition table and lock-duration evidence.

## Definition of done

- [ ] Acceptance and recovery criteria pass.
- [ ] No write lock spans external broker I/O.
- [ ] Event wire contract remains unchanged.
- [ ] PR description includes `Closes #<leaf-issue-number>` after publication.
