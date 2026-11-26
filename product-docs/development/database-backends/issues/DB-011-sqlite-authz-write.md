# DB-011 — Implement SQLite authorization mutations and guardrails

## Objective

Implement SQLite role, permission-block, policy, assignment, capability, group
hierarchy, membership, cleanup, and reverse guardrail behavior with safe writer
serialization and PostgreSQL-equivalent outcomes.

## Product and design context

- PRD: `product-docs/development/database-backends/PRD.md`
- RFC: `product-docs/development/database-backends/RFC.md`
- Requirements: FR-3, FR-5, FR-8; NFR-3, NFR-4, NFR-6, NFR-7, NFR-9
- Parent capability: Implement full SQLite behavior

## Ownership and AI execution contract

- Accountable human: `@arvindh123` (proposed)
- Human reviewer: Security and database reviewers TBD
- AI executor: Any approved coding agent
- Expected PR: One focused PR
- Stop and escalate when: SQLite trigger recursion, immediate transactions, or guardrail queries cannot preserve policy cleanup or assignment correctness under concurrency.

## Scope

**In scope:** SQLite implementation of DB-005 contracts, including hierarchy
serialization through immediate writes, reverse recursive guardrail queries,
idempotent membership/assignment behavior, and policy-target cleanup triggers.

**Out of scope:** Subject-forward decision queries and background purge scheduling.

## Verified repository context

- Relevant paths/symbols: DB-005 façades; PostgreSQL hierarchy locks and reverse queries; `purge_blocks_targeting_policy` triggers; role/permission/policy repositories.
- Existing conventions/contracts: object membership many-to-many; hierarchy is a tree; no-op mutations publish no event; policy cleanup must reach a fixpoint through cascades.
- Change boundaries: SQLite adapter and corresponding invariant/concurrency tests.

## Inputs, outputs, and interfaces

- Inputs/preconditions: DB-008 and SQLite identity data; immediate-write transaction support.
- Outputs/postconditions: Equivalent authorization management state, events, and conflicts.
- API/schema/event contract: No change.
- Compatibility requirement: Guardrail precedence, tenant boundaries, cleanup, soft-delete/restore/purge, and idempotency remain exact.

## Dependencies and sequencing

- Blocked by: DB-005, DB-008, DB-009
- Blocks: DB-015
- External dependency: None

## Failure modes and edge cases

- Concurrent parent changes -> one serialized valid tree, never a cycle.
- Concurrent link/delete -> FK/transaction prevents dangling role-block links.
- Cascade deletes policy objects -> recursive trigger cleanup reaches stable state.
- Busy timeout -> fail unavailable with full rollback.

## Acceptance criteria

- All role, permission block, policy, capability, applicability, group, guardrail, restore, and purge-reference tests pass on SQLite.
- Concurrent hierarchy, membership, assignment, and deletion scenarios preserve invariants and event idempotency.
- Reverse guardrail evaluation matches PostgreSQL without becoming a subject-forward decision source.
- One-connection tests complete without deadlock.

## Verification

- Tests to add/update: DB-005 suite on SQLite, trigger fixpoint, writer races, busy rollback, no-op events, one-connection flows.
- Commands: `cargo fmt --check`; `cargo clippy --locked -- -D warnings`; `cargo test`; SQLite and PostgreSQL authorization mutation suites.
- Manual/operational evidence: Concurrency/trigger invariant report.

## Definition of done

- [ ] Acceptance and concurrency evidence passes.
- [ ] Every DB-008 authz invariant owner is closed.
- [ ] No public or PostgreSQL semantic change is included.
- [ ] PR description includes `Closes #<leaf-issue-number>` after publication.
