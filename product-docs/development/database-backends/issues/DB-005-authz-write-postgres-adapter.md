# DB-005 — Isolate PostgreSQL authorization mutations and guardrails

## Objective

Move roles, permission blocks, policies, assignments, groups, capabilities,
applicability, hierarchy locking, and reverse guardrail validation behind
backend-neutral write contracts without changing authorization state semantics.

## Product and design context

- PRD: `product-docs/development/database-backends/PRD.md`
- RFC: `product-docs/development/database-backends/RFC.md`
- Requirements: FR-2, FR-5, FR-8, FR-10; NFR-1, NFR-6, NFR-7, NFR-9
- Parent capability: Isolate persistence without PostgreSQL regression

## Ownership and AI execution contract

- Accountable human: `@arvindh123` (proposed)
- Human reviewer: Security and database reviewers TBD
- AI executor: Any approved coding agent
- Expected PR: One focused PR
- Stop and escalate when: assignment tenant boundaries, hierarchy serialization, policy cleanup, idempotent membership, or guardrail precedence would change.

## Scope

**In scope:** PostgreSQL adapter boundaries for authorization management and
reverse assignment-time validation, including transaction-scoped locks and purge references.

**Out of scope:** PDP/read paths from DB-004, SQLite SQL, and public API changes.

## Verified repository context

- Relevant paths/symbols: mutation sections of `src/authz/repo.rs`, `src/guardrails.rs`, group mutation sections of `src/identity/repo.rs`, GraphQL authorization mutations.
- Existing conventions/contracts: hierarchy advisory/row locks, reverse `effective_access_edges` use is limited to guardrails/object lookups/assignment metadata, membership no-ops publish no event, policy-object cleanup trigger reaches a fixpoint.
- Change boundaries: preserve all PostgreSQL SQL and transaction behavior inside the adapter.

## Inputs, outputs, and interfaces

- Inputs/preconditions: Valid authenticated mutation inputs and DB-002 transactions.
- Outputs/postconditions: Existing role/policy/group/capability state and events.
- API/schema/event contract: No change.
- Compatibility requirement: Preserve idempotency, guardrails, cascade cleanup, soft delete/restore/purge, and conflict errors.

## Dependencies and sequencing

- Blocked by: DB-002
- Blocks: DB-006 boundary gate, DB-011
- External dependency: None

## Failure modes and edge cases

- Concurrent hierarchy/membership edits -> serialized without cycles or stale validation.
- Deleting policy/assignment through direct or cascaded path -> target blocks are removed to fixpoint.
- No-op membership/assignment -> commits without false domain event.
- One-connection pool -> validators stay on the caller transaction.

## Acceptance criteria

- Existing role, permission-block, policy, capability, hierarchy, guardrail, soft-delete, restore, purge, and event tests remain unchanged and green.
- Reverse guardrail expansion remains distinct from subject-forward decision expansion.
- Domain/transport code in scope contains no PostgreSQL types or raw SQL.

## Verification

- Tests to add/update: adapter dispatch, concurrent hierarchy/assignment, no-op event, cascade cleanup, guardrail precedence, one-connection deletion.
- Commands: `cargo fmt --check`; `cargo clippy --locked -- -D warnings`; `cargo test`; PostgreSQL ignored tests single-threaded.
- Manual/operational evidence: Lock and transaction inventory in PR.

## Definition of done

- [ ] Acceptance and concurrency criteria pass.
- [ ] Canonical forward/reverse boundaries remain documented and enforced.
- [ ] No unrelated read-path or SQLite implementation is included.
- [ ] PR description includes `Closes #<leaf-issue-number>` after publication.
