# DB-004 — Isolate PostgreSQL authorization decisions and visibility

## Objective

Move the PDP context loader, canonical effective grants, control-plane gates,
explain, and authorized visibility readers behind one backend-neutral
authorization-read contract without changing a decision.

## Product and design context

- PRD: `product-docs/development/database-backends/PRD.md`
- RFC: `product-docs/development/database-backends/RFC.md`
- Requirements: FR-2, FR-6, FR-10; NFR-1, NFR-2, NFR-7, NFR-10
- Parent capability: Isolate persistence without PostgreSQL regression

## Ownership and AI execution contract

- Accountable human: `@arvindh123` (proposed)
- Human reviewer: Security and database reviewers TBD
- AI executor: Any approved coding agent
- Expected PR: One focused PR
- Stop and escalate when: a reader would bypass `subject_effective_grants`, duplicate scope matching, weaken ABAC fail-closed, or change deny precedence.

## Scope

**In scope:** PostgreSQL adapter contract for PDP/explain context, effective
grants, scope matching, access-token ceilings, gates, tenant/audit visibility,
and entity/resource/group authorized listings.

**Out of scope:** Role/policy mutations, reverse assignment guardrails, SQLite queries.

## Verified repository context

- Relevant paths/symbols: `src/authz/engine.rs`, `src/authz/repo.rs`, `src/authz/access.rs`, `src/auth.rs`, authorized GraphQL/gRPC readers, `subject_effective_grants` and `grant_scope_matches` in migrations.
- Existing conventions/contracts: one canonical subject-forward expansion; online checks hit DB; deny overrides; conditions fail closed; tenant lifecycle and token ceilings filter visibility.
- Change boundaries: preserve PostgreSQL functions/views and query plans inside the adapter.

## Inputs, outputs, and interfaces

- Inputs/preconditions: Auth context, action, object, optional request context/credential ceiling.
- Outputs/postconditions: Existing decision, explanation, grants, and visible IDs.
- API/schema/event contract: No change.
- Compatibility requirement: Normalized output and query count/performance remain within current contracts and NFR-2.

## Dependencies and sequencing

- Blocked by: DB-002
- Blocks: DB-006 boundary gate, DB-010
- External dependency: None

## Failure modes and edge cases

- Missing/invalid conditions -> fail closed.
- Inactive/deleted entity or tenant -> deny/hide consistently.
- Matching deny plus allow -> deny immediately.
- Group cycles/corrupt paths -> current database guards and fail-closed behavior remain.

## Acceptance criteria

- Existing PDP, explain, gate, scope-parity, ceiling, and authorized-listing tests produce unchanged results.
- Every subject-forward reader calls the authorization-read façade and ultimately the same PostgreSQL canonical expansion.
- Benchmark p95 remains within NFR-2 and no per-grant round trips are introduced.

## Verification

- Tests to add/update: boundary/dispatch tests; existing authz, inheritance, conditions, gates, listings, audit visibility, and ceiling suites.
- Commands: `cargo fmt --check`; `cargo clippy --locked -- -D warnings`; `cargo test`; PostgreSQL ignored tests; benchmark command established by DB-001.
- Manual/operational evidence: Query-flow and benchmark comparison in PR.

## Definition of done

- [ ] Decision and visibility parity evidence passes.
- [ ] No subject-forward alternative expansion was introduced.
- [ ] PostgreSQL-specific logic is contained in its adapter.
- [ ] PR description includes `Closes #<leaf-issue-number>` after publication.
