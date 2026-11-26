# DB-010 — Implement SQLite authorization decisions and visibility

## Objective

Implement the canonical SQLite grant expansion, scope matcher, PDP/explain
context, control-plane gates, access-token ceilings, and authorized visibility
readers with PostgreSQL-equivalent results.

## Product and design context

- PRD: `product-docs/development/database-backends/PRD.md`
- RFC: `product-docs/development/database-backends/RFC.md`
- Requirements: FR-3, FR-6; NFR-2, NFR-4, NFR-7, NFR-9
- Parent capability: Implement full SQLite behavior

## Ownership and AI execution contract

- Accountable human: `@arvindh123` (proposed)
- Human reviewer: Security and database reviewers TBD
- AI executor: Any approved coding agent
- Expected PR: One focused PR
- Stop and escalate when: more than one subject-forward expansion/scope implementation is needed or a PostgreSQL result cannot be matched without changing public semantics.

## Scope

**In scope:** SQLite implementation of all DB-004 contracts using one reusable
recursive grant CTE and one scope-matching fragment; explicit null/sort/time/JSON
semantics where dialect defaults differ.

**Out of scope:** Authorization mutations, reverse guardrails, and PostgreSQL function rewrites.

## Verified repository context

- Relevant paths/symbols: DB-004 authorization-read façade; PostgreSQL `subject_effective_grants`, `grant_scope_matches`, `permission_block_scopes`, credential ceiling view, and `src/authz/engine.rs`.
- Existing conventions/contracts: batched online evaluation, deny-overrides, ABAC fail-closed, recursive groups, tenant lifecycle deny, visibility/PDP ceiling parity.
- Change boundaries: SQLite adapter only plus backend-neutral differential fixtures where necessary.

## Inputs, outputs, and interfaces

- Inputs/preconditions: SQLite identity/tenant data from DB-009 and DB-008 codecs.
- Outputs/postconditions: Identical normalized decision/explain/grant/listing outputs.
- API/schema/event contract: No change.
- Compatibility requirement: No permissions in tokens and no per-grant query round trips.

## Dependencies and sequencing

- Blocked by: DB-004, DB-008, DB-009
- Blocks: DB-015
- External dependency: None

## Failure modes and edge cases

- Conditional/malformed grant -> same fail-closed result as PostgreSQL.
- Multiple parent object groups -> membership and ancestor scopes match all valid paths.
- Inactive/deleted tenant/entity -> deny and hide consistently.
- NULL ordering/case/time comparison -> explicit dialect logic matches tested contract.

## Acceptance criteria

- PDP, bulk check, explain, gates, inheritance, ABAC operators, deny precedence, ceilings, tenant/audit visibility, and every authorized listing pass on SQLite.
- Differential fixtures compare normalized evaluated bindings and reasons, not generated IDs/timestamps.
- Static review finds exactly one SQLite subject-forward grant expansion and scope matcher consumed by all required readers.
- Query-count tests show no per-grant or per-binding round trips.

## Verification

- Tests to add/update: full DB-004 suite on SQLite plus differential scope/ABAC/ceiling/visibility matrices and query-count guard.
- Commands: `cargo fmt --check`; `cargo clippy --locked -- -D warnings`; `cargo test`; SQLite and PostgreSQL authz integration suites.
- Manual/operational evidence: Canonical query/data-flow review attached to PR.

## Definition of done

- [ ] Authorization parity and fail-closed criteria pass.
- [ ] Canonical expansion rule is documented and statically reviewable.
- [ ] No mutation or reverse-guardrail implementation is bundled.
- [ ] PR description includes `Closes #<leaf-issue-number>` after publication.
