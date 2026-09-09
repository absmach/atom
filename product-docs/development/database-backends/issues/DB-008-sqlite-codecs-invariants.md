# DB-008 — Add SQLite codecs, error mapping, and invariant coverage

## Objective

Provide reusable SQLite value conversion and error classification, and establish
an explicit schema/application invariant matrix before domain adapters write data.

## Product and design context

- PRD: `product-docs/development/database-backends/PRD.md`
- RFC: `product-docs/development/database-backends/RFC.md`
- Requirements: FR-8, FR-10; NFR-4, NFR-5, NFR-8, NFR-9
- Parent capability: Implement full SQLite behavior

## Ownership and AI execution contract

- Accountable human: `@arvindh123` (proposed)
- Human reviewer: Database and security reviewers TBD
- AI executor: Any approved coding agent
- Expected PR: One focused PR
- Stop and escalate when: a persisted enum/string meaning, uniqueness behavior, or security invariant cannot be represented consistently.

## Scope

**In scope:** UUID/time/boolean/enum/JSON/array adapters, SQLite row conversion
helpers, backend-neutral extended error mapping, constraint attribution, and
positive/negative tests for every baseline invariant.

**Out of scope:** Complete identity/authz/PKI repository queries.

## Verified repository context

- Relevant paths/symbols: `src/models/`, especially `models/enums.rs`; `src/error.rs`; all `sqlx::FromRow` models; PostgreSQL CHECK/FK/index/trigger definitions in migrations.
- Existing conventions/contracts: project enums serialize to stored text; unique/FK/check errors have stable caller semantics; PKI and policy cleanup use database triggers.
- Change boundaries: shared SQLite adapter support and baseline invariant tests.

## Inputs, outputs, and interfaces

- Inputs/preconditions: DB-007 migrated SQLite database.
- Outputs/postconditions: Domain values round-trip losslessly; database errors classify consistently; invariant coverage gaps are explicit and closed.
- API/schema/event contract: No public change.
- Compatibility requirement: Persisted strings and normalized transport errors match PostgreSQL meanings.

## Dependencies and sequencing

- Blocked by: DB-007
- Blocks: DB-009 through DB-014
- External dependency: None

## Failure modes and edge cases

- Invalid UUID/time/enum/JSON/array -> rejected without panic or permissive fallback.
- Unique error lacks index name -> adapter/repository context still returns the documented field-specific conflict.
- SQLite busy/locked after timeout -> service unavailable, not generic internal or partial commit.
- Trigger-inexpressible invariant -> documented same-transaction validator plus race test owner.

## Acceptance criteria

- Every supported scalar/JSON/array representation round-trips optional and required values.
- Unique, FK, CHECK, not-found, malformed-value, and busy errors map to the RFC matrix.
- An invariant table maps every PostgreSQL constraint/trigger relied on by Atom to a SQLite constraint/trigger or named same-transaction validator with a planned domain owner.
- Negative direct-schema tests reject invalid tenant, credential, policy-cleanup, and PKI shapes covered by the baseline.

## Verification

- Tests to add/update: codec property/table tests, malformed row tests, backend error matrix, schema invariant suite, busy timeout.
- Commands: `cargo fmt --check`; `cargo clippy --locked -- -D warnings`; `cargo test`; SQLite integration tests.
- Manual/operational evidence: Invariant matrix attached or checked into the RFC appendix if implementation changes it.

## Definition of done

- [ ] Acceptance criteria pass.
- [ ] No codec logs sensitive data or silently coerces invalid values.
- [ ] Every deferred application validator has a blocking owner among DB-009 through DB-014.
- [ ] PR description includes `Closes #<leaf-issue-number>` after publication.
