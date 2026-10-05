# DB-003 — Isolate PostgreSQL identity, tenant, and authentication storage

## Objective

Move identity, credential, session, profile, tenant, invitation, and bootstrap
persistence behind backend-neutral repository façades with no PostgreSQL behavior
change.

## Product and design context

- PRD: `product-docs/development/database-backends/PRD.md`
- RFC: `product-docs/development/database-backends/RFC.md`
- Requirements: FR-2, FR-5, FR-8, FR-10; NFR-1, NFR-2, NFR-6, NFR-7
- Parent capability: Isolate persistence without PostgreSQL regression

## Ownership and AI execution contract

- Accountable human: `@arvindh123` (proposed)
- Human reviewer: Identity/database reviewer TBD
- AI executor: Any approved coding agent
- Expected PR: One focused PR
- Stop and escalate when: authentication, credential revocation, restore provenance, or tenant lifecycle semantics would change.

## Scope

**In scope:** PostgreSQL adapter boundaries for identity repositories/services,
access tokens, profiles, tenants/invitations, authentication lookups, and YAML/env bootstrap.

**Out of scope:** Authorization repository internals, PKI issuance, and SQLite SQL.

## Verified repository context

- Relevant paths/symbols: `src/identity/repo.rs`, `src/identity/service.rs`, `src/identity/access_tokens.rs`, `src/identity/profile_repo.rs`, `src/tenants/repo.rs`, `src/auth.rs`, `src/bootstrap.rs`.
- Existing conventions/contracts: layered handler/service/repo flow, soft-delete/restore rules, tenant-delete revocation provenance, scoped-token ceilings, no second connection in a transaction.
- Change boundaries: preserve current function-level behaviors behind façades.

## Inputs, outputs, and interfaces

- Inputs/preconditions: DB-002 transaction/error contracts.
- Outputs/postconditions: domain and transport code receives existing models/errors without PostgreSQL types.
- API/schema/event contract: No change.
- Compatibility requirement: Existing credentials, sessions, tenant membership, bootstrap idempotency, and soft-delete behavior remain exact.

## Dependencies and sequencing

- Blocked by: DB-002
- Blocks: DB-006 boundary gate, DB-009
- External dependency: None

## Failure modes and edge cases

- Saturated one-connection pool -> all transaction reads remain on the transaction.
- Duplicate email/external ID/name -> field-specific conflicts remain actionable.
- Tenant/entity restore -> only credentials with the documented revocation provenance reactivate.
- Idempotent membership/bootstrap -> no false event is published.

## Acceptance criteria

- Given every existing identity/tenant integration scenario, when executed after the refactor, then results, errors, audit/events, and cache behavior are unchanged.
- Domain and transport modules in scope contain no `PgPool`, `PgConnection`, `Postgres`, PostgreSQL transaction, or raw SQL usage.
- Single-connection deletion, restoration, invitation, and credential tests pass.

## Verification

- Tests to add/update: compile-time/interface boundary tests plus all identity, tenant, profile, bootstrap, auth, credential, session, restore, purge, and invitation suites.
- Commands: `cargo fmt --check`; `cargo clippy --locked -- -D warnings`; `cargo test`; PostgreSQL ignored tests single-threaded.
- Manual/operational evidence: Before/after architecture search attached to PR.

## Definition of done

- [ ] Acceptance criteria pass with PostgreSQL evidence.
- [ ] Raw SQL for this domain exists only in the PostgreSQL storage adapter.
- [ ] Authz and PKI scope did not drift into the PR.
- [ ] PR description includes `Closes #<leaf-issue-number>` after publication.
