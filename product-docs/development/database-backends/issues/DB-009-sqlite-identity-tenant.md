# DB-009 — Implement SQLite identity, tenant, and authentication storage

## Objective

Implement SQLite parity for identity, credentials, sessions, profiles, tenants,
invitations, authentication, and bootstrap using the established repository contracts.

## Product and design context

- PRD: `product-docs/development/database-backends/PRD.md`
- RFC: `product-docs/development/database-backends/RFC.md`
- Requirements: FR-3, FR-5, FR-8; NFR-4 through NFR-7, NFR-9
- Parent capability: Implement full SQLite behavior

## Ownership and AI execution contract

- Accountable human: `@arvindh123` (proposed)
- Human reviewer: Identity, database, and security reviewers TBD
- AI executor: Any approved coding agent
- Expected PR: One focused PR
- Stop and escalate when: password/shared-key verification, revocation provenance, tenant boundaries, or restore semantics would differ from PostgreSQL.

## Scope

**In scope:** SQLite adapter implementations for the DB-003 contracts, including
entity/group membership portions owned by identity, credentials/access tokens,
sessions, profiles, tenants/invitations, auth lookups, and bootstrap idempotency.

**Out of scope:** Authorization decision/mutation adapters and certificate-specific PKI lifecycle.

## Verified repository context

- Relevant paths/symbols: PostgreSQL adapters originating from `src/identity/`, `src/tenants/repo.rs`, `src/auth.rs`, and `src/bootstrap.rs`; SQLite support from DB-007/008.
- Existing conventions/contracts: API key IDs allow O(1) lookup; access-token ceilings are online; membership no-ops publish no event; tenant/entity restore credential rules differ deliberately.
- Change boundaries: implement the same repository contracts without transport changes.

## Inputs, outputs, and interfaces

- Inputs/preconditions: DB-008 codecs/invariants and a migrated SQLite database.
- Outputs/postconditions: Existing identity and tenant models, events, and errors match PostgreSQL.
- API/schema/event contract: No change.
- Compatibility requirement: Password, HMAC/argon2 fallback, session, soft-delete, restore, purge-reference, and bootstrap behavior remain equivalent.

## Dependencies and sequencing

- Blocked by: DB-003, DB-008
- Blocks: DB-015
- External dependency: Redis only for existing cache-gated tests

## Failure modes and edge cases

- Concurrent duplicate email/name/external ID -> one success and documented conflict.
- Entity/tenant delete or restore -> immediate write transaction preserves revocation and event state.
- No-op membership/bootstrap -> no false event.
- One SQLite connection -> no nested pool acquisition.

## Acceptance criteria

- Every identity, tenant, authentication, profile, invitation, bootstrap, credential, session, delete/restore/purge test passes against SQLite.
- Normalized success and error outputs match the PostgreSQL fixture.
- Cache barriers and transactional events remain correctly ordered.
- Concurrency tests leave one valid result without partial state.

## Verification

- Tests to add/update: backend-parameterized DB-003 suite, duplicate-write races, one-connection flows, restart persistence, no-op events.
- Commands: `cargo fmt --check`; `cargo clippy --locked -- -D warnings`; `cargo test`; SQLite DB-gated tests with `--include-ignored --test-threads=1`.
- Manual/operational evidence: Normalized PostgreSQL/SQLite comparison summary.

## Definition of done

- [ ] Acceptance and parity criteria pass.
- [ ] No authorization/PKI scope was silently stubbed.
- [ ] All same-transaction validators assigned by DB-008 are implemented for this domain.
- [ ] PR description includes `Closes #<leaf-issue-number>` after publication.
