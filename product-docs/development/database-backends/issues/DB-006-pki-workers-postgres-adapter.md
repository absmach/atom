# DB-006 — Isolate PostgreSQL PKI, bootstrap, and background storage

## Objective

Complete the PostgreSQL boundary for signing keys, PKI, audit retention, outbox,
purge, lifecycle, startup/bootstrap, and custom endpoints, then enforce the
architecture rule in CI.

## Product and design context

- PRD: `product-docs/development/database-backends/PRD.md`
- RFC: `product-docs/development/database-backends/RFC.md`
- Requirements: FR-2, FR-5, FR-10; NFR-1, NFR-2, NFR-5 through NFR-7, NFR-10
- Parent capability: Isolate persistence without PostgreSQL regression

## Ownership and AI execution contract

- Accountable human: `@arvindh123` (proposed)
- Human reviewer: Database, PKI/security, and operations reviewers TBD
- AI executor: Any approved coding agent
- Expected PR: One focused PR
- Stop and escalate when: PKI trust/issuer semantics, secret handling, outbox delivery, purge retention, or startup ordering would change.

## Scope

**In scope:** PostgreSQL adapter boundaries for `keys`, all `certs` repositories
and services with SQL, audit/event/purge/lifecycle workers, API endpoints,
startup bootstraps, and the final static boundary check/removal of transitional accessors.

**Out of scope:** SQLite implementation and changes to certificate/public API semantics.

## Verified repository context

- Relevant paths/symbols: `src/keys.rs`, `src/certs/`, `src/audit.rs`, `src/events/mod.rs`, `src/purge.rs`, `src/api_endpoints/repo.rs`, `src/main.rs`, `src/bootstrap.rs`, `.github/workflows/rust.yml`.
- Existing conventions/contracts: nested serial-collision savepoints, async startup file I/O, transactional events, post-commit audit asymmetry, no key material in debug/logs, background advisory locks.
- Change boundaries: all remaining persistence; transports stay contract-identical.

## Inputs, outputs, and interfaces

- Inputs/preconditions: DB-002 plus completion of DB-003/004/005 before activating the global guard.
- Outputs/postconditions: No production code outside storage depends on a SQLx backend type or raw SQL.
- API/schema/event contract: No change.
- Compatibility requirement: Existing PKI, audit, event, purge, bootstrap, and custom endpoint suites remain exact.

## Dependencies and sequencing

- Blocked by: DB-002; final guard activation also requires DB-003, DB-004, DB-005
- Blocks: DB-007
- External dependency: Existing PKCS#11/AMQP test infrastructure where required

## Failure modes and edge cases

- Serial collision -> savepoint retry leaves caller transaction valid.
- Audit storage failure after valid commit -> operation remains successful.
- Broker stall -> bounded timeout and retryable undelivered rows.
- Purge/lifecycle overlap -> PostgreSQL locks retain current single-worker semantics.
- Architecture guard false positives -> allow only storage/migration/test-fixture paths.

## Acceptance criteria

- Existing PKI, signing, bootstrap, custom endpoint, audit, event, purge, and lifecycle tests pass unchanged on PostgreSQL.
- A CI check reports zero prohibited PostgreSQL type/raw-SQL references outside approved paths.
- Transitional PostgreSQL accessors are removed or private to the PostgreSQL adapter.
- NFR-2 benchmark and v1 contract checks still pass.

## Verification

- Tests to add/update: adapter dispatch; architecture guard; existing PKI migration/issuance/renewal/revocation/CRL/OCSP/enrollment/lifecycle; audit/outbox/purge/bootstrap.
- Commands: `cargo fmt --check`; `cargo clippy --locked -- -D warnings`; `cargo test --no-run --locked`; `cargo test`; PostgreSQL ignored suite; `scripts/check-v1-contracts.sh`.
- Manual/operational evidence: Final source-boundary inventory in PR.

## Definition of done

- [ ] Milestone A exit gate passes.
- [ ] No secret-bearing type gains unsafe `Debug`/logging.
- [ ] No released migration changes.
- [ ] PR description includes `Closes #<leaf-issue-number>` after publication.
