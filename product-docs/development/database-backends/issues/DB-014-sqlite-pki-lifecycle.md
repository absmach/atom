# DB-014 — Implement SQLite certificate and PKI lifecycle parity

## Objective

Implement SQLite certificate issuance, CSR/generated-key flows, renewal,
revocation evidence, CRL, OCSP, resolver, enrollment, lifecycle automation, and
purge behavior with PostgreSQL-equivalent security and recovery semantics.

## Product and design context

- PRD: `product-docs/development/database-backends/PRD.md`
- RFC: `product-docs/development/database-backends/RFC.md`
- Requirements: FR-3, FR-5, FR-8; NFR-4 through NFR-7, NFR-9
- Parent capability: Implement full SQLite behavior

## Ownership and AI execution contract

- Accountable human: `@arvindh123` (proposed)
- Human reviewer: PKI/security, database, and operations reviewers TBD
- AI executor: Any approved coding agent
- Expected PR: One focused PR
- Stop and escalate when: certificate identity, issuer derivation, serial collision, revocation immutability, CRL/OCSP correctness, or enrollment trust would differ.

## Scope

**In scope:** SQLite adapters for remaining certificate repositories/services,
nested serial-collision savepoints, issuance requests, renewal links, revocation
evidence, issuer CRLs, OCSP/resolver, enrollment accounting, automation, and PKI purge ordering.

**Out of scope:** New certificate APIs/profiles/transports or PKCS#11 provider design changes.

## Verified repository context

- Relevant paths/symbols: `src/certs/repo.rs`, `src/certs/service.rs`, `src/certs/enrollment/`, `src/certs/lifecycle/`, `src/certs/graphql.rs`, `src/grpc.rs`, migrations 014 through 023.
- Existing conventions/contracts: each serial-collision attempt is a nested transaction; revocation evidence is immutable/durable; certificates remain revoked across restore; issuer artifacts and tenant purge have strict ordering.
- Change boundaries: SQLite lifecycle adapter and parity tests.

## Inputs, outputs, and interfaces

- Inputs/preconditions: DB-013 authorities/profiles/keys and DB-009 entities/credentials.
- Outputs/postconditions: Existing certificate responses, stored evidence, artifacts, and lifecycle results.
- API/schema/event contract: No change.
- Compatibility requirement: Issuer/serial/fingerprint, tenant identity, audit/events, CRL/OCSP, and enrollment semantics match PostgreSQL.

## Dependencies and sequencing

- Blocked by: DB-009, DB-012, DB-013
- Blocks: DB-015
- External dependency: Existing real PKI smoke and PKCS#11 infrastructure where configured

## Failure modes and edge cases

- Serial collision -> savepoint retry without poisoning outer mutation.
- Crash/rollback during issuance/revocation -> no credential/event mismatch.
- Revocation update/delete attempt -> immutable evidence rejects it.
- Tenant purge -> ordered credential/evidence/authority cleanup without dangling authz references.
- Lifecycle overlap -> single-process worker and immediate transactions serialize safely.

## Acceptance criteria

- All CSR, generated issuance, renewal, revocation, CRL, OCSP, resolver, enrollment, lifecycle, legacy migration, and purge tests pass on SQLite.
- Cross-tenant/issuer and invalid-link cases fail identically to PostgreSQL.
- Serial collision, one-connection, rollback, and restart tests preserve atomicity and immutable evidence.
- Independent certificate/CRL/OCSP verification succeeds for SQLite-produced state.

## Verification

- Tests to add/update: backend-parameterized PKI suite, savepoint collision, revocation immutability, lifecycle contention, purge ordering, independent artifact verification.
- Commands: `cargo fmt --check`; `cargo clippy --locked -- -D warnings`; `cargo test`; SQLite PKI integration suite; existing PKI smoke commands where infrastructure is available.
- Manual/operational evidence: Security review plus artifact verification report.

## Definition of done

- [ ] Milestone B functional PKI parity passes.
- [ ] Every DB-008 lifecycle invariant owner is closed.
- [ ] No public PKI contract or trust boundary changes.
- [ ] PR description includes `Closes #<leaf-issue-number>` after publication.
