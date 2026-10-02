# DB-013 — Implement SQLite signing keys and PKI foundation

## Objective

Implement SQLite persistence for signing keys, encrypted database key providers,
authority registry/provisioning, certificate profiles, and PKI startup bootstrap
while preserving key isolation and tenant/issuer invariants.

## Product and design context

- PRD: `product-docs/development/database-backends/PRD.md`
- RFC: `product-docs/development/database-backends/RFC.md`
- Requirements: FR-3, FR-5, FR-8; NFR-4 through NFR-7, NFR-9
- Parent capability: Implement full SQLite behavior

## Ownership and AI execution contract

- Accountable human: `@arvindh123` (proposed)
- Human reviewer: PKI/security and database reviewers TBD
- AI executor: Any approved coding agent
- Expected PR: One focused PR
- Stop and escalate when: issuer selection, authority hierarchy, profile ceilings, KEK behavior, or secret observability would change.

## Scope

**In scope:** SQLite adapters for ES256 signing-key bootstrap/load/rotation,
encrypted authority keys, authority registry/import/provisioning, profile/version
storage and validation, and configured root/intermediate startup bootstrap.

**Out of scope:** Leaf issuance, renewal, revocation, CRL/OCSP, enrollment, and lifecycle automation.

## Verified repository context

- Relevant paths/symbols: `src/keys.rs`, `src/certs/authority/`, `src/certs/profile.rs`, profile repositories, PKI bootstrap in `src/main.rs`, migrations 011 through 013 and 021 through 024.
- Existing conventions/contracts: ES256 `kid` rotation, AES-GCM field encryption, no plaintext/unsafe `Debug`, issuer derived from entity scope, profile ceilings enforced in PostgreSQL functions/triggers.
- Change boundaries: SQLite adapter and invariant tests only.

## Inputs, outputs, and interfaces

- Inputs/preconditions: DB-008 codecs/invariants and configured KEKs/certificate files.
- Outputs/postconditions: Existing active keys, authorities, and profiles round-trip with equivalent validation.
- API/schema/event contract: No change.
- Compatibility requirement: Key material never becomes caller-selectable or observable; root/private-key trust boundary remains intact.

## Dependencies and sequencing

- Blocked by: DB-008, DB-009
- Blocks: DB-014, DB-015
- External dependency: Existing PKCS#11 tests remain compile/run gates where configured

## Failure modes and edge cases

- Missing/wrong KEK -> safe startup/operation failure without key bytes in errors.
- Concurrent key/authority enablement -> unique invariant and serialized result.
- Invalid authority parent/scope/validity or profile ceiling -> rejected in same transaction.
- Startup file I/O -> remains asynchronous/time-bounded as current conventions require.

## Acceptance criteria

- Signing-key, authority, provisioning, profile, bootstrap, encryption, rotation, and recovery suites pass on SQLite.
- Negative cross-tenant, parent, validity, enabled-issuer, profile ceiling, and secret-redaction tests match PostgreSQL.
- Nested transactions and one-connection pool behavior do not deadlock.
- No secret-bearing type or error emits key material.

## Verification

- Tests to add/update: DB-013 domain suites on SQLite, concurrent enable/rotation, invalid hierarchy/profile, KEK failures, debug/log redaction, restart persistence.
- Commands: `cargo fmt --check`; `cargo clippy --locked -- -D warnings`; `cargo test`; SQLite PKI foundation tests; configured PKCS#11 suite.
- Manual/operational evidence: Security review of storage and observable output.

## Definition of done

- [ ] Acceptance and security evidence passes.
- [ ] Every DB-008 PKI-foundation invariant owner is closed.
- [ ] Lifecycle scope remains in DB-014.
- [ ] PR description includes `Closes #<leaf-issue-number>` after publication.
