# DB-016 — Publish SQLite operations guidance and complete release readiness

## Objective

Provide PostgreSQL-first and SQLite single-instance deployment guidance,
container examples, backup/restore and rollback procedures, observability/support
boundaries, and the final human release review.

## Product and design context

- PRD: `product-docs/development/database-backends/PRD.md`
- RFC: `product-docs/development/database-backends/RFC.md`
- Requirements: FR-4, FR-7, FR-9, FR-10; NFR-3 through NFR-5, NFR-8 through NFR-10
- Parent capability: Prove parity and release safely

## Ownership and AI execution contract

- Accountable human: `@arvindh123` (proposed)
- Human reviewer: Product, database, security, documentation, and operations reviewers TBD
- AI executor: Any approved coding agent
- Expected PR: One focused PR
- Stop and escalate when: documentation would imply multi-instance/shared-storage support, safe transfer between backends, SQLCipher, or a rollback path not proven by a drill.

## Scope

**In scope:** README/config reference, quick-start choice, SQLite container volume
example, backup/restore/integrity procedure, file permissions/disk encryption,
capacity/topology guidance, observability, paired migration contributor rules,
rollback/upgrade notes, and release checklist/evidence review.

**Out of scope:** Changing PostgreSQL as default, data transfer tooling, managed backup automation, or release publication without approval.

## Verified repository context

- Relevant paths/symbols: `README.md`, `docker-compose.yml`, `Makefile`, `.env` guidance, `docs/content/docs/quickstart.mdx`, architecture docs, `product-docs/14-v1-compatibility.md`, `.github/workflows/rust.yml`.
- Existing conventions/contracts: PostgreSQL is current Quick Start/default Compose dependency; automatic migrations and release checks are documented; startup/readiness and graceful shutdown are production contracts.
- Change boundaries: documentation, examples, release checks, and only minimal safe container configuration needed for SQLite persistence.

## Inputs, outputs, and interfaces

- Inputs/preconditions: DB-015 passing evidence and a release-candidate binary.
- Outputs/postconditions: Operators can deploy, back up, restore, diagnose, upgrade, and roll back within the supported SQLite boundary.
- API/schema/event contract: No change.
- Compatibility requirement: Existing PostgreSQL Quick Start and Compose remain default and functional.

## Dependencies and sequencing

- Blocked by: DB-015
- Blocks: Epic acceptance and SQLite support announcement
- External dependency: Human reviewers and a durable-volume environment for restore drill

## Failure modes and edge cases

- Backup omits WAL state -> documented safe snapshot/checkpoint procedure and restore verification.
- File permissions/disk controls weak -> explicit production checklist.
- Operator starts two replicas/shared volume -> documentation and startup failure explain unsupported topology.
- Downgrade after SQLite migration -> only documented compatible binary or backup restore is allowed.

## Acceptance criteria

- A new operator can start PostgreSQL using the unchanged default path and SQLite using the documented file/memory paths.
- A clean SQLite volume survives restart; a documented backup restored to a new path passes integrity and Atom readiness checks with representative data.
- Docs clearly state one process/local file, WAL/full durability, pool defaults, busy behavior, disk encryption responsibility, no transfer tool, and PostgreSQL scaling recommendation.
- Contributor docs require paired post-025 migrations and both backend tests.
- Product, database, security, and operations reviewers sign off on DB-015 evidence and the release checklist.

## Verification

- Tests to add/update: documentation command smoke tests where automatable, Compose/config validation, backup/restore drill script or runbook verification.
- Commands: documented Quick Starts; `cargo fmt --check`; `cargo clippy --locked -- -D warnings`; `cargo test`; both DB suites; `scripts/check-v1-contracts.sh`.
- Manual/operational evidence: Fresh deploy, restart, backup, restore, integrity check, and rollback rehearsal report.

## Definition of done

- [ ] Acceptance criteria pass with operator evidence.
- [ ] PostgreSQL remains the recommended/default production path.
- [ ] No unsupported capability is implied.
- [ ] PR description includes `Closes #<leaf-issue-number>` after publication.
