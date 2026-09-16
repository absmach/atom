# PRD: Runtime Database Backends and SQLite Parity

| Field | Value |
|---|---|
| Status | Draft |
| Accountable owner | `@arvindh123` (proposed; confirm before publication) |
| Reviewers | Database, security, and operations reviewers TBD before publication |
| Target users | Atom operators, application teams, contributors, and edge deployments |
| Initiative slug | `database-backends` |
| Related RFC | `product-docs/development/database-backends/RFC.md` |
| Epic | `[Epic] Run Atom on PostgreSQL or SQLite with equivalent behavior` |

## Problem

Atom currently requires PostgreSQL. Runtime state exposes `PgPool`, at least 45
source files refer directly to PostgreSQL types, and roughly 434 dynamic SQL
calls are spread across repositories, services, startup, and background jobs.
The 25 current migrations contain PostgreSQL-specific JSONB, arrays, functions,
triggers, advisory locks, row locking, and `SKIP LOCKED` behavior.

This coupling prevents a small deployment from running Atom as one binary plus
one local database file, and makes every future backend a cross-cutting rewrite.
A superficial pool alias would be unsafe: authorization expansion, transactional
events, purge, and PKI invariants currently depend on PostgreSQL semantics.

## Goals

- **G-1:** Let an operator select PostgreSQL or SQLite from `DATABASE_URL` in the same Atom binary.
- **G-2:** Provide complete public-API and security-behavior parity on SQLite.
- **G-3:** Preserve existing PostgreSQL schema, upgrade, performance, and deployment behavior.
- **G-4:** Establish an internal backend boundary that can accept another database without changing transports or domain services.
- **G-5:** Keep PostgreSQL the recommended backend for multi-replica and high-write deployments while supporting SQLite as a production single-instance option.

## Non-goals

- **NG-1:** PostgreSQL-to-SQLite or SQLite-to-PostgreSQL data transfer.
- **NG-2:** Multiple Atom processes or network-shared storage for one SQLite file.
- **NG-3:** SQLCipher or another built-in whole-file encryption layer.
- **NG-4:** A public third-party database plugin ABI.
- **NG-5:** Replacing SQLx with an ORM or reducing PostgreSQL to a lowest-common-denominator query plan.
- **NG-6:** Changing Atom's HTTP, GraphQL, gRPC, event, bootstrap YAML, authz, or PKI contracts.
- **NG-7:** Resolving the health-check and serverless PostgreSQL behavior tracked separately in GitHub issue #42.

## Success metrics and guardrails

| ID | Metric | Baseline | Target | Window | Instrumentation owner |
|---|---|---|---|---|---|
| M-1 | DB-gated behavioral suites passing per backend | PostgreSQL only | 100% on PostgreSQL and SQLite | Every CI run | Engineering |
| M-2 | v1 contract artifact drift | 0 accepted drift | 0 drift | Every CI run | Engineering |
| M-3 | PostgreSQL-specific types or SQL outside backend storage | 45 source files currently reference PostgreSQL types | 0 prohibited references | Every CI run | Engineering |
| M-4 | Atomic mutation/outbox invariant failures | 0 known | 0 across crash and rollback tests | Every release | Database reviewer |
| M-5 | PostgreSQL authz hot-path regression | Benchmark to be captured before refactor | No greater than 10% p95 regression on the fixed CI fixture | Before release | Engineering |
| M-6 | SQLite parity defects open at release | Not applicable | 0 severity-1/2 parity defects | Release gate | Accountable owner |

## User journeys

### Journey 1: Start a file-backed SQLite deployment

1. An operator supplies a `sqlite://...` `DATABASE_URL` with a local path.
2. Atom validates the topology, creates the file if absent, applies SQLite migrations, and logs the selected backend.
3. The operator bootstraps and uses every Atom API without provisioning PostgreSQL.
4. A second Atom process targeting the same file fails startup with a clear single-owner error.

### Journey 2: Upgrade an existing PostgreSQL deployment

1. An operator deploys the new binary with the existing PostgreSQL URL.
2. Atom uses the unchanged PostgreSQL migration history and current pool configuration.
3. Existing clients, data, authorization decisions, audit events, and PKI artifacts behave as before.
4. Rollback follows the existing PostgreSQL release procedure because no SQLite cutover occurred.

### Journey 3: Develop or test ephemerally

1. A contributor supplies `sqlite::memory:`.
2. Atom uses a single connection, applies the SQLite baseline, and runs without external database infrastructure.
3. Tests observe the same domain and API results as the PostgreSQL fixture.

### Journey 4: Recover from SQLite operational failure

1. Atom detects a locked/busy database beyond the configured timeout, migration failure, corrupt file, or unavailable path.
2. Startup failures stop before serving; request-time exhaustion returns service unavailable without weakening authorization or committing a partial mutation.
3. The operator follows the documented backup/restore procedure and restarts one Atom instance.

## Functional requirements

- **FR-1:** Atom must select PostgreSQL for `postgres://`/`postgresql://` URLs and SQLite for `sqlite://`/`sqlite::memory:` URLs in one binary, rejecting unsupported schemes before serving.
- **FR-2:** Existing PostgreSQL databases must retain their migration history, stored meanings, public behavior, and supported in-place upgrade boundary.
- **FR-3:** SQLite must support every mounted HTTP, GraphQL, and gRPC operation plus bootstrap, authentication, authorization, audit/outbox, purge, signing-key, and PKI behavior.
- **FR-4:** Atom must automatically apply the migration set belonging to the selected backend and must fail startup on migration or compatibility errors.
- **FR-5:** Mutations must preserve Atom's current transaction, audit, cache-invalidation, and transactional-outbox rules on both backends.
- **FR-6:** SQLite authorization decisions and visibility must use one canonical grant expansion and scope matcher with deny-overrides, ABAC fail-closed behavior, access-token ceilings, and immediate revocation parity.
- **FR-7:** File-backed SQLite must enforce a single Atom owner, support concurrent in-process requests, and provide durable restart behavior; memory mode must remain isolated and ephemeral.
- **FR-8:** Backend constraint, not-found, conflict, invalid-reference, invalid-value, busy, and internal failures must map to the existing transport semantics consistently.
- **FR-9:** Operators must receive documented configuration, persistence, backup, restore, capacity, and unsupported-topology guidance for SQLite.
- **FR-10:** Domain and transport code must depend on backend-neutral database and repository interfaces; PostgreSQL- or SQLite-specific SQL and types must remain inside backend adapters.

## Non-functional requirements

- **NFR-1:** The checked-in v1 OpenAPI, GraphQL, and protobuf contracts must remain byte-for-byte unchanged.
- **NFR-2:** PostgreSQL authz hot-path p95 latency must not regress by more than 10% on the fixed benchmark fixture introduced before refactoring.
- **NFR-3:** SQLite file connections must enable foreign keys, recursive triggers, WAL, `synchronous=FULL`, and a 30-second busy timeout; write transactions must begin immediately.
- **NFR-4:** A SQLite busy timeout must fail closed and map to service unavailable; no mutation may be partially committed.
- **NFR-5:** Sensitive recoverable material must continue using Atom's existing application encryption, and neither backend may log plaintext or wrapped key material.
- **NFR-6:** A committed mutation that enables domain events must never lose its outbox row; duplicate delivery after recovery remains acceptable under the existing at-least-once contract.
- **NFR-7:** Both backend suites must cover single-connection execution so no transaction path can borrow a second pool connection.
- **NFR-8:** Released PostgreSQL migrations must remain immutable, and every post-baseline schema change must have paired PostgreSQL and SQLite migrations with the same version number.
- **NFR-9:** SQLite schema constraints/triggers or same-transaction application validation must preserve tenant isolation, soft-delete, policy cleanup, credential, and PKI invariants.
- **NFR-10:** Adding a future internal backend must not require changes to public transports, domain models, or event envelopes.

## Constraints and dependencies

- Rust 2021, Axum 0.7, SQLx 0.8.6, async-graphql 7.2.1, and the existing public contracts remain fixed for this initiative.
- PostgreSQL migrations in `migrations/` are release-controlled and cannot be edited or relocated.
- SQLite is a single-writer database; the supported topology is one Atom process with bounded concurrent readers.
- The canonical PostgreSQL grant expansion remains optimized SQL; SQLite needs an equivalent backend-specific implementation rather than a portable-SQL rewrite.
- The current GitHub token cannot read organization Projects; project placement must be confirmed before publication.

## Assumptions and validation

| Assumption | Impact if false | Validation | Owner |
|---|---|---|---|
| `@arvindh123` is the accountable owner | Publication ownership is wrong | Confirm before issue publication | Requester |
| SQLx's bundled SQLite build supplies required JSON and `RETURNING` support | Additional native dependency or query redesign | Compile and migration smoke test in DB-007 | DB-007 owner |
| One local process is acceptable for SQLite adopters | File locking and worker coordination design changes materially | Confirm in release review and docs | Product reviewer |
| Existing public APIs define parity; direct manual database writes are unsupported | More database-only compatibility work is needed | Approve RFC boundary | Database reviewer |
| A 10% PostgreSQL p95 regression budget is acceptable | Release guardrail must change | Capture baseline and approve before DB-003 | Engineering reviewer |

## Risks and mitigations

| Risk | Likelihood | Impact | Mitigation/contingency | Owner |
|---|---|---|---|---|
| Authorization semantics drift between dialects | High | High | Canonical backend queries, differential fixtures, deny/ceiling parity tests | Security reviewer |
| Large refactor regresses PostgreSQL | Medium | High | PostgreSQL-only foundation PRs, benchmark first, no migration edits | Engineering reviewer |
| SQLite writes block during broker or PKI work | Medium | High | Short immediate transactions; never hold SQLite write lock across broker I/O | Database reviewer |
| Schema triggers differ from PostgreSQL | High | High | Explicit invariant matrix and negative tests per backend | Database reviewer |
| SQLite is deployed on shared/network storage | Medium | High | Process lock, startup rejection where detectable, prominent unsupported-topology docs | Operations reviewer |
| Dual-backend CI becomes too slow | Medium | Medium | Fresh isolated SQLite files, bounded fixtures, separate exhaustive/nightly lanes if measured | CI owner |

## Acceptance and release criteria

- All existing PostgreSQL tests and v1 contract checks pass after each foundation PR.
- Every database-relevant integration test passes against a fresh PostgreSQL database and a fresh SQLite file.
- Differential authz, visibility, lifecycle, audit/outbox, purge, and PKI scenarios produce equivalent normalized results.
- SQLite durability, restart, file ownership, busy timeout, rollback, backup, and restore evidence is attached to the release issue.
- PostgreSQL benchmark regression remains within NFR-2.
- No prohibited backend-specific dependency remains outside storage adapters and fixtures.
- Documentation identifies PostgreSQL as the multi-replica/high-write default and SQLite as a supported single-instance alternative.
- Database, security, operations, and product reviewers approve the RFC and release evidence.

## Requirement traceability

| Requirement | Acceptance evidence | Issue or planned issue | Verification |
|---|---|---|---|
| FR-1, FR-4 | Runtime URL and migration-selection tests | DB-001, DB-007 | Unit and startup integration tests |
| FR-2, NFR-1, NFR-2 | Existing suite, contract checks, benchmark | DB-001 through DB-006, DB-015 | CI and benchmark report |
| FR-3 | Complete dual-backend matrix | DB-009 through DB-015 | DB-gated tests on both URLs |
| FR-5, NFR-6, NFR-7 | Rollback, cache, audit, outbox tests | DB-002, DB-012, DB-015 | Failure-injection and one-connection suites |
| FR-6 | Normalized PDP/explain/listing parity | DB-004, DB-010, DB-015 | Differential authorization suite |
| FR-7, NFR-3, NFR-4 | PRAGMA, ownership, restart, contention tests | DB-007, DB-012, DB-015 | SQLite operational integration tests |
| FR-8 | Backend-neutral error matrix | DB-002, DB-008, DB-015 | HTTP/GraphQL/gRPC negative tests |
| FR-9 | Reviewed operations guide | DB-016 | Documentation and restore drill |
| FR-10, NFR-10 | Architecture boundary check | DB-001 through DB-006 | Static CI guard and review |
| NFR-5, NFR-9 | Secret-redaction and invariant tests | DB-008, DB-013, DB-014, DB-015 | Security and schema negative tests |
| NFR-8 | Paired migration validation | DB-007, DB-016 | Migration-check script and CI |

## Decisions and follow-ups

| Item | Classification | Owner | Due/trigger | Resolution |
|---|---|---|---|---|
| SQLite feature level | Resolved | Product | Planning | Full production parity |
| Backend selection | Resolved | Product | Planning | Runtime `DATABASE_URL` scheme |
| Abstraction style | Resolved | Engineering | Planning | Internal backend adapters; no public plugin API |
| SQLite topology | Resolved | Operations | Planning | One Atom process per local file |
| Durability | Resolved | Database | Planning | WAL plus `synchronous=FULL` and immediate writes |
| Whole-file encryption | Resolved | Security | Planning | No SQLCipher; retain field encryption and require disk controls |
| Data transfer | Resolved | Product | Planning | Out of scope |
| Human reviewers | Blocking publication | Accountable owner | Before GitHub publication | TBD |
| GitHub Project/iteration | Owned follow-up | Accountable owner | Before GitHub publication | Project visibility unavailable to current token |
