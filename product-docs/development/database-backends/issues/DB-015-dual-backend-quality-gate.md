# DB-015 — Enforce dual-backend parity, concurrency, and performance gates

## Objective

Make SQLite support release-verifiable by running the complete database matrix,
differential scenarios, failure/concurrency tests, architecture/migration checks,
and PostgreSQL performance guard in CI. This issue owns final end-to-end proof.

## Product and design context

- PRD: `product-docs/development/database-backends/PRD.md`
- RFC: `product-docs/development/database-backends/RFC.md`
- Requirements: FR-1 through FR-8, FR-10; NFR-1 through NFR-10
- Parent capability: Prove parity and release safely

## Ownership and AI execution contract

- Accountable human: `@arvindh123` (proposed)
- Human reviewer: Product/API, database, security, CI, and operations reviewers TBD
- AI executor: Any approved coding agent
- Expected PR: One focused PR
- Stop and escalate when: a test is excluded for backend convenience, parity normalization hides a real semantic difference, or performance exceeds the approved budget.

## Scope

**In scope:** Backend-parameterized fixtures, clean-database-per-binary CI,
differential result normalizers, architecture and paired-migration gates,
concurrency/failure/restart suites, benchmark comparison, and release evidence generation.

**Out of scope:** Fixing domain defects discovered by the gate in the same PR unless narrowly test-infrastructure-related; feature implementation returns to its owning issue.

## Verified repository context

- Relevant paths/symbols: `tests/common/mod.rs`, all DB-gated tests in `tests/`, `.github/workflows/rust.yml`, `scripts/check-v1-contracts.sh`, DB-001 benchmark.
- Existing conventions/contracts: each PostgreSQL test binary gets a fresh database and runs single-threaded; AMQP and PKCS#11 tests have separate infrastructure handling; exact UUID/timestamp assertions are avoided.
- Change boundaries: test/CI/evidence infrastructure and minimal production observability hooks already specified by RFC.

## Inputs, outputs, and interfaces

- Inputs/preconditions: DB-009 through DB-014 complete.
- Outputs/postconditions: One CI result demonstrates every traceable requirement except operator documentation/restore runbook owned by DB-016.
- API/schema/event contract: v1 artifacts remain byte-for-byte unchanged.
- Compatibility requirement: PostgreSQL suite and benchmark remain mandatory, not replaced by SQLite.

## Dependencies and sequencing

- Blocked by: DB-009, DB-010, DB-011, DB-012, DB-013, DB-014
- Blocks: DB-016 and SQLite support release
- External dependency: PostgreSQL, Redis, and specialized AMQP/PKCS#11/PKI smoke infrastructure as currently documented

## Failure modes and edge cases

- Shared seeded rows -> fresh database per binary and single-threading preserved.
- SQLite file collision -> unique temporary file and cleanup per process.
- Normalization hides ordering/semantic drift -> normalize only generated IDs/timestamps; compare all contract fields and reasons.
- CI time exceeds budget -> measure and split exhaustive lane without reducing required release evidence.

## Acceptance criteria

- Every database-relevant test binary runs against fresh PostgreSQL and SQLite storage; documented external-infrastructure exclusions compile and retain their explicit lanes.
- Differential authz, error, lifecycle, audit/outbox, purge, and PKI results match after only approved normalization.
- Single-connection, busy timeout, concurrent writer, nested savepoint, crash-window, restart, process-lock, and migration pairing tests pass.
- Architecture check finds zero prohibited backend coupling.
- v1 contract check passes and PostgreSQL authz p95 regression is no greater than 10%.
- A machine-readable or Markdown release evidence summary maps every FR/NFR to passing jobs/tests.

## Verification

- Tests to add/update: all matrix and differential suites described above.
- Commands: `cargo fmt --check`; `cargo clippy --locked -- -D warnings`; `cargo test --no-run --locked`; `cargo test`; both ignored DB suites single-threaded; `scripts/check-v1-contracts.sh`; DB-001 benchmark command.
- Manual/operational evidence: Reviewer-approved CI/evidence report linked from the Epic.

## Definition of done

- [ ] All requirements owned by this issue have linked passing evidence.
- [ ] No skipped backend test lacks an explicit external-infrastructure reason and owner.
- [ ] Performance and contract gates pass.
- [ ] PR description includes `Closes #<leaf-issue-number>` after publication.
