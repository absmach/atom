# [Epic] Run Atom on PostgreSQL or SQLite with equivalent behavior

## Outcome

Operators can run the same Atom binary on an existing PostgreSQL deployment or
as a production single-instance SQLite deployment, while clients receive the
same identity, authorization, audit, lifecycle, and PKI behavior.

## Source of truth

- PRD: `product-docs/development/database-backends/PRD.md`
- RFC: `product-docs/development/database-backends/RFC.md`

## Goals and non-goals

- Goal: G-1 through G-5 — runtime backend choice, full parity, PostgreSQL safety,
  future internal extensibility, and explicit topology guidance.
- Non-goal: NG-1 through NG-7 — no transfer tool, SQLite replicas, SQLCipher,
  public plugin ABI, ORM rewrite, public contract change, or issue #42 expansion.

## Success and release gates

- All FR-1 through FR-10 and NFR-1 through NFR-10 have linked evidence.
- PostgreSQL and SQLite DB suites, differential tests, v1 contracts, lint, and
  format checks pass.
- PostgreSQL authz p95 stays within the approved 10% regression budget.
- SQLite restart, contention, single-owner, backup, and restore evidence passes.
- Required database, security, product, and operations reviews are complete.

## Delivery hierarchy

- Isolate persistence without PostgreSQL regression
  - DB-001 through DB-006
- Implement full SQLite behavior
  - DB-007 through DB-014
- Prove parity and release safely
  - DB-015 through DB-016

## Dependencies and risks

- Existing PostgreSQL migration immutability and v1 contract checks are hard gates.
- SQLite cannot be advertised before every domain adapter and parity test lands.
- Authorization, outbox, purge, and PKI semantics require specialized review.
- GitHub issue #42 is related but remains independently scoped.

## Ownership

- Accountable owner: `@arvindh123` (proposed)
- Product reviewer: TBD before publication
- Engineering/database reviewer: TBD before publication
- Security/operations reviewer: TBD before publication

## Epic acceptance

- [ ] All child capabilities have passed acceptance and are closed.
- [ ] Requirement traceability has no gaps.
- [ ] Required rollout, observability, security, and support readiness checks pass.
- [ ] Outcome evidence or the agreed measurement window is active.
