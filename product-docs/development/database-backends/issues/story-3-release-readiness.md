# Prove parity and release safely

## Capability

As an Atom operator or reviewer, I can rely on automated parity evidence and a
tested runbook so that selecting SQLite does not create an undocumented security,
durability, or recovery risk and PostgreSQL remains regression-free.

## Requirements

- FR-2, FR-3, FR-7 through FR-10
- NFR-1 through NFR-10

## Scope boundaries

**In scope:** Dual-backend CI, differential/concurrency/performance gates,
documentation, container guidance, backup/restore proof, and release approval.

**Out of scope:** Publishing support before all gates pass or adding a data
transfer utility.

## Acceptance criteria

- Given a pull request, when CI runs, then every DB-relevant suite executes on
  both backends and contract/migration architecture gates run.
- Given the release candidate, when reviewers inspect evidence, then authz,
  lifecycle, transaction, PKI, performance, and recovery criteria are complete.
- Given operator documentation, when a clean SQLite deployment and restore drill
  follow it, then Atom reaches ready state with preserved data.

## Dependencies

- Blocked by: Implement full SQLite behavior
- Blocks: SQLite support announcement/release

## Agent-sized child issues

- DB-015 Dual-backend parity, concurrency, and performance quality gate
- DB-016 Operator documentation, deployment examples, and release readiness

## Story acceptance

- [ ] Every child issue is closed with linked verification evidence.
- [ ] Capability-level acceptance passes end to end.
- [ ] Canonical PRD/RFC remains accurate.
