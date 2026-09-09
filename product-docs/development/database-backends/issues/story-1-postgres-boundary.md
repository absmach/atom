# Isolate persistence without PostgreSQL regression

## Capability

As an Atom maintainer, I can evolve persistence behind backend-neutral
interfaces so that existing PostgreSQL behavior stays stable and SQLite can be
implemented without leaking dialect concerns into domain or transport code.

## Requirements

- FR-2, FR-5, FR-8, FR-10
- NFR-1, NFR-2, NFR-6, NFR-7, NFR-10

## Scope boundaries

**In scope:** PostgreSQL-preserving database, transaction, error, and repository
boundaries plus a static architecture gate.

**Out of scope:** A selectable SQLite production path or SQLite schema.

## Acceptance criteria

- Given the existing PostgreSQL URL and data, when each child lands, then the
  full current PostgreSQL suite and v1 contract checks remain green.
- Given source outside storage and test fixtures, when the final child lands,
  then no PostgreSQL SQLx type or raw SQL is present.
- Transactional audit, outbox, cache invalidation, and one-connection tests pass.

## Dependencies

- Blocked by: None
- Blocks: Implement full SQLite behavior

## Agent-sized child issues

- DB-001 Database façade, runtime URL classification, and benchmark baseline
- DB-002 Backend-neutral transactions, commit helpers, and error classification
- DB-003 PostgreSQL identity, tenant, and authentication adapter boundary
- DB-004 PostgreSQL authorization decision and visibility adapter boundary
- DB-005 PostgreSQL authorization mutation and guardrail adapter boundary
- DB-006 PostgreSQL PKI, bootstrap, and worker adapter boundary plus CI guard

## Story acceptance

- [ ] Every child issue is closed with linked verification evidence.
- [ ] Capability-level acceptance passes end to end.
- [ ] Canonical PRD/RFC remains accurate.
