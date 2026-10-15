# Database Backend Delivery Roadmap

## Status

Draft execution plan for `PRD.md` and `RFC.md`. GitHub objects have not been
published. Implement one leaf issue per focused PR and do not advertise SQLite
until Milestone C exits.

## Delivery sequence

```text
DB-001 Database façade, URL selection, PostgreSQL benchmark
   |
   v
DB-002 Transaction, commit, and error abstraction
   |
   +----------+----------------+----------------+
   |          |                |                |
   v          v                v                v
DB-003     DB-004           DB-005           DB-006
Identity   Authz reads      Authz writes      PKI/workers
   |          |                |                |
   +----------+----------------+----------------+
                         |
                         v
              PostgreSQL boundary gate
                         |
                         v
DB-007 SQLite connection and migration baseline
   |
   v
DB-008 SQLite codecs, errors, and invariant matrix
   |
   +----------+----------------+----------------+----------------+
   |          |                |                |                |
   v          v                v                v                v
DB-009     DB-010           DB-011           DB-012           DB-013
Identity   Authz reads      Authz writes      Audit/workers    PKI foundation
   |          |                |                |                |
   |          |                |                |                v
   |          |                |                |             DB-014
   |          |                |                |             PKI lifecycle
   +----------+----------------+----------------+----------------+
                         |
                         v
DB-015 Dual-backend parity, concurrency, and performance gate
                         |
                         v
DB-016 Operator documentation and release readiness
```

## Milestone A — PostgreSQL-safe abstraction

Includes DB-001 through DB-006.

Exit gate:

- public contracts and all PostgreSQL behavior remain unchanged;
- the fixed PostgreSQL authz benchmark exists and the refactor stays within the
  approved regression budget;
- transports, domain services, bootstrap, and workers no longer expose SQLx
  PostgreSQL types or raw SQL;
- transactional audit/outbox and single-connection invariants still pass;
- a static boundary check prevents PostgreSQL coupling from escaping storage.

## Milestone B — Complete SQLite implementation

Includes DB-007 through DB-014.

Exit gate:

- file and memory URLs start, migrate, and restart correctly;
- one-process ownership and durability settings are enforced;
- all identity, tenant, authz, audit/outbox, purge, signing-key, and PKI paths
  have SQLite implementations;
- canonical grant and scope behavior is shared by every SQLite decision and
  visibility reader;
- schema and same-transaction validation cover every documented invariant;
- SQLite remains unadvertised until Milestone C.

## Milestone C — Parity and supported release

Includes DB-015 and DB-016.

Exit gate:

- all DB-relevant tests run against clean PostgreSQL and SQLite databases;
- normalized differential, concurrency, crash-window, and backup/restore tests pass;
- v1 contract artifacts do not change;
- PostgreSQL performance stays inside NFR-2;
- database, security, operations, and product reviewers accept the evidence;
- PostgreSQL-first and SQLite single-instance operational guidance is published.

## Cross-cutting rules

- Existing PostgreSQL migrations are immutable.
- A transaction never borrows a second pool connection.
- Domain events are inserted in the mutation transaction.
- SQLite never holds a write transaction across broker network I/O.
- Subject-forward authorization uses the canonical backend grant expansion;
  reverse guardrail expansion stays separate.
- No secret, key material, database URL, or unsafe file path enters logs/events.
- Every leaf issue updates tests before relaxing or replacing an invariant.
- A PR description closes only its published leaf issue with `Closes #<number>`.

## Review gates

- Database review: DB-001, DB-002, DB-004, DB-005, DB-007 through DB-015.
- Security review: DB-004, DB-005, DB-008 through DB-015.
- Operations review: DB-007, DB-012, DB-015, DB-016.
- Product/API review: DB-001, DB-015, DB-016.
