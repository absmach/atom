# Implement full SQLite behavior

## Capability

As a single-instance Atom operator, I can use a local SQLite file or ephemeral
memory database so that I receive the same supported identity and authorization
service without provisioning PostgreSQL.

## Requirements

- FR-1, FR-3 through FR-8
- NFR-3 through NFR-9

## Scope boundaries

**In scope:** SQLite runtime, schema, every storage domain, background workers,
and operational semantics required for parity.

**Out of scope:** Multiple processes per file, shared/network storage,
cross-backend transfer, SQLCipher, and release advertising before parity proof.

## Acceptance criteria

- Given `sqlite://` or `sqlite::memory:`, when Atom starts, then the correct
  migration and durability policy is applied before serving.
- Given each supported public operation, when run on SQLite, then its observable
  result and failure semantics match PostgreSQL.
- Given invalid, concurrent, or rollback scenarios, then authorization fails
  closed and no partial mutation or orphan event remains.

## Dependencies

- Blocked by: Isolate persistence without PostgreSQL regression
- Blocks: Prove parity and release safely

## Agent-sized child issues

- DB-007 through DB-014 as listed in `README.md`

## Story acceptance

- [ ] Every child issue is closed with linked verification evidence.
- [ ] Capability-level acceptance passes end to end.
- [ ] Canonical PRD/RFC remains accurate.
