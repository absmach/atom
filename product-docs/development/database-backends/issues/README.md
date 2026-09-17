# Draft Phase Specifications (Single-PR Delivery)

These files are draft phase specifications for the one database-backends PR
(see `../PRD.md` "Delivery model"). They are subordinate to `../PRD.md` and
`../RFC.md`. No GitHub issue has been created; only a single tracking issue is
proposed (see `../PUBLICATION-MANIFEST.md`), carrying this hierarchy as a
checklist rather than as native sub-issues.

## Epic

- `epic.md` — Run Atom on PostgreSQL or SQLite with equivalent behavior

## Capability 1 — Isolate persistence without PostgreSQL regression

- `story-1-postgres-boundary.md`
  - `DB-001-database-facade.md`
  - `DB-002-transaction-error-boundary.md`
  - `DB-003-identity-tenant-postgres-adapter.md`
  - `DB-004-authz-read-postgres-adapter.md`
  - `DB-005-authz-write-postgres-adapter.md`
  - `DB-006-pki-workers-postgres-adapter.md`

## Capability 2 — Implement full SQLite behavior

- `story-2-sqlite-parity.md`
  - `DB-007-sqlite-runtime-baseline.md`
  - `DB-008-sqlite-codecs-invariants.md`
  - `DB-009-sqlite-identity-tenant.md`
  - `DB-010-sqlite-authz-read.md`
  - `DB-011-sqlite-authz-write.md`
  - `DB-012-sqlite-audit-workers.md`
  - `DB-013-sqlite-pki-foundation.md`
  - `DB-014-sqlite-pki-lifecycle.md`

## Capability 3 — Prove parity and release safely

- `story-3-release-readiness.md`
  - `DB-015-dual-backend-quality-gate.md`
  - `DB-016-operations-release.md`

## Publication order

Create one tracking issue from `epic.md`, with the three capabilities and their
leaf issues (phases) represented as a Markdown checklist inside that single
issue, in the order given above. Apply dependencies from `ROADMAP.md` as
checklist ordering/notes. Create one PR implementing every phase, referencing
that tracking issue with `Closes #<number>`. Do not create native GitHub
sub-issues or separate PRs per phase.
