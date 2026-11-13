# Database Backends — Draft Publication Manifest

## Publication status

**Not published.** This manifest prepares GitHub planning objects only. Drafting
does not authorize issue, label, milestone, Project, assignment, or release mutations.

## Target

| Field | Value |
|---|---|
| Repository | `absmach/atom` |
| Default branch | `main` |
| Initiative slug | `database-backends` |
| Draft branch | `codex/database-backend-planning` |
| Viewer permission observed | `MAINTAIN` |
| Related existing issue | #42, serverless PostgreSQL pool/health behavior; related only, not absorbed or closed |

## Canonical files

| File | Status | Purpose |
|---|---|---|
| `product-docs/development/database-backends/PRD.md` | Draft | Product requirements, acceptance, and traceability |
| `product-docs/development/database-backends/RFC.md` | Draft | Backend architecture, data, security, migration, reliability, and operations decisions |
| `product-docs/development/database-backends/ROADMAP.md` | Draft | Staged dependencies, milestones, and review gates |
| `product-docs/development/database-backends/issues/` | Draft | Epic, capability, and 16 agent-ready leaf issue bodies |
| `product-docs/development/database-backends/README.md` | Draft | Reading order and authorization boundary |
| `product-docs/development/database-backends/PUBLICATION-MANIFEST.md` | Draft | Exact publication proposal and gate status |

## Conditional artifacts

- RFC: included because database interfaces, schema, migrations, authorization,
  security, reliability, and operations require consequential decisions.
- Acceptance strategy and traceability: included in the PRD and DB-015.
- Threat/privacy analysis: included in RFC `Security and privacy`; no separate
  document because the trust boundary does not change and the section covers the
  material risks.
- Migration/backfill: included in RFC `Compatibility and migration`; no transfer
  plan is created because cross-backend transfer is explicitly out of scope.
- Observability/SLO: included in RFC `Observability, capacity, and cost` and
  NFR/Metrics requirements; no separate SLO document is required for this draft.
- Rollout/rollback/runbook: rollout is in the RFC; the operator runbook is an
  explicit DB-016 implementation output rather than an empty pre-implementation artifact.
- UX: omitted because there is no end-user UI flow or accessibility change.

## Requirement and issue counts

- Goals: 5
- Non-goals: 7
- Functional requirements: 10
- Non-functional requirements: 10
- GitHub planning objects proposed: 20
  - 1 Epic
  - 3 capabilities/stories
  - 16 leaf implementation/validation issues
- Final end-to-end evidence owner: DB-015
- Operator/release evidence owner: DB-016

## Proposed Epic hierarchy

1. **[Epic] Run Atom on PostgreSQL or SQLite with equivalent behavior**
   1. **Isolate persistence without PostgreSQL regression**
      1. DB-001 — Add the database façade and PostgreSQL benchmark baseline
      2. DB-002 — Generalize transactions, commit helpers, and database errors
      3. DB-003 — Isolate PostgreSQL identity, tenant, and authentication storage
      4. DB-004 — Isolate PostgreSQL authorization decisions and visibility
      5. DB-005 — Isolate PostgreSQL authorization mutations and guardrails
      6. DB-006 — Isolate PostgreSQL PKI, bootstrap, and background storage
   2. **Implement full SQLite behavior**
      1. DB-007 — Add SQLite runtime policy and migration baseline
      2. DB-008 — Add SQLite codecs, error mapping, and invariant coverage
      3. DB-009 — Implement SQLite identity, tenant, and authentication storage
      4. DB-010 — Implement SQLite authorization decisions and visibility
      5. DB-011 — Implement SQLite authorization mutations and guardrails
      6. DB-012 — Implement SQLite audit, outbox, purge, and worker semantics
      7. DB-013 — Implement SQLite signing keys and PKI foundation
      8. DB-014 — Implement SQLite certificate and PKI lifecycle parity
   3. **Prove parity and release safely**
      1. DB-015 — Enforce dual-backend parity, concurrency, and performance gates
      2. DB-016 — Publish SQLite operations guidance and complete release readiness

Use native GitHub sub-issues for both levels. Create in the listed order, then
apply dependencies from `ROADMAP.md`. Do not use a checklist as the published hierarchy.

## Dependencies

- DB-001 -> DB-002.
- DB-002 -> DB-003, DB-004, DB-005, DB-006.
- DB-003 + DB-004 + DB-005 + DB-006 -> Milestone A boundary gate -> DB-007.
- DB-007 -> DB-008.
- DB-003 + DB-008 -> DB-009.
- DB-004 + DB-008 + DB-009 -> DB-010.
- DB-005 + DB-008 + DB-009 -> DB-011.
- DB-008 + DB-009 + DB-011 -> DB-012.
- DB-008 + DB-009 -> DB-013.
- DB-009 + DB-012 + DB-013 -> DB-014.
- DB-009 through DB-014 -> DB-015 -> DB-016.

The graph is acyclic. DB-003, DB-004, DB-005, and most of DB-006 may run in
parallel after DB-002, but DB-006 activates the final source-boundary gate only
after the other three merge. SQLite domain leaves may parallelize only according
to the dependencies above.

## Ownership and review

| Role | Proposed value | Publication state |
|---|---|---|
| Accountable owner | `@arvindh123` | Must be confirmed |
| Product/API reviewer | TBD | Blocking publication |
| Engineering/database reviewer | TBD | Blocking publication |
| Security/PKI reviewer | TBD | Blocking publication |
| Operations reviewer | TBD | Blocking publication |
| AI executor | Any approved coding agent | Ready in leaf contracts |

## Repository taxonomy observed

Existing labels observed on 2026-09-01:

- `bug`
- `documentation`
- `duplicate`
- `enhancement`
- `good first issue`
- `help wanted`
- `invalid`
- `question`
- `wontfix`

No open milestones were observed. Organization Project visibility was not
available because the token lacks `read:project`; no Project is claimed.

### Proposed issue metadata

- Epic: existing `enhancement`; proposed missing label `epic`.
- Capabilities: existing `enhancement`; proposed missing label `capability`.
- DB-001 through DB-015: existing `enhancement`; proposed missing labels
  `database`, `agent-ready`; add proposed `sqlite` to DB-007 through DB-016.
- DB-016: existing `documentation` and `enhancement`; proposed `database`, `sqlite`, `agent-ready`.
- Proposed milestone: `Database backends and SQLite parity`.
- Proposed Project: TBD after an authorized user with `read:project` confirms the
  target; do not create a new Project by default.
- Proposed iteration/fields: none until an existing Project is confirmed.

Missing labels and the milestone are proposals only. Publication approval must
explicitly say whether to create them or use only existing taxonomy.

## Publication procedure after approval

1. Confirm owners/reviewers, Project decision, labels, and milestone.
2. Approve the canonical Markdown diff in the repository.
3. Create the Epic from `issues/epic.md`.
4. Create capabilities and attach them as native Epic sub-issues.
5. Create leaves from their files and attach them as native capability sub-issues.
6. Apply only approved existing/new labels, assignments, milestone, and Project fields.
7. Add dependency relationships in the roadmap order.
8. Replace planned titles in PRD traceability with issue links/numbers without
   changing requirement meaning.
9. Verify every created object and record URLs; never infer success from command exit alone.

## Quality gate

| Gate | Result |
|---|---|
| Technical/product decisions complete | Pass for Draft |
| Goals and non-goals prevent scope drift | Pass |
| Stable requirements and observable acceptance | Pass |
| Requirement-to-issue traceability | Pass |
| RFC covers interfaces/data/security/migration/reliability/operations | Pass |
| Dependency graph coherent and acyclic | Pass |
| Leaf issues bounded and independently verifiable | Pass |
| Repository paths and commands verified | Pass |
| GitHub taxonomy verified or marked proposed | Pass |
| Human ownership/review confirmed | **Blocked for publication** |
| GitHub Project target known | **Open follow-up; not required if omitted** |
| GitHub mutation authorized | **No** |

The pack is complete as a reviewable Draft. It is not publication-ready until
the accountable owner and required human reviewers are confirmed and the user
explicitly approves this exact or a revised manifest.
