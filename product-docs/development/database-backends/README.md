# Database Backend Initiative

This directory is the draft planning source of truth for abstracting Atom's
PostgreSQL persistence layer and adding full SQLite support.

**Delivery is a single consolidated pull request**, not sixteen separate PRs.
See `PRD.md` ("Delivery model") for what that means for review and rollback.
The phase decomposition below (`ROADMAP.md`, `issues/`) is the implementation
and review plan, not a publication plan — every phase lands as its own
commit(s) inside one branch and one PR.

Read in this order:

1. `PRD.md`
2. `RFC.md`
3. `ROADMAP.md`
4. `issues/README.md`
5. the selected phase specification, in order
6. `PUBLICATION-MANIFEST.md` before publishing the tracking issue and PR

These documents plan delivery only. They do not authorize implementation,
GitHub issue publication, or release.
