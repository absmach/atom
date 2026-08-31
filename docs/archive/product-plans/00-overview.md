# Query & Search Endpoints — Product Requirements

## Status: Draft
## Date: 2026-04-24

This document is supporting background for query and search requirements. The source of truth is [Atom Product Requirements Document](./PRD.md), and authorization terminology is defined in [Atom Access Model Simplification](./11-access-model-simplification.md).

For non-technical onboarding and diagrams, use the rendered docs source:

- [Atom in Simple Words](../docs/content/docs/simple-words.mdx)
- [Architecture diagrams](../docs/content/docs/architecture/index.mdx)
- [Certificate flow](../docs/content/docs/authentication/certificates.mdx)
- [Magistrala on Atom](../docs/content/docs/magistrala-on-atom.mdx)

---

## Problem

Atom's current API covers CRUD operations for all domain objects and a single `POST /authz/check` endpoint for yes/no authorization decisions. This is sufficient for runtime access control, but insufficient for **operating** an authorization system.

Administrators, security auditors, and operators cannot answer basic questions without manually querying the database or calling multiple endpoints and joining the results:

- "What resources can this device access?"
- "Why was this entity denied?"
- "Who will be affected if I change this role?"
- "Who can access this production resource?"
- "Are there any broken or orphaned assignments?"

These questions apply to all entity kinds equally — humans, devices, services, workloads, and applications.

---

## Goals

1. Enable administrators to understand and debug the authorization state without direct database access.
2. Provide reverse lookups (resource → subjects, role → holders) for impact analysis.
3. Expose audit logs for compliance and troubleshooting.
4. Surface system hygiene issues (orphaned assignments, unprotected resources, expiring credentials).
5. No schema changes — all endpoints query existing tables.

## Non-goals

1. Real-time streaming or push notifications (webhooks are a future item).
2. A general-purpose policy query language — Atom exposes product-specific GraphQL operations instead.
3. Policy simulation ("what-if" analysis) — deferred to a future iteration.

---

## Endpoint summary

### Priority 1 — Must-have

| # | Endpoint | Category | Purpose |
|---|----------|----------|---------|
| 1 | `POST /authz/explain` | Authorization | Full decision trail for a single check |
| 2 | `GET /entities/:id/access` | Entity-centric | What resources can this entity access? |
| 3 | `GET /resources/:id/access` | Resource-centric | Who can access this resource? |
| 4 | `GET /audit` | Audit | Read audit logs with filters |

### Priority 2 — Should-have

| # | Endpoint | Category | Purpose |
|---|----------|----------|---------|
| 5 | `POST /authz/check/bulk` | Authorization | Check multiple actions in one call |
| 6 | `GET /roles/:id/holders` | Role-centric | Who holds this role? |
| 7 | Principal Group access query | Principal Group-centric | What access does this Principal Group grant? |
| 8 | Entity effective actions query | Entity-centric | Flat resolved action/source list |

### Priority 3 — Nice-to-have

| # | Endpoint | Category | Purpose |
|---|----------|----------|---------|
| 9 | Orphan assignment query | Hygiene | Assignments referencing deleted objects |
| 10 | `GET /admin/unprotected-resources` | Hygiene | Resources with no read-access coverage |
| 11 | `GET /admin/expiring-credentials` | Hygiene | Credentials expiring within N days |

---

## Common conventions

All query endpoints follow these rules:

- **Read-only** — no state modifications.
- **Authenticated** — all require a valid Bearer token.
- **Paginated** — list endpoints accept `limit` (1-100, default 20) and `offset` (default 0).
- **Resolved responses** — responses include names and details, not just UUIDs.
- **Source tracking** — where access comes from multiple paths, the response shows the Role Assignment, Direct Policy, Permission Block, and Principal Group source.
- **Tenant-aware filters** — most endpoints accept an optional `tenant_id` filter.

---

## File impact

```
New files:
  src/models/access.rs          — response structs for access/explain/bulk
  src/audit/handlers.rs         — audit listing handler (if separated)

Modified files:
  src/models/mod.rs             — add access module
  src/authz/handlers.rs         — add handler functions for new endpoints
  src/authz/repo.rs             — add query functions
  src/authz/engine.rs           — add explain() variant returning decision trail
  src/identity/handlers.rs      — add audit listing handler (if kept here)
  src/identity/repo.rs          — add audit query function
  src/routes.rs                 — wire new routes

No schema changes required.
```

---

## Detailed requirements

Each endpoint is specified in its own document:

> Note: the access model was simplified after several endpoint drafts were written. [Atom access model](./11-access-model-simplification.md) is authoritative. Endpoint drafts marked as legacy must be rewritten before implementation to use roles, permission blocks, assignments, Object Groups, and Principal Groups.

1. [POST /authz/explain](./01-authz-explain.md)
2. [GET /entities/:id/access](./02-entity-access.md)
3. [GET /resources/:id/access](./03-resource-access.md)
4. [GET /audit](./04-audit.md)
5. [POST /authz/check/bulk](./05-bulk-check.md)
6. [GET /roles/:id/holders](./06-role-holders.md)
7. [Principal Group access](./07-group-access.md)
8. [Entity effective actions](./08-effective-actions.md)
9. [Admin hygiene endpoints](./09-admin-hygiene.md)
10. [Building Magistrala on Atom](./10-magistrala-on-atom.md)
11. [Atom access model](./11-access-model-simplification.md)
12. [Atom certificates](./12-certificates.md)
