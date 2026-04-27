# Query & Search Endpoints — Product Requirements

## Status: Draft
## Date: 2026-04-24

This document details query and search endpoints. For the top-level project requirements, see [Atom Product Requirements Document](./PRD.md).

---

## Problem

Atom's current API covers CRUD operations for all domain objects and a single `POST /authz/check` endpoint for yes/no authorization decisions. This is sufficient for runtime access control, but insufficient for **operating** an authorization system.

Administrators, security auditors, and operators cannot answer basic questions without manually querying the database or calling multiple endpoints and joining the results:

- "What resources can this device access?"
- "Why was this entity denied?"
- "Who will be affected if I change this role?"
- "Who can access this production resource?"
- "Are there any broken or orphaned policies?"

These questions apply to all entity kinds equally — humans, devices, services, workloads, and applications.

---

## Goals

1. Enable administrators to understand and debug the authorization state without direct database access.
2. Provide reverse lookups (resource → subjects, role → holders) for impact analysis.
3. Expose audit logs for compliance and troubleshooting.
4. Surface system hygiene issues (orphaned policies, unprotected resources, expiring credentials).
5. No schema changes — all endpoints query existing tables.

## Non-goals

1. Real-time streaming or push notifications (webhooks are a future item).
2. GraphQL or other query languages — these are fixed, purpose-built endpoints.
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
| 7 | `GET /groups/:id/access` | Group-centric | What access does this group grant? |
| 8 | `GET /entities/:id/effective-capabilities` | Entity-centric | Flat resolved capability list |

### Priority 3 — Nice-to-have

| # | Endpoint | Category | Purpose |
|---|----------|----------|---------|
| 9 | `GET /admin/orphan-policies` | Hygiene | Policies referencing deleted objects |
| 10 | `GET /admin/unprotected-resources` | Hygiene | Resources with no policy coverage |
| 11 | `GET /admin/expiring-credentials` | Hygiene | Credentials expiring within N days |

---

## Common conventions

All query endpoints follow these rules:

- **Read-only** — no state modifications.
- **Authenticated** — all require a valid Bearer token.
- **Paginated** — list endpoints accept `limit` (1-100, default 20) and `offset` (default 0).
- **Resolved responses** — responses include names and details, not just UUIDs.
- **Source tracking** — where access comes from multiple paths (direct vs. group, capability vs. role), the response shows the source.
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

1. [POST /authz/explain](./01-authz-explain.md)
2. [GET /entities/:id/access](./02-entity-access.md)
3. [GET /resources/:id/access](./03-resource-access.md)
4. [GET /audit](./04-audit.md)
5. [POST /authz/check/bulk](./05-bulk-check.md)
6. [GET /roles/:id/holders](./06-role-holders.md)
7. [GET /groups/:id/access](./07-group-access.md)
8. [GET /entities/:id/effective-capabilities](./08-effective-capabilities.md)
9. [Admin hygiene endpoints](./09-admin-hygiene.md)
10. [Building Magistrala on Atom](./10-magistrala-on-atom.md)
