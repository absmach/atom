# Admin Hygiene Endpoints

## Priority: 3 (Nice-to-have)

---

## Problem

Over time, an authorization system accumulates stale data:
- Assignments that reference entities, Principal Groups, or roles that have been deleted.
- Resources that no readable role permission covers — either intentionally hidden or accidentally unreachable.
- Credentials that are about to expire, which could break integrations silently.

Without hygiene endpoints, an administrator must write custom SQL queries to surface these issues.

---

## Endpoints

```
GET /admin/orphan-assignments
GET /admin/unprotected-resources
GET /admin/expiring-credentials
```

**Authentication:** Bearer token required. All admin endpoints require platform administration permission.

---

## 1. GET /admin/orphan-assignments

Returns role assignments where the referenced subject (entity or Principal Group) or role no longer exists.

### Query parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `limit` | int | 50 | Results per page (1-200) |
| `offset` | int | 0 | Pagination offset |

### Response

```json
{
  "items": [
    {
      "id": "assignment-1...",
      "subject_kind": "entity",
      "subject_id": "aaa-...",
      "role_id": "role-1...",
      "effect": "allow",
      "conditions": {},
      "created_at": "2026-03-15T12:00:00Z",
      "orphan_reason": "subject_not_found"
    },
    {
      "id": "assignment-2...",
      "subject_kind": "principal_group",
      "subject_id": "pg1-...",
      "role_id": "missing-role...",
      "effect": "allow",
      "conditions": {},
      "created_at": "2026-02-01T08:00:00Z",
      "orphan_reason": "role_not_found"
    }
  ],
  "total": 2
}
```

### `orphan_reason` values

| Value | Meaning |
|---|---|
| `subject_not_found` | The referenced entity or Principal Group has been deleted |
| `role_not_found` | The referenced role has been deleted |

### Implementation notes

```sql
-- Subject orphans
SELECT ra.* FROM role_assignments ra
LEFT JOIN entities e ON ra.subject_kind = 'entity' AND ra.subject_id = e.id
LEFT JOIN principal_groups pg ON ra.subject_kind = 'principal_group' AND ra.subject_id = pg.id
WHERE
  (ra.subject_kind = 'entity' AND e.id IS NULL)
  OR (ra.subject_kind = 'principal_group' AND pg.id IS NULL);

-- Role orphans
SELECT ra.* FROM role_assignments ra
LEFT JOIN roles r ON ra.role_id = r.id
WHERE r.id IS NULL;
```

These can be combined into a single query that checks both subject and role orphans.

---

## 2. GET /admin/unprotected-resources

Returns resources that have **no read-access coverage** through role permission blocks and assignments.

### Query parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `tenant_id` | UUID | — | Filter by tenant |
| `kind` | string | — | Filter by resource kind |
| `limit` | int | 50 | Results per page (1-200) |
| `offset` | int | 0 | Pagination offset |

### Response

```json
{
  "items": [
    {
      "id": "r5-...",
      "kind": "secret",
      "name": "db-password",
      "tenant_id": "t1-...",
      "owner_id": null,
      "created_at": "2026-04-20T14:00:00Z"
    },
    {
      "id": "r6-...",
      "kind": "device",
      "name": "test-sensor",
      "tenant_id": "t2-...",
      "owner_id": "aaa-...",
      "created_at": "2026-04-22T09:00:00Z"
    }
  ],
  "total": 2
}
```

### Implementation notes

A resource is "unprotected" if no assigned role permission block gives any subject `read` access to it:

```sql
SELECT r.* FROM resources r
WHERE NOT EXISTS (
  SELECT 1
  FROM role_assignments ra
  JOIN role_permission_blocks rpb ON rpb.role_id = ra.role_id
  JOIN role_permission_actions rpa ON rpa.permission_block_id = rpb.id
  WHERE rpa.action = 'read'
    AND role_permission_applies_to_resource(rpb.id, r.id)
);
```

The exact SQL helper shape is implementation-defined, but the check must use authorization filtering in SQL rather than per-resource PDP calls.

---

## 3. GET /admin/expiring-credentials

Returns credentials that will expire within a specified number of days. Useful for proactive rotation before integrations break.

### Query parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `days` | int | 30 | Show credentials expiring within this many days |
| `entity_id` | UUID | — | Filter by entity |
| `kind` | `password` \| `access_token` \| `certificate` | — | Filter by credential kind |
| `limit` | int | 50 | Results per page (1-200) |
| `offset` | int | 0 | Pagination offset |

### Response

```json
{
  "items": [
    {
      "id": "cr1-...",
      "entity_id": "bbb-...",
      "entity_name": "sensor-01",
      "entity_kind": "device",
      "kind": "access_token",
      "status": "active",
      "expires_at": "2026-05-10T00:00:00Z",
      "days_remaining": 16,
      "created_at": "2026-01-10T00:00:00Z"
    },
    {
      "id": "cr2-...",
      "entity_id": "ccc-...",
      "entity_name": "billing-service",
      "entity_kind": "service",
      "kind": "access_token",
      "status": "active",
      "expires_at": "2026-04-28T00:00:00Z",
      "days_remaining": 4,
      "created_at": "2025-10-28T00:00:00Z"
    }
  ],
  "total": 2
}
```

### Implementation notes

```sql
SELECT c.*, e.name AS entity_name, e.kind AS entity_kind
FROM credentials c
JOIN entities e ON c.entity_id = e.id
WHERE c.status = 'active'
  AND c.expires_at IS NOT NULL
  AND c.expires_at <= now() + ($1 || ' days')::interval
ORDER BY c.expires_at ASC;
```

`days_remaining` is computed as `expires_at - now()` in the application layer.

Note: `secret_hash` and `identifier` are **never** included in the response — only metadata about the credential.

---

## Authorization

All three endpoints require platform administration permission. These are administrative endpoints — regular entities should not be able to enumerate system-wide orphans, unprotected resources, or credentials.

---

## Use cases

### 1. Regular cleanup

Run `GET /admin/orphan-assignments` weekly. Delete any orphaned assignments to keep the access graph clean.

### 2. Security audit

Run `GET /admin/unprotected-resources` to verify that every resource in a tenant has expected read-access coverage.

### 3. Credential rotation alerts

Run `GET /admin/expiring-credentials?days=7` daily. Alert on any credentials expiring within the next week so teams can rotate before services break.
