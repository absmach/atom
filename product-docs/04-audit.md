# GET /audit

## Priority: 1 (Must-have)

---

## Problem

Atom writes audit log entries for authorization checks, logins, logouts, and credential operations. But there is **no endpoint to read them**. The data is captured and trapped in the database.

Successful high-volume `authz.check`, `auth.login`, and gRPC credential-authentication allow events are metrics/traces by default rather than durable DB rows. Operators can opt in to durable allow rows with `ATOM_AUDIT_HOT_PATH_ALLOW_DB_ENABLED=true`; deny/error audit events, explicit explain/debug actions, admin mutations, lifecycle changes, and credential changes remain durable DB audit.

Operators need to:
- Debug why a specific entity was denied access in the last hour.
- Review all authorization decisions for a resource during an incident.
- Provide audit trails for compliance.
- Monitor login activity and credential changes.

---

## Endpoints

```
GET /audit
GET /entities/:id/audit
```

**Authentication:** Bearer token required.

`GET /entities/:id/audit` is a convenience alias for `GET /audit?entity_id=:id`.

---

## Query parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `entity_id` | UUID | — | Filter by entity |
| `event` | string | — | Filter by event type (e.g. `authz.check`, `auth.login`, `auth.logout`, `credential.create`, `credential.revoke`) |
| `outcome` | `allow` \| `deny` \| `error` | — | Filter by outcome |
| `from` | datetime (ISO 8601) | — | Start of time range (inclusive) |
| `to` | datetime (ISO 8601) | — | End of time range (exclusive) |
| `limit` | int | 50 | Results per page (1-200) |
| `offset` | int | 0 | Pagination offset |

---

## Response

```json
{
  "items": [
    {
      "id": "log1-...",
      "entity_id": "aaa-...",
      "event": "authz.check",
      "outcome": "deny",
      "details": {
        "action": "write",
        "resource_id": "r1-...",
        "reason": "no matching allow policy"
      },
      "created_at": "2026-04-24T10:30:00Z"
    },
    {
      "id": "log2-...",
      "entity_id": "aaa-...",
      "event": "auth.login",
      "outcome": "allow",
      "details": {
        "credential_kind": "password",
        "session_id": "s1-..."
      },
      "created_at": "2026-04-24T10:25:00Z"
    },
    {
      "id": "log3-...",
      "entity_id": "bbb-...",
      "event": "credential.revoke",
      "outcome": "allow",
      "details": {
        "credential_id": "cr1-...",
        "credential_kind": "access_token"
      },
      "created_at": "2026-04-24T09:15:00Z"
    }
  ],
  "total": 142
}
```

---

## Response fields

| Field | Type | Description |
|---|---|---|
| `id` | UUID | Audit log entry ID |
| `entity_id` | UUID \| null | Entity associated with this event (null if entity was deleted) |
| `event` | string | Event type |
| `outcome` | `allow` \| `deny` \| `error` | What happened |
| `details` | object | Event-specific details (varies by event type) |
| `created_at` | datetime | When the event occurred |

---

## Event types

| Event | When it's written | Details contain |
|---|---|---|
| `authz.check` | Authorization check decision; successful allows require `ATOM_AUDIT_HOT_PATH_ALLOW_DB_ENABLED=true` | `action`, `resource_id`, `reason` |
| `authz.explain` | Every `POST /authz/explain` call | `action`, `resource_id`, `reason` |
| `auth.login` | Login decision; successful allows require `ATOM_AUDIT_HOT_PATH_ALLOW_DB_ENABLED=true` | `credential_kind`, `session_id` (if successful) |
| `auth.logout` | Session revocation via logout | `session_id` |
| `credential.create` | Password or access-token credential created | `credential_id`, `credential_kind` |
| `credential.revoke` | Credential revoked | `credential_id`, `credential_kind` |

---

## Use cases

### 1. "Why was sensor-01 denied in the last hour?"

```
GET /audit?entity_id=bbb&event=authz.check&outcome=deny&from=2026-04-24T09:30:00Z
```

### 2. "Show failed login activity today, plus successful logins when hot-path allow DB audit is enabled"

```
GET /audit?event=auth.login&from=2026-04-24T00:00:00Z
```

### 3. "All audit events for Alice"

```
GET /entities/aaa/audit
```

### 4. "All failed authorization checks"

```
GET /audit?event=authz.check&outcome=deny&limit=100
```

### 5. "All credential changes in the last week"

```
GET /audit?event=credential.create&from=2026-04-17T00:00:00Z
GET /audit?event=credential.revoke&from=2026-04-17T00:00:00Z
```

---

## Implementation notes

- This is a straightforward query against the existing `audit_logs` table with dynamic WHERE clauses.
- The `from`/`to` filters use the `idx_audit_time` index (created_at DESC).
- The `entity_id` filter uses `idx_audit_entity`.
- The `event` filter uses `idx_audit_event`.
- Default sort: `created_at DESC` (most recent first).
- Higher default limit (50) than other endpoints because audit logs are typically browsed in larger batches.
- No write or delete operations — audit logs are immutable.
