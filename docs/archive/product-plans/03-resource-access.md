# Object Access Query

## Priority: 1 (Must-have)

This query answers who can access one protected object.

Authoritative model: [Atom access model](./11-access-model-simplification.md).

---

## Question

```text
Who can access this entity, resource, tenant, or Object Group?
```

---

## Input

The exact GraphQL field name is implementation-defined. Product behavior:

```text
objectAccess(objectKind, objectId, action, entityKind, effect, limit, offset)
```

| Parameter | Type | Description |
|---|---|---|
| `objectKind` | string | Protected object kind |
| `objectId` | UUID | Protected object ID |
| `action` | string | Optional action filter |
| `entityKind` | string | Optional subject entity kind filter |
| `effect` | `allow` or `deny` | Optional effect filter |
| `limit` | int | Page size |
| `offset` | int | Pagination offset |

---

## Response Shape

```json
{
  "object": {
    "id": "resource-...",
    "kind": "resource",
    "type": "channel",
    "tenant_id": "tenant-..."
  },
  "items": [
    {
      "subject": {
        "kind": "entity",
        "id": "entity-...",
        "name": "sensor-01",
        "entity_kind": "device"
      },
      "action": "publish",
      "effect": "allow",
      "permission_block": {
        "id": "block-...",
        "scope_mode": "object",
        "object_kind": "resource",
        "object_type": "channel",
        "object_id": "resource-..."
      },
      "source": {
        "kind": "direct_policy",
        "direct_policy_id": "policy-..."
      }
    }
  ],
  "total": 1
}
```

---

## Rules

- Match Permission Blocks whose scope covers the target object.
- Include Permission Blocks reached through Role Assignments.
- Include Permission Blocks reached through Direct Policies.
- Expand Principal Group membership so operators can see individual affected entities.
- Preserve source information so admins know what to revoke.
- Apply deny-overrides-allow for effective access summaries.
