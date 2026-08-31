# Entity Access Query

## Priority: 1 (Must-have)

This query answers what a subject can access by expanding effective Permission Blocks.

Authoritative model: [Atom access model](./11-access-model-simplification.md).

---

## Question

```text
What objects can this entity access, and where does that access come from?
```

---

## Input

The exact GraphQL field name is implementation-defined. Product behavior:

```text
entityAccess(entityId, tenantId, objectKind, objectType, action, effect, limit, offset)
```

| Parameter | Type | Description |
|---|---|---|
| `entityId` | UUID | Entity being inspected |
| `tenantId` | UUID | Optional tenant boundary |
| `objectKind` | string | Optional protected object kind |
| `objectType` | string | Optional protected object type such as `resource:channel` or `entity:device` |
| `action` | string | Optional action filter |
| `effect` | `allow` or `deny` | Optional effect filter |
| `limit` | int | Page size |
| `offset` | int | Pagination offset |

---

## Response Shape

```json
{
  "entity_id": "entity-...",
  "entity_name": "alice",
  "entity_kind": "human",
  "items": [
    {
      "object": {
        "id": "resource-...",
        "kind": "resource",
        "type": "channel",
        "name": "temperature",
        "tenant_id": "tenant-..."
      },
      "action": "read",
      "effect": "allow",
      "permission_block": {
        "id": "block-...",
        "scope_mode": "object_type",
        "object_kind": "resource",
        "object_type": "channel",
        "object_id": null,
        "group_id": null,
        "conditions": {}
      },
      "source": {
        "kind": "role_assignment",
        "role_id": "role-...",
        "role_name": "channel-reader",
        "assignment_id": "assignment-...",
        "principal_group_path": []
      }
    }
  ],
  "total": 1
}
```

---

## Rules

- Expand direct Role Assignments, inherited Principal Group Role Assignments, Direct Policies, and inherited Principal Group Direct Policies.
- Expand Roles into Permission Blocks.
- Expand Permission Block scopes into matching objects.
- Apply deny-overrides-allow when presenting effective access for the same object/action.
- Return resolved object and source metadata for operator review.
- Filter and paginate after authorization expansion.

This is an inspection endpoint. Normal application listing must use authorization-aware list queries that return only objects the caller can `read`.
