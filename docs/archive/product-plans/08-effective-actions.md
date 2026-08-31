# Entity Effective Actions Query

## Priority: 2 (Should-have)

This query lists the effective actions an entity receives and shows the source paths.

Authoritative model: [Atom access model](./11-access-model-simplification.md).

---

## Question

```text
Which actions can this entity perform, and through which Permission Blocks?
```

---

## Input

```text
entityEffectiveActions(entityId, tenantId, objectKind, objectType)
```

| Parameter | Type | Description |
|---|---|---|
| `entityId` | UUID | Entity being inspected |
| `tenantId` | UUID | Optional tenant filter |
| `objectKind` | string | Optional protected object kind filter |
| `objectType` | string | Optional protected object type filter |

---

## Response Shape

```json
{
  "entity_id": "entity-...",
  "entity_name": "alice",
  "entity_kind": "human",
  "actions": [
    {
      "id": "action-...",
      "name": "read",
      "sources": [
        {
          "permission_block_id": "block-...",
          "effect": "allow",
          "scope_mode": "object_type",
          "object_kind": "resource",
          "object_type": "channel",
          "source": {
            "kind": "role_assignment",
            "role_id": "role-...",
            "role_name": "channel-reader",
            "assignment_id": "assignment-..."
          }
        }
      ]
    }
  ]
}
```

---

## Rules

- Expand Role Assignments and Direct Policies into Permission Blocks.
- Include Principal Group inheritance.
- Deduplicate actions by action ID/name.
- Keep all source paths so operators know what must be revoked.
- Include deny sources for visibility; deny sources do not grant access.
- This query is for inspection. Runtime decisions still use authorization check semantics.
