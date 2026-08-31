# Role Holders Query

## Priority: 2 (Should-have)

This query lists who receives a Role through Role Assignments.

Authoritative model: [Atom access model](./11-access-model-simplification.md).

---

## Question

```text
Who has this role assigned directly or through a Principal Group?
```

---

## Input

```text
roleHolders(roleId, tenantId, subjectKind, limit, offset)
```

| Parameter | Type | Description |
|---|---|---|
| `roleId` | UUID | Role ID |
| `tenantId` | UUID | Optional tenant filter |
| `subjectKind` | `entity` or `principal_group` | Optional subject filter |
| `limit` | int | Page size |
| `offset` | int | Pagination offset |

---

## Response Shape

```json
{
  "role": {
    "id": "role-...",
    "tenant_id": "tenant-...",
    "name": "Plant-A Operator",
    "permission_blocks": [
      {
        "id": "block-...",
        "scope_mode": "group_direct_objects",
        "object_kind": "resource",
        "object_type": "channel",
        "actions": ["read", "publish"]
      }
    ]
  },
  "items": [
    {
      "assignment_id": "assignment-...",
      "subject_kind": "entity",
      "entity": {
        "id": "entity-...",
        "name": "alice",
        "kind": "human"
      },
      "principal_group": null
    },
    {
      "assignment_id": "assignment-...",
      "subject_kind": "principal_group",
      "entity": null,
      "principal_group": {
        "id": "pg-...",
        "name": "Operators",
        "member_count": 12
      }
    }
  ],
  "total": 2
}
```

---

## Rules

- Read from Role Assignments, not Direct Policies.
- Include direct entity assignments.
- Include Principal Group assignments with member counts.
- Do not include scope columns on the assignment; scope comes from the Role's Permission Blocks.
- Use this endpoint before changing or deleting a Role.
