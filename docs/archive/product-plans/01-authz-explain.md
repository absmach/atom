# Authorization Explain Query

## Priority: 1 (Must-have)

This query explains one authorization decision using the simplified access model.

Authoritative model: [Atom access model](./11-access-model-simplification.md).

---

## Question

```text
Why can, or cannot, this subject perform this action on this object?
```

---

## Input

The exact GraphQL field name is implementation-defined. Product behavior:

```text
authzExplain(subjectId, action, objectKind, objectId, context)
```

| Field | Type | Required | Description |
|---|---|---|---|
| `subjectId` | UUID | Yes | Entity attempting the action |
| `action` | string | Yes | Action name such as `read`, `publish`, `role.manage` |
| `objectKind` | string | Yes | Protected object kind such as `tenant`, `entity`, `resource`, `object_group` |
| `objectId` | UUID | Yes | Protected object ID |
| `context` | object | No | Additional ABAC context |

---

## Response Shape

```json
{
  "allowed": false,
  "reason": "denied by permission block 9f3a...",
  "subject": {
    "id": "entity-...",
    "name": "sensor-01",
    "kind": "device",
    "status": "active"
  },
  "object": {
    "id": "resource-...",
    "kind": "resource",
    "type": "channel",
    "tenant_id": "tenant-..."
  },
  "action": {
    "id": "action-...",
    "name": "publish"
  },
  "matched_permission": {
    "permission_block_id": "9f3a-...",
    "effect": "deny",
    "scope_mode": "object_type",
    "object_kind": "resource",
    "object_type": "channel",
    "object_id": null,
    "group_id": null,
    "conditions": {},
    "source": {
      "kind": "role_assignment",
      "assignment_id": "assignment-...",
      "role_id": "role-...",
      "role_name": "restricted-devices",
      "principal_group_path": ["restricted-devices"]
    }
  },
  "evaluated_permissions": [
    {
      "permission_block_id": "allow-...",
      "effect": "allow",
      "result": "matched",
      "skip_reason": null,
      "source": {
        "kind": "direct_policy",
        "direct_policy_id": "policy-..."
      }
    },
    {
      "permission_block_id": "9f3a-...",
      "effect": "deny",
      "result": "matched",
      "skip_reason": null,
      "source": {
        "kind": "role_assignment",
        "assignment_id": "assignment-..."
      }
    }
  ]
}
```

---

## Rules

- Resolve the requested action and verify action applicability for the protected object.
- Build the effective permission set from:
  - direct Role Assignments to the subject;
  - Role Assignments inherited through Principal Group membership;
  - Direct Policies attached to the subject;
  - Direct Policies inherited through Principal Group membership.
- Expand Roles into Permission Blocks.
- Match Permission Block scope against the protected object.
- Evaluate conditions.
- Deny overrides allow.
- Return the matching deny if any deny matches.
- Otherwise return the matching allow if one exists.
- Otherwise return default deny.

---

## Diagnostic Source Kinds

| Source kind | Meaning |
|---|---|
| `role_assignment` | Permission came through a Role Assignment. |
| `direct_policy` | Permission came through a Direct Policy. |
| `principal_group` | Subject inherited the assignment/policy through Principal Group membership. |

Object Groups may appear in scope explanations, but Object Groups are not subjects and do not grant access by membership.
