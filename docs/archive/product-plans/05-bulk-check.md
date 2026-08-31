# Bulk Authorization Check

## Priority: 2 (Should-have)

Bulk check evaluates many actions for the same subject/object using the same effective Permission Block set.

Authoritative model: [Atom access model](./11-access-model-simplification.md).

---

## Input

```text
authzBulkCheck(subjectId, objectKind, objectId, actions, context)
```

| Field | Type | Required | Description |
|---|---|---|---|
| `subjectId` | UUID | Yes | Entity attempting the actions |
| `objectKind` | string | Yes | Protected object kind |
| `objectId` | UUID | Yes | Protected object ID |
| `actions` | string[] | Yes | Action names to check |
| `context` | object | No | Additional ABAC context |

---

## Response Shape

```json
{
  "subject_id": "entity-...",
  "object_kind": "resource",
  "object_id": "resource-...",
  "results": {
    "read": { "allowed": true, "reason": "allowed" },
    "write": { "allowed": false, "reason": "no matching allow" },
    "publish": { "allowed": false, "reason": "denied by permission block 9f3a..." }
  }
}
```

---

## Rules

- Load subject, object, Principal Group memberships, Role Assignments, Direct Policies, Roles, Permission Blocks, and actions once.
- Resolve and validate all requested actions.
- Evaluate each action against the same effective permission set.
- Deduplicate requested action names.
- Unknown or inapplicable actions return denied for that action.
- Deny overrides allow independently per action.
- Each result must have the same semantics as a single authorization check.
