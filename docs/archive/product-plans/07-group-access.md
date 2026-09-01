# Principal Group Access Query

## Priority: 2 (Should-have)

---

## Problem

Principal Groups are used to give the same roles to many identities. Before adding a user, service, application, workload, or device to a Principal Group, an administrator needs to know what access the new member will inherit.

This query answers:

```text
What access does this Principal Group grant through its role assignments?
```

Object Groups are not queried here. Object Groups are boundaries used inside role permission blocks.

---

## Query

The exact GraphQL field name is implementation-defined, but the product behavior is:

```text
principalGroupAccess(principalGroupId, tenantId, action, objectType, limit, offset)
```

Equivalent REST-style naming, if exposed internally, should use Principal Group language rather than overloaded `groups`.

---

## Parameters

| Parameter | Type | Description |
|---|---|---|
| `principalGroupId` | UUID | Principal Group ID |
| `tenantId` | UUID | Tenant/domain filter |
| `action` | string | Optional action filter |
| `objectType` | string | Optional object type filter such as `entity:device` or `resource:channel` |
| `limit` | int | Results per page |
| `offset` | int | Pagination offset |

---

## Response Shape

```json
{
  "principal_group_id": "pg-...",
  "principal_group": {
    "name": "field-devices",
    "tenant_id": "tenant-...",
    "member_count": 8
  },
  "assignments": [
    {
      "assignment_id": "assignment-...",
      "role": {
        "id": "role-...",
        "name": "Plant-A Publisher"
      },
      "permissions": [
        {
          "applies_to": "channels in Object Group Plant-A",
          "object_type": "resource:channel",
          "actions": ["publish"]
        }
      ],
      "conditions": {}
    }
  ],
  "total": 1
}
```

---

## Use Cases

### What does joining this Principal Group grant?

```text
principalGroupAccess(principalGroupId: "field-devices")
```

An admin reviews this before adding a device or user to the Principal Group.

### What channel access does this Principal Group grant?

```text
principalGroupAccess(principalGroupId: "field-devices", objectType: "resource:channel")
```

### Does this Principal Group grant publish?

```text
principalGroupAccess(principalGroupId: "field-devices", action: "publish")
```

---

## Implementation Notes

- Load role assignments where subject is the Principal Group.
- Expand assigned role permission blocks and actions.
- Do not use assignment scope; assignments have no scope.
- Do not query Object Group membership as if it grants access. Object Group only affects whether a role permission block applies to an object.
- Return resolved names and human-readable `applies_to` labels for UI review.
- If the Principal Group is not found, return `404`.
