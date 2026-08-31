# Building Magistrala on Atom

## Status: Draft
## Date: 2026-05-21

---

## Purpose

Atom is the identity provider, authentication provider, authorization provider, and access listing service for Magistrala.

Magistrala should not maintain a separate identity, credential, role, group, policy, or authorization database. Magistrala creates its security-relevant objects in Atom and stores Magistrala-specific fields in `attributes.magistrala`.

The rule is:

- Atom owns generic security fields: `id`, `name`, `kind`, `tenant_id`, `status`, credentials, Object Groups, Principal Groups, actions, roles, assignments, sessions, and audit logs.
- Magistrala owns application-specific fields inside `attributes.magistrala`.
- Runtime access decisions always go through Atom authorization checks.
- Listings return objects the caller can `read`; Atom must apply authorization filtering in SQL.

This is not a translation layer. Magistrala is built on Atom's native primitives.

See also: [Atom access model](./11-access-model-simplification.md).

---

## Concept Mapping

| Magistrala concept | Atom primitive | Notes |
|---|---|---|
| Domain | Tenant | Reuse Magistrala domain UUID as `tenants.id`. |
| User | Entity | `kind = human`, normally global with `tenant_id = null`. |
| Client | Entity | `kind = device` or `service`, tenant-owned. |
| Channel | Resource | `kind = channel`, tenant-owned. |
| Rule | Resource | `kind = rule`, tenant-owned. |
| Report | Resource | `kind = report`, tenant-owned. |
| Alarm | Resource | `kind = alarm`, tenant-owned. |
| Magistrala group boundary | Object Group | Contains clients, channels, rules, reports, alarms, and child Object Groups. |
| User/service set | Principal Group | Contains users, services, apps, workloads, or devices that should receive the same roles. |
| MG role | Atom Role | Role has permission blocks: applies-to + actions. |
| MG role member | Atom Assignment | Assignment gives a role to an entity or Principal Group. |
| Client-channel connection | Role assignment or trusted Direct Policy | Normal UI should prefer roles; strict runtime links may use audited Direct Policies. |

---

## Access Model In MG Terms

```text
Domain = Tenant
Group page boundary = Object Group
Members/operators/services = Principal Group
Role = actions + where they apply
Assignment = who gets the role
```

Example:

```text
Tenant: factory-1

Object Group: Plant-A
  client sensor-001
  channel temperature

Principal Group: Field Devices
  sensor-001

Role: Plant-A Publisher
  Applies to: channels in Object Group Plant-A
  Actions: publish

Assignment:
  Give Plant-A Publisher to Principal Group Field Devices
```

At runtime, Magistrala asks:

```text
Can sensor-001 publish to temperature?
```

Atom answers by checking:

1. `publish` is valid for channel.
2. `sensor-001` is active.
3. `sensor-001` is directly assigned a role or belongs to a Principal Group with a role.
4. The role has a permission block that applies to `temperature`.
5. Deny overrides allow.
6. Default deny if no allow matches.

---

## Object Storage

### Domain

Create an Atom tenant. The tenant ID is the Magistrala domain ID.

```json
{
  "id": "domain-uuid",
  "name": "factory-1",
  "alias": "factory-1",
  "attributes": {
    "magistrala": {
      "metadata": {
        "created_by": "magistrala"
      }
    }
  }
}
```

### User

Create a global human entity.

```json
{
  "kind": "human",
  "name": "alice@example.com",
  "tenant_id": null,
  "attributes": {
    "magistrala": {
      "email": "alice@example.com",
      "first_name": "Alice",
      "last_name": "Iyer"
    }
  }
}
```

User participation in a domain is handled through tenant membership and role assignments.

### Client

Create a tenant-owned entity.

```json
{
  "kind": "device",
  "name": "sensor-001",
  "tenant_id": "domain-uuid",
  "attributes": {
    "magistrala": {
      "identity": "sensor-001",
      "tags": ["temperature"],
      "metadata": {
        "site": "plant-a"
      }
    }
  }
}
```

Create an API key credential or certificate credential for device runtime authentication. API key plaintext and generated certificate private keys are shown once and must be stored by Magistrala only once. CSR-issued certificates do not expose a private key to Atom or Magistrala.

### Channel

Create a tenant-owned resource.

```json
{
  "kind": "channel",
  "name": "temperature",
  "alias": "temperature",
  "tenant_id": "domain-uuid",
  "owner_id": "alice-entity-id",
  "attributes": {
    "magistrala": {
      "status": "enabled",
      "tags": ["temperature"]
    }
  }
}
```

Rules, reports, and alarms follow the same resource pattern with `kind = rule`, `kind = report`, and `kind = alarm`.

---

## Object Groups

Use Object Groups for Magistrala object boundaries.

Example:

```text
Object Group Plant-A
  Object Group Line-1
    sensor-001
    temperature
```

Rules:

- Object Group can contain clients and resources.
- Object Group can contain child Object Groups.
- Object Group is not a subject that receives roles.
- Object Group containment alone does not grant access.

Use Object Groups for UI scopes such as:

```text
This group
Clients in this group
Channels in this group
Clients in subgroups
Channels in subgroups
All subgroups
```

---

## Principal Groups

Use Principal Groups for users, services, applications, workloads, or devices that should receive the same access.

Examples:

```text
Principal Group Operators
  alice@example.com
  bob@example.com

Principal Group Field Devices
  sensor-001
  sensor-002

Principal Group MG Services
  mg-service
  reports-service
```

Rules:

- Principal Group receives role assignments.
- Principal Group is not an object boundary.
- Principal Groups are flat in V1.

---

## Roles And Assignments

Roles are the main access model. A role contains one or more permission blocks.

Example role:

```text
Role: Plant-A Operator

Permission block 1:
  Applies to: clients in Object Group Plant-A
  Actions: read, write

Permission block 2:
  Applies to: channels in Object Group Plant-A
  Actions: read, publish, subscribe
```

Assignment gives the role to a subject:

```text
Assign Plant-A Operator to Principal Group Operators
Assign Plant-A Operator to user1
Assign MG Service Admin to mg-service
```

Assignment has no scope. The role already says where access applies.

Normal roles belong to one tenant. Platform roles are reserved for system/admin/service automation.

---

## Actions

Actions are global action names.

Use canonical Atom action names:

```text
read
write
delete
publish
subscribe
execute
manage
role.manage
policy.manage
create
revoke
rotate
authz.check
```

Hybrid action naming:

- stored protected objects use generic actions, for example `read` on `audit_log`, `manage` or `revoke` on `credential`, `create` or `manage` on `tenant`, and `rotate` on `signing_key`;
- certificate credentials additionally use `read`, `rotate`, `revoke`, and `manage` on `credential`;
- `role.manage` and `policy.manage` stay explicit because they mean scoped role/member administration for a client, channel, group, rule, report, alarm, or domain;
- `authz.check` stays explicit because it is an operation, not an object.

Do not expose old MG-style aliases in role management:

```text
client_read
channel_publish
group_set_parent
report_execute
```

Action Applicability validates action/object pairs:

```text
publish -> channel
subscribe -> channel
execute -> rule/report
read/write/delete -> clients/channels/rules/reports/alarms/Object Groups
```

---

## Client-channel Connections

Preferred model:

```text
Role: Temperature Publisher
  Applies to: channel temperature
  Actions: publish

Assignment:
  Give Temperature Publisher to client sensor-001
```

For strict runtime-only links, a trusted Magistrala service may create a Direct Policy:

```text
sensor-001 can publish to temperature
```

This is generic Atom behavior, not a Magistrala-specific table. Atom stores the link as a Direct Policy that references a Permission Block:

```text
Direct Policy:
  subject = client entity
  permission_block = publish/subscribe block for channel resource
```

Guardrails:

- Direct Policies are not exposed in normal UI.
- Direct Policies are created only by trusted service/system flows.
- Direct Policies are audited.
- Roles and assignments remain the main model.
- No separate MG-specific `direct_grants` table is needed.

---

## Runtime Authorization

When `sensor-001` publishes to `temperature`, Magistrala asks Atom:

```json
{
  "subject_id": "sensor-001-entity-id",
  "resource_id": "temperature-resource-id",
  "action": "publish",
  "context": {
    "protocol": "mqtt",
    "topic": "factory-1.temperature"
  }
}
```

Allowed:

```json
{
  "allowed": true,
  "reason": "allowed"
}
```

Denied:

```json
{
  "allowed": false,
  "reason": "no matching allow"
}
```

Magistrala must treat Atom as authoritative. If Atom denies, the operation is rejected.

---

## Listing And Search

Magistrala UI should list objects through Atom by read access.

Rule:

```text
Listing = return objects the caller can read
```

Do not require a separate `list` action for normal object listing.

Do not fetch all objects and call authorization one by one. Atom/MG must apply authorization filters in SQL.

Examples:

```text
List channels in domain -> channels caller can read
List clients in Object Group -> clients caller can read
List rules in domain -> rules caller can read
```

---

## Recommended Magistrala Flow

1. Magistrala starts with a service entity in Atom.
2. Magistrala authenticates to Atom and receives a service token.
3. On domain creation, Magistrala creates an Atom tenant using the domain UUID.
4. On user creation, Magistrala creates a global `human` entity and password credential.
5. On client creation, Magistrala creates a tenant-owned `device` or `service` entity and either an API key credential or Atom-issued certificate credential.
6. On channel/rule/report/alarm creation, Magistrala creates a tenant-owned resource.
7. On group creation, Magistrala creates an Object Group.
8. For shared user/service/device access, Magistrala creates a Principal Group.
9. For access control, Magistrala creates roles with permission blocks and assigns them to entities or Principal Groups.
10. If a client presents a certificate, the runtime service resolves the certificate serial through Atom gRPC before authorization. The runtime service must authenticate to Atom and hold `authz.check` on the resolved tenant or platform.
11. On every publish, subscribe, read, write, execute, or management operation, Magistrala calls Atom authorization.
12. For admin UI listings, Magistrala queries Atom with authorization filtering instead of maintaining local access joins.

---

## Why This Shape Works

Magistrala keeps its product concepts:

- domains
- users
- clients
- channels
- groups
- connections
- rules
- reports
- alarms

Atom owns the security model:

- domains are tenants
- users and clients are entities
- channels/rules/reports/alarms are resources
- Magistrala group boundaries are Object Groups
- sets of users/services/devices are Principal Groups
- access is roles plus assignments
- credentials are Atom credentials
- former Magistrala certs service behavior is Atom certificate credential behavior
- certificate revocation, CRL, OCSP, and CA chain publication are served by Atom
- sessions and tokens are Atom authentication
- decisions and explanations are Atom authorization
- listings are Atom read-access queries

This avoids a second identity system, a separate certificate service, and duplicated access-control logic inside Magistrala.
