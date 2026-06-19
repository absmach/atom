# Atom Product Requirements Document

## Status: Draft
## Date: 2026-04-27

---

## Summary

Atom is a lightweight identity and access service for Magistrala and other cloud-native or edge systems.

It replaces a large external identity provider such as Keycloak with a single Rust binary backed by one PostgreSQL database.

Atom provides three main product areas:

1. **Entity management**

   Atom manages the objects that participate in identity and access control:

   - entities: humans, devices, services, workloads, and applications;
   - tenants: isolation boundaries such as Magistrala domains;
   - Object Groups: boundaries that contain protected objects;
   - Principal Groups: collections of identities used for shared access;
   - resources: protected application objects such as channels;
   - roles: reusable permission sets;
   - credentials: passwords, API keys, and Atom-issued certificates;
   - ownerships: parent-child relationships between entities.

2. **Authentication**

   Atom verifies who the caller is:

   - password login;
   - JWT sessions;
   - API keys;
   - credential revocation;
   - session tracking;
   - JWKS for external JWT verification;
   - signing key rotation.

3. **Authorization / access control**

   Atom decides what the caller can do:

   - actions;
   - roles;
   - assignments;
   - RBAC;
   - ABAC;
   - group-based access;
   - `POST /authz/check`;
   - `POST /authz/explain`;
   - access query endpoints;
   - audit logs.

Applications such as Magistrala store product-specific metadata in `attributes`. Runtime services call Atom for authorization decisions instead of embedding permissions in tokens. Operators use Atom's query APIs to understand access, debug denials, and keep the assignment graph clean.

---

## Problem

Magistrala and similar IoT platforms need identity and authorization for humans, devices, services, workloads, applications, domains, channels, and other resources. Keycloak can solve parts of this, but it is operationally heavy and does not map cleanly to IoT-native authorization questions.

The current project needs a single PRD because product intent must not be spread across stale specs, implementation plans, code comments, and endpoint-specific notes. Without a consolidated requirements document, it is easy to miss major decisions:

- there is no special user type;
- tenants are first-class isolation boundaries;
- Magistrala domains map directly to Atom tenants;
- tokens do not carry permissions;
- denies override allows;
- audit and explainability are product requirements, not optional diagnostics;
- query endpoints are required for operating the system, not just for convenience.

---

## Goals

1. Provide a compact identity and authorization service that is simple to deploy, operate, and reason about.
2. Support humans, devices, services, workloads, and applications using one consistent entity model.
3. Support password login, JWT sessions, API keys, and certificate credentials without changing the core entity model.
4. Provide role-based authorization with assignments, optional ABAC conditions, trusted Direct Policies, and deny-overrides semantics.
5. Make tenants first-class isolation boundaries, with Magistrala domains mapping directly to Atom tenants.
6. Keep authorization online: every access decision is evaluated against current database state.
7. Provide explain, access listing, audit, and hygiene endpoints so operators can understand and maintain access state.
8. Expose GraphQL-first management APIs and stable runtime authorization APIs.
9. Keep the implementation small: one binary, one Postgres database, automatic migrations.

## Non-goals

1. Atom is not a full Keycloak clone.
2. Atom does not provide a hosted login UI in the current scope.
3. Atom is not a general-purpose OAuth authorization server; configured OIDC signup/login federation is in scope.
4. Atom does not provide SCIM provisioning in the current scope.
5. Atom does not embed permissions into JWTs.
6. Atom does not replace application domain models; application-specific fields remain in `attributes`.
7. Atom does not provide a general-purpose policy language in the current scope.

---

## Users

### Platform operator

Runs Atom, configures tenants, rotates credentials, inspects audit logs, and cleans up stale assignments.

Needs:

- predictable deployment;
- simple bootstrap admin path;
- auditability;
- admin-only management APIs;
- hygiene reports for broken assignment state.

### Application backend

Calls Atom from Magistrala or another service to create identities, create resources, assign roles, and check authorization at runtime.

Needs:

- low-latency `check` and bulk check APIs;
- stable GraphQL and runtime authorization contracts;
- domain objects expressible as Atom tenants/resources/entities;
- deterministic authorization semantics.

### Security administrator

Manages roles, Object Groups, Principal Groups, assignments, and incident investigations.

Needs:

- "why was access denied?";
- "who can access this resource?";
- "what can this entity do?";
- "who holds this role?";
- "which assignments are orphaned or risky?".

### Magistrala integrator

Maps Magistrala users, clients, Object Groups, Principal Groups, domains, and channels to Atom primitives.

Needs:

- direct domain-to-tenant mapping;
- client API keys;
- channel publish/subscribe checks;
- Principal Group and role based authorization;
- Magistrala metadata preserved under `attributes.magistrala`.

---

## Product Principles

1. **Entity first**: every principal is an entity. `human`, `device`, `service`, `workload`, and `application` are kinds of the same object.
2. **Tenant as boundary**: a tenant is an isolation boundary, not a principal. Global objects use `tenant_id = null`.
3. **Online authorization**: tokens authenticate identity; they do not authorize actions.
4. **Default deny**: no matching allow assignment means denied.
5. **Deny overrides allow**: a matching deny wins immediately.
6. **Human-friendly access**: roles define actions and where they apply; assignments define who gets the role.
7. **Explainable operations**: every important access question should be answerable through Atom APIs.
8. **Application metadata stays namespaced**: application-owned fields live in `attributes`, for example `attributes.magistrala`.
9. **Operational simplicity**: one binary, one database, migrations on startup.

---

## Core Concepts

### Tenant

A tenant is a first-class isolation boundary with `name`, optional `alias`, `tags`, `attributes`, lifecycle status, and audit fields.

Status values:

- `active`
- `inactive`
- `frozen`
- `deleted`

Entities, resources, Object Groups, Principal Groups, and roles can belong to a tenant through `tenant_id`. Magistrala domains map directly to Atom tenants; the Magistrala domain UUID should be reused as `tenants.id`.

When a tenant is created, Atom must bootstrap tenant administration:

- create a tenant-owned role named `tenant-admin`;
- grant that role tenant administration action for the created tenant;
- bind that role to the entity that created the tenant.

The generated `tenant-admin` role is the starting administrative role for that tenant. It is not a hardcoded global role. A tenant admin can later create other tenant-owned roles such as `tenant-manager`, `operator`, `viewer`, or `auditor`.

Tenant lifecycle affects authorization. If a tenant is `inactive`, `frozen`, or `deleted`, Atom must deny authorization checks for objects inside that tenant and return a reason that includes the tenant state.

Example reasons:

```text
tenant is inactive
tenant is frozen
tenant is deleted
```

### Platform Roles

Platform roles are tenant-free roles reserved for system, admin, and service automation.

Examples:

- platform admin: manage platform-level objects and tenant administration workflows;
- tenant lifecycle manager: create tenants through `create` on `tenant`, and update, freeze, and delete tenants through `manage` on `tenant`;
- cross-tenant service role: allow trusted services to operate across tenants.

Normal tenant users must not create tenant-free roles. Tenant-free roles require platform-level administration.

### Tenant Administration Role

For tenant administration, Atom uses tenant-owned roles with permission blocks that apply inside the tenant.

The generated `tenant-admin` role should include permission blocks for:

- normal tenant objects through `manage`;
- tenant audit logs through `read` on `audit_log`;
- credentials for tenant-owned entities through `manage` on `credential`;
- tenant-owned assignments through `policy.manage`;
- tenant-owned roles through `role.manage`.

The seeded `tenant-admin` role intentionally does not include platform `manage` on `tenant`. A tenant admin cannot rename, freeze, or delete their own tenant unless a platform admin explicitly delegates that ability.

Device and workload runtime permissions should normally be granted through roles and assignments, or through trusted Direct Policies for strict runtime links such as client-channel publish/subscribe.

Example:

```text
Good:
Role Sensor Publisher applies to channel temperature with action publish.
Assignment gives Sensor Publisher to device sensor-1.

Good:
Role Field Device Publisher applies to channels in Object Group Plant-A.
Assignment gives Field Device Publisher to Principal Group Field Devices.

Risky:
device sensor-1 receives broad tenant administration access.
```

By default, action applicability and guardrails should prevent devices from receiving broad tenant-level administration actions such as `manage`, `write`, or `delete`.

### Entity

An entity is any principal that can authenticate or be authorized.

Kinds:

- `human`
- `device`
- `service`
- `workload`
- `application`

An entity has a name, optional tenant, status, and JSON attributes. The `tenant_id` on an entity means ownership or home tenant, not access membership.

Tenant ownership and tenant membership are different concepts:

```text
tenant_id = this object belongs to this tenant
tenant membership = this human participates in this tenant
```

For devices, services, workloads, applications, Object Groups, Principal Groups, resources, roles, assignments, and audit logs, `tenant_id` should represent tenant ownership or boundary.

Examples:

```text
sensor-1 belongs to factory-1
channel-1 belongs to factory-1
role operator belongs to factory-1
Object Group plant-a belongs to factory-1
Principal Group operators belongs to factory-1
```

This direct `tenant_id` model keeps tenant filtering, uniqueness, lifecycle enforcement, and authorization checks simple.

Human users are different because a single person may participate in many tenants. Human users are global by default:

```text
alice@example.com
kind = human
tenant_id = null
```

Alice can administer or access one or more tenants through role assignments without becoming tenant-scoped:

```text
Alice has tenant-admin on factory-1
Alice has tenant-viewer on factory-2
```

The MVP must not duplicate the same human as separate tenant-local entities. Duplicating humans creates login ambiguity, split audit history, duplicate credentials, and confusing policy behavior.

For tenant-local human profile, invitation, and membership status, Atom uses a dedicated tenant membership table rather than replacing `tenant_id` everywhere.

Tenant membership shape:

```sql
tenant_memberships (
  tenant_id   uuid not null,
  entity_id   uuid not null,
  status      text not null,
  local_name  text null,
  attributes  jsonb not null default '{}',
  created_at  timestamptz not null default now(),
  primary key (tenant_id, entity_id)
)
```

This table is used for human participation, tenant-local profile, tenant-local status, and invitation lifecycle. It does not replace direct `tenant_id` ownership for devices, resources, Object Groups, Principal Groups, roles, assignments, or audit logs.

Entity is the principal model. Some entities can also be protected objects when another entity manages them.

Examples:

- `sensor-1` publishes to `temperature-channel`
  - `sensor-1` is the acting entity.
  - `temperature-channel` is the protected resource.
  - `publish` is the action.
- `alice` updates `sensor-1` metadata
  - `alice` is the acting entity.
  - `sensor-1` is the protected object being managed.
  - `write` or `manage` is the action.
- `tenant-admin` disables `device-1`
  - `tenant-admin` is the acting entity.
  - `device-1` is also an entity, but in this request it is the protected object.
  - Tenant-level administration rules decide whether the action is allowed.

This avoids treating every manageable entity as a separate application resource. The same record can act as a subject in one request and be protected as an object in another request.

Entity subtypes are not separate protected object kinds. Atom should use `object_kind = "entity"` plus an entity-kind filter when a Permission Block or authorization check targets humans, devices, services, workloads, or applications.

Examples:

```text
Alice can manage all devices in tenant A
```

is represented as:

```text
subject = Alice
action = manage
object_kind = entity
entity_kind = device
tenant_id = tenant A
```

```text
Alice can manage one specific device
```

is represented as:

```text
subject = Alice
action = manage
object_kind = entity
entity_kind = device
object_id = device entity UUID
```

Human-facing APIs and UI may label this as "device access", but internally the protected object is still an entity with `kind = device`.

### Credential

A credential belongs to an entity.

Kinds:

- `password`
- `api_key`
- `certificate`

Password and API key secrets are argon2-hashed. API keys use the format:

```text
atom_<32-hex-credential-id>_<64-hex-secret>
```

The plaintext API key is revealed once and must not be recoverable later.

Certificate credentials are first-class Atom credentials. Atom owns certificate issuance, CSR signing, renewal, revocation, entity-wide revocation, CA chain publication, CRL publication, OCSP responses, and runtime certificate identity lookup. Certificates are issued from operator-supplied CA files loaded at startup. Atom must not store CA certificates or CA private keys in Postgres. Issued leaf certificate PEM is stored on the certificate credential and may be retrieved by authorized callers. Generated leaf private keys are revealed once and must not be recoverable later. CSR-issued private keys are never known to Atom. Certificate fingerprints are computed over certificate DER, not PEM text.

Credential management authority follows the entity's `tenant_id`, not tenant membership:

- A tenant admin may manage credentials only for entities owned by that tenant (`entity.tenant_id = <tenant>`).
- A tenant admin must not manage credentials for entities owned by another tenant.
- A tenant admin must not manage credentials for global entities (`tenant_id = null`), even if the global entity participates in that tenant through `tenant_memberships`. Membership grants presence and access in a tenant; it does not grant the tenant's admin credential authority over the member.
- Credentials of global entities can be managed only by a platform admin, unless platform assignment explicitly delegates credential authority over a specific global entity to a specific tenant admin.
- This rule applies to all credential operations: create, rotate, revoke, and read.

### Session and JWT

Login creates a session and returns a JWT. JWTs identify the entity and session. JWTs may include tenant context, but must not carry permissions.

### Resource

A resource is an application object protected by authorization, such as a channel, device, workspace, secret, node, or any other object kind.

Resources have a kind, optional name, optional tenant, optional owner, and attributes.

### Object Group

An Object Group is a named boundary/container for protected objects inside a tenant.

Object Groups answer:

```text
where does this role apply?
```

Object Groups can contain protected objects:

- clients/devices (`entity.kind = device` or `service`)
- channels (`resource.kind = channel`)
- rules
- reports
- alarms
- child Object Groups

Object Group supports nesting:

```text
Factory-1
  Plant-A
    Line-1
      client1
      channel1
    Line-2
      client2
      channel2
```

Object Group rules:

- Object Group is not a subject that receives roles.
- Object Group containment alone grants no access.
- One object belongs to one Object Group in V1.
- Nested Object Groups are used only for boundary matching.

### Principal Group

A Principal Group is a named collection of identities.

Principal Groups answer:

```text
who receives this role?
```

Principal Groups can contain:

- humans
- services
- applications
- workloads
- devices if needed

Examples:

```text
Principal Group Operators = alice, bob
Principal Group MG Services = mg-service, reports-service
```

Principal Group rules:

- Principal Group is a subject that can receive role assignments.
- Principal Group is not an object boundary.
- Principal Groups are flat in V1.

### Action

An action is a global action name such as:

- `read`
- `write`
- `delete`
- `publish`
- `subscribe`
- `execute`
- `manage`
- `create`
- `revoke`
- `rotate`
- `policy.manage`
- `role.manage`
- `authz.check`

Do not create object-specific action names such as:

```text
client_read
channel_publish
report_execute
```

The action is global. Applicability decides where the action is valid.

Actions are not limited to the list above. The seeded set should cover common platform, tenant administration, and runtime use cases. Product-specific actions may be added by platform administrators.

Recommended action groups:

| Group | Actions | Purpose |
|---|---|---|
| General object access | `read`, `write`, `delete`, `manage` | Administrative CRUD and object management |
| Messaging/runtime | `publish`, `subscribe`, `execute` | Device, workload, and service runtime operations |
| Credentials and keys | `manage`, `revoke`, `rotate` | Credential lifecycle and key rotation |
| Access control | `policy.manage`, `role.manage` | Policy and role administration |
| Tenant administration | `create`, `manage` | Tenant lifecycle and tenant-scoped administration |
| Audit | `read` | Audit log access |

Devices should normally receive only runtime-oriented actions such as `publish`, `subscribe`, and limited `read` for configuration or state. Devices should not receive administrative actions such as `manage`, `write`, or `delete` by default.

### Action Applicability

Action Applicability says which object types support which actions.

It validates the role model. It does not grant access.

Examples:

| Action | Valid objects |
|---|---|
| `read`, `write`, `delete` | common protected objects such as entities, resources, Object Groups, rules, reports, and alarms |
| `publish`, `subscribe` | channels |
| `execute` | rules and reports |
| `manage`, `revoke` | credentials |
| `create`, `manage` | tenant lifecycle |
| `rotate` | signing keys |
| `role.manage`, `policy.manage` | roles and assignments |

Invalid action/object pairs must be rejected:

```text
publish on client -> invalid
execute on channel -> invalid
```

### Object Kinds

Every protected object is described by a (kind, type) pair.

The **kind** (`object_kind`) is the broad category. The canonical set is:

- `entity`
- `resource`
- `group`
- `tenant`
- `role`
- `policy`
- `credential`
- `audit_log`
- `signing_key`

`action` is a definition rather than a protected runtime object and is not in this set; action mutation is governed by `policy.manage` and `role.manage`.

The **type** (`object_type`) is the finer sub-kind, written as `<kind>:<sub-kind>`:

- entity sub-kinds: `entity:human`, `entity:device`, `entity:service`, `entity:workload`, `entity:application`
- resource sub-kinds: `resource:channel`, `resource:<app-defined>`

For kinds without sub-kinds (`group`, `tenant`, `role`, `policy`, `credential`, `audit_log`), `object_type` is null.

The kind prefix on `object_type` is intentionally redundant with `object_kind` so that audit logs and explain output are self-describing. Bare values such as `device` or `channel` must not appear as stored object type values or in audit records.

These values must be used consistently across action applicability, Permission Blocks, authorization checks, guardrail rules, and audit logs.

### Permission Block

A Permission Block is the atomic permission unit and the only source of scope plus actions.

Each permission block says:

```text
where it applies + actions
```

It also carries:

```text
tenant boundary + effect + optional conditions
```

Permission Block is reused by both roles and direct policies. Neither roles nor direct policies duplicate scope/action fields.

### Role

A role is a named collection of Permission Blocks.

Example:

```text
Role: Plant-A Operator

Permission block 1:
  Applies to: clients in Object Group Plant-A
  Actions: read, write

Permission block 2:
  Applies to: channels in Object Group Plant-A
  Actions: read, publish, subscribe
```

Normal roles are tenant-owned:

```text
role.tenant_id = tenant.id
```

Tenant-free platform roles are reserved for:

- system admin
- Atom internal services
- Magistrala service entities
- cross-tenant service automation

Normal UI must not allow tenant users to create tenant-free roles.

### Assignment

Assignment is the human-facing name for granting a role to a subject.

An assignment connects:

```text
subject -> role
```

Subject can be:

- a single entity
- a Principal Group

Rules:

- Assignment has no scope. The role already defines where access applies.
- Role tenant must match the subject tenant context.
- Principal Group tenant must match role tenant.
- Cross-tenant assignment is allowed only for platform/system roles.
- Normal UI should show "assignment", not "policy binding".

Examples:

```text
Assign Plant-A Operator to user1
Assign Plant-A Operator to Principal Group Operators
Assign MG Cross Tenant Service to mg-service
```

### Direct Policy

Direct Policy is an advanced/security feature for granting one Permission Block directly to a subject.

It connects:

```text
subject -> permission block
```

Direct Policy has no duplicated scope, action, effect, or condition fields. Those live only in the referenced Permission Block.

Direct Policies may be used for:

- machine-created runtime links, such as strict client-channel publish/subscribe connections;
- service grants;
- explicit deny rules;
- temporary or conditional access;
- break-glass access.

Guardrails:

- Direct Policies are not exposed in normal user-facing role assignment UI.
- Direct Policies are created only by trusted service/system or advanced security flows.
- Direct Policies are audited.
- The main product model remains Permission Blocks, Roles, and Role Assignments.

### Listing Rule

Atom should not require a separate `list` action for normal object listing.

Listing means:

```text
return objects the caller can read
```

This must be implemented through SQL authorization filtering, not by loading every object and checking access one by one.

### ABAC Conditions

Advanced assignments may include `conditions`. Conditions are a flat JSON object where keys are dot-paths. Each value is either a literal (treated as `eq`) or an object specifying an operator. All conditions must match for the assignment to apply.

Supported operators:

- `eq` — value equals the operand (default for a literal value).
- `neq` — value does not equal the operand.
- `contains` — for strings, substring match; for arrays, element membership.
- `in` — value is one of the operands (operand is an array).
- `gt`, `gte`, `lt`, `lte` — numeric or timestamp comparison.

Operator example:

```json
{
  "context.mfa_verified": true,
  "object.attributes.tags": { "contains": "production" },
  "context.time": { "gte": "2026-01-01T00:00:00Z" },
  "entity.attributes.department": { "in": ["operations", "security"] }
}
```

If a referenced field is missing on the subject, object, tenant, or context, the condition does not match and the assignment does not apply.

ABAC conditions may reference three categories of data:

1. **Top-level fields**

   These are real fields from Atom's domain objects. They should not need to be duplicated inside JSON attributes.

   Examples:

   ```text
   entity.id
   entity.kind
   entity.tenant_id
   entity.status
   resource.id
   resource.kind
   resource.tenant_id
   tenant.id
   tenant.status
   object.kind
   object.type
   object.id
   object.tenant_id
   ```

2. **Attributes**

   These are JSON fields stored under `attributes` on entities, resources, tenants, and protected objects.

   Examples:

   ```text
   entity.attributes.department
   entity.attributes.region
   resource.attributes.env
   resource.attributes.site
   tenant.attributes.plan
   object.attributes.magistrala.tags
   ```

3. **Request context**

   These are values supplied by the caller during an authorization check.

   Examples:

   ```text
   context.ip
   context.method
   context.client_id
   context.mfa_verified
   context.time
   ```

Example condition:

```json
{
  "entity.kind": "human",
  "entity.attributes.department": "operations",
  "object.type": "entity:device",
  "object.attributes.site": "plant-a",
  "tenant.status": "active",
  "context.mfa_verified": true
}
```

This means:

```text
Apply this advanced conditional assignment only when a human from operations is acting on a device at plant-a, inside an active tenant, after MFA verification.
```

Top-level fields and attributes are both required. Top-level fields provide stable system facts such as kind, tenant, status, and object type. Attributes provide application-specific facts such as department, region, tags, site, plan, or Magistrala metadata.

### Action Assignment Guardrails

Actions are generic. Entity kind describes what the subject is, but entity kind should not directly grant permissions.

Runtime authorization answers:

```text
Can subject X do action Y on object Z?
```

Action assignment guardrails answer a different question:

```text
Is it safe to create this Role Assignment, Permission Block, Direct Policy, or Principal Group membership?
```

This prevents unsafe access from being created accidentally.

Example:

- A `device` should usually be allowed to `publish` to a `channel`.
- A `device` should usually not be allowed to `create`, `write`, `delete`, or `manage` a `channel`.
- A `human` or trusted `service` may be allowed to manage tenant resources if a role assignment grants it.
- A tenant may define stricter local rules, but platform-level absolute denies cannot be overridden by a tenant.

The PDP stays generic and evaluates current access state. Guardrails run when access is assigned or changed.

Guardrails should be evaluated when:

- creating a role assignment;
- assigning a role to an entity;
- assigning a role to a Principal Group;
- adding an action to a Permission Block;
- adding an entity to a Principal Group that already has role assignments;
- creating tenant-owned admin roles during tenant creation.

Direct Policies, Role Assignments, Permission Block changes, and Principal Group membership changes must all be validated. Otherwise unsafe access can be hidden inside a role or inherited through a Principal Group.

Recommended storage:

```sql
action_assignment_rules (
  id              uuid primary key,
  tenant_id       uuid null,
  entity_kind     text not null,
  action_name text not null,
  object_kind     text not null,
  object_type     text null,
  decision        text not null check (decision in ('allow', 'deny', 'require_override')),
  is_absolute     boolean not null default false,
  created_at      timestamptz not null default now()
)
```

Field meaning:

- `tenant_id = null` means the rule is a global default.
- `tenant_id = <tenant>` means the rule applies only inside that tenant.
- `entity_kind` is the kind of the subject receiving access.
- `action_name` is the action being granted.
- `object_kind` is the protected object type, such as `resource`, `entity`, `group`, `tenant`, `role`, `policy`, `credential`, `audit_log`, or `signing_key`.
- `object_type` narrows the rule to a specific sub-kind such as `resource:channel` or `entity:device`. Always namespaced with its kind. Null means the rule applies to every sub-kind under the given `object_kind`.
- `decision = allow` means the assignment is allowed.
- `decision = deny` means the assignment is rejected.
- `decision = require_override` means only a platform admin can force the assignment, and the override must be audited.
- `is_absolute = true` means the rule cannot be overridden by tenant-specific rules.

Guardrail management rules:

- platform admins manage global guardrail rules;
- tenant admins may create tenant-specific guardrail rules only for their tenant;
- for MVP, tenant admins may only make tenant-specific rules stricter, such as adding deny rules;
- tenant admins cannot override global absolute deny rules;
- tenant admins cannot create global guardrails.

Example global rules:

| Entity kind | Action | Object kind | Object type | Decision |
|---|---|---|---|---|
| `device` | `publish` | `resource` | `resource:channel` | `allow` |
| `device` | `subscribe` | `resource` | `resource:channel` | `allow` |
| `device` | `manage` | `resource` | `resource:channel` | `deny` |
| `device` | `delete` | `resource` | `resource:channel` | `deny` |
| `human` | `manage` | `resource` | `resource:channel` | `allow` |
| `service` | `manage` | `resource` | `resource:channel` | `allow` |

Example tenant-specific rule:

| Tenant | Entity kind | Action | Object kind | Object type | Decision |
|---|---|---|---|---|---|
| `factory-1` | `device` | `read` | `resource` | `resource:device_config` | `allow` |

Recommended rule precedence:

1. Global absolute deny.
2. Global absolute require override.
3. Tenant deny.
4. Tenant require override.
5. Tenant allow.
6. Global deny.
7. Global require override.
8. Global allow.
9. Default deny.

This means tenants can become stricter than the platform defaults. Tenants can add local allows only where the platform has not declared an absolute deny.

Example rejected assignment:

```json
{
  "subject_kind": "entity",
  "subject_id": "device-id",
  "role_id": "channel-admin-role-id"
}
```

Response:

```json
{
  "error": "action_not_allowed_for_entity_kind",
  "message": "device entities cannot be granted delete on resource kind channel by default"
}
```

Example role validation:

- Role `channel-admin` has a permission block with `delete` on channels.
- An assignment tries to give `channel-admin` to a `device`.
- Atom expands the role's Permission Blocks during assignment validation.
- The assignment is rejected because `device + delete + resource:channel` is denied.

Example Principal Group validation:

- Principal Group `floor-sensors` has an assignment to a role that grants `publish` to channels.
- Adding a `device` to `floor-sensors` is allowed.
- If the Principal Group later receives a role with `delete` on channels, Atom must validate all current group members and reject the assignment if devices would inherit a denied action.
- If a Principal Group already has `delete` on channels, adding a `device` to that group must be rejected.

MVP recommendation:

- Add the `action_assignment_rules` table.
- Seed global default rules for common entity kinds and common actions.
- Support optional tenant-specific rules.
- Allow tenant admins to create stricter tenant-specific deny rules.
- Validate Role Assignment creation, Direct Policy creation, Permission Block changes, and Principal Group membership changes.
- Make deny beat allow.
- Make absolute global deny impossible to override.
- Audit every rejected assignment and every override.
- Keep the PDP unchanged in purpose: guardrails prevent unsafe access state from being created, while `/authz/check` continues to evaluate current assignments.

---

## Functional Requirements

Priority levels: "Must" items are required for general availability and ship across the phases below; "Should" items are strongly desired but may slip past GA without blocking release.

### Identity

| ID | Requirement | Priority |
|---|---|---|
| ID-1 | The system must create, list, read, update, and delete entities. | Must |
| ID-2 | The system must support entity kinds `human`, `device`, `service`, `workload`, and `application`. | Must |
| ID-3 | The system must support entity status checks so inactive or suspended entities cannot authorize successfully. | Must |
| ID-4 | The system must support arbitrary JSON attributes on entities. | Must |
| ID-5 | Entity names must be unique per tenant. | Must |
| ID-6 | The system must support global entities with `tenant_id = null`. | Must |
| ID-7 | Entity `tenant_id` must represent ownership or home tenant, not access membership. | Must |
| ID-8 | Human users must be global by default, with tenant access granted through role assignments. | Must |
| ID-9 | The MVP must not require duplicate tenant-local human entities for the same person. | Must |
| ID-10 | Atom must provide a tenant membership table for human tenant participation, tenant-local profile, tenant-local status, and invitations. | Must |

### Credentials and Authentication

| ID | Requirement | Priority |
|---|---|---|
| AUTH-1 | The system must authenticate password credentials and return JWT sessions. | Must |
| AUTH-2 | The system must support API key credentials for long-lived machine access. | Must |
| AUTH-3 | API keys must embed the credential ID for direct lookup. | Must |
| AUTH-4 | Plaintext API key secrets must be shown only once. | Must |
| AUTH-5 | Credentials must be revocable. | Must |
| AUTH-6 | Sessions must be stored and revocable. | Must |
| AUTH-7 | JWT signing keys must support JWKS publication for external verifiers. | Should |
| AUTH-8 | Signing keys must be rotatable through a manage-protected endpoint. | Should |
| AUTH-9 | Tenant admins may manage credentials for tenant-scoped entities in their tenant. | Must |
| AUTH-10 | Tenant admins must not manage credentials for any entity not owned by their tenant, including global entities (`tenant_id = null`), entities owned by other tenants, and platform admins. Platform policy may explicitly delegate credential authority over a specific entity to a specific tenant admin. | Must |
| AUTH-11 | The system must support Atom-issued certificate credentials backed by an operator-supplied file issuer CA. | Must |
| AUTH-12 | CA certificates and CA private keys must be loaded from mounted files and must not be stored in Postgres. | Must |
| AUTH-13 | The system must support generated leaf certificates with one-time private key reveal. | Must |
| AUTH-14 | The system must support CSR signing without storing or returning a private key. | Must |
| AUTH-15 | The system must support certificate renewal, serial revocation, entity-wide certificate revocation, CRL publication, OCSP responses, and CA chain publication. | Must |
| AUTH-16 | Runtime services must be able to resolve a certificate serial to an active Atom entity through Atom's runtime API. | Must |
| AUTH-17 | Certificate TTL requests greater than the configured maximum must be rejected. | Must |
| AUTH-18 | CSR-issued certificates must always be non-CA client-auth leaf certificates regardless of requested CSR extensions. | Must |
| AUTH-19 | OCSP responses must validate issuer hashes and return `unknown` for mismatched issuers. | Must |
| AUTH-20 | CRL responses must be cached and regenerated only when revocation state changes or the CRL expires. | Must |

### Tenants

| ID | Requirement | Priority |
|---|---|---|
| TEN-1 | The system must expose first-class tenant CRUD and lifecycle APIs. | Must |
| TEN-2 | Tenant lifecycle must support active, inactive, frozen, and deleted states. | Must |
| TEN-3 | Tenant deletion must be soft delete by setting status to `deleted`. | Must |
| TEN-4 | Tenant create must require platform `create` on `tenant`; update, freeze, and delete operations must require platform `manage` on `tenant`. | Must |
| TEN-5 | Entities, resources, Object Groups, Principal Groups, and roles must be able to reference tenants by `tenant_id`. | Must |
| TEN-6 | Magistrala domains must map directly to Atom tenants. | Must |
| TEN-7 | Authorization checks must support tenant objects through `object_kind = "tenant"` and `object_id`. | Must |
| TEN-8 | Tenant-wide Permission Blocks must apply only to objects whose `tenant_id` matches the tenant. | Must |
| TEN-9 | For MVP, `manage` on a tenant must grant administration over normal tenant-scoped objects, while sensitive operations use explicit actions. | Must |
| TEN-10 | Tenant-owned Permission Blocks must not apply to other tenants or global platform objects where `tenant_id = null`. | Must |
| TEN-11 | Device and workload runtime access should normally use roles, role assignments, and trusted Direct Policies that reference Permission Blocks rather than broad tenant administration access. | Should |
| TEN-12 | Atom must create a tenant-scoped `tenant-admin` role for every new tenant. | Must |
| TEN-13 | The tenant creator must receive the generated `tenant-admin` role. | Must |
| TEN-14 | Authorization checks for inactive, frozen, or deleted tenants must be denied with a reason that includes tenant state. | Must |
| TEN-15 | Atom must provide a tenant membership table for tenant-local human profile and membership state, while humans remain global by default in the entity model. | Must |
| TEN-16 | The generated `tenant-admin` role must include tenant-scoped `manage`, `read`, `policy.manage`, and `role.manage`. Audit access is represented by `read` on `audit_log`; credential administration is represented by `manage` on `credential`. | Must |

### Authorization

| ID | Requirement | Priority |
|---|---|---|
| AZ-1 | The system must expose `POST /authz/check` for runtime authorization decisions. | Must |
| AZ-2 | The system must support resource checks by `resource_id`. | Must |
| AZ-3 | The system must support protected object checks by `object_kind` and `object_id`. | Must |
| AZ-4 | The PDP must load the subject and require it to be active. | Must |
| AZ-5 | The PDP must resolve the requested action and validate action applicability for the protected object type. | Must |
| AZ-6 | The PDP must evaluate direct entity role assignments. | Must |
| AZ-7 | The PDP must evaluate Principal Group role assignments inherited through membership. | Must |
| AZ-8 | The PDP must evaluate Permission Blocks and their actions through both role assignments and Direct Policies. | Must |
| AZ-9 | The PDP must evaluate one effective-permission shape built from role assignments and Direct Policies. | Must |
| AZ-10 | The PDP must support Permission Block scopes for platform, tenant, object kind, object type, exact object, and Object Group containment. | Must |
| AZ-11 | The PDP must support ABAC conditions against top-level fields, attributes, and request context. | Must |
| AZ-12 | A matching deny must override any allow. | Must |
| AZ-13 | No matching allow must return denied. | Must |
| AZ-14 | The system must expose `POST /authz/check/bulk` for checking multiple decisions in one request. | Should |
| AZ-15 | The system must expose gRPC authorization check APIs for runtime integrations. gRPC is runtime-only for now; management APIs remain HTTP-only. Management APIs may be added to gRPC later if needed. | Should |
| AZ-16 | Authorization checks must evaluate tenant lifecycle state for tenant-scoped objects. | Must |
| AZ-17 | Entity subtypes must be represented as `object_kind = entity` with an entity-kind/object-type filter, not as separate protected object kinds. | Must |
| AZ-18 | Role Assignments must not have a separate scope; where access applies must come from the assigned role's Permission Blocks. | Must |
| AZ-19 | Entity subtype permission blocks must use object type values such as `entity:device` and `entity:human`. | Must |
| AZ-20 | ABAC conditions must support top-level fields such as `entity.kind`, `entity.tenant_id`, `tenant.status`, `object.kind`, and `object.type`. | Must |
| AZ-21 | ABAC conditions must support JSON attributes such as `entity.attributes.*`, `resource.attributes.*`, `tenant.attributes.*`, and `object.attributes.*`. | Must |
| AZ-22 | ABAC conditions must support request context fields such as `context.ip`, `context.client_id`, and `context.mfa_verified`. | Must |

### Access Management

| ID | Requirement | Priority |
|---|---|---|
| AM-1 | The system must create, list, read, update, and delete tenant-owned roles. | Must |
| AM-2 | The system must create, list, read, update, and delete Permission Blocks and their actions. | Must |
| AM-3 | The system must create, list, read, and delete actions. | Must |
| AM-4 | Action, role, and assignment mutation must require manage permission. | Must |
| AM-5 | The system must create, list, read, and delete role assignments. | Must |
| AM-6 | The system must create, update, nest, and delete Object Groups. | Must |
| AM-7 | The system must create and delete Principal Groups and add, list, and remove Principal Group members. | Must |
| AM-8 | The system must support ownership relationships between entities. | Should |
| AM-9 | Role assignments must store tenant ownership directly, with `null` reserved for platform/system assignments. | Must |
| AM-10 | Tenant admins must be able to manage role assignments owned by their tenant. | Must |
| AM-11 | Tenant-owned role assignments must not grant access outside their tenant unless the assigned role is a platform/system role. | Must |

### Action Assignment Guardrails

| ID | Requirement | Priority |
|---|---|---|
| GR-1 | The system must support action applicability rules that define which actions are valid for which object types. | Must |
| GR-2 | The system must support global guardrail rules with `tenant_id = null`. | Must |
| GR-3 | The system must support tenant-specific guardrail rules. | Should |
| GR-4 | The system must support absolute global denies that tenant-specific rules cannot override. | Must |
| GR-5 | The system must validate Direct Policies before creating them. | Must |
| GR-6 | The system must validate role assignments by checking the assigned role's Permission Blocks and actions. | Must |
| GR-7 | The system must validate Permission Block changes against existing role holders and Direct Policy subjects. | Must |
| GR-8 | The system must validate Principal Group assignment changes against existing group members. | Must |
| GR-9 | The system must validate Principal Group membership changes against assignments the new member would inherit. | Must |
| GR-10 | The system should support `require_override` for assignments that are risky but platform-admin approved. | Should |
| GR-11 | The system must audit rejected assignments and override-based assignments. | Must |
| GR-12 | Guardrails must not replace PDP evaluation; they prevent unsafe access state from being created. | Must |
| GR-13 | Platform admins must manage global guardrail rules. | Must |
| GR-14 | Tenant admins may create only stricter tenant-specific guardrail rules in MVP. | Should |
| GR-15 | Tenant admins must not override global absolute deny guardrail rules. | Must |

### Query, Explainability, and Operations

| ID | Requirement | Priority |
|---|---|---|
| QRY-1 | The system must explain a single authorization decision through `POST /authz/explain`. | Must |
| QRY-2 | The system must list what resources an entity can access. | Must |
| QRY-3 | The system must list who can access a resource. | Must |
| QRY-4 | The system must expose audit logs with useful filters. | Must |
| QRY-5 | The system should list who holds a role. | Should |
| QRY-6 | The system should list what access a Principal Group grants. | Should |
| QRY-7 | The system should list an entity's effective actions. | Should |
| QRY-8 | The system should report orphaned assignments. | Should |
| QRY-9 | The system should report unprotected resources. | Should |
| QRY-10 | The system should report expiring credentials. | Should |

### Audit

Audit logs should store `tenant_id` directly.

Rules:

- `tenant_id = null` means platform/global audit event.
- `tenant_id = <tenant>` means tenant-owned audit event.
- tenant admins can read audit logs for their tenant.
- platform admins can read global audit logs and cross-tenant audit logs according to platform policy.
- authz denials caused by tenant lifecycle state must be audited with the tenant ID and state.

| ID | Requirement | Priority |
|---|---|---|
| AUD-1 | The system must write audit logs for login decisions. | Must |
| AUD-2 | The system must write audit logs for logout and credential operations. | Must |
| AUD-3 | The system must write audit logs for authorization checks and explain calls. | Must |
| AUD-4 | Audit writes must never block or fail the caller's operation. | Must |
| AUD-5 | Audit entries must include event, outcome, entity, details, and timestamp. | Must |
| AUD-6 | Audit logs must store `tenant_id` directly for tenant-owned events. | Must |
| AUD-7 | Tenant admins must be able to read audit logs for their tenant. | Must |
| AUD-8 | Authorization denials caused by tenant lifecycle state must include tenant state in the audit details. | Must |

### Magistrala Integration

| ID | Requirement | Priority |
|---|---|---|
| MAG-1 | Magistrala domain ID must be usable as Atom tenant ID. | Must |
| MAG-2 | Magistrala users must map to global `human` entities. | Must |
| MAG-3 | Magistrala clients must map to `device` or `service` entities scoped to a tenant. | Must |
| MAG-4 | Magistrala channels must map to `resource` rows with `kind = "channel"`. | Must |
| MAG-5 | Client-channel publish and subscribe permissions must be expressible as Atom role assignments or trusted Direct Policies. | Must |
| MAG-6 | Magistrala metadata must be stored under `attributes.magistrala`. | Must |
| MAG-7 | Magistrala runtime access checks must call Atom instead of maintaining a separate authorization database. | Must |

---

## API Scope

Atom must expose these API categories:

- Health: service health check.
- Authentication: login, logout, session read, JWKS, signing key rotation.
- Entities: entity CRUD and Principal Group membership views.
- Credentials: password creation, API key creation, credential listing, credential revocation.
- Certificates: certificate issuance, CSR signing, renewal, revocation, entity-wide revocation, CA chain, CRL, OCSP, and runtime certificate identity lookup.
- Tenants: tenant CRUD and lifecycle transitions.
- Object Groups: boundary CRUD, hierarchy, and object containment management.
- Principal Groups: principal collection CRUD and membership management.
- Ownerships: entity-to-entity parent/child relations.
- Resources: protected object CRUD.
- Roles: role CRUD and permission block management.
- Actions: action CRUD.
- Assignments: role assignment CRUD.
- Authorization: single check, bulk check, explain.
- Query endpoints: entity access, resource access, Principal Group access, role holders, effective actions.
- Audit: audit log listing.
- Admin hygiene: orphan assignments, unprotected resources, expiring credentials.
- gRPC: runtime authorization-oriented service interface only for now; management APIs remain HTTP-only unless added later.

Detailed endpoint requirements are maintained in the linked product docs:

1. [Query and search endpoint overview](./00-overview.md)
2. [POST /authz/explain](./01-authz-explain.md)
3. [GET /entities/:id/access](./02-entity-access.md)
4. [GET /resources/:id/access](./03-resource-access.md)
5. [GET /audit](./04-audit.md)
6. [POST /authz/check/bulk](./05-bulk-check.md)
7. [GET /roles/:id/holders](./06-role-holders.md)
8. [Principal Group access](./07-group-access.md)
9. [GET /entities/:id/effective-actions](./08-effective-actions.md)
10. [Admin hygiene endpoints](./09-admin-hygiene.md)
11. [Building Magistrala on Atom](./10-magistrala-on-atom.md)
12. [Atom access model](./11-access-model-simplification.md)
13. [Atom certificates](./12-certificates.md)

---

## Non-functional Requirements

### Deployment

- Atom must run as a single binary.
- Atom must use PostgreSQL as its only required persistent datastore.
- Migrations must run automatically on startup.
- The service must be configurable through environment variables.

### Security

- Secrets must be hashed with argon2.
- JWTs must be signed and verifiable through published keys.
- CA private keys must be provided through mounted files and must not be stored in Postgres.
- Atom must fail startup when certificate support is enabled without valid file issuer CA material.
- Management endpoints must require a manage-capable caller.
- Authorization must be denied by default.
- API keys must not be recoverable after creation.
- Issued certificate private keys must not be recoverable after creation.

### Reliability

- Audit failures must not fail authentication or authorization flows.
- Database `RowNotFound` errors must map to not found responses.
- Unique constraint violations must map to conflict responses.
- Tenant foreign key violations must return a clear bad request or conflict-style error.

### Performance

- Authorization checks must avoid per-assignment Permission Block queries.
- Role permission blocks and actions must be batch-loaded for authorization evaluation.
- API key authentication must avoid full credential-table scans by using the embedded credential ID.
- CRL generation must be concurrency-safe across Atom replicas.
- List endpoints must support pagination.

### Compatibility

- Existing `resource_id` authorization checks must remain supported.
- New `object_kind` and `object_id` authorization checks must not break the legacy shape.
- New APIs should use explicit object kind and object type values such as `object_kind = "resource"` and `object_type = "channel"`. No legacy scope or resource-kind form should appear in stored Permission Blocks, assignments, Direct Policies, guardrail rules, or audit records.
- GraphQL, custom endpoint, and runtime authorization semantics must match.

---

## Success Metrics

Atom is successful when:

- Magistrala can model domains, users, clients, channels, Object Groups, Principal Groups, roles, and permissions without a separate auth database.
- Runtime services can answer authorization decisions through Atom with deterministic deny-by-default behavior.
- Operators can answer "why denied?", "who can access this?", and "what can this entity access?" without direct SQL.
- Credential creation, certificate issuance, revocation, runtime certificate lookup, and audit inspection can be done through APIs.
- Tenants can represent Magistrala domain lifecycle states.
- The service can be deployed with Postgres and a small set of environment variables.

---

## Phased Scope

### Phase 1: Core service

- Entity model
- Password login
- JWT sessions
- API keys
- Resources
- Actions
- Roles
- Assignments
- Single authorization check
- Audit table and basic audit writes
- Admin bootstrap

### Phase 2: Operability

- Explain endpoint
- Entity access endpoint
- Resource access endpoint
- Audit listing endpoint
- Bulk check endpoint
- Role holders endpoint
- Principal Group access endpoint
- Effective actions endpoint
- Admin hygiene endpoints

### Phase 3: Tenant and Magistrala alignment

- First-class tenant table and lifecycle endpoints
- Tenant foreign keys from scoped objects
- Tenant admin role bootstrap on tenant creation
- Tenant creator receives the generated `tenant-admin` role
- Tenant memberships table for human tenant participation
- `tenant_id` on role assignments
- `tenant_id` on audit logs
- Tenant lifecycle enforcement in authorization checks
- Object-based authorization checks for tenants
- Magistrala domain-to-tenant mapping
- Magistrala integration guide
- HTTP/OpenAPI and gRPC contract updates
- Atom-native certificate credential lifecycle

### Phase 4: Action assignment guardrails

- `action_assignment_rules` table
- Global default assignment rules
- Tenant-specific assignment rules
- Absolute global deny support
- Validation during assignment creation
- Validation during role assignment and Permission Block updates
- Validation during Principal Group membership changes
- Rejected-assignment and override audit logs

### Phase 5: Future extensions

- SCIM provisioning
- Additional federation provider capabilities
- Workload identity with SPIFFE or X.509
- Extended token lifecycle management
- Audit webhooks
- Prometheus metrics
- Rate limiting

---

## Open Questions

1. **Guardrail validation on large Principal Groups (GR-8, GR-9).** When an assignment or membership change requires re-validating all existing Principal Group members, and the group has tens or hundreds of thousands of members, should validation be synchronous (transactional, but slow) or asynchronous (fast, but unsafe state can exist briefly)? Decide the model and any size threshold.

2. **`require_override` workflow (GR-10).** Is `require_override` a synchronous flag a platform admin sets on the request, or a multi-step approval workflow (request → approval → apply)? Define the API shape and the audit trail.

3. **Session validation on the authz path (AUTH-6).** Validating session liveness in the database on every `/authz/check` is expensive at high QPS. Options: (a) DB lookup per check, (b) short-lived JWT plus refresh token with no per-check DB hit, (c) in-process revocation set refreshed by polling or Postgres `LISTEN/NOTIFY` for bounded-staleness revocation. Recommendation: (c) with a documented staleness bound (e.g., 1–5 s).

4. **Migrations on startup with multiple replicas.** When N replicas start concurrently, how are migrations serialized? Options: Postgres advisory lock around the migration step, leader-only migration via deployment ordering, or first-replica-wins with retries on the others. This is not a current priority because Postgres replicas are out of scope for now, but keep the question open for future multi-replica deployments. Decide.

---

## References

- [README](../README.md)
- [Access model](./11-access-model-simplification.md)
- [OpenAPI spec](../apidocs/openapi.yaml)
- [gRPC reference](../apidocs/grpc-reference.md)
- [Magistrala integration](./10-magistrala-on-atom.md)
