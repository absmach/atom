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
   - groups: collections of entities used for shared access;
   - resources: protected application objects such as channels;
   - roles: reusable bundles of capabilities;
   - credentials: passwords, API keys, and future credential types;
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

   - capabilities;
   - roles;
   - policy bindings;
   - RBAC;
   - ABAC;
   - group-based access;
   - `POST /authz/check`;
   - `POST /authz/explain`;
   - access query endpoints;
   - audit logs.

Applications such as Magistrala store product-specific metadata in `attributes`. Runtime services call Atom for authorization decisions instead of embedding permissions in tokens. Operators use Atom's query APIs to understand access, debug denials, and keep the policy graph clean.

---

## Problem

Magistrala and similar IoT platforms need identity and authorization for humans, devices, services, workloads, applications, domains, channels, and other resources. Keycloak can solve parts of this, but it is operationally heavy and does not map cleanly to IoT-native authorization questions.

The current project needs a single PRD because the important product intent is spread across code, API docs, `spec.md`, and endpoint-specific product docs. Without a consolidated requirements document, it is easy to miss major decisions:

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
3. Support password login, JWT sessions, API keys, and future credential types without changing the core entity model.
4. Provide policy-based authorization with RBAC, ABAC, direct grants, group grants, and deny-overrides semantics.
5. Make tenants first-class isolation boundaries, with Magistrala domains mapping directly to Atom tenants.
6. Keep authorization online: every access decision is evaluated against current database state.
7. Provide explain, access listing, audit, and hygiene endpoints so operators can understand and maintain access state.
8. Expose both HTTP and gRPC interfaces for runtime integration.
9. Keep the implementation small: one binary, one Postgres database, automatic migrations.

## Non-goals

1. Atom is not a full Keycloak clone.
2. Atom does not provide a hosted login UI in the current scope.
3. Atom does not implement OAuth/OIDC federation in the current scope.
4. Atom does not provide SCIM provisioning in the current scope.
5. Atom does not embed permissions into JWTs.
6. Atom does not replace application domain models; application-specific fields remain in `attributes`.
7. Atom does not require GraphQL or a general-purpose policy language in the current scope.

---

## Users

### Platform operator

Runs Atom, configures tenants, rotates credentials, inspects audit logs, and cleans up stale policies.

Needs:

- predictable deployment;
- simple bootstrap admin path;
- auditability;
- admin-only management APIs;
- hygiene reports for broken policy state.

### Application backend

Calls Atom from Magistrala or another service to create identities, create resources, bind policies, and check authorization at runtime.

Needs:

- low-latency `check` and bulk check APIs;
- stable HTTP and gRPC contracts;
- domain objects expressible as Atom tenants/resources/entities;
- deterministic authorization semantics.

### Security administrator

Manages roles, groups, policies, and incident investigations.

Needs:

- "why was access denied?";
- "who can access this resource?";
- "what can this entity do?";
- "who holds this role?";
- "which policies are orphaned or risky?".

### Magistrala integrator

Maps Magistrala users, clients, groups, domains, and channels to Atom primitives.

Needs:

- direct domain-to-tenant mapping;
- client API keys;
- channel publish/subscribe checks;
- group and role based authorization;
- Magistrala metadata preserved under `attributes.magistrala`.

---

## Product Principles

1. **Entity first**: every principal is an entity. `human`, `device`, `service`, `workload`, and `application` are kinds of the same object.
2. **Tenant as boundary**: a tenant is an isolation boundary, not a principal. Global objects use `tenant_id = null`.
3. **Online authorization**: tokens authenticate identity; they do not authorize actions.
4. **Default deny**: no matching allow policy means denied.
5. **Deny overrides allow**: a matching deny policy wins immediately.
6. **Composable access**: direct grants, roles, groups, scopes, and ABAC conditions can combine.
7. **Explainable operations**: every important access question should be answerable through Atom APIs.
8. **Application metadata stays namespaced**: application-owned fields live in `attributes`, for example `attributes.magistrala`.
9. **Operational simplicity**: one binary, one database, migrations on startup.

---

## Core Concepts

### Tenant

A tenant is a first-class isolation boundary with `name`, optional `route`, `tags`, `attributes`, lifecycle status, and audit fields.

Status values:

- `active`
- `inactive`
- `frozen`
- `deleted`

Entities, groups, resources, and roles can be scoped to a tenant through `tenant_id`. Magistrala domains map directly to Atom tenants; the Magistrala domain UUID should be reused as `tenants.id`.

When a tenant is created, Atom must bootstrap tenant administration:

- create a tenant-scoped role named `tenant-admin`;
- grant that role tenant administration capability for the created tenant;
- bind that role to the entity that created the tenant.

The generated `tenant-admin` role is the starting administrative role for that tenant. It is not a hardcoded global role. A tenant admin can later create other tenant-scoped roles such as `tenant-manager`, `operator`, `viewer`, or `auditor`.

Tenant lifecycle affects authorization. If a tenant is `inactive`, `frozen`, or `deleted`, Atom must deny authorization checks for objects inside that tenant and return a reason that includes the tenant state.

Example reasons:

```text
tenant is inactive
tenant is frozen
tenant is deleted
```

### Tenant Policy Inheritance

A tenant policy can be used to grant access over objects inside a tenant.

The core rule is:

```text
If a subject has capability X on tenant T,
then the subject may use capability X on tenant-scoped objects where tenant_id = T.
```

Example:

```text
Alice has manage on tenant factory-1
```

This can allow Alice to manage objects inside `factory-1`, such as:

- entities in `factory-1`;
- groups in `factory-1`;
- resources in `factory-1`;
- roles in `factory-1`;
- policies in `factory-1`;
- credentials for tenant-scoped entities in `factory-1`;
- audit logs associated with `factory-1`.

Tenant policy inheritance must never apply to:

- another tenant's objects;
- global platform objects where `tenant_id = null`;
- platform-wide administration such as signing key rotation;
- global capabilities or global guardrail rules unless separately allowed by platform policy.

There are two possible models for tenant policy inheritance.

#### Option A: Equal Inheritance

In this model, tenant capabilities apply equally to all tenant-scoped object types.

Example:

```text
manage on tenant = manage everything inside the tenant
read on tenant = read everything inside the tenant
```

If Alice has `manage` on tenant `factory-1`, she can manage:

- tenant entities;
- tenant groups;
- tenant resources;
- tenant roles;
- tenant policies;
- tenant-scoped credentials;
- tenant audit logs.

Benefits:

- simple to explain;
- simple to implement;
- useful for MVP;
- easy for platform admins to reason about;
- matches the common expectation of a tenant admin.

Risks:

- broad access;
- `read` on a tenant may include sensitive objects such as audit logs or credential metadata;
- `manage` on a tenant may allow powerful operations such as policy changes and credential revocation;
- mistakes in one tenant-level policy can affect many object types.

#### Option B: Sensitive Object Capabilities

In this model, tenant policy inheritance applies broadly, but sensitive object types require specific capabilities.

Example:

```text
manage on tenant = manage normal tenant objects
read_audit on tenant = read tenant audit logs
manage_credentials on tenant = manage tenant credentials
manage_policies on tenant = manage tenant policies
```

Under this model, Alice may have `manage` on tenant `factory-1`, but still need explicit capabilities to:

- read audit logs;
- revoke credentials;
- create or delete tenant policies;
- create another tenant admin;
- view sensitive credential metadata.

Benefits:

- safer;
- clearer security boundaries;
- easier to give limited roles such as tenant viewer, support user, auditor, or credential operator.

Costs:

- more capabilities;
- more policy complexity;
- more UI/API decisions;
- harder to implement correctly in the first version.

#### MVP Choice

For tenant administration, Atom uses a split model:

```text
manage on tenant grants administration over normal tenant-scoped objects.
Sensitive tenant operations require explicit sensitive capabilities.
```

This means the generated `tenant-admin` role should include:

- `manage` on the tenant;
- `audit.read` for tenant audit logs;
- `credential.manage` for credentials of tenant-scoped entities;
- `policy.manage` for tenant-owned policies;
- `role.manage` for tenant-scoped roles.

With those capabilities, a tenant admin can manage:

- entities in the tenant through `manage`;
- groups in the tenant through `manage`;
- resources in the tenant through `manage`;
- roles in the tenant through `role.manage`;
- policies in the tenant through `policy.manage`;
- credentials for tenant-scoped entities through `credential.manage`;
- audit logs for the tenant through `audit.read`.

Tenant credential access follows entity scope:

- a tenant admin can manage credentials for tenant-scoped entities in that tenant;
- a tenant admin cannot manage credentials for global human users with `tenant_id = null` unless separately allowed by platform policy;
- a tenant admin cannot manage platform admin credentials unless separately allowed by platform policy.

However, broad tenant inheritance is intended for tenant administration, mainly by `human` and trusted `service` entities. It should not be used as the normal model for device runtime access.

Device and workload runtime permissions should normally be granted through explicit resource, resource-kind, role, or group policies.

Example:

```text
Good:
device sensor-1 has publish on channel temperature

Good:
group floor-sensors has publish on resource_kind channel

Risky:
device sensor-1 has publish on tenant factory-1
```

The risky form may be allowed only if capability assignment guardrails permit it. By default, guardrails should prevent devices from receiving broad tenant-level administration capabilities such as `manage`, `write`, or `delete`.

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

For devices, services, workloads, applications, groups, resources, roles, policies, and audit logs, `tenant_id` should represent tenant ownership or boundary.

Examples:

```text
sensor-1 belongs to factory-1
channel-1 belongs to factory-1
role operator belongs to factory-1
group floor-sensors belongs to factory-1
```

This direct `tenant_id` model keeps tenant filtering, uniqueness, lifecycle enforcement, and authorization checks simple.

Human users are different because a single person may participate in many tenants. Human users are global by default:

```text
alice@example.com
kind = human
tenant_id = null
```

Alice can administer or access one or more tenants through policy bindings without becoming tenant-scoped:

```text
Alice has tenant-admin on factory-1
Alice has tenant-viewer on factory-2
```

The MVP should not duplicate the same human as separate tenant-local entities by default. Duplicating humans creates login ambiguity, split audit history, duplicate credentials, and confusing policy behavior.

If an application needs tenant-local human profile, invitation, or membership status later, Atom should add a dedicated tenant membership model for humans rather than replacing `tenant_id` everywhere.

Future tenant membership shape:

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

This table should be used for human participation, tenant-local profile, tenant-local status, and invitation lifecycle. It should not replace direct `tenant_id` ownership for devices, resources, groups, roles, policies, or audit logs.

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

Entity subtypes are not separate protected object kinds. Atom should use `object_kind = "entity"` plus an entity-kind filter when a policy or authorization check targets humans, devices, services, workloads, or applications.

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

Certificate credentials are schema-supported but behavior-deferred for now. The MVP should not build full certificate issuance, verification, rotation, or mTLS identity flows. Full certificate credentials remain a future extension.

### Session and JWT

Login creates a session and returns a JWT. JWTs identify the entity and session. JWTs may include tenant context, but must not carry permissions.

### Resource

A resource is an application object protected by authorization, such as a channel, device, workspace, secret, node, or any other object kind.

Resources have a kind, optional name, optional tenant, optional owner, and attributes.

### Group

A group is a named collection of entities. Policies can bind to groups, and group members inherit those policy bindings.

### Capability

A capability is an atomic permission such as:

- `read`
- `create`
- `write`
- `update`
- `delete`
- `publish`
- `subscribe`
- `execute`
- `manage`
- `list`
- `revoke`
- `rotate`
- `audit.read`
- `credential.manage`
- `policy.manage`
- `role.manage`
- `tenant.manage`

A capability may apply globally or to one resource kind.

Capabilities are not limited to the list above. The seeded set should cover common platform, tenant administration, and runtime use cases. Product-specific capabilities may be added by platform administrators.

Recommended capability groups:

| Group | Capabilities | Purpose |
|---|---|---|
| General object access | `read`, `list`, `create`, `write`, `update`, `delete`, `manage` | Administrative CRUD and object management |
| Messaging/runtime | `publish`, `subscribe`, `execute` | Device, workload, and service runtime operations |
| Credentials and keys | `credential.manage`, `revoke`, `rotate` | Credential lifecycle and key rotation |
| Access control | `policy.manage`, `role.manage` | Policy and role administration |
| Tenant administration | `tenant.manage`, `manage` | Tenant lifecycle and tenant-scoped administration |
| Audit | `audit.read` | Audit log access |

Devices should normally receive only runtime-oriented capabilities such as `publish`, `subscribe`, and limited `read` for configuration or state. Devices should not receive administrative capabilities such as `manage`, `create`, `write`, `update`, or `delete` by default.

### Role

A role is a named bundle of capabilities, optionally scoped to a tenant.

### Policy Binding

A policy binding grants or denies a capability or role to an entity or group over a scope.

Policy fields:

- `tenant_id`: tenant that owns the policy binding, or `null` for global platform policy
- `subject_kind`: `entity` or `group`
- `subject_id`: entity or group UUID
- `grant_kind`: `capability` or `role`
- `grant_id`: capability or role UUID
- `scope_kind`: `all`, `tenant`, `object_kind`, `object_type`, or `object`
- `scope_ref`: tenant UUID, object kind, object type, or object UUID when needed
- `effect`: `allow` or `deny`
- `conditions`: flat JSON object of ABAC dot-path conditions

Policy bindings should store `tenant_id` directly. Inferring tenant ownership from subject, role, resource scope, or conditions is too ambiguous for tenant administration, query APIs, guardrails, and audit.

Rules:

- `tenant_id = null` means platform/global policy.
- `tenant_id = <tenant>` means tenant-owned policy.
- tenant admins can manage policies only for their tenant.
- global/platform policies require platform-level permission.
- a tenant-owned policy must not grant access outside its tenant unless explicitly allowed by platform policy.

Policy scope meanings:

| Scope kind | Meaning | Example |
|---|---|---|
| `all` | Applies to every protected object in the policy boundary | platform admin over all objects |
| `tenant` | Applies to one tenant and, through tenant inheritance, tenant-scoped objects | manage tenant `factory-1` |
| `object_kind` | Applies to all objects of a kind in the policy boundary | manage all entities in tenant A |
| `object_type` | Applies to a subtype of an object kind | manage all `entity:device` objects in tenant A |
| `object` | Applies to one specific object ID | manage one device entity |

For entity subtypes, `object_type` should use the format:

```text
entity:human
entity:device
entity:service
entity:workload
entity:application
```

Examples:

```text
manage all entities in tenant A
scope_kind = object_kind
scope_ref = entity
tenant_id = tenant A
```

```text
manage all devices in tenant A
scope_kind = object_type
scope_ref = entity:device
tenant_id = tenant A
```

```text
manage one specific device
scope_kind = object
scope_ref = <device entity UUID>
```

### ABAC Conditions

Policy bindings may include `conditions`. Conditions are a flat JSON object where keys are dot-paths and values must match exactly. All conditions must match for the policy binding to apply.

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
Apply this policy only when a human from operations is acting on a device at plant-a, inside an active tenant, after MFA verification.
```

Top-level fields and attributes are both required. Top-level fields provide stable system facts such as kind, tenant, status, and object type. Attributes provide application-specific facts such as department, region, tags, site, plan, or Magistrala metadata.

### Capability Assignment Guardrails

Capabilities are generic. Entity kind describes what the subject is, but entity kind should not directly grant permissions.

Runtime authorization answers:

```text
Can subject X do action Y on object Z?
```

Capability assignment guardrails answer a different question:

```text
Is it safe to create this policy, role binding, role capability, or group membership?
```

This prevents unsafe access from being created accidentally.

Example:

- A `device` should usually be allowed to `publish` to a `channel`.
- A `device` should usually not be allowed to `create`, `write`, `delete`, or `manage` a `channel`.
- A `human` or trusted `service` may be allowed to manage tenant resources if a policy grants it.
- A tenant may define stricter local rules, but platform-level absolute denies cannot be overridden by a tenant.

The PDP stays generic and policy-based. Guardrails run when access is assigned or changed.

Guardrails should be evaluated when:

- creating a policy binding;
- binding a role to an entity;
- binding a role to a group;
- adding a capability to a role;
- adding an entity to a group that already has policies;
- creating tenant-scoped admin roles during tenant creation.

Direct grants, role grants, and group grants must all be validated. Otherwise an unsafe grant can be hidden inside a role or inherited through a group.

Recommended storage:

```sql
capability_assignment_rules (
  id              uuid primary key,
  tenant_id       uuid null,
  entity_kind     text not null,
  capability_name text not null,
  object_kind     text not null,
  resource_kind   text null,
  decision        text not null check (decision in ('allow', 'deny', 'require_override')),
  is_absolute     boolean not null default false,
  created_at      timestamptz not null default now()
)
```

Field meaning:

- `tenant_id = null` means the rule is a global default.
- `tenant_id = <tenant>` means the rule applies only inside that tenant.
- `entity_kind` is the kind of the subject receiving access.
- `capability_name` is the action being granted.
- `object_kind` is the protected object type, such as `resource`, `entity`, `group`, `tenant`, `role`, `policy`, `credential`, or `audit_log`.
- `resource_kind` narrows the rule for resources, such as `channel`.
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

| Entity kind | Capability | Object kind | Resource kind | Decision |
|---|---|---|---|---|
| `device` | `publish` | `resource` | `channel` | `allow` |
| `device` | `subscribe` | `resource` | `channel` | `allow` |
| `device` | `manage` | `resource` | `channel` | `deny` |
| `device` | `delete` | `resource` | `channel` | `deny` |
| `human` | `manage` | `resource` | `channel` | `allow` |
| `service` | `manage` | `resource` | `channel` | `allow` |

Example tenant-specific rule:

| Tenant | Entity kind | Capability | Object kind | Resource kind | Decision |
|---|---|---|---|---|---|
| `factory-1` | `device` | `read` | `resource` | `device_config` | `allow` |

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

Example rejected policy:

```json
{
  "subject_kind": "entity",
  "subject_id": "device-id",
  "grant_kind": "capability",
  "grant_id": "delete-channel-capability-id",
  "scope_kind": "resource_kind",
  "scope_ref": "channel"
}
```

Response:

```json
{
  "error": "capability_not_allowed_for_entity_kind",
  "message": "device entities cannot be granted delete on resource kind channel by default"
}
```

Example role validation:

- Role `channel-admin` contains `delete` on `channel`.
- A policy tries to bind `channel-admin` to a `device`.
- Atom expands the role capabilities during assignment validation.
- The assignment is rejected because `device + delete + resource:channel` is denied.

Example group validation:

- Group `floor-sensors` has a policy that grants `publish` to channels.
- Adding a `device` to `floor-sensors` is allowed.
- If the group later receives `delete` on channels, Atom must validate all current group members and reject the policy if devices would inherit a denied capability.
- If a group already has `delete` on channels, adding a `device` to that group must be rejected.

MVP recommendation:

- Add the `capability_assignment_rules` table.
- Seed global default rules for common entity kinds and common capabilities.
- Support optional tenant-specific rules.
- Allow tenant admins to create stricter tenant-specific deny rules.
- Validate policy creation, role binding, role capability changes, and group membership changes.
- Make deny beat allow.
- Make absolute global deny impossible to override.
- Audit every rejected assignment and every override.
- Keep the PDP unchanged: guardrails prevent unsafe policies from being created, while `/authz/check` continues to evaluate existing policies.

---

## Functional Requirements

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
| ID-8 | Human users must be global by default, with tenant access granted through policies. | Must |
| ID-9 | The MVP must not require duplicate tenant-local human entities for the same person. | Must |
| ID-10 | A future tenant membership model should be used for human tenant participation, tenant-local profile, tenant-local status, and invitations if needed. | Should |

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
| AUTH-10 | Tenant admins must not manage credentials for global human users or platform admins unless separately allowed by platform policy. | Must |
| AUTH-11 | Certificate credentials should remain schema-supported but behavior-deferred for now. | Should |

### Tenants

| ID | Requirement | Priority |
|---|---|---|
| TEN-1 | The system must expose first-class tenant CRUD and lifecycle APIs. | Must |
| TEN-2 | Tenant lifecycle must support active, inactive, frozen, and deleted states. | Must |
| TEN-3 | Tenant deletion must be soft delete by setting status to `deleted`. | Must |
| TEN-4 | Tenant create, update, and lifecycle changes must require global manage permission. | Must |
| TEN-5 | Entities, groups, resources, and roles must be able to reference tenants by `tenant_id`. | Must |
| TEN-6 | Magistrala domains must map directly to Atom tenants. | Must |
| TEN-7 | Authorization checks must support tenant objects through `object_kind = "tenant"` and `object_id`. | Must |
| TEN-8 | Tenant policy inheritance must allow tenant capabilities to apply to objects whose `tenant_id` matches the tenant. | Must |
| TEN-9 | For MVP, `manage` on a tenant must grant administration over normal tenant-scoped objects, while sensitive operations use explicit capabilities. | Must |
| TEN-10 | Tenant policy inheritance must not apply to other tenants or global platform objects where `tenant_id = null`. | Must |
| TEN-11 | Device and workload runtime access should normally use explicit resource, resource-kind, role, or group policies rather than broad tenant inheritance. | Should |
| TEN-12 | Atom must create a tenant-scoped `tenant-admin` role for every new tenant. | Must |
| TEN-13 | The tenant creator must receive the generated `tenant-admin` role. | Must |
| TEN-14 | Authorization checks for inactive, frozen, or deleted tenants must be denied with a reason that includes tenant state. | Must |
| TEN-15 | Atom should support a future tenant membership model for applications that require tenant-local human profile or membership state, while keeping global humans as the default MVP model. | Should |
| TEN-16 | The generated `tenant-admin` role must include `manage`, `audit.read`, `credential.manage`, `policy.manage`, and `role.manage` for the tenant. | Must |

### Authorization

| ID | Requirement | Priority |
|---|---|---|
| AZ-1 | The system must expose `POST /authz/check` for runtime authorization decisions. | Must |
| AZ-2 | The system must support resource checks by `resource_id`. | Must |
| AZ-3 | The system must support protected object checks by `object_kind` and `object_id`. | Must |
| AZ-4 | The PDP must load the subject and require it to be active. | Must |
| AZ-5 | The PDP must resolve the requested capability by action and protected object kind. | Must |
| AZ-6 | The PDP must evaluate direct entity policy bindings. | Must |
| AZ-7 | The PDP must evaluate group policy bindings inherited through membership. | Must |
| AZ-8 | The PDP must support role grants by resolving role capabilities. | Must |
| AZ-9 | The PDP must batch-load role capabilities before evaluating policy bindings. | Must |
| AZ-10 | The PDP must support scopes `all`, `tenant`, `object_kind`, `object_type`, and `object`. | Must |
| AZ-11 | The PDP must support ABAC conditions against top-level fields, attributes, and request context. | Must |
| AZ-12 | A matching deny must override any allow. | Must |
| AZ-13 | No matching allow must return denied. | Must |
| AZ-14 | The system must expose `POST /authz/check/bulk` for checking multiple decisions in one request. | Should |
| AZ-15 | The system must expose gRPC authorization check APIs for runtime integrations. gRPC is runtime-only for now; management APIs remain HTTP-only. Management APIs may be added to gRPC later if needed. | Should |
| AZ-16 | Authorization checks must evaluate tenant lifecycle state for tenant-scoped objects. | Must |
| AZ-17 | Entity subtypes must be represented as `object_kind = entity` with an entity-kind/object-type filter, not as separate protected object kinds. | Must |
| AZ-18 | Policy scopes must support `all`, `tenant`, `object_kind`, `object_type`, and `object`. | Must |
| AZ-19 | Entity subtype policy scopes must use object type values such as `entity:device` and `entity:human`. | Must |
| AZ-20 | ABAC conditions must support top-level fields such as `entity.kind`, `entity.tenant_id`, `tenant.status`, `object.kind`, and `object.type`. | Must |
| AZ-21 | ABAC conditions must support JSON attributes such as `entity.attributes.*`, `resource.attributes.*`, `tenant.attributes.*`, and `object.attributes.*`. | Must |
| AZ-22 | ABAC conditions must support request context fields such as `context.ip`, `context.client_id`, and `context.mfa_verified`. | Must |

### Access Management

| ID | Requirement | Priority |
|---|---|---|
| AM-1 | The system must create, list, read, and delete roles. | Must |
| AM-2 | The system must add and remove capabilities on roles. | Must |
| AM-3 | The system must create, list, read, and delete capabilities. | Must |
| AM-4 | Capability and policy mutation must require manage permission. | Must |
| AM-5 | The system must create, list, read, and delete policy bindings. | Must |
| AM-6 | The system must create and delete groups. | Must |
| AM-7 | The system must add, list, and remove group members. | Must |
| AM-8 | The system must support ownership relationships between entities. | Should |
| AM-9 | Policy bindings must store `tenant_id` directly, with `null` reserved for platform/global policies. | Must |
| AM-10 | Tenant admins must be able to manage policy bindings owned by their tenant. | Must |
| AM-11 | Tenant-owned policies must not grant access outside their tenant unless separately allowed by platform policy. | Must |

### Capability Assignment Guardrails

| ID | Requirement | Priority |
|---|---|---|
| GR-1 | The system must support capability assignment rules that define which entity kinds may receive which capabilities for which object/resource kinds. | Must |
| GR-2 | The system must support global guardrail rules with `tenant_id = null`. | Must |
| GR-3 | The system must support tenant-specific guardrail rules. | Should |
| GR-4 | The system must support absolute global denies that tenant-specific rules cannot override. | Must |
| GR-5 | The system must validate direct capability grants before creating policy bindings. | Must |
| GR-6 | The system must validate role grants by expanding role capabilities before creating policy bindings. | Must |
| GR-7 | The system must validate role capability changes against existing role holders. | Must |
| GR-8 | The system must validate group policy changes against existing group members. | Must |
| GR-9 | The system must validate group membership changes against policies the new member would inherit. | Must |
| GR-10 | The system should support `require_override` for assignments that are risky but platform-admin approved. | Should |
| GR-11 | The system must audit rejected assignments and override-based assignments. | Must |
| GR-12 | Guardrails must not replace PDP evaluation; they prevent unsafe policy state from being created. | Must |
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
| QRY-6 | The system should list what access a group grants. | Should |
| QRY-7 | The system should list an entity's effective capabilities. | Should |
| QRY-8 | The system should report orphaned policies. | Should |
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
| MAG-5 | Client-channel publish and subscribe permissions must be expressible as Atom policy bindings. | Must |
| MAG-6 | Magistrala metadata must be stored under `attributes.magistrala`. | Must |
| MAG-7 | Magistrala runtime access checks must call Atom instead of maintaining a separate authorization database. | Must |

---

## API Scope

Atom must expose these API categories:

- Health: service health check.
- Authentication: login, logout, session read, JWKS, signing key rotation.
- Entities: entity CRUD and entity group membership views.
- Credentials: password creation, API key creation, credential listing, credential revocation.
- Tenants: tenant CRUD and lifecycle transitions.
- Groups: group CRUD and membership management.
- Ownerships: entity-to-entity parent/child relations.
- Resources: protected object CRUD.
- Roles: role CRUD and role-capability membership.
- Capabilities: capability CRUD.
- Policies: policy binding CRUD.
- Authorization: single check, bulk check, explain.
- Query endpoints: entity access, resource access, group access, role holders, effective capabilities.
- Audit: audit log listing.
- Admin hygiene: orphan policies, unprotected resources, expiring credentials.
- gRPC: runtime authorization-oriented service interface only for now; management APIs remain HTTP-only unless added later.

Detailed endpoint requirements are maintained in the linked product docs:

1. [Query and search endpoint overview](./00-overview.md)
2. [POST /authz/explain](./01-authz-explain.md)
3. [GET /entities/:id/access](./02-entity-access.md)
4. [GET /resources/:id/access](./03-resource-access.md)
5. [GET /audit](./04-audit.md)
6. [POST /authz/check/bulk](./05-bulk-check.md)
7. [GET /roles/:id/holders](./06-role-holders.md)
8. [GET /groups/:id/access](./07-group-access.md)
9. [GET /entities/:id/effective-capabilities](./08-effective-capabilities.md)
10. [Admin hygiene endpoints](./09-admin-hygiene.md)
11. [Building Magistrala on Atom](./10-magistrala-on-atom.md)

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
- Management endpoints must require a manage-capable caller.
- Authorization must be denied by default.
- API keys must not be recoverable after creation.

### Reliability

- Audit failures must not fail authentication or authorization flows.
- Database `RowNotFound` errors must map to not found responses.
- Unique constraint violations must map to conflict responses.
- Tenant foreign key violations must return a clear bad request or conflict-style error.

### Performance

- Authorization checks must avoid per-policy role capability queries.
- Role capabilities must be batch-loaded for authorization evaluation.
- API key authentication must avoid full credential-table scans by using the embedded credential ID.
- List endpoints must support pagination.

### Compatibility

- Existing `resource_id` authorization checks must remain supported.
- New `object_kind` and `object_id` authorization checks must not break the legacy shape.
- HTTP and gRPC authorization semantics must match.

---

## Success Metrics

Atom is successful when:

- Magistrala can model domains, users, clients, channels, groups, and permissions without a separate auth database.
- Runtime services can answer authorization decisions through Atom with deterministic deny-by-default behavior.
- Operators can answer "why denied?", "who can access this?", and "what can this entity access?" without direct SQL.
- Credential creation, revocation, and audit inspection can be done through APIs.
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
- Capabilities
- Roles
- Policies
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
- Group access endpoint
- Effective capabilities endpoint
- Admin hygiene endpoints

### Phase 3: Tenant and Magistrala alignment

- First-class tenant table and lifecycle endpoints
- Tenant foreign keys from scoped objects
- Tenant admin role bootstrap on tenant creation
- Tenant creator receives the generated `tenant-admin` role
- `tenant_id` on policy bindings
- `tenant_id` on audit logs
- Tenant lifecycle enforcement in authorization checks
- Object-based authorization checks for tenants
- Magistrala domain-to-tenant mapping
- Magistrala integration guide
- HTTP/OpenAPI and gRPC contract updates

### Phase 4: Capability assignment guardrails

- `capability_assignment_rules` table
- Global default assignment rules
- Tenant-specific assignment rules
- Absolute global deny support
- Validation during policy creation
- Validation during role binding and role capability updates
- Validation during group membership changes
- Rejected-assignment and override audit logs

### Phase 5: Future extensions

- SCIM provisioning
- OIDC federation
- Workload identity with SPIFFE or X.509
- Full certificate credential lifecycle
- Tenant memberships for human tenant participation and local profile/status
- Token introspection
- Audit webhooks
- Prometheus metrics
- Rate limiting

---

## Open Questions

No open product questions remain in this PRD draft. Future implementation work may still uncover API or schema details that need separate design notes.

---

## References

- [README](../README.md)
- [Technical spec](../spec.md)
- [OpenAPI spec](../apidocs/openapi.yaml)
- [gRPC reference](../apidocs/grpc-reference.md)
- [Magistrala integration](./10-magistrala-on-atom.md)
