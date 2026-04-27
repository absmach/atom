# Atom Product Requirements Document

## Status: Draft
## Date: 2026-04-27

---

## Summary

Atom is a lightweight identity, authentication, authorization, tenant, and audit service for Magistrala and other cloud-native or edge systems.

It replaces a large external identity provider such as Keycloak with a single Rust binary backed by one PostgreSQL database. Atom treats every principal as an `entity`, protects every application object through online authorization checks, and keeps authorization decisions inspectable through query and audit APIs.

The product direction is:

- Atom owns generic security primitives: identities, credentials, sessions, tenants, groups, roles, capabilities, policies, authorization decisions, and audit logs.
- Applications such as Magistrala store product-specific metadata in `attributes`.
- Runtime services call Atom for every authorization decision instead of embedding permissions in tokens.
- Operators use Atom's query APIs to understand access, debug denials, and keep the policy graph clean.

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

### Entity

An entity is any principal that can authenticate or be authorized.

Kinds:

- `human`
- `device`
- `service`
- `workload`
- `application`

An entity has a name, optional tenant, status, and JSON attributes. Human users may be global identities with `tenant_id = null`; their tenant access comes from policy bindings.

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
- `write`
- `delete`
- `publish`
- `subscribe`
- `execute`
- `manage`

A capability may apply globally or to one resource kind.

### Role

A role is a named bundle of capabilities, optionally scoped to a tenant.

### Policy Binding

A policy binding grants or denies a capability or role to an entity or group over a scope.

Policy fields:

- `subject_kind`: `entity` or `group`
- `subject_id`: entity or group UUID
- `grant_kind`: `capability` or `role`
- `grant_id`: capability or role UUID
- `scope_kind`: `all`, `resource_kind`, or `resource`
- `scope_ref`: resource kind or resource UUID when needed
- `effect`: `allow` or `deny`
- `conditions`: flat JSON object of ABAC dot-path conditions

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
| AZ-10 | The PDP must support scopes `all`, `resource_kind`, and `resource`. | Must |
| AZ-11 | The PDP must support ABAC conditions against entity attributes, resource or object attributes, and request context. | Must |
| AZ-12 | A matching deny must override any allow. | Must |
| AZ-13 | No matching allow must return denied. | Must |
| AZ-14 | The system must expose `POST /authz/check/bulk` for checking multiple decisions in one request. | Should |
| AZ-15 | The system must expose gRPC authorization check APIs for runtime integrations. | Should |

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

| ID | Requirement | Priority |
|---|---|---|
| AUD-1 | The system must write audit logs for login decisions. | Must |
| AUD-2 | The system must write audit logs for logout and credential operations. | Must |
| AUD-3 | The system must write audit logs for authorization checks and explain calls. | Must |
| AUD-4 | Audit writes must never block or fail the caller's operation. | Must |
| AUD-5 | Audit entries must include event, outcome, entity, details, and timestamp. | Must |

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
- gRPC: runtime authorization-oriented service interface.

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
- Object-based authorization checks for tenants
- Magistrala domain-to-tenant mapping
- Magistrala integration guide
- HTTP/OpenAPI and gRPC contract updates

### Phase 4: Future extensions

- SCIM provisioning
- OIDC federation
- Workload identity with SPIFFE or X.509
- Token introspection
- Audit webhooks
- Prometheus metrics
- Rate limiting

---

## Open Questions

1. Should inactive or frozen tenants block authorization checks for resources inside that tenant, or should applications enforce tenant lifecycle separately?
2. Should ABAC evaluation expose top-level fields such as `entity.tenant_id`, `resource.tenant_id`, and `tenant.status` as first-class condition paths?
3. Should policy bindings get a direct `tenant_id` column for faster tenant-scoped administration, or is scope plus resource tenant filtering sufficient?
4. Should gRPC eventually expose the same management APIs as HTTP, or remain focused on runtime checks?
5. Should certificate credentials become first-class in the next milestone, or remain schema-supported but behavior-deferred?

---

## References

- [README](../README.md)
- [Technical spec](../spec.md)
- [OpenAPI spec](../apidocs/openapi.yaml)
- [gRPC reference](../apidocs/grpc-reference.md)
- [Magistrala integration](./10-magistrala-on-atom.md)
