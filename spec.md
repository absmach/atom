# ATOM — Identity & Authorization Service

**Version:** 0.1  
**License:** Apache-2.0  
**Language:** Rust (Axum + PostgreSQL)  

---

## Purpose

Atom is a unified Identity + Authorization service for IoT and cloud-native systems — the auth layer for Magistrala and similar platforms.

It replaces Keycloak with a minimal, fast, single-binary service that is simple to deploy and operate.

---

## Design Principles

1. **Entity-first** — everything is an entity (human, device, service, workload, application). No special user class.
2. **Online authorization** — tokens carry no permissions; all decisions evaluated at runtime.
3. **Deny-by-default** — explicit DENY overrides any ALLOW; no matching policy → deny.
4. **Single binary** — one deployable service, one Postgres database.
5. **UUID everywhere** — primary keys are UUIDs.
6. **JSONB attributes** — flexible schemaless attributes on entities and resources, usable in ABAC conditions.

---

## Architecture

```
Atom
├── Identity Module    — entities, credentials, sessions, groups, ownerships
├── Authorization Module — resources, roles, capabilities, policy bindings, PDP engine
└── Audit Module       — immutable event log (table, hooks not yet wired)
```

---

## Core Concepts

### Entity
Any principal: `human | device | service | workload | application`.  
Has a `kind`, a `name` (unique per tenant), arbitrary `attributes` (JSONB), and a `status`.

### Credential
Attached to an entity. Kinds: `password | api_key | certificate`.  
- Password: argon2-hashed, looked up by entity name.  
- API key: format `atom_<32-hex-cred-id>_<64-hex-secret>`. ID-embedded for O(1) lookup. Secret is argon2-hashed. Only shown once on creation.

### Session
Created on login. Referenced by JWT (`sub=entity_id, sid=session_id`). Can be revoked.

### Group
Named collection of entities, scoped per tenant. Used as policy subjects.

### Ownership
Parent-child relation between entities (`owner_id → owned_id`). Supports any `relation` type string.

### Resource
Anything protected by authorization: channel, device, workspace, secret, node, etc.  
Has a `kind`, optional `name`, `tenant_id`, `owner_id`, and JSONB `attributes`.

### Capability
Atomic permission, optionally scoped to a resource kind.  
Seeded defaults: `read, write, delete, publish, subscribe, execute, manage`.

### Role
Named bundle of capabilities, scoped per tenant.

### Policy Binding
Grants (or denies) a capability or role to a subject (entity or group) over a resource scope.

| Field          | Values                              |
|----------------|-------------------------------------|
| `subject_kind` | `entity` \| `group`                 |
| `grant_kind`   | `capability` \| `role`              |
| `scope_kind`   | `all` \| `resource_kind` \| `resource` |
| `scope_ref`    | kind name or resource UUID (text)   |
| `effect`       | `allow` \| `deny`                   |
| `conditions`   | JSONB dot-path ABAC conditions      |

---

## Authorization Flow (PDP)

```
POST /authz/check  {subject_id, action, resource_id, context?}
```

1. Load entity (check active)
2. Load resource (check exists)
3. Find capability by action name (matched against resource kind)
4. Load all policy bindings for entity (direct + via group membership)
5. For each binding:
   - Check scope matches the resource
   - Check grant covers the capability (direct or via role)
   - Evaluate ABAC conditions against `{entity.attributes, resource.attributes, context}`
6. **DENY wins** — first matching deny returns immediately
7. If any allow matched → `allowed: true`
8. Otherwise → `allowed: false`

### ABAC Conditions

Conditions are a flat JSON object where keys are dot-paths into the evaluation context and values are the expected values. All entries must match (AND logic).

```json
{
  "entity.attributes.department": "engineering",
  "resource.attributes.env": "prod",
  "context.ip_trusted": "true"
}
```

The evaluation context is:
```json
{
  "entity":   { "attributes": { ... } },
  "resource": { "attributes": { ... } },
  "context":  { ... }          // from the check request
}
```

---

## Database Schema

### `entities`
```sql
id, kind, name, tenant_id, status, attributes (JSONB), created_at, updated_at
```

### `credentials`
```sql
id, entity_id→entities, kind, identifier, secret_hash, metadata (JSONB),
status, expires_at, created_at
```

### `sessions`
```sql
id, entity_id→entities, expires_at, revoked_at, created_at
```

### `groups`
```sql
id, name, tenant_id, description, created_at, updated_at
```

### `group_members`
```sql
(group_id, entity_id) PK
```

### `ownerships`
```sql
(owner_id, owned_id) PK, relation, created_at
```

### `resources`
```sql
id, kind, name, tenant_id, owner_id→entities, attributes (JSONB), created_at, updated_at
```

### `roles`
```sql
id, name, tenant_id, description, created_at
```

### `capabilities`
```sql
id, name, resource_kind (nullable), description
UNIQUE(name, resource_kind)
```

### `role_capabilities`
```sql
(role_id, capability_id) PK
```

### `policy_bindings`
```sql
id, subject_kind, subject_id, grant_kind, grant_id,
scope_kind, scope_ref, effect, conditions (JSONB), created_at
```

### `audit_logs`
```sql
id, entity_id→entities, event, outcome, details (JSONB), created_at
```

---

## API

### Auth
```
POST /auth/login                          {identifier, secret, kind?}  → {token, entity_id, session_id, expires_at}
POST /auth/logout
GET  /auth/sessions/:id
```

### Entities
```
POST   /entities
GET    /entities?kind=&tenant_id=&status=&limit=&offset=
GET    /entities/:id
PUT    /entities/:id
DELETE /entities/:id
```

### Credentials
```
POST   /entities/:id/credentials/password  {password}
POST   /entities/:id/credentials/api-keys  {expires_at?, description?}  → {credential_id, key (once!), expires_at}
GET    /entities/:id/credentials
DELETE /entities/:entity_id/credentials/:cred_id
```

### Groups
```
POST   /groups
GET    /groups?tenant_id=&limit=&offset=
GET    /groups/:id
DELETE /groups/:id
POST   /groups/:id/members        {entity_id}
GET    /groups/:id/members
DELETE /groups/:group_id/members/:entity_id
GET    /entities/:id/groups
```

### Ownerships
```
POST   /entities/:id/owned        {owned_id, relation?}
GET    /entities/:id/owned
DELETE /entities/:owner_id/owned/:owned_id
```

### Resources
```
POST   /resources
GET    /resources?kind=&tenant_id=&limit=&offset=
GET    /resources/:id
PUT    /resources/:id
DELETE /resources/:id
```

### Roles
```
POST   /roles
GET    /roles?tenant_id=&limit=&offset=
GET    /roles/:id
DELETE /roles/:id
POST   /roles/:id/capabilities    {capability_id}
GET    /roles/:id/capabilities
DELETE /roles/:role_id/capabilities/:cap_id
```

### Capabilities
```
POST   /capabilities
GET    /capabilities?resource_kind=
GET    /capabilities/:id
DELETE /capabilities/:id
```

### Policy Bindings
```
POST   /policies
GET    /policies?subject_id=&subject_kind=&limit=&offset=
GET    /policies/:id
DELETE /policies/:id
```

### Authorization Check
```
POST /authz/check
{
  "subject_id":  "uuid",
  "action":      "publish",
  "resource_id": "uuid",
  "context":     {}      // optional ABAC context
}
→ {"allowed": bool, "reason": "string"}
```

---

## Authentication

All endpoints except `GET /health` and `POST /auth/login` require:

```
Authorization: Bearer <token>
```

- **JWT** (short-lived, default 1h): returned by `/auth/login`
- **API key** (long-lived): format `atom_<...>` — passes `Authorization: Bearer atom_...`

---

## Multi-tenancy

- Entities, groups, resources, and roles all carry an optional `tenant_id`.
- Filtering by `tenant_id` is supported on all list endpoints.
- Cross-tenant access requires an explicit policy binding.

---

## Future
- SCIM provisioning
- External IdP (OIDC federation)
- Workload identity (SPIFFE/X.509)
- Audit log webhooks
- Token introspection endpoint
