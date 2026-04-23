# Atom

Simple Identity and Authorization service — a lightweight alternative to Keycloak, written in Rust.

Built for [Magistrala](https://github.com/absmach/magistrala) IoT platform, but generic enough for any cloud-native or edge system.

**License:** Apache-2.0

---

## What it does

- **Identity** — CRUD for any principal type: humans, devices, services, workloads, applications. All are first-class *entities*; no special user class.
- **Authentication** — password login (JWT), long-lived API keys, session management.
- **Authorization** — policy-based decision engine (PDP) supporting RBAC, ABAC, and hybrid.
- **Grouping** — entities belong to groups; policies apply to groups.
- **Ownership** — parent/child relationships between entities.
- **Multi-tenancy** — all resources are tenant-scoped.

---

## Quick start

```bash
# 1. Copy and edit config
cp .env.example .env
# set a real JWT_SECRET (32+ random chars)

# 2. Start Postgres
docker-compose up postgres -d

# 3. Run (migrations apply automatically on startup)
cargo run

# or with Docker
docker-compose up
```

The service starts on `http://localhost:8080`.

---

## Configuration

| Variable         | Default                                    | Description                     |
|------------------|--------------------------------------------|---------------------------------|
| `DATABASE_URL`   | *(required)*                               | Postgres connection string      |
| `LISTEN_ADDR`    | `0.0.0.0:8080`                             | Bind address                    |
| `JWT_SECRET`     | *(required)*                               | HS256 signing secret (32+ chars)|
| `JWT_EXPIRY_SECS`| `3600`                                     | JWT lifetime in seconds         |
| `RUST_LOG`       | `info`                                     | Log level filter                |

---

## Authentication

All endpoints except `GET /health` and `POST /auth/login` require:

```
Authorization: Bearer <token>
```

Two token types are accepted:

**JWT** — returned by `/auth/login`, short-lived (default 1 hour):
```bash
curl -s -X POST http://localhost:8080/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"identifier": "alice", "secret": "s3cr3t"}'
# → {"token":"eyJ...", "entity_id":"...", "session_id":"...", "expires_at":"..."}
```

**API key** — created per entity, long-lived, format `atom_<id>_<secret>`:
```bash
curl -s -X POST http://localhost:8080/entities/<id>/credentials/api-keys \
  -H 'Authorization: Bearer eyJ...' \
  -H 'Content-Type: application/json' \
  -d '{"description": "device-01 production key"}'
# → {"credential_id":"...", "key":"atom_abc123...", "expires_at":null}
# The key is shown exactly once — store it securely.

# Use it:
curl http://localhost:8080/entities/<id> \
  -H 'Authorization: Bearer atom_abc123...'
```

---

## RBAC

Role-Based Access Control is the primary authorization model. Roles bundle capabilities and are assigned to entities or groups.

### Example: device that can publish to channels

```bash
# 1. List seeded capabilities to find "publish"
curl http://localhost:8080/capabilities -H "Authorization: Bearer $TOKEN"

# 2. Create a role
ROLE=$(curl -s -X POST http://localhost:8080/roles \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name": "channel-publisher"}' | jq -r .id)

# 3. Add the "publish" capability to the role
curl -s -X POST http://localhost:8080/roles/$ROLE/capabilities \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d "{\"capability_id\": \"$PUBLISH_CAP_ID\"}"

# 4. Bind the role to a device, scoped to all resources of kind "channel"
curl -s -X POST http://localhost:8080/policies \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d "{
    \"subject_kind\": \"entity\",
    \"subject_id\":   \"$DEVICE_ID\",
    \"grant_kind\":   \"role\",
    \"grant_id\":     \"$ROLE\",
    \"scope_kind\":   \"resource_kind\",
    \"scope_ref\":    \"channel\",
    \"effect\":       \"allow\"
  }"

# 5. Check authorization
curl -s -X POST http://localhost:8080/authz/check \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d "{
    \"subject_id\":  \"$DEVICE_ID\",
    \"action\":      \"publish\",
    \"resource_id\": \"$CHANNEL_ID\"
  }"
# → {"allowed": true, "reason": "allowed"}
```

### Group-based RBAC

```bash
# Create a group and assign the role to it
curl -X POST http://localhost:8080/groups \
  -d '{"name": "floor-sensors", "tenant_id": "..."}'

# Add devices to the group
curl -X POST http://localhost:8080/groups/$GROUP_ID/members \
  -d "{\"entity_id\": \"$DEVICE_ID\"}"

# Bind the role to the group (all group members inherit it)
curl -X POST http://localhost:8080/policies \
  -d "{\"subject_kind\": \"group\", \"subject_id\": \"$GROUP_ID\", ...}"
```

---

## ABAC

Attribute-Based Access Control uses `conditions` on a policy binding. Conditions are a flat JSON object where keys are dot-paths into the evaluation context and values must match exactly (AND logic).

The evaluation context is:
```json
{
  "entity":   { "attributes": { ...entity.attributes... } },
  "resource": { "attributes": { ...resource.attributes... } },
  "context":  { ...extra fields from the check request... }
}
```

### Example: only allow access to resources tagged `env=prod` from trusted IPs

```bash
# Policy binding with conditions
curl -X POST http://localhost:8080/policies \
  -d '{
    "subject_kind": "entity",
    "subject_id":   "<svc-id>",
    "grant_kind":   "capability",
    "grant_id":     "<read-cap-id>",
    "scope_kind":   "resource_kind",
    "scope_ref":    "secret",
    "effect":       "allow",
    "conditions": {
      "resource.attributes.env":  "prod",
      "context.ip_trusted":       "true"
    }
  }'

# Check — must pass context fields to satisfy conditions
curl -X POST http://localhost:8080/authz/check \
  -d '{
    "subject_id":  "<svc-id>",
    "action":      "read",
    "resource_id": "<secret-id>",
    "context": {
      "ip_trusted": "true"
    }
  }'
```

### RBAC + ABAC hybrid

Conditions can be layered on any policy binding, including role-based ones. A binding is only considered if all conditions match.

---

## Authorization Rules

- **DENY overrides ALLOW** — an explicit deny binding wins regardless of allow bindings.
- **Default DENY** — no matching allow policy means denied.
- **Group inheritance** — bindings on a group apply to all group members.
- **Scope** — policies can apply to `all` resources, a specific resource `kind`, or a single `resource` by ID.

---

## API Reference

### Health
```
GET  /health
```

### Auth
```
POST /auth/login                           {identifier, secret, kind?}
POST /auth/logout
GET  /auth/sessions/:id
```

### Entities
```
POST   /entities                           {kind, name, tenant_id?, attributes?}
GET    /entities?kind=&tenant_id=&status=&limit=&offset=
GET    /entities/:id
PUT    /entities/:id                       {name?, status?, attributes?}
DELETE /entities/:id
```

Entity `kind` values: `human | device | service | workload | application`

### Credentials
```
POST   /entities/:id/credentials/password    {password}
POST   /entities/:id/credentials/api-keys    {expires_at?, description?}
GET    /entities/:id/credentials
DELETE /entities/:entity_id/credentials/:cred_id
```

### Groups & Membership
```
POST   /groups                             {name, tenant_id?, description?}
GET    /groups?tenant_id=&limit=&offset=
GET    /groups/:id
DELETE /groups/:id
POST   /groups/:id/members                 {entity_id}
GET    /groups/:id/members
DELETE /groups/:group_id/members/:entity_id
GET    /entities/:id/groups
```

### Ownerships
```
POST   /entities/:id/owned                 {owned_id, relation?}
GET    /entities/:id/owned
DELETE /entities/:owner_id/owned/:owned_id
```

### Resources
```
POST   /resources                          {kind, name?, tenant_id?, owner_id?, attributes?}
GET    /resources?kind=&tenant_id=&limit=&offset=
GET    /resources/:id
PUT    /resources/:id                      {name?, attributes?}
DELETE /resources/:id
```

### Roles
```
POST   /roles                              {name, tenant_id?, description?}
GET    /roles?tenant_id=&limit=&offset=
GET    /roles/:id
DELETE /roles/:id
POST   /roles/:id/capabilities             {capability_id}
GET    /roles/:id/capabilities
DELETE /roles/:role_id/capabilities/:cap_id
```

### Capabilities
```
POST   /capabilities                       {name, resource_kind?, description?}
GET    /capabilities?resource_kind=
GET    /capabilities/:id
DELETE /capabilities/:id
```

Seeded defaults (apply to all resource kinds): `read, write, delete, publish, subscribe, execute, manage`

### Policy Bindings
```
POST   /policies                           {subject_kind, subject_id, grant_kind, grant_id, scope_kind, scope_ref?, effect?, conditions?}
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
  "context":     {}
}
→ {"allowed": true, "reason": "allowed"}
```

---

## Data Model Summary

```
Entity ─── has many ─── Credentials (password, api_key, certificate)
Entity ─── has many ─── Sessions
Entity ─── member of ── Groups
Entity ─── owns ──────── Entities (via Ownerships)

PolicyBinding ─── subject: Entity | Group
              ─── grant:   Capability | Role
              ─── scope:   all | resource_kind | resource
              ─── effect:  allow | deny
              ─── conditions: ABAC dot-path map

Role ─── has many ─── Capabilities
```

---

## Development

```bash
# Check
cargo check

# Build
cargo build

# Run with live reload
cargo watch -x run

# Run Postgres only
docker-compose up postgres -d
```

Migrations run automatically on startup via `sqlx::migrate!`. To add a migration, create `migrations/002_<name>.sql`.

---

## Roadmap

- [ ] SCIM provisioning endpoint
- [ ] OIDC federation (external IdP)
- [ ] Workload identity (SPIFFE / X.509)
- [ ] Audit log webhooks
- [ ] Token introspection endpoint
- [ ] Rate limiting
- [ ] Metrics (Prometheus)
