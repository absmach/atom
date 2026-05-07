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
- **Multi-tenancy** — first-class tenants; entities, groups, resources, and roles can be scoped to a tenant. Magistrala domains map directly to Atom tenants.

---

## Quick start

```bash
# 1. Copy and edit config
cp .env.example .env
# set ADMIN_SECRET on first boot to create the admin password

# 2. Start Postgres
docker-compose up postgres -d

# 3. Run (migrations apply automatically on startup)
cargo run

# or with Docker (release image on :8080)
docker-compose up atom

# or with the dev image (debug build with GraphQL playground on :8081)
docker-compose --profile dev up atom-dev
```

The service starts on `http://localhost:8080`.

The release Docker image serves Atom on `http://localhost:8080`.

The dev Docker image serves Atom on `http://localhost:8081`; because it is built in debug mode, the GraphQL playground is available at `http://localhost:8081/graphql/playground`.

GraphQL is available at `POST /graphql` in both images. GraphQL uses the same Bearer token authentication as REST.

The dev playground is preloaded with helper tabs for:

- logging in via the REST `/auth/login` endpoint
- listing profiles
- creating an entity from a profile

It also seeds the HTTP headers editor with an `Authorization: Bearer ...` placeholder so you can paste a JWT or API key once and reuse it across tabs.

The initial GraphQL schema covers health, profiles, profile versions, entities, and profile-driven entity creation. REST remains the primary API for full administration.

Profiles keep Atom's internal runtime/authz kind separate from user/domain subtypes:

- `kind` is the internal Atom entity kind used by authorization (`human`, `device`, `service`, `workload`, `application`).
- `profile` is the user-customizable subtype/schema selector, such as `client`, `gateway`, or `water_meter`.
- `profileVersion` identifies the JSON Schema used to validate entity attributes. It is not used by authorization.

```graphql
query {
  profiles(objectKind: "entity", kind: "device") {
    items {
      id
      key
      displayName
    }
  }
}

query {
  profileVersions(profileId: "...") {
    id
    version
    jsonSchema
    uiSchema
    status
  }
}

mutation {
  createEntity(input: {
    profileId: "...",
    name: "meter-001",
    attributes: {
      serial_no: "WM-001"
    }
  }) {
    id
    kind
    profileId
    profileVersionId
    attributes
  }
}
```

---

## Configuration

| Variable         | Default                                    | Description                     |
|------------------|--------------------------------------------|---------------------------------|
| `DATABASE_URL`   | *(required)*                               | Postgres connection string      |
| `LISTEN_ADDR`    | `0.0.0.0:8080`                             | HTTP bind address               |
| `GRPC_ADDR`      | `0.0.0.0:8081`                             | gRPC bind address               |
| `JWT_EXPIRY_SECS`| `3600`                                     | JWT lifetime in seconds         |
| `ADMIN_SECRET`   | *(optional)*                               | Seeds admin password on first boot |
| `ADMIN_ENTITY_ID`| `00000000-0000-0000-0000-000000000001`     | Override seeded admin UUID      |
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

### Tenants
```
POST   /tenants                            {name, route?, tags?, attributes?}     # RequireManage
GET    /tenants?name=&route=&status=&limit=&offset=
GET    /tenants/:id
PUT    /tenants/:id                        {name?, route?, tags?, attributes?}    # RequireManage
POST   /tenants/:id/enable                                                        # RequireManage → status=active
POST   /tenants/:id/disable                                                       # RequireManage → status=inactive
POST   /tenants/:id/freeze                                                        # RequireManage → status=frozen
DELETE /tenants/:id                                                               # RequireManage → status=deleted (soft)
```

A tenant is an isolation boundary, not a principal. Other rows
reference it via `tenant_id` (NULL for platform/global objects).
Tenant status values: `active | inactive | frozen | deleted`.

#### Magistrala Domain → Atom Tenant mapping

| Magistrala field | Atom field          |
|------------------|---------------------|
| domain `id`      | `tenants.id`        |
| domain `name`    | `tenants.name`      |
| `route`          | `tenants.route`     |
| `metadata`       | `tenants.attributes`|
| `tags`           | `tenants.tags`      |
| `enabled`        | `status = active`   |
| `disabled`       | `status = inactive` |
| `freezed`        | `status = frozen`   |
| `deleted`        | `status = deleted`  |

Reuse the Magistrala domain UUID as the Atom `tenants.id`. All Atom
objects in that domain (entities, groups, resources, roles) carry
the same UUID in their `tenant_id` column.

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

The protected object can also be addressed explicitly via
`object_kind` + `object_id`. This is required for non-resource
objects such as tenants:

```
POST /authz/check
{
  "subject_id":  "uuid",
  "action":      "manage",
  "object_kind": "tenant",
  "object_id":   "uuid",
  "context":     {}
}
```

Supported `object_kind` values: `resource`, `tenant`. When
`object_kind`/`object_id` are supplied they win over `resource_id`;
otherwise the legacy `resource_id` form is used unchanged.

Policy bindings continue to apply against tenant objects:

- `scope_kind = all` — covers every protected object including tenants.
- `scope_kind = resource_kind`, `scope_ref = "tenant"` — covers all tenants.
- `scope_kind = resource`, `scope_ref = <tenant UUID>` — covers one tenant.

---

## Data Model Summary

```
Tenant ─── isolation boundary; tenant_id on Entity, Group, Resource, Role
       ─── status: active | inactive | frozen | deleted

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

# Build (also re-generates gRPC stubs from proto/atom/v1/atom.proto via build.rs)
cargo build

# Run with live reload
cargo watch -x run

# Run Postgres only
docker-compose up postgres -d

# Lint
cargo clippy -- -D warnings
cargo fmt --check
```

Migrations run automatically on startup via `sqlx::migrate!`. To add a migration, create `migrations/NNN_<name>.sql`.

---

## Generating proto stubs and docs

### Prerequisites

```bash
# protoc (Protocol Buffer compiler)
# macOS: brew install protobuf
# Linux: apt install -y protobuf-compiler

# buf (proto toolchain)
# https://buf.build/docs/installation
# macOS: brew install bufbuild/buf/buf

# protoc-gen-doc (proto → Markdown)
go install github.com/pseudomuto/protoc-gen-doc/cmd/protoc-gen-doc@latest
```

### Rust gRPC stubs

Stubs are generated automatically by `cargo build` via `build.rs`. The source proto is at `proto/atom/v1/atom.proto`. No manual step is needed.

```bash
# Force regeneration
touch proto/atom/v1/atom.proto && cargo build
```

### Proto documentation (`apidocs/grpc-reference.md`)

`apidocs/grpc-reference.md` is auto-generated from the proto and **must be committed** after any proto change. CI fails if the committed file is out of date.

```bash
buf generate          # regenerates apidocs/grpc-reference.md
git add apidocs/grpc-reference.md
```

### Lint and breaking-change check

```bash
buf lint              # validate proto style
buf breaking --against '.git#branch=main'   # detect breaking changes vs main
```

### OpenAPI spec (`apidocs/openapi.yaml`)

The OpenAPI spec is hand-maintained. Validate it locally before pushing:

```bash
npx @redocly/cli lint apidocs/openapi.yaml
```

To render it as interactive docs:

```bash
# Redoc preview
npx @redocly/cli preview-docs apidocs/openapi.yaml

# Swagger UI (Docker)
docker run -p 8090:8080 \
  -e SWAGGER_JSON=/spec/openapi.yaml \
  -v $(pwd)/apidocs:/spec \
  swaggerapi/swagger-ui
```

### Docs website

```bash
cd docs
pnpm install
pnpm dev     # http://localhost:3000
```

---

## Roadmap

- [ ] SCIM provisioning endpoint
- [ ] OIDC federation (external IdP)
- [ ] Workload identity (SPIFFE / X.509)
- [ ] Audit log webhooks
- [ ] Token introspection endpoint
- [ ] Rate limiting
- [ ] Metrics (Prometheus)
