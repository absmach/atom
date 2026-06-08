# Atom

Simple Identity and Authorization service — a lightweight alternative to Keycloak, written in Rust.

Built for [Magistrala](https://github.com/absmach/magistrala) IoT platform, but generic enough for any cloud-native or edge system.

**License:** Apache-2.0

---

## What it does

- **Identity** — CRUD for any principal type: humans, devices, services, workloads, applications. All are first-class *entities*; no special user class.
- **Authentication** — password login (JWT), long-lived API keys, session management.
- **Authorization** — actions, permission blocks, roles, role assignments, Direct Policies, and ABAC guardrails.
- **Grouping** — Object Groups define where access applies; Principal Groups define who receives roles.
- **Ownership** — parent/child relationships between entities.
- **Multi-tenancy** — first-class tenants; entities, groups, resources, and roles can be scoped to a tenant. Magistrala domains map directly to Atom tenants.

---

## Documentation source of truth

This README is the quickstart and orientation document. It should not duplicate the full product specification.

- Product source of truth: [product-docs/PRD.md](product-docs/PRD.md)
- Access model source of truth: [product-docs/11-access-model-simplification.md](product-docs/11-access-model-simplification.md)
- Magistrala integration source of truth: [product-docs/10-magistrala-on-atom.md](product-docs/10-magistrala-on-atom.md)
- Certificate lifecycle source of truth: [product-docs/12-certificates.md](product-docs/12-certificates.md)
- Beginner/operator guide: [docs/content/docs/simple-words.mdx](docs/content/docs/simple-words.mdx)
- Architecture diagrams: [docs/content/docs/architecture/index.mdx](docs/content/docs/architecture/index.mdx)
- Certificate guide with flow diagram: [docs/content/docs/authentication/certificates.mdx](docs/content/docs/authentication/certificates.mdx)
- Magistrala integration guide with flow diagram: [docs/content/docs/magistrala-on-atom.mdx](docs/content/docs/magistrala-on-atom.mdx)

Do not use older pre-May-2026 authorization terminology as the product model. Atom now uses Actions, Permission Blocks, Roles, Role Assignments, Direct Policies, Principal Groups, and Object Groups.

---

## Access model in simple words

Atom’s normal product model uses these ideas:

| Atom word | Simple meaning | Example |
|-----------|----------------|---------|
| Tenant | Top boundary | Magistrala domain `d1` |
| Action | One action | `read`, `write`, `publish`, `role.manage` |
| Action Applicability | Which object types support an action | `publish` is valid for channels, not clients |
| Permission Block | Scope + actions + effect + conditions | channels in Plant-A -> read, publish |
| Role | Named collection of Permission Blocks | `Plant Operator` bundles client and channel access |
| Role Assignment | Gives a role to an entity or Principal Group | assign `Plant Operator` to `user1` |
| Direct Policy | Gives one Permission Block directly to a subject | `client1` can publish to `channel1` |
| Principal Group | Collection of identities | `Operators` contains `user1`, `user2`, `mg-service` |
| Object Group | Boundary/container for objects | `Plant-A` contains clients, channels, child groups |

Action naming is hybrid:

- real stored objects use generic actions, for example `read` on `audit_log`, `manage` or `revoke` on `credential`, `create` or `manage` on `tenant`, and `rotate` on `signing_key`;
- scoped access administration keeps explicit actions: `role.manage` manages roles for a Permission Block scope, and `policy.manage` adds/removes assignments for that scope;
- operation checks keep operation names such as `authz.check`.

Read a normal assignment as one sentence:

```text
Give <who> this <role>.
```

Example:

```text
Assign Plant-A Operator to Principal Group Operators.
```

That means:

```text
Every entity in Operators receives the permissions defined inside the Plant-A Operator role.
```

The role itself says where access applies:

```text
Role: Plant-A Operator
Permission: clients in Object Group Plant-A -> read, write
Permission: channels in Object Group Plant-A -> read, publish, subscribe
```

Roles can have the same name in different tenants, but they are still separate rows:

```text
Tenant d1 has tenant-admin role with role ID role-a.
Tenant d2 has tenant-admin role with role ID role-b.
```

Changing actions on `role-a` affects only tenant `d1`. It does not change `role-b` in tenant `d2`.

So `tenant-admin` is not one global shared role. Each tenant gets its own tenant-scoped `tenant-admin` role.

Direct Policies exist for advanced/security flows. They attach an existing Permission Block directly to a subject; they do not redefine scope or actions.

Normal object listing does not require a separate `list` action. Listing should return objects the caller can `read`, using authorization-aware SQL filtering.

Short version:

```text
Action             = action
Action Applicability = valid action/object pair
Permission Block       = where actions apply
Role                   = named set of Permission Blocks
Role Assignment        = who gets the role
Direct Policy          = who gets one Permission Block directly
Principal Group        = who
Object Group           = where
```

---

## Quick start

```bash
# 1. Copy and edit config
cp .env.example .env
# set ADMIN_SECRET on first boot to create the admin password
# mount issuer CA files under ATOM_CERTS_CA_DIR when ATOM_CERTS_ENABLED=true

# 2. Start Postgres
docker-compose up postgres -d

# 3. Run (migrations apply automatically on startup)
cargo run

# or with Docker (release image on :8080)
docker compose up --build atom

# or with the dev image on :8081
docker compose --profile dev up --build atom-dev

# or with the optional Next UI on :3005
docker compose --profile atom-ui up -d --build
```

The service starts on `http://localhost:8080`.

GraphQL is available at `POST /graphql` in both images. GraphQL uses the same Bearer token authentication as REST.

Certificate support is enabled by default. Atom loads issuer CA material from mounted files and does not store CA certificates or CA private keys in Postgres. Production deployments should use `ATOM_CERTS_CA_MODE=file_intermediate_issuer` with root certificate, intermediate certificate, and intermediate private key files mounted read-only; `file_root_issuer` is supported for local/dev when only root certificate and root private key files exist. Public PKI endpoints are available at `GET /certs/ca-chain`, `GET /certs/crl`, and `POST /certs/ocsp`.

The Atom Next UI is a separate optional service. In Docker Compose it is enabled with the `atom-ui` profile and is available at `http://localhost:3005`.

Shared Magistrala/Cube deployments may consume `ghcr.io/absmach/atom:latest` and `ghcr.io/absmach/atom-ui:latest`, but those tags are mutable. Before consuming `latest`, publish both images from the same stabilized Atom commit. Production deployments that need immutability should override the image with a digest or fixed release tag.

For local UI development, run the backend and frontend separately:

```bash
# backend on http://localhost:8080
cargo run

# Next UI on http://localhost:3000
cd app
pnpm install
pnpm dev
```

When using the dev Docker backend on `http://localhost:8081`, set `ATOM_GRAPHQL_URL=http://localhost:8081/graphql` for the Next UI.

If a host port is already occupied, override only the host-side port:

```bash
POSTGRES_HOST_PORT=55432 ATOM_HTTP_PORT=18080 docker compose up --build atom
```

The Atom container still connects to Postgres through Docker DNS at `postgres:5432`.

Production builds can be made with:

```bash
cargo build --release
pnpm --dir app build
```

The UI includes an API Endpoint Builder for super admins. It creates metadata-backed custom HTTP endpoints under `/api/custom/*` that execute inline generic Atom GraphQL operations and return JSON responses.

- `api_endpoint` is the only custom API object. It stores the HTTP route, operation kind, GraphQL operation, variable mapping, request schema, response mapping, auth mode, and status.
- UI presets are local shortcuts for filling endpoint fields; they are not backend records.
- `caller_context` executes the endpoint GraphQL with the caller's authenticated Atom context and is the default.
- `service_context` executes with a configured service entity and should be used only for tightly controlled admin-created endpoints.

Example:

```text
POST /api/custom/devices
```

can run an inline `createEntity` GraphQL operation with a variables mapping such as:

```json
{
  "input.name": "$body.name",
  "input.tenantId": "$body.tenantId",
  "input.profileId": "$body.profileId",
  "input.attributes": "$body.attributes",
  "context.actorId": "$auth.entityId"
}
```

Custom API endpoints do not inspect raw Postgres tables, do not change REST or GraphQL semantics, and do not add external-system aliases. Every execution is audited with redacted request/response summaries. Paths must stay under `/api/custom/`, request bodies are size-limited and JSON-schema validated when a request schema is configured, and active method/path duplicates are rejected.

The Atom Next UI includes admin workflows for tenants, entities, groups, resources, roles, policies, audit, authz debugging, and custom API endpoints. The GraphQL playground includes starter operations, schema introspection search, variables, response viewing, and copyable curl/fetch snippets.

Atom is GraphQL-first for catalog, authorization, audit, roles, assignments, permission blocks, actions, Principal Groups, and Object Groups.

Public non-GraphQL endpoints are intentionally limited to auth, health, JWKS, and custom API endpoint execution. The full API surface is documented in [product-docs/PRD.md](product-docs/PRD.md).

Atom GraphQL is generic. No Magistrala-specific GraphQL aliases exist; use the generic application mappings below.

GraphQL uses typed enums for Atom's fixed vocabularies, including `EntityKind`, `EntityStatus`, `TenantStatus`, `Effect`, `CredentialKind`, and `AuditOutcome`. Inline GraphQL uses enum values without quotes, such as `kind: device`. When using variables, send the same value as a JSON string, such as `"device"`.

Profiles keep Atom's internal runtime/authz kind separate from user/domain subtypes:

- `kind` is the internal Atom entity kind used by authorization (`human`, `device`, `service`, `workload`, `application`).
- `profile` is the user-customizable subtype/schema selector, such as `client`, `gateway`, or `water_meter`.
- `profileVersion` identifies the JSON Schema used to validate entity attributes. It is not used by authorization.

```graphql
mutation {
  login(input: {
    identifier: "atom-admin",
    secret: "change-me",
    kind: "password"
  }) {
    token
    entityId
    sessionId
    expiresAt
  }
}

mutation {
  createTenant(input: {
    name: "factory-a",
    route: "factory-a"
  }) {
    id
    name
    route
    status
  }
}

mutation {
  createEntity(input: {
    profileId: "client-profile-id",
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

mutation {
  createResource(input: {
    kind: "channel",
    name: "telemetry",
    attributes: {
      topic: "telemetry"
    }
  }) {
    id
    kind
    name
    attributes
  }
}

mutation {
  authzCheck(input: {
    subjectId: "client-entity-id",
    action: "publish",
    resourceId: "channel-resource-id"
  }) {
    allowed
    reason
  }
}
```

Generic application mapping:

- a domain-like app calls `createTenant`
- a client-like app calls `createEntity` with a device/client profile
- a channel-like app calls `createResource` with `kind="channel"`
- a connection-like app creates a Permission Block and Direct Policy for the strict subject-to-object grant
- a role-based app creates Permission Blocks, attaches them to Roles, and assigns Roles to entities or Principal Groups

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
| `ATOM_SIGNUP_ENABLED` | `false`                              | Enables unauthenticated global human signup |
| `ATOM_DEV_ALLOW_UNVERIFIED_EMAIL_LOGIN` | `false`           | Development-only password login before email verification |
| `ATOM_PUBLIC_BASE_URL` | `http://localhost:8080`             | Public URL used for email verification and OAuth callbacks |
| `ATOM_EMAIL_VERIFICATION_REDIRECT` | `/auth/email/verify` | URL that verifies email tokens |
| `ATOM_OAUTH_SUCCESS_REDIRECT` | `/auth/callback` | Frontend URL that receives the OAuth exchange code |
| `ATOM_OAUTH_ERROR_REDIRECT` | `/auth/callback` | Frontend URL that receives OAuth errors |
| `ATOM_OIDC_PROVIDERS` | `[]`                                 | JSON array of OIDC providers, for example Google |
| `ATOM_SMTP_HOST` / `ATOM_SMTP_FROM` | *(optional)*          | SMTP settings for signup verification email |
| `RUST_LOG`       | `info`                                     | Log level filter                |

---

## Authentication

All endpoints except `GET /health`, `POST /auth/login`, email verification,
OAuth start/callback/exchange, and optionally `POST /auth/signup` require:

```
Authorization: Bearer <token>
```

Two token types are accepted:

**JWT** — returned by `/auth/login`, short-lived (default 1 hour):
```bash
curl -s -X POST http://localhost:8080/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"identifier": "alice@example.com", "secret": "s3cr3t"}'
# → {"token":"eyJ...", "entity_id":"...", "session_id":"...", "expires_at":"..."}
```

**Human signup** — disabled by default. When `ATOM_SIGNUP_ENABLED=true`,
`/auth/signup` creates a global human entity (`tenant_id = NULL`), stores the
normalized email, creates a password credential keyed by that email, and sends
a verification email. It returns `202 Accepted` and does not issue a JWT until
the email is verified. It never creates a tenant or grants platform privileges:

```bash
curl -s -X POST http://localhost:8080/auth/signup \
  -H 'Content-Type: application/json' \
  -d '{"name": "Alice", "email": "alice@example.com", "password": "s3cr3t"}'
```

```bash
curl -s 'http://localhost:8080/auth/email/verify?token=atomv_...'

curl -s -X POST http://localhost:8080/auth/email/resend \
  -H 'Content-Type: application/json' \
  -d '{"email": "alice@example.com"}'
```

For local development only, `ATOM_DEV_ALLOW_UNVERIFIED_EMAIL_LOGIN=true`
allows password login before verification while still rejecting inactive or
suspended entities.

**OIDC/OAuth signup and login** — configure providers with
`ATOM_OIDC_PROVIDERS`. The callback requires a provider-verified email, creates
or links a global human account, redirects with a one-time exchange code, and
the client exchanges that code for the normal login response:

```bash
curl -i 'http://localhost:8080/auth/oauth/google/start?return_to=/dashboard'
curl -s -X POST http://localhost:8080/auth/oauth/exchange \
  -H 'Content-Type: application/json' \
  -d '{"code": "atomx_..."}'
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

## RBAC And Direct Policies

Role-Based Access Control is the normal product model. A role does not contain scope columns directly. A role links to one or more Permission Blocks, and each Permission Block contains the scope, actions, effect, and optional ABAC conditions.

### Example: device that can publish to channels

```text
Action:
  publish

Action Applicability:
  publish is valid on resource:channel

Permission Block:
  tenant_id = d1
  scope_mode = object_type
  object_kind = resource
  object_type = channel
  effect = allow
  actions = [publish]

Role:
  channel-publisher
  permission_blocks = [the publish block]

Role Assignment:
  subject = device sensor-001
  role = channel-publisher
```

The same runtime link can also be represented as a Direct Policy when a trusted service needs a strict one-off grant:

```text
Permission Block:
  tenant_id = d1
  scope_mode = object
  object_kind = resource
  object_type = channel
  object_id = channel-001
  effect = allow
  actions = [publish]

Direct Policy:
  subject = device sensor-001
  permission_block = the exact-channel publish block
```

Direct Policies are advanced/security records. Normal UI should prefer Roles and Role Assignments.

### Principal Groups

Principal Groups are who-containers. A Role Assignment can target a Principal Group, and all members inherit that role.

```text
Principal Group: floor-sensors
Members: sensor-001, sensor-002
Assignment: floor-sensors gets channel-publisher
```

### Object Groups

Object Groups are where-containers. They do not receive roles. They are used by Permission Blocks to describe where a permission applies.

```text
Object Group: Plant-A
Contains: channel-001, sensor-001, child groups

Permission Block:
  scope_mode = group_direct_objects
  group_id = Plant-A
  object_kind = resource
  object_type = channel
  actions = [read, publish]
```

---

## ABAC

Attribute-Based Access Control uses `conditions` on Permission Blocks. Conditions are a flat JSON object where keys are dot-paths into the evaluation context and values must match exactly.

The evaluation context is:

```json
{
  "entity": { "attributes": { "...": "..." } },
  "object": { "kind": "resource", "type": "channel", "attributes": { "...": "..." } },
  "tenant": { "attributes": { "...": "..." } },
  "context": { "...": "..." }
}
```

Conditions can be used in Role Permission Blocks or Direct Policy Permission Blocks. A Permission Block matches only when all conditions match.

---

## Authorization Rules

- **DENY overrides ALLOW** — a matching deny Permission Block wins over matching allow blocks.
- **Default DENY** — no matching allow means denied.
- **Role Assignment has no scope** — it only says who gets a role.
- **Direct Policy has no duplicated scope/actions** — it only links a subject to one Permission Block.
- **Scope lives in Permission Blocks** — this is the single source of truth.
- **Listing uses read** — ordinary list queries return only objects the caller can `read`.
- **Listing is DB-filtered** — no fetch-all and PDP-per-row listing.

---

## API Surface

Atom is GraphQL-first for catalog, authorization, audit, roles, assignments, permission blocks, actions, Principal Groups, and Object Groups.

Public non-GraphQL endpoints are intentionally limited to:

```text
GET  /health
POST /graphql
GET  /.well-known/jwks.json
POST /auth/login
POST /auth/logout
POST /auth/signup
POST /auth/introspect
GET/POST /auth/email/*
GET/POST /auth/password/reset*
GET/POST /auth/oauth/*
POST /auth/keys/rotate
ANY /api/custom/*
```

Core access-model APIs should use GraphQL object names:

```text
Action
ActionApplicability
PermissionBlock
Role
RoleAssignment
DirectPolicy
PrincipalGroup
ObjectGroup
```

---

## Tenant Mapping

A tenant is an isolation boundary, not a principal. Other rows reference it via `tenant_id` unless they are platform/global rows.

Tenant status values:

```text
active | inactive | frozen | deleted
```

### Magistrala Domain -> Atom Tenant

| Magistrala field | Atom field |
|---|---|
| domain `id` | `tenants.id` |
| domain `name` | `tenants.name` |
| `route` | `tenants.route` |
| `metadata` | `tenants.attributes` |
| `tags` | `tenants.tags` |
| `enabled` | `status = active` |
| `disabled` | `status = inactive` |
| `freezed` | `status = frozen` |
| `deleted` | `status = deleted` |

Reuse the Magistrala domain UUID as the Atom `tenants.id`. Objects in that domain carry the same UUID in their `tenant_id` column.

---

## Data Model Summary

```
Tenant ─── isolation boundary; tenant_id on tenant-owned rows

Entity ─── identity: human | device | service | workload | application
Entity ─── has credentials and sessions

Action ─── atomic operation: read | write | publish | ...
Action Applicability ─── says which object kinds/types support an action

PermissionBlock ─── tenant_id
                ─── scope_mode + object_kind/object_type/object_id/group_id
                ─── effect: allow | deny
                ─── conditions
                ─── has many Actions

Role ─── tenant-owned metadata
     ─── has many PermissionBlocks

RoleAssignment ─── subject: Entity | PrincipalGroup
               ─── role: Role

DirectPolicy ─── subject: Entity | PrincipalGroup
             ─── permission_block: PermissionBlock

PrincipalGroup ─── who-container; has members
ObjectGroup ─── where-container; contains entities/resources/child groups
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
pnpm dev     # http://localhost:3000/docs/atom/
```

The rendered docs site is a static Next.js export served under `/docs/atom/`.
It follows the same Cloudflare Workers static-assets deployment pattern as
FluxMQ docs: `pnpm run build` exports and nests the site under
`docs/out/docs/atom/`, then `wrangler deploy` publishes `docs/out/`.

```bash
cd docs
pnpm run build
pnpm exec wrangler deploy --dry-run
pnpm run deploy
```

Cloudflare build settings:

| Setting         | Value                         |
|-----------------|-------------------------------|
| Build command   | `pnpm run build`              |
| Deploy command  | `npx wrangler deploy`         |
| Version command | `npx wrangler versions upload` |
| Root directory  | `/docs`                       |

Set Cloudflare Workers **Build watch paths** for the `atom-docs` Worker to:

| Setting       | Value    |
|---------------|----------|
| Include paths | `docs/*` |
| Exclude paths | empty    |

---

## Roadmap

- [ ] SCIM provisioning endpoint
- [x] OIDC federation (external IdP)
- [ ] Workload identity (SPIFFE / X.509)
- [ ] Audit log webhooks
- [ ] Token introspection endpoint
- [ ] Rate limiting
- [ ] Metrics (Prometheus)
