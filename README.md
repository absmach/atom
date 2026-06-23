# Atom

Simple Identity and Authorization service — a lightweight alternative to Keycloak, written in Rust.

Built for the [Magistrala](https://github.com/absmach/magistrala) IoT platform, but generic enough for any cloud-native or edge system.

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

This README is the quick start and orientation document. It should not duplicate the full product specification.

- Product source of truth: [product-docs/PRD.md](product-docs/PRD.md)
- Access model source of truth: [product-docs/11-access-model-simplification.md](product-docs/11-access-model-simplification.md)
- Magistrala integration source of truth: [product-docs/10-magistrala-on-atom.md](product-docs/10-magistrala-on-atom.md)
- Certificate lifecycle source of truth: [product-docs/12-certificates.md](product-docs/12-certificates.md)
- Beginner/operator guide: [docs/content/docs/simple-words.mdx](docs/content/docs/simple-words.mdx)
- Architecture diagrams: [docs/content/docs/architecture/index.mdx](docs/content/docs/architecture/index.mdx)
- Certificate guide with flow diagram: [docs/content/docs/authentication/certificates.mdx](docs/content/docs/authentication/certificates.mdx)
- Magistrala integration guide with flow diagram: [docs/content/docs/magistrala-on-atom.mdx](docs/content/docs/magistrala-on-atom.mdx)

---

## Access model in simple words

Atom’s normal product model uses these ideas:

| Atom word            | Simple meaning                                   | Example                                             |
| -------------------- | ------------------------------------------------ | --------------------------------------------------- |
| Tenant               | Top boundary                                     | Magistrala domain `d1`                              |
| Action               | One action                                       | `read`, `write`, `publish`, `role.manage`           |
| Action Applicability | Which object types support an action             | `publish` is valid for channels, not clients        |
| Permission Block     | Scope + actions + effect + conditions            | channels in Plant-A -> read, publish                |
| Role                 | Named collection of Permission Blocks            | `Plant Operator` bundles client and channel access  |
| Role Assignment      | Gives a role to an entity or Principal Group     | assign `Plant Operator` to `user1`                  |
| Direct Policy        | Gives one Permission Block directly to a subject | `client1` can publish to `channel1`                 |
| Principal Group      | Collection of identities                         | `Operators` contains `user1`, `user2`, `mg-service` |
| Object Group         | Boundary/container for objects                   | `Plant-A` contains clients, channels, child groups  |

Action naming is hybrid:

- real stored objects use generic actions, for example `read` on `audit_log`, `manage` or `revoke` on `credential`, `create` or `manage` on `tenant`, and `rotate` on `signing_key`;
- scoped access administration keeps explicit actions: `role.manage` manages roles for a Permission Block scope, and `policy.manage` adds/removes assignments for that scope;
- operation checks keep operation names such as `authz.check`.

That means Atom does not use one naming style for every action. It chooses the
name that makes the authorization decision easiest to understand:

| Action style               | What it means                                               | Example                                              |
| -------------------------- | ----------------------------------------------------------- | ---------------------------------------------------- |
| Generic object action      | The action is common, and the object kind gives it meaning. | `read` on `audit_log`, `revoke` on `credential`      |
| Scoped access admin action | The action manages access rules inside a specific scope.    | `role.manage` for roles in one tenant or group scope |
| Runtime operation action   | The action protects a service operation, not a stored row.  | `authz.check` for services allowed to call the PDP   |

For stored objects, the object kind is part of the authorization question:

```text
Can user1 revoke credential cred-123?
Can admin1 manage tenant d1?
Can key-admin rotate signing_key key-1?
```

These use short generic actions because `credential`, `tenant`, and
`signing_key` already identify what kind of object is being protected. Action
Applicability decides which action/object pairs are valid, so `revoke` can be
valid for credentials without becoming a global action for every object type.

For access administration, `role.manage` and `policy.manage` are intentionally
more explicit. They do not mean "manage every role everywhere." They mean
"manage role or policy assignments inside the Permission Block scope being
checked." For example, a tenant admin can receive `role.manage` for tenant `d1`
without receiving permission to manage roles in tenant `d2`.

For runtime operations, there may be no normal stored object to protect. A
service calling Atom's authorization endpoint is asking to perform the operation
`authz.check`, so Atom keeps that operation name as the action. This makes
service-to-service permissions and audit logs clear.

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

There is one config file. Copy the example and start the stack:

```bash
# 1. Create your local config
cp .env.example .env

# 2. Start Postgres, Atom, and the Atom Next UI
#    (builds the images the first time; reuses them after)
make up

# 3. Follow backend and UI logs
make logs
```

`.env.example` ships working local defaults: admin login `admin` /
`12345678`, password login allowed before email verification
(`ATOM_ALLOW_UNVERIFIED_EMAIL_LOGIN=true`), and certificates disabled, so a
fresh copy boots with no SMTP, OAuth, or CA setup.

`make up` runs Docker Compose with `.env`, `--profile default`, and
`--profile atom-ui`. It starts:

- Atom REST/GraphQL on `http://localhost:8080`
- Atom Next UI on `http://localhost:3005`
- Postgres on `127.0.0.1:5432`

Log in to get a token:

```bash
curl -s -X POST http://localhost:8080/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"identifier": "admin", "secret": "12345678"}'
```

`make up` reuses the existing images and does not rebuild. After changing
backend or UI code, rebuild explicitly:

```bash
make build      # or: make atom-build / make ui-build
make up

make down       # stop the stack
make restart    # stop and start again (no rebuild)
```

GraphQL is available at `POST http://localhost:8080/graphql`. Migrations apply
automatically on startup.

### Backend development with Cargo

Run Atom on the host and keep only Postgres in Docker. Postgres is published on
`127.0.0.1:5432`, and `.env` points `DATABASE_URL` at `localhost:5432`, so
`cargo run` connects with no extra setup:

```bash
make db        # start only Postgres
cargo run      # Atom on http://localhost:8080
```

Plain `cargo run` uses `LISTEN_ADDR` from `.env` (`8080`), so it collides with
`make up`. To run both together, use `make dev` (below), which moves the host
backend to a separate port.

### UI development and running everything at once

The host dev flow uses its own ports so it can run **alongside** `make up` on
the same Postgres. `make dev` starts Postgres (Docker) plus Atom and the Next
UI on the host (Ctrl-C stops both; needs host `cargo` and `pnpm`):

```bash
make dev       # cargo run (:8090) + pnpm dev (:3000), Postgres shared
```

| Flow                | Backend | UI      | Postgres          |
| ------------------- | ------- | ------- | ----------------- |
| `make up` (Compose) | `:8080` | `:3005` | `:5432`           |
| `make dev` (host)   | `:8090` | `:3000` | `:5432` (same DB) |

Log in to either with the same admin credentials (`admin` / `12345678`); both
read `ADMIN_SECRET` from `.env` and share one database.

Run both at once to compare a code change against the released image — they
share the one Postgres volume. Override ports with `DEV_HTTP_PORT` and
`DEV_UI_PORT` if needed.

To run the UI pieces yourself instead:

```bash
make db && cargo run     # backend on :8080

cd app
pnpm install
ATOM_GRAPHQL_URL=http://localhost:8080/graphql pnpm dev   # UI on :3000
```

The dev UI reads the backend GraphQL endpoint from `ATOM_GRAPHQL_URL`
(server-side). Browser origins `:3000` and `:3005` are already allowed by the
default `ATOM_CORS_ALLOWED_ORIGINS`.

### Certificates (optional)

Certificates are off by default for local dev. To enable the PKI endpoints
(`GET /certs/ca-chain`, `GET /certs/crl`, `POST /certs/ocsp`), generate a local
root CA and flip the cert vars in `.env`:

```bash
mkdir -p certs
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout certs/root-ca.key -out certs/root-ca.crt -days 3650 \
  -subj "/CN=Atom Dev Root CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"

# in .env:
#   ATOM_CERTS_ENABLED=true
#   ATOM_CERTS_CA_MODE=file_root_issuer
#   ATOM_CERTS_ROOT_CA_CERT_PATH=/certs/root-ca.crt   (host: ./certs/root-ca.crt for cargo run)
#   ATOM_CERTS_ROOT_CA_KEY_PATH=/certs/root-ca.key
```

Compose mounts `./certs` at `/certs:ro`; a host `cargo run` reads the files
directly, so use `./certs/...` paths there. Production should use
`ATOM_CERTS_CA_MODE=file_intermediate_issuer` with root certificate,
intermediate certificate, and intermediate private key files mounted
read-only. Atom never stores CA certificates or CA private keys in Postgres.

### Port overrides

If a host port is already occupied, override only the host-side port:

```bash
POSTGRES_HOST_PORT=55432 ATOM_HTTP_PORT=28080 ATOM_UI_HTTP_PORT=3006 make up
```

The Atom container still connects to Postgres through Docker DNS at
`postgres:5432`.

Shared Magistrala/Cube deployments may consume `ghcr.io/absmach/atom:latest` and `ghcr.io/absmach/atom-ui:latest`, but those tags are mutable. Before consuming `latest`, publish both images from the same stabilized Atom commit. Production deployments that need immutability should override the image with a digest or fixed release tag.

## Makefile commands

Run `make help` to print the current target list from the Makefile.

| Command                     | What it does                                                                           |
| --------------------------- | -------------------------------------------------------------------------------------- |
| `make db`                   | Starts only Postgres (for a host `cargo run`).                                         |
| `make dev`                  | Host `cargo run` (:8090) + UI dev (:3000) on the shared Postgres; runs with `make up`. |
| `make build`                | Builds and tags the Atom backend and Atom UI images for local Compose use.             |
| `make atom-build`           | Builds and tags only the Atom backend image.                                           |
| `make ui-build`             | Builds and tags only the Atom UI image.                                                |
| `make up`                   | Starts Postgres, Atom, and Atom UI with `.env` (builds images only if missing).        |
| `make restart`              | Stops and starts the Compose stack again (no rebuild; run `make build` first).         |
| `make logs`                 | Follows Atom backend and Atom UI logs.                                                 |
| `make down`                 | Stops the local Compose stack.                                                         |
| `make docker-build`         | Builds the raw Atom Docker image using `BUILD_TARGET`, `IMAGE_NAME`, and `IMAGE_TAG`.  |
| `make docker-build-release` | Builds the raw release Docker image.                                                   |

Common overrides:

```bash
# Use another env file
DEV_ENV_FILE=.env.local make up

# Build a specific image tag
IMAGE_TAG=2026-06-12 make build

# Start only selected Compose profiles
COMPOSE_PROFILES="--profile default" make up
```

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

can run an inline `createEntity` GraphQL operation with a variable mapping such as:

```json
{
  "input.name": "$body.name",
  "input.tenantId": "$body.tenantId",
  "input.profileId": "$body.profileId",
  "input.attributes": "$body.attributes",
  "context.actorId": "$auth.entityId"
}
```

Custom API endpoints do not inspect raw Postgres tables, do not change REST or GraphQL semantics, and do not add external-system aliases. Every execution is audited with redacted request/response summaries. Paths must stay under `/api/custom/`, request bodies are size-limited and JSON Schema validated when a request schema is configured, and active method/path duplicates are rejected.

The Atom Next UI includes admin workflows for tenants, entities, groups, resources, roles, policies, audit, authz debugging, and custom API endpoints. The GraphQL playground includes starter operations, schema introspection search, variables, response viewing, and copyable curl/fetch snippets.

The API surface is summarized below. The full product behavior is documented in [product-docs/PRD.md](product-docs/PRD.md).

Atom GraphQL is generic. No Magistrala-specific GraphQL aliases exist; use the generic application mappings below.

GraphQL uses typed enums for Atom's fixed vocabularies, including `EntityKind`, `EntityStatus`, `TenantStatus`, `Effect`, `CredentialKind`, and `AuditOutcome`. Inline GraphQL uses enum values without quotes, such as `kind: device`. When using variables, send the same value as a JSON string, such as `"device"`.

Profiles keep Atom's internal runtime/authz kind separate from user/domain subtypes:

- `kind` is the internal Atom entity kind used by authorization (`human`, `device`, `service`, `workload`, `application`).
- `profile` is the user-customizable subtype/schema selector, such as `client`, `gateway`, or `water_meter`.
- `profileVersion` identifies the JSON Schema used to validate entity attributes. It is not used by authorization.

```graphql
mutation {
  login(input: {
    identifier: "admin",
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
    alias: "factory-a"
  }) {
    id
    name
    alias
    status
  }
}

mutation {
  createEntity(input: {
    profileId: "client-profile-id",
    name: "meter-001",
    alias: "meter-001",
    attributes: {
      serial_no: "WM-001"
    }
  }) {
    id
    kind
    alias
    profileId
    profileVersionId
    attributes
  }
}

mutation {
  createResource(input: {
    kind: "channel",
    name: "telemetry",
    alias: "telemetry",
    attributes: {
      topic: "telemetry"
    }
  }) {
    id
    kind
    name
    alias
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

`.env.example` is the local template. These are the main runtime and Compose variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | *(required)* | Postgres connection string |
| `LISTEN_ADDR` | `0.0.0.0:8080` | HTTP bind address |
| `GRPC_ADDR` | `0.0.0.0:8081` | gRPC bind address |
| `ATOM_DB_MAX_CONNECTIONS` / `ATOM_DB_MIN_CONNECTIONS` | `20` / `0` | Postgres pool size controls |
| `ATOM_DB_ACQUIRE_TIMEOUT_SECS` / `ATOM_DB_CONNECT_TIMEOUT_SECS` | `30` / `10` | Pool acquire and startup connect timeouts |
| `ATOM_DB_IDLE_TIMEOUT_SECS` / `ATOM_DB_MAX_LIFETIME_SECS` | `600` / `1800` | Pool idle and lifetime limits |
| `ATOM_KEY_ENCRYPTION_KEY` | *(required for production)* | Base64 32-byte AES-256-GCM key used to encrypt signing private keys |
| `ATOM_KEY_ENCRYPTION_KEY_ID` | `local:v1` | Operator-visible signing-key encryption key id |
| `ATOM_ALLOW_PLAINTEXT_SIGNING_KEYS` | `false` | Development-only fallback for plaintext signing key rows |
| `ATOM_AUDIT_RETENTION_DAYS` / `ATOM_AUDIT_RETENTION_ENABLED` | `365` / `true` | Background audit cleanup policy |
| `ATOM_AUDIT_CLEANUP_INTERVAL_SECS` / `ATOM_AUDIT_CLEANUP_BATCH_SIZE` | `86400` / `5000` | Audit cleanup cadence and batch size |
| `ATOM_LOGIN_FAILURE_LIMIT` / `ATOM_LOGIN_FAILURE_WINDOW_SECS` | `5` / `900` | Password login throttle |
| `ATOM_RATE_LIMIT_ENABLED` | `true` | Enables in-process HTTP rate limits |
| `ATOM_TRUSTED_PROXY_CIDRS` | *(empty)* | Comma-separated proxy CIDRs whose forwarded client IP headers Atom may trust |
| `ATOM_HTTP_RATE_LIMIT_AUTH_ROUTES` / `ATOM_HTTP_RATE_LIMIT_AUTH_WINDOW_SECS` | `30` / `60` | Auth route rate-limit policy |
| `ATOM_HTTP_RATE_LIMIT_PUBLIC_ROUTES` / `ATOM_HTTP_RATE_LIMIT_PUBLIC_WINDOW_SECS` | `120` / `60` | JWKS and public PKI rate-limit policy |
| `ATOM_HTTP_RATE_LIMIT_GRAPHQL` / `ATOM_HTTP_RATE_LIMIT_GRAPHQL_WINDOW_SECS` | `120` / `60` | GraphQL rate-limit policy |
| `ATOM_HTTP_RATE_LIMIT_CUSTOM_ENDPOINTS` / `ATOM_HTTP_RATE_LIMIT_CUSTOM_ENDPOINTS_WINDOW_SECS` | `120` / `60` | Custom endpoint rate-limit policy |
| `ATOM_HTTP_RATE_LIMIT_ADMIN_ROUTES` / `ATOM_HTTP_RATE_LIMIT_ADMIN_WINDOW_SECS` | `300` / `60` | Authenticated REST admin route rate-limit policy |
| `ATOM_AUTH_BODY_LIMIT_BYTES` / `ATOM_GRAPHQL_BODY_LIMIT_BYTES` / `ATOM_CUSTOM_ENDPOINT_BODY_LIMIT_BYTES` | `32768` / `1048576` / `1048576` | Request body limits |
| `ATOM_GRAPHQL_MAX_DEPTH` / `ATOM_GRAPHQL_MAX_COMPLEXITY` | `20` / `1000` | GraphQL validation limits |
| `ATOM_GRAPHQL_INTROSPECTION_ENABLED` | `false` | Enables GraphQL introspection (off by default; opt in for dev) |
| `JWT_EXPIRY_SECS` | `3600` | JWT lifetime in seconds |
| `ATOM_JWT_ISSUER` | `ATOM_PUBLIC_BASE_URL` | JWT issuer claim |
| `ATOM_JWT_AUDIENCE` | `magistrala` | JWT audience claim |
| `ADMIN_SECRET` | *(optional)* | Seeds the admin password on first boot |
| `ADMIN_ENTITY_ID` | `00000000-0000-0000-0000-000000000001` | Override seeded admin UUID |
| `ATOM_SERVICE_SECRET` / `ATOM_SERVICE_ENTITY_ID` | *(optional)* / seeded service UUID | Seeds a service entity password on first boot |
| `ATOM_MIN_PASSWORD_CHARS` | `12` | Minimum password length |
| `ATOM_CORS_ALLOWED_ORIGINS` | `ATOM_PUBLIC_BASE_URL` | Comma-separated allowed CORS origins |
| `ATOM_AUTH_COOKIE_SECURE` / `ATOM_AUTH_COOKIE_DOMAIN` | auto-detect HTTPS / *(unset)* | Auth cookie options for UI flows |
| `ATOM_SELF_REGISTRATION_ENABLED` | `true` | Enables unauthenticated global human self-registration |
| `ATOM_UI_REGISTRATION_ENABLED` | `true` | UI service only; exposes `/register` and the login-page signup link |
| `ATOM_UI_FORWARD_CLIENT_IP_HEADERS` | `false` | UI service only; forwards client IP headers to Atom proxy calls when explicitly enabled |
| `ATOM_SIGNUP_ENABLED` | *(legacy alias)* | Backward-compatible alias for `ATOM_SELF_REGISTRATION_ENABLED` |
| `ATOM_ALLOW_UNVERIFIED_EMAIL_LOGIN` | `false` | Development-only password login before email verification |
| `ATOM_PUBLIC_BASE_URL` | `http://localhost:8080` | Public URL used for issuer and redirect defaults |
| `ATOM_EMAIL_VERIFICATION_REDIRECT` | `http://localhost:8080/auth/email/verify` | URL that verifies email tokens |
| `ATOM_PASSWORD_RESET_REDIRECT` | `http://localhost:8080/reset-password` | Frontend URL for password reset tokens |
| `ATOM_INVITATION_REDIRECT` | `http://localhost:8080/invitations/accept` | Frontend URL for invitation tokens |
| `ATOM_OAUTH_SUCCESS_REDIRECT` | `http://localhost:8080/auth/callback` | Frontend URL that receives the OAuth exchange code |
| `ATOM_OAUTH_ERROR_REDIRECT` | `http://localhost:8080/auth/callback` | Frontend URL that receives OAuth errors |
| `ATOM_OIDC_PROVIDERS` | `[]` | JSON array of OIDC providers, for example Google |
| `ATOM_EMAIL_VERIFICATION_EXPIRY_SECS` | `86400` | Email verification token lifetime |
| `ATOM_INVITATION_EXPIRY_SECS` | `604800` | Invitation token lifetime |
| `ATOM_OAUTH_STATE_EXPIRY_SECS` | `600` | OAuth state token lifetime |
| `ATOM_AUTH_EXCHANGE_CODE_EXPIRY_SECS` | `300` | OAuth exchange code lifetime |
| `ATOM_SMTP_HOST` / `ATOM_SMTP_FROM` | *(optional)* | Required pair for signup and password reset email delivery |
| `ATOM_SMTP_PORT` / `ATOM_SMTP_TLS` | `587` / `starttls` | SMTP port and TLS mode |
| `ATOM_SMTP_USERNAME` / `ATOM_SMTP_PASSWORD` | *(optional)* | SMTP credentials |
| `ATOM_CERTS_ENABLED` | `true` | Enables certificate lifecycle support |
| `ATOM_CERTS_CA_MODE` | `file_intermediate_issuer` | CA mode: `file_intermediate_issuer` or `file_root_issuer` |
| `ATOM_CERTS_ROOT_CA_CERT_PATH` | *(optional)* | Mounted root CA certificate path |
| `ATOM_CERTS_INTERMEDIATE_CA_CERT_PATH` | *(optional)* | Mounted intermediate CA certificate path |
| `ATOM_CERTS_INTERMEDIATE_CA_KEY_PATH` | *(optional)* | Mounted intermediate CA private key path |
| `ATOM_CERTS_ROOT_CA_KEY_PATH` | *(optional)* | Mounted root CA private key path for `file_root_issuer` |
| `ATOM_CERTS_LEAF_DEFAULT_TTL_SECS` | `2592000` | Default issued certificate lifetime |
| `ATOM_CERTS_LEAF_MAX_TTL_SECS` | `2592000` | Maximum issued certificate lifetime |
| `ATOM_CERTS_CA_DIR` | `./certs` | Docker Compose host directory mounted at `/certs:ro` |
| `POSTGRES_HOST_PORT` / `ATOM_HTTP_PORT` / `ATOM_GRPC_PORT` / `ATOM_DEV_HTTP_PORT` / `ATOM_DEV_GRPC_PORT` / `ATOM_UI_HTTP_PORT` | `5432` / `8080` / `8081` / `8081` / `18081` / `3005` | Docker Compose host ports |
| `ATOM_GRAPHQL_URL` | `http://atom:8080/graphql` | GraphQL endpoint used by the Dockerized Next UI |
| `RUST_LOG` | `info` | Log level filter |

Rate limiting uses the socket peer IP by default. `X-Forwarded-For` and
`X-Real-IP` are ignored unless the immediate peer IP is inside
`ATOM_TRUSTED_PROXY_CIDRS`. Keep this empty unless Atom is behind a proxy or
ingress that overwrites client IP headers. If the Atom UI is also proxying
requests to Atom, enable `ATOM_UI_FORWARD_CLIENT_IP_HEADERS=true` only behind an
upstream proxy that sanitizes those headers.

---

## Authentication

The examples below use `http://localhost:8080`, the default address for both
the `make up` Compose backend and a direct `cargo run`.

Authenticated REST, GraphQL, and custom endpoint requests use:

```
Authorization: Bearer <token>
```

The public HTTP routes that do not require an existing Bearer token are
`GET /health`, `GET /.well-known/jwks.json`, `GET /certs/ca-chain`,
`GET /certs/crl`, `POST /certs/ocsp`, `GET /auth/public-config`,
`POST /auth/login`, `GET /auth/email/verify`, `POST /auth/email/resend`,
`POST /auth/password/reset/request`, `POST /auth/password/reset`,
`GET /auth/oauth/:provider/start`, `GET /auth/oauth/:provider/callback`,
`POST /auth/oauth/exchange`, and `POST /auth/signup` when signup is enabled.
Custom API endpoint execution under `/api/custom/*` follows the configured
endpoint auth mode.

Two token types are accepted:

**JWT** — returned by `/auth/login`, short-lived (default 1 hour):
```bash
curl -s -X POST http://localhost:8080/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"identifier": "alice@example.com", "secret": "s3cr3t"}'
# → {"token":"eyJ...", "entity_id":"...", "session_id":"...", "expires_at":"..."}
```

**Human self-registration** — enabled by default. When
`ATOM_SELF_REGISTRATION_ENABLED=false`, public signup is disabled and users must
be onboarded by an administrator. When enabled, `/auth/signup` creates a global
human entity (`tenant_id = NULL`), stores the normalized email, creates a
password credential keyed by that email, and sends a verification email. It
returns `202 Accepted` and does not issue a JWT until the email is verified. It
never creates a tenant or grants platform privileges:

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

For local development only, `ATOM_ALLOW_UNVERIFIED_EMAIL_LOGIN=true`
allows password login before verification while still rejecting inactive or
suspended entities.

The optional Next UI shows `/register` only when both
`ATOM_UI_REGISTRATION_ENABLED=true` and backend self-registration are enabled.

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
curl -s -X POST http://localhost:8080/graphql \
  -H 'Authorization: Bearer eyJ...' \
  -H 'Content-Type: application/json' \
  -d '{
    "query": "mutation ($entityId: ID!, $input: CreateApiKeyInput!) { createApiKey(entityId: $entityId, input: $input) { credentialId key expiresAt } }",
    "variables": {
      "entityId": "<id>",
      "input": { "description": "device-01 production key" }
    }
  }'
# → {"data":{"createApiKey":{"credentialId":"...","key":"atom_abc123...","expiresAt":null}}}
# The key is shown exactly once — store it securely.

# Use it:
curl http://localhost:8080/auth/introspect \
  -H 'Authorization: Bearer atom_abc123...'
```

---

## RBAC and Direct Policies

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

Atom is GraphQL-first for catalog, authorization, audit, roles, assignments, permission blocks, actions, Principal Groups, and Object Groups. GraphQL is available at:

```text
POST /graphql
```

Non-GraphQL HTTP endpoints are intentionally limited to auth, health, JWKS,
public PKI artifacts, and custom API endpoint execution:

```text
GET  /health
GET  /health/live
GET  /health/ready
GET  /.well-known/jwks.json
GET  /certs/ca-chain
GET  /certs/crl
POST /certs/ocsp
GET  /auth/public-config
POST /auth/login
POST /auth/logout
POST /auth/signup
GET  /auth/introspect
GET  /auth/session
GET  /auth/sessions/:id
GET  /auth/email/verify
POST /auth/email/resend
POST /auth/password/reset/request
POST /auth/password/reset
GET  /auth/oauth/:provider/start
GET  /auth/oauth/:provider/callback
POST /auth/oauth/exchange
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

| Magistrala field | Atom field           |
| ---------------- | -------------------- |
| domain `id`      | `tenants.id`         |
| domain `name`    | `tenants.name`       |
| domain `route`   | `tenants.alias`      |
| `metadata`       | `tenants.attributes` |
| `tags`           | `tenants.tags`       |
| `enabled`        | `status = active`    |
| `disabled`       | `status = inactive`  |
| `freezed`        | `status = frozen`    |
| `deleted`        | `status = deleted`   |

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

# Build (also regenerates gRPC stubs from proto/atom/v1/atom.proto via build.rs)
cargo build

# Run with live reload
cargo watch -x run

# Run Postgres only for cargo run
docker compose --env-file .env up -d postgres

# Run unit tests without external services
cargo test

# Run DB-gated integration tests, including #[ignore] tests
set -a; source .env; set +a
cargo test -- --include-ignored --test-threads=1

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

The gRPC listener also exposes the standard gRPC health service on `GRPC_ADDR`.
Docker Compose maps it with `ATOM_GRPC_PORT` for production and
`ATOM_DEV_GRPC_PORT` for the dev profile.

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

| Setting         | Value                          |
| --------------- | ------------------------------ |
| Build command   | `pnpm run build`               |
| Deploy command  | `npx wrangler deploy`          |
| Version command | `npx wrangler versions upload` |
| Root directory  | `/docs`                        |

Set Cloudflare Workers **Build watch paths** for the `atom-docs` Worker to:

| Setting       | Value    |
| ------------- | -------- |
| Include paths | `docs/*` |
| Exclude paths | empty    |

---

## Roadmap

- [ ] SCIM provisioning endpoint
- [x] OIDC federation (external IdP)
- [ ] Workload identity (SPIFFE / X.509)
- [ ] Audit log webhooks
- [x] Token introspection endpoint
- [ ] Rate limiting
- [ ] Metrics (Prometheus)
