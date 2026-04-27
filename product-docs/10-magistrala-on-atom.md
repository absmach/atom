# Building Magistrala on Atom

## Status: Draft
## Date: 2026-04-24

---

## Purpose

Atom is the identity provider, authentication provider, authorization provider, and access listing service.

An external application such as Magistrala should not need its own identity, credential, group membership, policy, or authorization database. Magistrala creates its domain objects in Atom and stores Magistrala-specific fields in `attributes`.

The rule is:

- Atom owns generic security fields: `id`, `name`, `kind`, `tenant_id`, `status`, credentials, groups, capabilities, policy bindings, sessions, audit logs.
- Magistrala owns application-specific fields inside `attributes.magistrala`.
- Runtime access decisions always go through Atom `POST /authz/check`.
- Operator listings and debugging use Atom query endpoints such as entity access, resource access, group access, audit, and explain.

This is not a translation layer. Magistrala is built on Atom's native primitives.

---

## Concept mapping

| Magistrala concept | Atom primitive | Atom fields | Magistrala fields |
|---|---|---|---|
| Domain | `tenant` | `tenants.id` (= domain UUID), `tenants.name` (= domain name), `tenants.route`, `tenants.tags`, `tenants.attributes` (= metadata), `tenants.status` (`active` ↔ enabled, `inactive` ↔ disabled, `frozen` ↔ freezed, `deleted` ↔ deleted) | Atom owns the tenant record; reuse the Magistrala domain UUID as `tenants.id` |
| User | `entity` | `kind = "human"`, `name`, `tenant_id = null` | `attributes.magistrala.email`, `first_name`, `last_name`, `profile_picture`, `verified_at`, `metadata` |
| Client | `entity` | `kind = "device"` or `kind = "service"`, `name`, `tenant_id` | `attributes.magistrala.identity`, `tags`, `metadata`, `parent_group_id` |
| Channel | `resource` | `kind = "channel"`, `name`, `tenant_id`, `owner_id` | `attributes.magistrala.route`, `tags`, `metadata`, `status` |
| Group | `group` | `name`, `tenant_id`, `description` | Group hierarchy/tags live in a companion `resource` if needed |
| Client-channel connection | `policy_binding` | subject = client, scope = channel, grant = publish/subscribe capability | Connection metadata can live in client/channel attributes |

In Magistrala terms, domain is tenant. Atom now exposes `tenant` as a first-class object with its own table and lifecycle endpoints (`POST /tenants`, `GET /tenants`, enable/disable/freeze/delete). It is **not** modelled as a `resources(kind='tenant')` row — the tenant is a boundary, not a principal.

When Magistrala creates a domain, the domain UUID becomes both the new tenant's `id` and the `tenant_id` reused on every other Atom object scoped to that domain (entities, groups, resources, roles).

Human users are global identities. A user is not stored inside one tenant. A user's access to tenant resources comes from policy bindings.

Important PDP note: if Atom needs broad tenant-scoped authorization such as "this group can publish to all channels in this tenant", the authorization context must include top-level tenant fields such as `resource.tenant_id` and, for tenant-scoped subjects like clients, `entity.tenant_id`. Human users remain global and receive tenant access through policy bindings. Atom's current ABAC evaluator reads attributes and request context; it should be extended to expose top-level tenant fields for first-class tenant authorization. Until that is done, use direct resource-scoped policies for strict client-channel connections.

---

## Attribute contract

Magistrala should namespace all application-specific data:

```json
{
  "magistrala": {
    "route": "factory-1",
      "tags": ["production", "eu"],
      "metadata": {
      "site": "plant-a"
    }
  }
}
```

Atom should not interpret those fields for authentication or authorization unless they are explicitly used in ABAC conditions.

For example, this ABAC condition is valid because Atom can read dot-paths in attributes:

```json
{
  "entity.attributes.magistrala.metadata.site": "plant-a",
  "resource.attributes.magistrala.metadata.site": "plant-a"
}
```

---

## Real use case

Scenario:

- Magistrala creates a domain/tenant for `factory-1`.
- Alice is a global human user who is granted access to that tenant's resources.
- `sensor-001` is a client device in that domain.
- `temperature` is a channel in that domain.
- Devices in the `field-devices` group can publish to channels.
- Alice can subscribe to channels.
- At runtime, Magistrala asks Atom whether `sensor-001` can publish to `temperature`.

---

## Step 1: Create the tenant

Magistrala creates an Atom tenant for the domain. The tenant `id`
is the domain UUID — reuse it as `tenant_id` on every other object.

```http
POST /tenants
Authorization: Bearer <admin-token>
Content-Type: application/json
```

```json
{
  "name": "factory-1",
  "route": "factory-1",
  "tags": ["pilot"],
  "attributes": {
    "magistrala": {
      "region": "eu",
      "metadata": {"created_by": "magistrala"}
    }
  }
}
```

Response:

```json
{
  "id": "11111111-1111-1111-1111-111111111111",
  "name": "factory-1",
  "status": "active",
  ...
}
```

Status transitions map to the Magistrala domain lifecycle:

- `POST /tenants/:id/enable`  → `active`   (Magistrala `enabled`)
- `POST /tenants/:id/disable` → `inactive` (Magistrala `disabled`)
- `POST /tenants/:id/freeze`  → `frozen`   (Magistrala `freezed`)
- `DELETE /tenants/:id`       → `deleted`  (soft delete; row retained)

To enforce admin-only access to one specific tenant via Atom's
authorization engine, point a policy at it directly:

```json
{
  "subject_id": "<admin_or_service_id>",
  "action": "manage",
  "object_kind": "tenant",
  "object_id":   "11111111-1111-1111-1111-111111111111"
}
```

---

## Step 2: Create a user

```http
POST /entities
Authorization: Bearer <admin-token>
Content-Type: application/json
```

```json
{
  "kind": "human",
  "name": "alice@example.com",
  "tenant_id": null,
  "attributes": {
    "magistrala": {
      "email": "alice@example.com",
      "first_name": "Alice",
      "last_name": "Iyer",
      "tags": ["operator"],
      "metadata": {
        "team": "operations"
      }
    }
  }
}
```

Then create Alice's password credential:

```http
POST /entities/:alice_id/credentials/password
Authorization: Bearer <admin-token>
Content-Type: application/json
```

```json
{
  "password": "change-me"
}
```

Alice now authenticates through Atom:

```http
POST /auth/login
Content-Type: application/json
```

```json
{
  "identifier": "alice@example.com",
  "secret": "change-me",
  "kind": "password"
}
```

---

## Step 3: Create a client

```http
POST /entities
Authorization: Bearer <admin-token>
Content-Type: application/json
```

```json
{
  "kind": "device",
  "name": "sensor-001",
  "tenant_id": "11111111-1111-1111-1111-111111111111",
  "attributes": {
    "magistrala": {
      "identity": "sensor-001",
      "tags": ["temperature", "field"],
      "metadata": {
        "site": "plant-a",
        "line": "line-7"
      }
    }
  }
}
```

Create an API key for the client:

```http
POST /entities/:client_id/credentials/api-keys
Authorization: Bearer <admin-token>
Content-Type: application/json
```

```json
{
  "description": "sensor-001 production key",
  "expires_at": "2026-12-31T00:00:00Z"
}
```

Magistrala stores the returned API key once and uses it when the device connects.

---

## Step 4: Create a channel

```http
POST /resources
Authorization: Bearer <admin-token>
Content-Type: application/json
```

```json
{
  "kind": "channel",
  "name": "temperature",
  "tenant_id": "11111111-1111-1111-1111-111111111111",
  "owner_id": "<alice_id>",
  "attributes": {
    "magistrala": {
      "route": "factory-1.temperature",
      "status": "enabled",
      "tags": ["temperature"],
      "metadata": {
        "site": "plant-a",
        "unit": "celsius"
      }
    }
  }
}
```

---

## Step 5: Create groups

Atom groups are authorization subject groups. Use them when membership should grant access.

```http
POST /groups
Authorization: Bearer <admin-token>
Content-Type: application/json
```

```json
{
  "name": "field-devices",
  "tenant_id": "11111111-1111-1111-1111-111111111111",
  "description": "Devices deployed in the field"
}
```

Add the client to the group:

```http
POST /groups/:field_devices_group_id/members
Authorization: Bearer <admin-token>
Content-Type: application/json
```

```json
{
  "entity_id": "<client_id>"
}
```

If Magistrala needs group hierarchy, path, tags, or metadata, store the rich group profile as a resource and link it to the Atom group:

```http
POST /resources
Authorization: Bearer <admin-token>
Content-Type: application/json
```

```json
{
  "kind": "group_profile",
  "name": "field-devices",
  "tenant_id": "11111111-1111-1111-1111-111111111111",
  "attributes": {
    "magistrala": {
      "atom_group_id": "<field_devices_group_id>",
      "parent_id": null,
      "path": "field-devices",
      "level": 1,
      "tags": ["field"],
      "metadata": {
        "site": "plant-a"
      }
    }
  }
}
```

This keeps Atom's group table focused on authorization membership and keeps Magistrala-specific hierarchy data in attributes.

---

## Step 6: Use capabilities directly

Atom already seeds common capabilities such as `publish`, `subscribe`, `read`, `write`, `delete`, and `manage`.

Magistrala does not need roles for the core client-channel model. It can grant seeded capabilities directly in policy bindings.

```http
GET /capabilities
Authorization: Bearer <admin-token>
```

Find the IDs for:

- `publish`
- `subscribe`
- any other action Magistrala wants to enforce

---

## Step 7: Grant access

Grant field devices publish access to the `temperature` channel:

```http
POST /policies
Authorization: Bearer <admin-token>
Content-Type: application/json
```

```json
{
  "subject_kind": "group",
  "subject_id": "<field_devices_group_id>",
  "grant_kind": "capability",
  "grant_id": "<publish_capability_id>",
  "scope_kind": "resource",
  "scope_ref": "<channel_id>",
  "effect": "allow",
  "conditions": {}
}
```

Grant Alice subscribe access to the `temperature` channel:

```json
{
  "subject_kind": "entity",
  "subject_id": "<alice_id>",
  "grant_kind": "capability",
  "grant_id": "<subscribe_capability_id>",
  "scope_kind": "resource",
  "scope_ref": "<channel_id>",
  "effect": "allow",
  "conditions": {}
}
```

For a strict connection between one client and one channel, grant the client directly on that channel:

```json
{
  "subject_kind": "entity",
  "subject_id": "<client_id>",
  "grant_kind": "capability",
  "grant_id": "<publish_capability_id>",
  "scope_kind": "resource",
  "scope_ref": "<channel_id>",
  "effect": "allow",
  "conditions": {}
}
```

In this model, a Magistrala connection is an authorization fact. Listing connections is done by asking Atom what channels a client can access.

---

## Step 8: Runtime authorization

When `sensor-001` publishes a message to `temperature`, Magistrala asks Atom:

```http
POST /authz/check
Authorization: Bearer <mg-service-token>
Content-Type: application/json
```

```json
{
  "subject_id": "<client_id>",
  "resource_id": "<channel_id>",
  "action": "publish",
  "context": {
    "protocol": "mqtt",
    "topic": "factory-1.temperature"
  }
}
```

Allowed response:

```json
{
  "allowed": true,
  "reason": "allowed"
}
```

Denied response:

```json
{
  "allowed": false,
  "reason": "no matching allow policy"
}
```

Magistrala should treat Atom as authoritative. If Atom denies, the publish is rejected.

---

## Step 9: Listing and debugging

### What channels can this client publish to?

```http
GET /entities/:client_id/access?resource_kind=channel&action=publish
Authorization: Bearer <admin-token>
```

This is the Magistrala "list connected channels for client" view.

### Who can publish to this channel?

```http
GET /resources/:channel_id/access?action=publish&entity_kind=device
Authorization: Bearer <admin-token>
```

This is the inverse security view for a channel.

### What access does this group grant?

```http
GET /groups/:field_devices_group_id/access?resource_kind=channel
Authorization: Bearer <admin-token>
```

This is the review step before adding a client to a group.

### Why was publish denied?

```http
POST /authz/explain
Authorization: Bearer <admin-token>
Content-Type: application/json
```

```json
{
  "subject_id": "<client_id>",
  "resource_id": "<channel_id>",
  "action": "publish",
  "context": {
    "protocol": "mqtt"
  }
}
```

The response shows which policies were evaluated, which conditions matched, and why the decision was allow or deny.

### Audit channel access

```http
GET /audit?event=authz.check&entity_id=<client_id>
Authorization: Bearer <admin-token>
```

Use this for compliance, debugging, and support.

---

## Recommended Magistrala integration flow

1. Magistrala starts with a service identity in Atom.
2. Magistrala authenticates to Atom and receives a service token.
3. On domain creation, Magistrala reuses the domain UUID as Atom `tenant_id`.
4. On user creation, Magistrala creates a `human` entity and password credential.
5. On client creation, Magistrala creates a `device` or `service` entity and API key credential.
6. On channel creation, Magistrala creates a `channel` resource.
7. On group creation, Magistrala creates an Atom group for membership and optionally a `group_profile` resource for hierarchy metadata.
8. On connect, Magistrala creates a direct policy binding, or adds the client to a group that already has channel access.
9. On every publish, subscribe, read, or write operation, Magistrala calls `POST /authz/check`.
10. For admin UI listings, Magistrala calls Atom query endpoints instead of maintaining its own joins.

---

## Why this shape works

Atom remains generic and does not need to know Magistrala's full domain schema.

Magistrala keeps its product concepts:

- domains
- users
- clients
- channels
- groups
- connections

But the security source of truth is Atom:

- users and clients are Atom entities
- channels are Atom resources
- domains are Atom tenant IDs
- groups are Atom group subjects
- connections are Atom authorization grants
- credentials are Atom credentials
- sessions and tokens are Atom authentication
- decisions and explanations are Atom authorization
- listings are Atom access queries

This avoids a second identity system and avoids duplicating access-control logic inside Magistrala.

---

## Current gap

Atom entities and resources already have `attributes`, so users, clients, and channels fit this model directly.

Atom groups currently have `name`, `tenant_id`, and `description`, but no `attributes` field. Until groups support attributes directly, Magistrala has two options:

1. Use Atom groups only for authorization membership and store group hierarchy/profile data as a `group_profile` resource.
2. Add `attributes JSONB` to Atom groups in a future schema migration.

Option 1 requires no Atom schema change. Option 2 is cleaner if Magistrala needs first-class group hierarchy and tags inside Atom itself.
