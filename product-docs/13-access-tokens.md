# Scoped Access Tokens

## Status: Active v1
## Date: 2026-07-01

This document defines self-service scoped access tokens. The source of truth for overall product requirements is [Atom Product Requirements Document](./PRD.md), and authorization terminology is defined in [Atom access model](./11-access-model-simplification.md).

---

## Product Goal

Access tokens let a human, service, workload, or application create a least-privilege bearer token for CLI and API use without asking an operator for a broad platform key.

The token should be useful for automation, but it must never become a second authorization system. Atom still evaluates current database state on every request.

---

## Product Shape

Atom has two product labels for bearer credentials backed by `credentials.kind = access_token`:

| Product label | Creator | Scope | Intended use |
|---|---|---|---|
| API key | Credential administrator | Unscoped | Provisioned machine or service access with the owner's live grants |
| Scoped access token | Token owner, or an administrator via delegation | Scoped by a permission ceiling | Personal, CLI, integration, service, and automation access that is narrower than the owner |

> **Status (interim):** the dedicated unscoped **API-key creation** surface
> (`createApiKey`) has been removed. Unscoped `access_token` credentials still
> authenticate (bootstrap and pre-existing keys), but the only token-minting API is
> now `createAccessToken`, which always produces a scoped token. Provisioned service
> access is covered by **delegated minting** (below). A future "mirror owner" ceiling
> preset will reproduce the unscoped, live-grant-tracking behaviour under the single
> primitive.

Both use the same one-time-reveal token format:

```text
atom_<32-hex-credential-id>_<64-hex-secret>
```

The credential ID is embedded for direct lookup. The secret is argon2-hashed; plaintext is never stored and cannot be recovered.

---

## Permission Ceiling

A scoped access token carries a permission ceiling. Each ceiling row is an allow-list entry with:

- one or more action names;
- one scope mode: `platform`, `tenant`, `object_kind`, `object_type`, or `object`;
- the matching scope reference, such as a tenant ID, object kind, full object type (`entity:device`), or object ID;
- optional ABAC conditions.

Effective access is always:

```text
owner live authority intersect access-token ceiling
```

The ceiling cannot grant anything the owner does not already hold. If the owner's role or Direct Policy is removed, the token loses that access immediately. If the token is revoked, expired, or its ceiling rows are removed, the token is denied on the next request.

An empty ceiling is not interpreted as "full access". It is a closed ceiling and permits nothing.

---

## Authorization Semantics

Scoped tokens are evaluated in the same PDP path as normal requests.

- `authzCheck`, `authzBulkCheck`, gRPC `AuthzService.Check`, and object reads apply the ceiling when the checked subject is the token owner.
- `authzExplain` also applies the ceiling. If the owner would be allowed but the token ceiling omits the requested action or scope, the reason is `denied by access token permission ceiling`.
- Delegated checks about another subject are not altered by the caller's token ceiling. The caller still needs permission to invoke the check, and that caller permission is capped by the caller's scoped token.
- Owner-policy `deny` still overrides allow.
- Conditional ceiling entries are evaluated where a full object decision exists. Coarse control-plane gates that do not have enough object context must fail closed unless the ceiling contains an unconditional matching allow.

Scoped tokens cannot call broad authorized-listing surfaces that are not ceiling-aware. They must use per-object `authzCheck` or direct object reads. This avoids leaking the owner's full authorized set while ceiling-aware SQL listing and pagination are deferred.

---

## Self-Escalation Guardrails

A scoped token must not be able to widen itself or create a broader sibling.

The following operations require an unscoped session or unscoped credential:

- create a scoped access token;
- replace a scoped access token's permissions;
- revoke an access token;
- create, rotate, reveal, or revoke credentials through credential-management APIs.

This is stricter than checking whether the owner has `manage` on `credential`; the token itself is not allowed to exercise credential-management authority.

### Delegated minting

`createAccessToken` accepts an optional `subjectId`. Omitted or equal to the
caller, it is self-service (the caller mints for itself). A different `subjectId`
is a *delegated* mint and requires an unscoped caller with `manage` on the target
subject (or its tenant) — the same gate as any other credential-management
operation, so a scoped token can never mint delegated tokens.

The ceiling is never validated against the target's grants at mint time. Effective
access stays `target live authority intersect ceiling`, evaluated on every request,
so a delegated token can never exceed the target even if the ceiling names more.

---

## GraphQL Surface

Access tokens are managed through the authenticated profile surface:

```graphql
query AccessTokens {
  accessTokens {
    items {
      credentialId
      name
      description
      identifier
      status
      scoped
      permissions {
        actions
        scopeMode
        tenantId
        objectKind
        objectType
        objectId
        conditions
      }
      expiresAt
      createdAt
    }
    total
  }
}
```

Create a read-only token for all resources:

```graphql
mutation CreateAccessToken($input: CreateAccessTokenInput!) {
  createAccessToken(input: $input) {
    credentialId
    token
    name
    expiresAt
  }
}
```

Example variables:

```json
{
  "input": {
    "name": "laptop CLI",
    "description": "Local automation token",
    "permissions": [
      {
        "actions": ["read"],
        "scopeMode": "object_kind",
        "objectKind": "resource"
      }
    ]
  }
}
```

Mint a token for a service (delegated — requires an unscoped caller with `manage`
on the target subject). `subjectId` sets the token owner; omit it for self-service:

```json
{
  "input": {
    "name": "ingest-svc token",
    "subjectId": "<service-entity-id>",
    "permissions": [
      { "actions": ["read"], "scopeMode": "object", "objectId": "<channel-id>" }
    ]
  }
}
```

Conditional (ABAC) ceiling entry — evaluated where a full object decision exists;
coarse control-plane gates fail closed on conditional entries:

```json
{
  "actions": ["read"],
  "scopeMode": "object_kind",
  "objectKind": "resource",
  "conditions": { "context.region": "eu" }
}
```

Replace the ceiling:

```graphql
mutation ReplaceAccessTokenPermissions(
  $credentialId: ID!
  $permissions: [AccessTokenPermissionInput!]!
) {
  replaceAccessTokenPermissions(
    credentialId: $credentialId
    permissions: $permissions
  )
}
```

Revoke a token:

```graphql
mutation RevokeAccessToken($credentialId: ID!) {
  revokeAccessToken(credentialId: $credentialId)
}
```

---

## Scope Input Rules

| `scopeMode` | Required field | Optional | Example |
|---|---|---|---|
| `platform` | none | — | all platform-scoped objects |
| `tenant` | `tenantId` | — | one tenant UUID |
| `object_kind` | `objectKind` | `tenantId` | `resource` |
| `object_type` | `objectKind`, `objectType` | `tenantId` | `entity:device` |
| `object` | `objectId` | — | one protected object UUID |

`objectType` must be the full namespaced value (`entity:device`, `resource:channel`), not the bare sub-kind; a mismatched or bare value is rejected at creation.

When `tenantId` is set on an `object_kind` / `object_type` entry, matches are confined to that tenant; omit it for a tenant-agnostic ceiling. At least one permission is required — an empty ceiling is closed and permits nothing.

---

## Audit And Operations

Access-token lifecycle changes are credential lifecycle events:

- create: `credential.create`
- permission replacement: `credential.update`
- revoke: `credential.revoke`

Operators should treat scoped tokens as live credentials:

- set expirations for temporary automation;
- revoke unused tokens;
- inspect token permissions before debugging an authorization failure;
- prefer exact-object or object-type scopes over platform scopes for CLI tokens.

---

## Non-Goals In v1

- OAuth authorization-code or device-code grants.
- Refresh tokens for scoped access tokens.
- Token introspection that returns embedded permission claims.
- Ceiling-aware authorized-listing pagination.
- Admin lifecycle parity for delegated tokens: `accessTokens`,
  `replaceAccessTokenPermissions`, and `revokeAccessToken` are owner-scoped, so a
  delegated token is listed/replaced only by its owner. Revoke it as an admin via
  `revokeCredential` (`manage` on the target).
