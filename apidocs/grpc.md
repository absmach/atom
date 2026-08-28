# gRPC API Reference

Atom exposes four gRPC services on port **8081** by default, configurable with `GRPC_ADDR`.

The proto source lives at [`proto/atom/v1/atom.proto`](../proto/atom/v1/atom.proto). The generated proto reference lives at [`apidocs/grpc-reference.md`](./grpc-reference.md) and should be regenerated only when the proto changes.

---

## Connection

```text
host: atom:8081 inside Docker Compose, localhost:8081 only when explicitly exposed
protocol: gRPC (HTTP/2)
TLS: plaintext unless ATOM_GRPC_TLS_CERT_PATH and ATOM_GRPC_TLS_KEY_PATH are both set
mTLS: set ATOM_GRPC_TLS_CLIENT_CA_PATH in addition to the server certificate and key
```

Runtime services should call Atom over the service network. The default
container bind address is `0.0.0.0:8081` so sibling containers can reach Atom
gRPC at `atom:8081`. A plaintext listener must stay on a private network or
behind a service mesh that supplies transport security. Setting only one of
the server certificate/key paths, or configuring an unreadable TLS file,
aborts startup. `ATOM_GRPC_TLS_CLIENT_CA_PATH` makes client certificates
mandatory and verified.

### Authentication Metadata

`AuthzService.Check`, `AuthService.AuthenticateCredential`,
`AliasService.ResolveAlias`, `CertificateService.ResolveCertificateV2`, and
`CertificateService.RevokeEntityCertificates` require gRPC metadata:

```text
authorization: Bearer <jwt-or-api-key>
```

`AuthService.Authenticate` is different: it validates a token passed in the request body and does not require authorization metadata.

### grpcurl

```bash
# List services from another container on the same Compose network.
grpcurl -plaintext atom:8081 list

# Describe a service.
grpcurl -plaintext atom:8081 describe atom.v1.AuthzService
```

---

## Services

### `atom.v1.AuthzService`

Authorization decisions. Call `Check` on every protected operation in a downstream service.

#### `Check`

```text
rpc Check(CheckRequest) returns (CheckResponse)
```

Evaluates whether a subject may perform an action on a protected object. Runs the same PDP algorithm as HTTP/GraphQL authorization checks: DB-backed permissions, deny-overrides-allow, and ABAC evaluation.

Requires `authorization: Bearer <token>` metadata. The caller must have `authz.check` permission for the relevant tenant or platform.

**Request: `CheckRequest`**

| Field | Type | Required | Description |
|---|---|---|---|
| `subject_id` | `string` UUID | yes | Entity performing the action. |
| `action` | `string` | yes | Action name, for example `publish`, `read`, or `manage`. |
| `resource_id` | `string` UUID | conditional | Legacy resource-row target. Mutually exclusive with `object_kind`/`object_id`; explicit object fields win if both are sent. |
| `object_kind` | `string` | conditional | Explicit protected object kind: `resource`, `tenant`, `entity`, `group`, `credential`, or `platform`. Non-platform kinds require `object_id`; `platform` requires it to be empty. |
| `object_id` | `string` UUID | conditional | Explicit protected object id. Required with every non-platform `object_kind`; forbidden for `platform`. |
| `context` | `map<string, string>` | no | Flat ABAC context injected under the `context` key during evaluation. |

The gRPC interface supports flat `string -> string` context values only. Use
the GraphQL `authzCheck` input for nested JSON context.

**Response: `CheckResponse`**

| Field | Type | Description |
|---|---|---|
| `allowed` | `bool` | Authorization decision. |
| `reason` | `string` | Human-readable explanation. |

**gRPC status codes**

| Code | Condition |
|---|---|
| `OK` | Decision returned; check the `allowed` field. |
| `INVALID_ARGUMENT` | UUID fields are malformed or target fields are inconsistent. |
| `UNAUTHENTICATED` | Authorization metadata is missing, malformed, expired, or invalid. |
| `PERMISSION_DENIED` | Caller lacks `authz.check` authority for the request scope. |
| `INTERNAL` | Database or internal error. |

**Example**

```bash
grpcurl -plaintext \
  -H 'authorization: Bearer '"$ATOM_TOKEN" \
  -d '{
    "subject_id": "550e8400-e29b-41d4-a716-446655440000",
    "action": "publish",
    "object_kind": "resource",
    "object_id": "7c4b7f1e-4b9e-4b7f-8b4b-7f1e4b9e4b7f",
    "context": {
      "ip_trusted": "true"
    }
  }' \
  atom:8081 atom.v1.AuthzService/Check
```

---

### `atom.v1.AuthService`

Token authentication. Use `Authenticate` to validate incoming Bearer tokens in downstream services without decoding JWTs locally.

#### `Authenticate`

```text
rpc Authenticate(AuthenticateRequest) returns (AuthenticateResponse)
```

Validates a JWT or API key and returns the caller identity. JWTs are checked
against the live signing keys and session state. API keys use their embedded
credential id for lookup, then a constant-time keyed HMAC-SHA256 verifier under
the deployment KEK (with the legacy Argon2 verifier fallback when no KEK is
configured), plus live status and expiry checks.

This RPC does not require authorization metadata because the token to validate is carried in the request body.

**Request: `AuthenticateRequest`**

| Field | Type | Required | Description |
|---|---|---|---|
| `token` | `string` | yes | JWT or Atom API key, without the `Bearer ` prefix. |

**Response: `AuthenticateResponse`**

| Field | Type | Description |
|---|---|---|
| `entity_id` | `string` UUID | Authenticated entity. |
| `tenant_id` | `string` UUID | Entity tenant; empty string if none. |
| `session_id` | `string` UUID | Backing JWT session; empty string for API keys. |

**gRPC status codes**

| Code | Condition |
|---|---|
| `OK` | Token valid. |
| `UNAUTHENTICATED` | Token missing, malformed, expired, revoked, or invalid. |
| `PERMISSION_DENIED` | A configured authentication callout denies the operation. |
| `INTERNAL` | Database or internal error. |

**Example**

```bash
grpcurl -plaintext \
  -d '{"token": "'"$ATOM_TOKEN"'"}' \
  atom:8081 atom.v1.AuthService/Authenticate
```

#### `AuthenticateCredential`

```text
rpc AuthenticateCredential(AuthenticateCredentialRequest) returns (AuthenticateCredentialResponse)
```

Authenticates a password or shared key for a protocol adapter without minting
a session. This is a delegated operation: the adapter authenticates itself
with `authorization: Bearer <token>` metadata, while the target identity's
plaintext credential is carried in the request body. The caller must hold
`authz.check` for the selected tenant, or at platform scope when no tenant is
selected.

At most one of `tenant_id` and `tenant_alias` may be supplied. Leaving both
empty selects the global namespace. An explicitly selected tenant must exist
and be active. Authentication failures do not reveal whether the tenant,
identity, or credential exists.

**Request: `AuthenticateCredentialRequest`**

| Field | Type | Required | Description |
|---|---|---|---|
| `identifier` | `string` | yes | Password: entity UUID, email, name, or tenant-scoped alias. Shared key: machine-entity identifier. |
| `secret` | `string` | yes | Plaintext password or shared key. Never stored in plaintext or forwarded to callouts. |
| `kind` | `string` | no | `password` (also the empty-string default) or `shared_key`. |
| `tenant_id` | `string` UUID | conditional | Tenant UUID selector; mutually exclusive with `tenant_alias`. |
| `tenant_alias` | `string` | conditional | Case-insensitive tenant alias selector; mutually exclusive with `tenant_id`. |

**Response: `AuthenticateCredentialResponse`**

| Field | Type | Description |
|---|---|---|
| `entity_id` | `string` UUID | Authenticated entity. |
| `tenant_id` | `string` UUID | Owning tenant; empty for a global entity. |
| `credential_id` | `string` UUID | Exact credential that authenticated. |

**gRPC status codes**

| Code | Condition |
|---|---|
| `OK` | Credential valid and caller authorized. |
| `INVALID_ARGUMENT` | Kind or tenant selector shape is invalid. |
| `UNAUTHENTICATED` | Caller metadata or target credential is invalid. |
| `PERMISSION_DENIED` | Caller lacks delegated `authz.check` authority or a configured callout denies the operation. |
| `INTERNAL` | Database or internal error. |

**Example**

```bash
grpcurl -plaintext \
  -H 'authorization: Bearer '"$ATOM_TOKEN" \
  -d '{
    "identifier": "device-a",
    "secret": "<target-shared-key>",
    "kind": "shared_key",
    "tenant_alias": "factory-a"
  }' \
  atom:8081 atom.v1.AuthService/AuthenticateCredential
```

---

### `atom.v1.AliasService`

Alias resolution converts human-friendly tenant/entity/resource handles into canonical UUIDs. Resolution does not grant access; callers must authorize the returned object UUID separately with `AuthzService.Check`.

#### `ResolveAlias`

```text
rpc ResolveAlias(ResolveAliasRequest) returns (ResolveAliasResponse)
```

Requires `authorization: Bearer <token>` metadata.

Exactly one tenant selector is required:

- `tenant_id` for a tenant UUID;
- `tenant_alias` for a case-insensitive tenant alias;
- `global = true` for an entity or resource whose `tenant_id` is null.

`object_kind` must be exactly `entity` or `resource` (case-insensitive). Other values return `INVALID_ARGUMENT`.

**Request: `ResolveAliasRequest`**

| Field | Type | Required | Description |
|---|---|---|---|
| `tenant_id` | `string` UUID | conditional | Tenant UUID selector. |
| `tenant_alias` | `string` | conditional | Tenant alias selector. |
| `global` | `bool` | conditional | Select the global null-tenant namespace. |
| `object_kind` | `string` | yes | `entity` or `resource`. |
| `object_alias` | `string` | yes | Object alias within the selected namespace. |

**Response: `ResolveAliasResponse`**

| Field | Type | Description |
|---|---|---|
| `tenant_id` | `string` UUID | Resolved tenant; empty for global objects. |
| `object_id` | `string` UUID | Resolved entity or resource UUID. |

**Example**

```bash
grpcurl -plaintext \
  -H 'authorization: Bearer '"$ATOM_TOKEN" \
  -d '{
    "tenant_alias": "factory-a",
    "object_kind": "resource",
    "object_alias": "telemetry"
  }' \
  atom:8081 atom.v1.AliasService/ResolveAlias
```

---

### `atom.v1.CertificateService`

Certificate runtime lookup and entity-wide certificate revocation for services that terminate mTLS outside Atom.

#### `ResolveCertificateV2`

```text
rpc ResolveCertificateV2(ResolveCertificateV2Request) returns (ResolveCertificateV2Response)
```

Resolves an authoritative certificate identity without relying on a globally unique serial. Supply at least one of leaf DER, leaf SHA-256 fingerprint, or the managed issuer-fingerprint/serial pair. If more than one selector is supplied, every selector must identify the same credential.

Atom denies credentials that are unknown, `revocation_pending`, revoked, expired, owned by an inactive/deleted entity, owned by a frozen/deleted tenant, or issued by an authority that is unavailable for verification. Certificates from retiring and retained retired issuers continue to verify until expiry. An optional expected tenant is compared before the caller proceeds to authorization; a global entity always returns an empty tenant.

Requires `authorization: Bearer <token>` metadata. The caller must have `authz.check` permission for the resolved certificate tenant or platform.

**Request: `ResolveCertificateV2Request`**

| Field | Type | Required | Description |
|---|---|---|---|
| `certificate_der` | `bytes` | conditional | Complete leaf certificate DER, limited to 64 KiB. Atom derives its SHA-256 fingerprint. |
| `fingerprint_sha256` | `string` | conditional | SHA-256 over leaf DER; separators and case are normalized. |
| `issuer_fingerprint_sha256` | `string` | conditional | Managed issuer certificate SHA-256. Must be paired with `serial_number`. |
| `serial_number` | `string` | conditional | Normalized certificate serial. Must be paired with `issuer_fingerprint_sha256`. |
| `expected_tenant_id` | `string` UUID | no | Tenant the relying party expects. A mismatch, including global versus tenant-owned, is denied. |

**Response: `ResolveCertificateV2Response`**

| Field | Type | Description |
|---|---|---|
| `entity_id` | `string` UUID | Entity that owns the certificate. |
| `tenant_id` | `string` UUID | Owning tenant; empty for a global entity. |
| `credential_id` | `string` UUID | Exact certificate credential. |
| `issuer_id` | `string` UUID | Exact managed issuer; empty only for a legacy file-issuer credential resolved by DER/fingerprint. |
| `expires_at` | `string` RFC3339 | Certificate expiry. |
| `status` | `string` | Verified credential status (`active`). |

**gRPC status codes**

| Code | Condition |
|---|---|
| `OK` | All selectors agree, every lifecycle check passes, and the caller is authorized. |
| `INVALID_ARGUMENT` | Selector shape, UUID, fingerprint, serial, or DER is invalid or oversized. |
| `NOT_FOUND` | The sole exact selector does not identify a credential. |
| `UNAUTHENTICATED` | Caller metadata is invalid, selectors disagree, or certificate lifecycle validation fails. |
| `PERMISSION_DENIED` | Expected tenant mismatches or the caller lacks `authz.check` authority. |
| `INTERNAL` | Database or internal error. |

**Example**

```bash
grpcurl -plaintext \
  -H 'authorization: Bearer '"$ATOM_TOKEN" \
  -d '{
    "fingerprint_sha256": "0f2d...",
    "issuer_fingerprint_sha256": "8a91...",
    "serial_number": "01af23",
    "expected_tenant_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479"
  }' \
  atom:8081 atom.v1.CertificateService/ResolveCertificateV2
```

#### Cache invalidation events

When event publishing is configured, the existing `certificate.issue`, `certificate.renew`, `certificate.revoke`, and `certificate.revoke_entity` outbox events are the resolver cache-invalidation contract. Resolver caches should store the returned `credential_id`, `issuer_id`, and tenant alongside their lookup key so these exact lifecycle events can evict entries. Entity, tenant, and authority lifecycle events must also invalidate entries for their affected scope. Event delivery is at least once; consumers must make invalidation idempotent.

#### `RevokeEntityCertificates`

```text
rpc RevokeEntityCertificates(RevokeEntityCertificatesRequest) returns (RevokeEntityCertificatesResponse)
```

Revokes all active certificate credentials for an entity and marks CRL state dirty.

Requires `authorization: Bearer <token>` metadata. The caller must have credential `manage` authority on the target entity or its owning tenant.

**Request: `RevokeEntityCertificatesRequest`**

| Field | Type | Required | Description |
|---|---|---|---|
| `entity_id` | `string` UUID | yes | Entity whose active certificates should be revoked. |
| `reason` | `string` | no | Revocation reason stored in certificate metadata. |

**Response: `RevokeEntityCertificatesResponse`**

| Field | Type | Description |
|---|---|---|
| `revoked` | `uint64` | Number of certificates revoked. |

**gRPC status codes**

| Code | Condition |
|---|---|
| `OK` | Entity certificate revocation completed. |
| `INVALID_ARGUMENT` | `entity_id` is malformed. |
| `UNAUTHENTICATED` | Authorization metadata is missing, malformed, expired, or invalid. |
| `PERMISSION_DENIED` | Caller lacks credential manage authority. |
| `NOT_FOUND` | Target entity does not exist. |
| `INTERNAL` | Database or internal error. |

**Example**

```bash
grpcurl -plaintext \
  -H 'authorization: Bearer '"$ATOM_TOKEN" \
  -d '{
    "entity_id": "550e8400-e29b-41d4-a716-446655440000",
    "reason": "decommissioned"
  }' \
  atom:8081 atom.v1.CertificateService/RevokeEntityCertificates
```

---

## Client Examples

### Go

```go
md := metadata.Pairs("authorization", "Bearer "+token)
ctx := metadata.NewOutgoingContext(context.Background(), md)

authz := atomv1.NewAuthzServiceClient(conn)
resp, err := authz.Check(ctx, &atomv1.CheckRequest{
    SubjectId:  deviceID,
    Action:     "publish",
    ObjectKind: "resource",
    ObjectId:   channelID,
})
if err != nil {
    return err
}
if !resp.Allowed {
    return fmt.Errorf("denied: %s", resp.Reason)
}
```

### Python

```python
metadata = (("authorization", f"Bearer {token}"),)
response = stub.Check(atom_pb2.CheckRequest(
    subject_id=device_id,
    action="publish",
    object_kind="resource",
    object_id=channel_id,
), metadata=metadata)
if not response.allowed:
    raise PermissionError(response.reason)
```

### Rust (tonic)

```rust
use tonic::metadata::MetadataValue;
use atom_v1::authz_service_client::AuthzServiceClient;
use atom_v1::CheckRequest;

let mut client = AuthzServiceClient::connect("http://atom:8081").await?;
let mut request = tonic::Request::new(CheckRequest {
    subject_id: device_id.to_string(),
    action: "publish".to_string(),
    resource_id: String::new(),
    context: Default::default(),
    object_kind: "resource".to_string(),
    object_id: channel_id.to_string(),
});
request.metadata_mut().insert(
    "authorization",
    MetadataValue::try_from(format!("Bearer {token}"))?,
);

let resp = client.check(request).await?.into_inner();
```

---

## gRPC vs HTTP

| | gRPC | HTTP/GraphQL |
|---|---|---|
| Runtime authorization checks | Preferred | Works |
| Runtime token authentication | Preferred | Works |
| Runtime certificate lookup | Preferred | Not exposed as public management API |
| Management operations | Limited to certificate entity-wide revoke | Preferred |
| Browser clients | Not intended | Preferred |
| ABAC context | Flat `string -> string` only | Full JSON object |
