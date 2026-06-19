# gRPC API Reference

Atom exposes four gRPC services on port **8081** by default, configurable with `GRPC_ADDR`.

The proto source lives at [`proto/atom/v1/atom.proto`](../proto/atom/v1/atom.proto). The generated proto reference lives at [`apidocs/grpc-reference.md`](./grpc-reference.md) and should be regenerated only when the proto changes.

---

## Connection

```text
host: atom:8081 inside Docker Compose, localhost:8081 only when explicitly exposed
protocol: gRPC (HTTP/2)
TLS: none inside the trusted service network; terminate TLS at the service mesh or load balancer in production
```

Runtime services should call Atom over the service network. The default container bind address is `0.0.0.0:8081` so sibling containers can reach Atom gRPC at `atom:8081`.

### Authentication Metadata

`AuthzService.Check`, `AliasService.ResolveAlias`, `CertificateService.ResolveCertificate`, and `CertificateService.RevokeEntityCertificates` require gRPC metadata:

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
| `object_kind` | `string` | conditional | Explicit protected object kind, for example `resource` or `tenant`. Must be set with `object_id`. |
| `object_id` | `string` UUID | conditional | Explicit protected object id. Must be set with `object_kind`. |
| `context` | `map<string, string>` | no | Flat ABAC context injected under the `context` key during evaluation. |

The gRPC interface supports flat `string -> string` context values only. Use HTTP/GraphQL for nested JSON context.

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

Validates a JWT or API key and returns the caller identity. JWTs are checked against the live signing keys and session state. API keys are checked by embedded credential id, argon2 hash, status, and expiry.

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
| `INTERNAL` | Database or internal error. |

**Example**

```bash
grpcurl -plaintext \
  -d '{"token": "'"$ATOM_TOKEN"'"}' \
  atom:8081 atom.v1.AuthService/Authenticate
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

#### `ResolveCertificate`

```text
rpc ResolveCertificate(ResolveCertificateRequest) returns (ResolveCertificateResponse)
```

Resolves an active Atom certificate credential by serial number, optionally checking the SHA-256 certificate fingerprint. Use this after a runtime service extracts a client certificate from mTLS.

Requires `authorization: Bearer <token>` metadata. The caller must have `authz.check` permission for the resolved certificate tenant or platform.

**Request: `ResolveCertificateRequest`**

| Field | Type | Required | Description |
|---|---|---|---|
| `serial_number` | `string` | yes | Normalized certificate serial number. |
| `fingerprint_sha256` | `string` | no | SHA-256 fingerprint over certificate DER. When provided, it must match the stored certificate fingerprint. |

**Response: `ResolveCertificateResponse`**

| Field | Type | Description |
|---|---|---|
| `entity_id` | `string` UUID | Entity that owns the certificate. |
| `tenant_id` | `string` UUID | Owning tenant; empty string if none. |
| `credential_id` | `string` UUID | Certificate credential id. |
| `expires_at` | `string` RFC3339 | Certificate expiry. |

**gRPC status codes**

| Code | Condition |
|---|---|
| `OK` | Certificate resolved and caller is authorized. |
| `UNAUTHENTICATED` | Authorization metadata is missing, malformed, expired, or invalid. |
| `PERMISSION_DENIED` | Caller lacks `authz.check` authority for the resolved tenant or platform. |
| `NOT_FOUND` | Certificate serial is unknown, revoked, expired, or fingerprint does not match. |
| `INTERNAL` | Database or internal error. |

**Example**

```bash
grpcurl -plaintext \
  -H 'authorization: Bearer '"$ATOM_TOKEN" \
  -d '{
    "serial_number": "01af23",
    "fingerprint_sha256": "0f2d..."
  }' \
  atom:8081 atom.v1.CertificateService/ResolveCertificate
```

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
