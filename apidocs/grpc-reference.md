# Protocol Documentation
<a name="top"></a>

## Table of Contents

- [atom/v1/atom.proto](#atom_v1_atom-proto)
    - [AuthenticateCredentialRequest](#atom-v1-AuthenticateCredentialRequest)
    - [AuthenticateCredentialResponse](#atom-v1-AuthenticateCredentialResponse)
    - [AuthenticateRequest](#atom-v1-AuthenticateRequest)
    - [AuthenticateResponse](#atom-v1-AuthenticateResponse)
    - [CheckRequest](#atom-v1-CheckRequest)
    - [CheckRequest.ContextEntry](#atom-v1-CheckRequest-ContextEntry)
    - [CheckResponse](#atom-v1-CheckResponse)
    - [ResolveAliasRequest](#atom-v1-ResolveAliasRequest)
    - [ResolveAliasResponse](#atom-v1-ResolveAliasResponse)
    - [ResolveCertificateV2Request](#atom-v1-ResolveCertificateV2Request)
    - [ResolveCertificateV2Response](#atom-v1-ResolveCertificateV2Response)
    - [RevokeEntityCertificatesRequest](#atom-v1-RevokeEntityCertificatesRequest)
    - [RevokeEntityCertificatesResponse](#atom-v1-RevokeEntityCertificatesResponse)
  
    - [AliasService](#atom-v1-AliasService)
    - [AuthService](#atom-v1-AuthService)
    - [AuthzService](#atom-v1-AuthzService)
    - [CertificateService](#atom-v1-CertificateService)
  
- [atom/v1/callout.proto](#atom_v1_callout-proto)
    - [Actor](#atom-v1-Actor)
    - [CalloutServiceCheckRequest](#atom-v1-CalloutServiceCheckRequest)
    - [CalloutServiceCheckResponse](#atom-v1-CalloutServiceCheckResponse)
  
    - [CalloutServiceCheckResponse.Decision](#atom-v1-CalloutServiceCheckResponse-Decision)
  
    - [CalloutService](#atom-v1-CalloutService)
  
- [Scalar Value Types](#scalar-value-types)



<a name="atom_v1_atom-proto"></a>
<p align="right"><a href="#top">Top</a></p>

## atom/v1/atom.proto



<a name="atom-v1-AuthenticateCredentialRequest"></a>

### AuthenticateCredentialRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| identifier | [string](#string) |  | Username-style identifier supplied by protocol adapters. For password credentials this may be an entity UUID, email, name, or a tenant-scoped entity alias. For shared_key credentials this identifies the machine entity whose key is being presented. |
| secret | [string](#string) |  | Plaintext secret supplied by the caller. Atom stores an Argon2 verifier for authentication. Retrievable shared keys also store an encrypted reveal copy and a keyed lookup digest; plaintext is never stored. |
| kind | [string](#string) |  | Supported values are &#34;password&#34; and &#34;shared_key&#34;. Empty falls back to &#34;password&#34; — the simplest auth model (basic username/secret). |
| tenant_id | [string](#string) |  |  |
| tenant_alias | [string](#string) |  |  |






<a name="atom-v1-AuthenticateCredentialResponse"></a>

### AuthenticateCredentialResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| entity_id | [string](#string) |  |  |
| tenant_id | [string](#string) |  |  |
| credential_id | [string](#string) |  |  |






<a name="atom-v1-AuthenticateRequest"></a>

### AuthenticateRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| token | [string](#string) |  | JWT (&#34;eyJ...&#34;) or API key (&#34;atom_...&#34;) — same as the HTTP Bearer value. |






<a name="atom-v1-AuthenticateResponse"></a>

### AuthenticateResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| entity_id | [string](#string) |  |  |
| tenant_id | [string](#string) |  | empty string if entity has no tenant |
| session_id | [string](#string) |  | empty string for API key authentication |






<a name="atom-v1-CheckRequest"></a>

### CheckRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| subject_id | [string](#string) |  |  |
| action | [string](#string) |  | capability name, e.g. &#34;publish&#34; |
| resource_id | [string](#string) |  | Legacy form: identifies a row in the `resources` table. Resolved with kind = `resources.kind`. Mutually exclusive with object_kind/object_id; if both are supplied, object_kind/object_id win. |
| context | [CheckRequest.ContextEntry](#atom-v1-CheckRequest-ContextEntry) | repeated | Optional ABAC context — flat string key/value pairs injected into the evaluation context under the &#34;context&#34; key. Note: only string values are supported over gRPC; use the GraphQL authzCheck input when nested JSON context is required. |
| object_kind | [string](#string) |  | Explicit form: identifies any first-class protected object. resource, tenant, entity, group, role, policy, credential, and api_endpoint require object_id. platform requires object_id to be empty. Supplying the explicit form takes precedence over the legacy resource_id field. |
| object_id | [string](#string) |  |  |






<a name="atom-v1-CheckRequest-ContextEntry"></a>

### CheckRequest.ContextEntry



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| key | [string](#string) |  |  |
| value | [string](#string) |  |  |






<a name="atom-v1-CheckResponse"></a>

### CheckResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| allowed | [bool](#bool) |  |  |
| reason | [string](#string) |  |  |






<a name="atom-v1-ResolveAliasRequest"></a>

### ResolveAliasRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| tenant_id | [string](#string) |  | Tenant selector — exactly one of tenant_id, tenant_alias, or global must be set. tenant_alias is the case-folded tenant slug. |
| tenant_alias | [string](#string) |  |  |
| object_kind | [string](#string) |  | Which table the object alias addresses: &#34;entity&#34; (clients/devices) or &#34;resource&#34; (channels). Other values are rejected. Generic on purpose — no domain/channel vocabulary. |
| object_alias | [string](#string) |  | The object&#39;s alias slug, unique within the tenant. |
| global | [bool](#bool) |  | Resolve an entity or resource whose tenant_id is NULL. |






<a name="atom-v1-ResolveAliasResponse"></a>

### ResolveAliasResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| tenant_id | [string](#string) |  | empty string for global objects |
| object_id | [string](#string) |  |  |






<a name="atom-v1-ResolveCertificateV2Request"></a>

### ResolveCertificateV2Request
Unambiguous runtime resolution. At least one of certificate_der,
fingerprint_sha256, or the issuer-fingerprint/serial pair is required. When
multiple selectors are supplied they must all identify the same credential.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| certificate_der | [bytes](#bytes) |  |  |
| fingerprint_sha256 | [string](#string) |  |  |
| issuer_fingerprint_sha256 | [string](#string) |  |  |
| serial_number | [string](#string) |  |  |
| expected_tenant_id | [string](#string) |  | Optional tenant binding. Empty means no expected tenant; a global entity still resolves with an empty tenant_id and never acquires tenant scope. |






<a name="atom-v1-ResolveCertificateV2Response"></a>

### ResolveCertificateV2Response



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| entity_id | [string](#string) |  |  |
| tenant_id | [string](#string) |  |  |
| credential_id | [string](#string) |  |  |
| issuer_id | [string](#string) |  |  |
| expires_at | [string](#string) |  |  |
| status | [string](#string) |  |  |






<a name="atom-v1-RevokeEntityCertificatesRequest"></a>

### RevokeEntityCertificatesRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| entity_id | [string](#string) |  |  |
| reason | [string](#string) |  |  |






<a name="atom-v1-RevokeEntityCertificatesResponse"></a>

### RevokeEntityCertificatesResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| revoked | [uint64](#uint64) |  |  |





 

 

 


<a name="atom-v1-AliasService"></a>

### AliasService
AliasService resolves human-friendly alias slugs to canonical UUIDs.
Atom owns the alias registry and its uniqueness; callers (e.g. a message
broker) resolve an alias once, cache the UUID, then authorize by UUID via
AuthzService.Check. Resolution is capability-neutral — it reveals only the
UUIDs; the Check call is the authorization gate.

| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| ResolveAlias | [ResolveAliasRequest](#atom-v1-ResolveAliasRequest) | [ResolveAliasResponse](#atom-v1-ResolveAliasResponse) | Requires authorization: Bearer &lt;JWT-or-Atom-access-token&gt; metadata. Alias resolution itself has no capability gate; callers must authorize the returned UUID separately with AuthzService.Check. |


<a name="atom-v1-AuthService"></a>

### AuthService
AuthService validates tokens and delegated password/shared-key credentials.
Use Authenticate to validate incoming tokens without decoding JWTs locally.

| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| Authenticate | [AuthenticateRequest](#atom-v1-AuthenticateRequest) | [AuthenticateResponse](#atom-v1-AuthenticateResponse) | Requires no authorization metadata. The credential being authenticated is the token carried in the request body. |
| AuthenticateCredential | [AuthenticateCredentialRequest](#atom-v1-AuthenticateCredentialRequest) | [AuthenticateCredentialResponse](#atom-v1-AuthenticateCredentialResponse) | Requires authorization: Bearer &lt;JWT-or-Atom-access-token&gt; metadata. The caller must hold authz.check for the selected tenant, or at platform scope when no tenant is selected. The plaintext target credential stays in the request body and is never treated as caller authentication. |


<a name="atom-v1-AuthzService"></a>

### AuthzService
AuthzService evaluates authorization decisions.
Call this on every request to protected downstream resources.

| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| Check | [CheckRequest](#atom-v1-CheckRequest) | [CheckResponse](#atom-v1-CheckResponse) | Requires authorization: Bearer &lt;JWT-or-Atom-access-token&gt; metadata. The caller must hold authz.check for the target tenant or platform; the subject being evaluated may be different from the caller. |


<a name="atom-v1-CertificateService"></a>

### CertificateService
CertificateService resolves and revokes Atom certificate credentials for
runtime services that terminate mTLS outside Atom.

| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| ResolveCertificateV2 | [ResolveCertificateV2Request](#atom-v1-ResolveCertificateV2Request) | [ResolveCertificateV2Response](#atom-v1-ResolveCertificateV2Response) | ResolveCertificate was removed before v1; its RPC name is reserved by contract and must not be reused. Consumers use ResolveCertificateV2. Requires authorization: Bearer &lt;JWT-or-Atom-access-token&gt; metadata. The caller must hold authz.check for the resolved tenant or platform. |
| RevokeEntityCertificates | [RevokeEntityCertificatesRequest](#atom-v1-RevokeEntityCertificatesRequest) | [RevokeEntityCertificatesResponse](#atom-v1-RevokeEntityCertificatesResponse) | Requires authorization: Bearer &lt;JWT-or-Atom-access-token&gt; metadata. The caller must hold manage on the target entity or its owning tenant. |

 



<a name="atom_v1_callout-proto"></a>
<p align="right"><a href="#top">Top</a></p>

## atom/v1/callout.proto



<a name="atom-v1-Actor"></a>

### Actor



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| entity_id | [string](#string) |  |  |
| tenant_id | [string](#string) |  |  |
| scope | [string](#string) |  | &#34;session&#34; | &#34;access_token&#34; | &#34;&#34; |
| credential_id | [string](#string) |  |  |
| source_ip | [string](#string) |  |  |
| user_agent | [string](#string) |  |  |






<a name="atom-v1-CalloutServiceCheckRequest"></a>

### CalloutServiceCheckRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| operation | [string](#string) |  | Operation identifier — a GraphQL resolver name (e.g. &#34;createEntity&#34;) or a fully-qualified gRPC method (&#34;atom.v1.AuthzService/Check&#34;). |
| surface | [string](#string) |  | Which atom surface the call is originating from.

&#34;graphql&#34; | &#34;grpc&#34; |
| request_id | [string](#string) |  | Correlation id atom assigns to each callout request. |
| time | [string](#string) |  | RFC-3339 UTC timestamp when the callout was issued. |
| actor | [Actor](#atom-v1-Actor) |  | The authenticated caller. Populated from atom&#39;s AuthContext post-authn, so it is safe to trust here for policy evaluation. |
| args | [google.protobuf.Struct](#google-protobuf-Struct) |  | The operation&#39;s arguments, filtered by the per-operation `include:` list in atom&#39;s config. A whitelist is applied and a hard denylist strips any obviously-sensitive keys (secret, password, key) as a safety net. |
| extra | [google.protobuf.Struct](#google-protobuf-Struct) |  | Static key/value pairs merged in from config (`extra:` per operation). |






<a name="atom-v1-CalloutServiceCheckResponse"></a>

### CalloutServiceCheckResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| decision | [CalloutServiceCheckResponse.Decision](#atom-v1-CalloutServiceCheckResponse-Decision) |  |  |
| reason | [string](#string) |  | Human-readable reason surfaced back to the caller on deny. |





 


<a name="atom-v1-CalloutServiceCheckResponse-Decision"></a>

### CalloutServiceCheckResponse.Decision
DECISION_UNSPECIFIED is the zero value and is treated as DENY at runtime
to preserve atom&#39;s default-deny invariant: an unset or undecodable
response never accidentally allows the operation.

| Name | Number | Description |
| ---- | ------ | ----------- |
| DECISION_UNSPECIFIED | 0 |  |
| DECISION_ALLOW | 1 |  |
| DECISION_DENY | 2 |  |


 

 


<a name="atom-v1-CalloutService"></a>

### CalloutService
CalloutService is the wire contract atom speaks with an external policy
service.

Atom sends one Check() per intercepted operation, before executing it. The
external service inspects the operation, actor and per-operation args, and
replies with ALLOW (proceed) or DENY (short-circuit with the given reason).
Multiple endpoints may be chained in config; atom calls them in order and
fails fast on the first non-ALLOW response.

See docs in AGENTS.md and config/examples/callouts.yaml for configuration.

| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| Check | [CalloutServiceCheckRequest](#atom-v1-CalloutServiceCheckRequest) | [CalloutServiceCheckResponse](#atom-v1-CalloutServiceCheckResponse) |  |

 



## Scalar Value Types

| .proto Type | Notes | C++ | Java | Python | Go | C# | PHP | Ruby |
| ----------- | ----- | --- | ---- | ------ | -- | -- | --- | ---- |
| <a name="double" /> double |  | double | double | float | float64 | double | float | Float |
| <a name="float" /> float |  | float | float | float | float32 | float | float | Float |
| <a name="int32" /> int32 | Uses variable-length encoding. Inefficient for encoding negative numbers – if your field is likely to have negative values, use sint32 instead. | int32 | int | int | int32 | int | integer | Bignum or Fixnum (as required) |
| <a name="int64" /> int64 | Uses variable-length encoding. Inefficient for encoding negative numbers – if your field is likely to have negative values, use sint64 instead. | int64 | long | int/long | int64 | long | integer/string | Bignum |
| <a name="uint32" /> uint32 | Uses variable-length encoding. | uint32 | int | int/long | uint32 | uint | integer | Bignum or Fixnum (as required) |
| <a name="uint64" /> uint64 | Uses variable-length encoding. | uint64 | long | int/long | uint64 | ulong | integer/string | Bignum or Fixnum (as required) |
| <a name="sint32" /> sint32 | Uses variable-length encoding. Signed int value. These more efficiently encode negative numbers than regular int32s. | int32 | int | int | int32 | int | integer | Bignum or Fixnum (as required) |
| <a name="sint64" /> sint64 | Uses variable-length encoding. Signed int value. These more efficiently encode negative numbers than regular int64s. | int64 | long | int/long | int64 | long | integer/string | Bignum |
| <a name="fixed32" /> fixed32 | Always four bytes. More efficient than uint32 if values are often greater than 2^28. | uint32 | int | int | uint32 | uint | integer | Bignum or Fixnum (as required) |
| <a name="fixed64" /> fixed64 | Always eight bytes. More efficient than uint64 if values are often greater than 2^56. | uint64 | long | int/long | uint64 | ulong | integer/string | Bignum |
| <a name="sfixed32" /> sfixed32 | Always four bytes. | int32 | int | int | int32 | int | integer | Bignum or Fixnum (as required) |
| <a name="sfixed64" /> sfixed64 | Always eight bytes. | int64 | long | int/long | int64 | long | integer/string | Bignum |
| <a name="bool" /> bool |  | bool | boolean | boolean | bool | bool | boolean | TrueClass/FalseClass |
| <a name="string" /> string | A string must always contain UTF-8 encoded or 7-bit ASCII text. | string | String | str/unicode | string | string | string | String (UTF-8) |
| <a name="bytes" /> bytes | May contain any arbitrary sequence of bytes. | string | ByteString | str | []byte | ByteString | string | String (ASCII-8BIT) |

