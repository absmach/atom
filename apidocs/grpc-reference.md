# Protocol Documentation
<a name="top"></a>

## Table of Contents

- [atom/v1/atom.proto](#atom_v1_atom-proto)
    - [AuthenticateRequest](#atom-v1-AuthenticateRequest)
    - [AuthenticateResponse](#atom-v1-AuthenticateResponse)
    - [CheckRequest](#atom-v1-CheckRequest)
    - [CheckRequest.ContextEntry](#atom-v1-CheckRequest-ContextEntry)
    - [CheckResponse](#atom-v1-CheckResponse)
    - [ResolveAliasRequest](#atom-v1-ResolveAliasRequest)
    - [ResolveAliasResponse](#atom-v1-ResolveAliasResponse)
    - [ResolveCertificateRequest](#atom-v1-ResolveCertificateRequest)
    - [ResolveCertificateResponse](#atom-v1-ResolveCertificateResponse)
    - [RevokeEntityCertificatesRequest](#atom-v1-RevokeEntityCertificatesRequest)
    - [RevokeEntityCertificatesResponse](#atom-v1-RevokeEntityCertificatesResponse)
  
    - [AliasService](#atom-v1-AliasService)
    - [AuthService](#atom-v1-AuthService)
    - [AuthzService](#atom-v1-AuthzService)
    - [CertificateService](#atom-v1-CertificateService)
  
- [Scalar Value Types](#scalar-value-types)



<a name="atom_v1_atom-proto"></a>
<p align="right"><a href="#top">Top</a></p>

## atom/v1/atom.proto



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
| context | [CheckRequest.ContextEntry](#atom-v1-CheckRequest-ContextEntry) | repeated | Optional ABAC context — flat string key/value pairs injected into the evaluation context under the &#34;context&#34; key. Note: only string values are supported over gRPC; use REST for nested JSON. |
| object_kind | [string](#string) |  | Explicit form: identifies any first-class protected object. Supported object_kind values: &#34;resource&#34; (same as resource_id) or &#34;tenant&#34; (resolved from the `tenants` table; kind = &#34;tenant&#34;). Both fields must be set together, or both empty. |
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






<a name="atom-v1-ResolveCertificateRequest"></a>

### ResolveCertificateRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| serial_number | [string](#string) |  |  |
| fingerprint_sha256 | [string](#string) |  |  |






<a name="atom-v1-ResolveCertificateResponse"></a>

### ResolveCertificateResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| entity_id | [string](#string) |  |  |
| tenant_id | [string](#string) |  |  |
| credential_id | [string](#string) |  |  |
| expires_at | [string](#string) |  |  |






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
| ResolveAlias | [ResolveAliasRequest](#atom-v1-ResolveAliasRequest) | [ResolveAliasResponse](#atom-v1-ResolveAliasResponse) |  |


<a name="atom-v1-AuthService"></a>

### AuthService
AuthService validates tokens and returns caller identity.
Use this to authenticate incoming requests without decoding JWTs locally.

| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| Authenticate | [AuthenticateRequest](#atom-v1-AuthenticateRequest) | [AuthenticateResponse](#atom-v1-AuthenticateResponse) |  |


<a name="atom-v1-AuthzService"></a>

### AuthzService
AuthzService evaluates authorization decisions.
Call this on every request to protected downstream resources.

| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| Check | [CheckRequest](#atom-v1-CheckRequest) | [CheckResponse](#atom-v1-CheckResponse) |  |


<a name="atom-v1-CertificateService"></a>

### CertificateService
CertificateService resolves and revokes Atom certificate credentials for
runtime services that terminate mTLS outside Atom.

| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| ResolveCertificate | [ResolveCertificateRequest](#atom-v1-ResolveCertificateRequest) | [ResolveCertificateResponse](#atom-v1-ResolveCertificateResponse) |  |
| RevokeEntityCertificates | [RevokeEntityCertificatesRequest](#atom-v1-RevokeEntityCertificatesRequest) | [RevokeEntityCertificatesResponse](#atom-v1-RevokeEntityCertificatesResponse) |  |

 



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

