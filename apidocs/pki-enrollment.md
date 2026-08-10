# PKI enrollment APIs

The native and RFC 7030 EST enrollment APIs are served only on the dedicated TLS listener
configured by `ATOM_PKI_ENROLLMENT_LISTEN_ADDR`. It is not mounted on Atom's
main HTTP port.

## `POST /pki/enroll`

Authenticate with `Authorization: Bearer <Atom token>`, where the token is an
active access token or a JWT session created by password/shared-key login. Atom
derives the target entity and tenant from that credential.

## `POST /pki/reenroll`

Authenticate with the certificate being replaced during the TLS handshake.
Atom verifies the chain in process against its managed trust bundle and resolves
the exact leaf DER to an active credential. HTTP headers cannot assert a peer
identity. A bearer token, if sent, is ignored on this operation.

## Request

Both operations use:

```json
{
  "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----\n...",
  "ttl_secs": 86400,
  "idempotency_key": "stable-key-for-an-exact-retry"
}
```

`ttl_secs` is optional. Unknown fields are rejected. The request never accepts
an entity, tenant, issuer, profile, subject, or downstream-consumer selector.

## Success response

```json
{
  "credential_id": "uuid",
  "entity_id": "uuid",
  "tenant_id": "uuid-or-null",
  "issuer_id": "uuid",
  "profile_id": "uuid",
  "profile_name": "client",
  "identity_uri": "urn:atom:tenant:...:entity:...",
  "serial_number": "lowercase-hex",
  "certificate_pem": "-----BEGIN CERTIFICATE-----\n...",
  "chain_pem": "-----BEGIN CERTIFICATE-----\n...",
  "not_after": "RFC3339 timestamp",
  "renewal_threshold_seconds": 86400,
  "renewal_due_at": "RFC3339 timestamp",
  "idempotent_replay": false
}
```

The renewal threshold is the effective certificate profile value. Exact retries
return the original credential with `idempotent_replay: true`. `429` responses
include `Retry-After`.

Expired, revoked, unknown, or inactive certificate subjects cannot use
re-enrollment. Recover by calling first enrollment with an active
non-certificate Atom credential.

## RFC 7030 EST adapter

The same listener exposes the standard EST paths below. EST is a wire adapter
over the native enrollment service; the authenticated subject still determines
the tenant, client profile, and active issuer. Atom does not implement an EST
additional path segment, and no selector field is accepted.

| Operation | Authentication | Request | Response |
| --- | --- | --- | --- |
| `GET /.well-known/est/cacerts` | none | empty | base64 certs-only PKCS#7 matching `/certs/trust-bundle.pem` |
| `POST /.well-known/est/simpleenroll` | HTTP Basic Atom password credential, or Bearer token | base64 DER PKCS#10; `application/pkcs10` | base64 certs-only PKCS#7 |
| `POST /.well-known/est/simplereenroll` | certificate being replaced in the TLS handshake | base64 DER PKCS#10; `application/pkcs10` | base64 certs-only PKCS#7 |
| `POST /.well-known/est/serverkeygen` | HTTP Basic Atom password credential, or Bearer token | base64 DER PKCS#10; `application/pkcs10` | `multipart/mixed` containing a one-time PKCS#8 key and certs-only PKCS#7 |
| `GET /.well-known/est/csrattrs` | HTTP Basic Atom password credential, or Bearer token | empty | base64 `application/csrattrs` derived from the applicable client profile |

For HTTP Basic authentication, use the entity UUID as the username and its
Atom password credential as the password. Atom derives scope from the
credential; URL segments, query parameters, and headers cannot choose another
tenant, issuer, entity, or profile. The generated private key returned by
`serverkeygen` is zeroized after the response and is never persisted or logged.
