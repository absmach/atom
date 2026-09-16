# GraphQL error contract (v1)

Issue [#101](https://github.com/absmach/atom/issues/101). This is the
product-level definition of Atom's stable GraphQL error metadata — the
response shape, the code table, retry behavior, and the security rules
governing what a message may contain. `apidocs/openapi.yaml` carries the
same contract as an OpenAPI schema (`GraphQLErrorExtensions`); this
document is the narrative version. It applies to Atom's base GraphQL
endpoint (`POST /graphql`) only — configured custom endpoints
(`/api/custom/*`) keep their own REST-shaped status/body mapping, unchanged
by this document.

**Compatibility rule.** The code table below, the response shape, and the
retry semantics are frozen for v1: a code is never renamed or repurposed,
and `retryable` for an existing code never flips. New optional keys may be
added to `extensions`; a client must ignore keys it does not recognize.

## What HTTP success means here

`POST /graphql` returning HTTP 200 means Atom parsed and attempted the
request — nothing more. A single GraphQL operation can touch several
fields, and each field resolves independently: the response commonly
carries **both** partial `data` and a non-empty `errors` array in the same
payload. A client must inspect `errors`, not only the HTTP status, before
treating a response as a success. This issue does not change that
partial-data model — it only adds stable metadata to whatever errors
already appear.

Transport-level failures that occur before any resolver runs — a missing or
invalid bearer token, an untrusted cookie origin, a policy callout denying
the operation, or async-graphql's own parse/validation/depth/complexity
rejection of a malformed request — are returned the same way, as GraphQL
errors in the same envelope, also at HTTP 200. They are not distinguished
from resolver failures at the transport level; `extensions.code` is what
distinguishes them.

## Response shape

```json
{
  "message": "forbidden",
  "path": ["updateResource"],
  "extensions": {
    "code": "FORBIDDEN",
    "retryable": false,
    "requestId": "2cc55e48-d44f-49ce-99e2-b08f06f619a6"
  }
}
```

- `message` — human-readable, safe to log or display, but **not** a stable
  API. Never parse it to classify an error; that is what `code` is for.
- `path` / `locations` — present when the error occurred inside a resolver;
  standard GraphQL fields, unchanged by this contract.
- `extensions.code` — always present. One of the nine values below.
- `extensions.retryable` — always present. Whether re-sending the identical
  request might succeed without any change from the client.
- `extensions.requestId` — always present. Matches this response's
  `X-Request-ID` header (see below) and every other error in the same
  response.
- `extensions.retryAfterSeconds` — present only when `code` is
  `RATE_LIMITED` and Atom knows the wait window.

## Codes

| Code | Meaning | Retryable |
|---|---|---|
| `BAD_REQUEST` | Invalid GraphQL syntax, validation, input, or reference | No |
| `UNAUTHENTICATED` | Authentication is missing, expired, revoked, or invalid | No |
| `FORBIDDEN` | The authenticated caller is not allowed | No |
| `NOT_FOUND` | The requested object does not exist or is not visible | No |
| `CONFLICT` | The request conflicts with current state | No |
| `PAYLOAD_TOO_LARGE` | The accepted payload limit was exceeded | No |
| `RATE_LIMITED` | A request limit was exceeded | Yes |
| `SERVICE_UNAVAILABLE` | A required dependency is temporarily unavailable | Yes |
| `INTERNAL` | Atom could not safely complete the operation | No |

This is the complete set for v1 — there is no tenth code, and there is no
per-validation-message code (`BAD_REQUEST` covers every input/validation
failure; the distinguishing detail, if any, stays in `message`).

A `false` `retryable` does not mean the *operation* can never succeed —
`BAD_REQUEST`/`CONFLICT`/`FORBIDDEN` are often resolved by changing the
request, not by retrying it unchanged. It means retrying the *identical*
request is not expected to help.

## Request correlation

Every Atom HTTP response — not only `/graphql` — carries an `X-Request-ID`
header. If the incoming request already has a valid one (bounded length,
letters/digits/`-`/`_`/`.` only), Atom echoes it back; otherwise Atom
generates one. "Valid" exists to stop a client from using this header to
smuggle unbounded or unsafe text into logs and error payloads — an invalid
incoming value is treated as absent, not rejected.

On `/graphql`, the same ID is stamped into `extensions.requestId` on every
error in the response. Use it to correlate a client-visible failure with
server-side logs and `audit_logs` rows for the same request.

## Security rules

- A message is never SQL, a database driver message, a stack trace, a
  secret, a credential, or an authorization-policy internal detail
  (permission block contents, role names a caller isn't entitled to see,
  etc.). Anything in that category is logged server-side and replaced with
  a generic `INTERNAL`/`database error`/`internal error` message.
- `NOT_FOUND` vs `FORBIDDEN` follows the same existence-masking rules the
  rest of Atom's authorization model already uses — do not assume the two
  are interchangeable or that either confirms an object's existence to an
  unauthorized caller.
- `requestId` and `code` are safe to log and display; `message` is safe to
  display but should not be parsed.

## Producing this contract (implementation notes)

- `AppError::public_contract()` (`src/error.rs`) is the one exhaustive
  mapping from `AppError` to `{code, message, retryable, retry_after_secs}`.
  It is reused by `graphql::auth::gql_error` (the adapter every GraphQL
  resolver failure goes through — see its doc comment) and by
  `graphql::graphql_error` (transport-level authentication failures that
  never reach a resolver). It does not replace the REST `IntoResponse` or
  gRPC `tonic::Status` conversions, which keep their own, separately
  frozen behavior.
- `graphql::attach_error_metadata` stamps `requestId` on every error in the
  final response and — only for errors that reach it with no `code` yet
  (async-graphql's own parse/validation/depth/complexity/introspection
  failures) — a default `BAD_REQUEST`/non-retryable.
- The callout-deny path (`graphql::callout_ext`) sets `FORBIDDEN` directly,
  since without that it would otherwise fall through to the same
  `BAD_REQUEST` default, which would misclassify a policy decision as a
  malformed request.
- `src/request_id.rs` owns generation/validation and the `X-Request-ID`
  response header, applied as the outermost HTTP layer so every response
  carries it, not only `/graphql`'s.

## Non-goals (v1)

- A published, standalone client SDK.
- Changing custom REST-shaped endpoint (`/api/custom/*`) status/body
  mapping.
- Request IDs on every persisted `audit_logs` row.
- A unique code per domain validation message.
- Any change to GraphQL's partial-data execution semantics.
