# PKI lifecycle automation and fleet operations

PR-015 adds expiry visibility and bounded revocation operations without adding
notification delivery or bulk issuance.

## Expiry listings

The existing `certificates` GraphQL query accepts these additional filters:

- `expiresFrom` — inclusive RFC3339 lower bound;
- `expiresBefore` — exclusive RFC3339 upper bound;
- `issuerId`, `tenantId`, and `status`;
- `limit` (maximum 100) and `offset`.

Tenant authorization is translated into the SQL tenant predicate before rows
are read. Expiry-filtered pages are ordered by `(expires_at, credential_id)` and
`total` is the full authorized match count, not the page length.

```graphql
query Expiring($before: String!) {
  certificates(
    expiresBefore: $before
    status: "active"
    limit: 100
    offset: 0
  ) {
    total
    items { credentialId issuerId entityId tenantId expiresAt renewalDueAt }
  }
}
```

## Bounded bulk revocation

`bulkRevokeCertificates` accepts exactly one of `tenantId`, `issuerId`, or
`principalGroupId`, plus an optional reason, `afterCredentialId`, and batch
`limit` (1–500).

```graphql
mutation RevokeFleet($input: BulkRevokeCertificatesInput!) {
  bulkRevokeCertificates(input: $input) {
    complete
    nextCursor
    items { credentialId entityId issuerId outcome errorCode }
  }
}
```

Rows are selected in stable credential-UUID order. Every item has its own
transaction, revocation evidence, audit record, and outbox event. Processing
stops on the first failure; `nextCursor` remains the last contiguous success,
so passing it back selects the failed item again. Repeating the prior cursor
after a lost response is also safe because committed revocations no longer
match the active-candidate query.

## Sweeper

Enable the background job with:

```text
ATOM_PKI_LIFECYCLE_ENABLED=true
ATOM_PKI_LIFECYCLE_INTERVAL_SECS=60
ATOM_PKI_LIFECYCLE_BATCH_SIZE=250
ATOM_PKI_EXPIRY_WARNING_SECS=86400
ATOM_PKI_AUTHORITY_WARNING_SECS=2592000
```

The sweeper uses each certificate's stored or referenced profile renewal
threshold. It emits `certificate.expiring` for the renewal and critical-expiry
windows and `certificate.authority_expiring` for CA rotation lead time. A
PostgreSQL advisory lock coordinates replicas; a durable unique marker and the
outbox row commit atomically, giving exactly one event per subject/window across
restarts. If event publishing is not configured, no marker is consumed and the
events remain eligible when publishing is enabled later.

Events carry issuer, credential, entity, and tenant identifiers (null where an
authority has no leaf subject), timestamps, and the bounded window name. They
never carry certificate PEM, CSR input, private keys, or subject secrets.

## Metrics

- `atom_pki_lifecycle_operations_total`
- `atom_pki_certificate_expiry_count`
- `atom_pki_crl_size_bytes`
- `atom_pki_crl_generation_duration_seconds`
- `atom_pki_authority_time_to_expiry_seconds`

Labels use fixed operation, outcome, state, expiry-bucket, CRL-scope, and
authority-kind vocabularies only. Tenant, entity, credential, issuer, and key
identifiers are not metric labels.
