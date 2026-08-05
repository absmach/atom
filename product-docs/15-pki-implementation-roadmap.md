# Atom-Native PKI Implementation Roadmap

## Status

Approved execution plan following `14-atom-native-multitenant-pki.md`.

## Goal

Deliver a production-ready, OpenBao-free, multi-tenant private PKI inside Atom. The production root remains offline; each tenant receives a versioned intermediate CA; global entities are served by a platform leaf issuer; Atom remains the certificate credential and authorization source of truth.

## How to use this roadmap

Before implementing any PKI PR, read:

1. `product-docs/14-atom-native-multitenant-pki.md`
2. `product-docs/development/pki/README.md`
3. `product-docs/development/pki/AI-GUIDELINES.md`
4. the relevant PR specification
5. `product-docs/development/pki/TEST-PLAN.md`
6. `product-docs/development/pki/DEFINITION-OF-DONE.md`

Do not begin a PR until all declared dependencies are merged.

## Delivery sequence

```text
PR-000 v1 Correctness Hotfixes  (independent, no dependencies)

PR-001 Authority Registry (this foundation PR)
        |
        v
PR-002 Key Provider Abstraction
        |
        +----------------------+
        |                      |
        v                      v
PR-003 CA Provisioning    PR-004 Certificate Profiles
        |                      |
        +----------+-----------+
                   v
            PR-005 CSR Import
                   |
                   v
            PR-006 Leaf Issuance          <-- flagged off in production
                   |                          until PR-010 completes
            +------+------+
            |             |
            v             v
      PR-007 Renewal  PR-008 Revocation
            |             |
            +------+------+
                   v
              PR-009 CRL
                   |
                   v
              PR-010 OCSP
                   |
                   +---------------------+
                   |                     |
                   v                     v
        PR-011 Runtime Resolver v2   PR-015 Lifecycle Automation
                   |                     |
                   v                     |
            PR-014 Enrollment <----------+
                   |     \
                   |      `--> PR-014b EST Adapter (on trigger, not scheduled)
                   v
        PR-012 Relying-Party Integration
                   |
                   v
          PR-013 HSM/KMS Signers
```

## Milestones

### Milestone A — Safe foundation

Includes PR-000 through PR-004.

Exit gate:

- published v1 CRL and OCSP artifacts verify with an independent client;
- authority hierarchy and lifecycle are persisted, including the platform leaf issuer;
- existing v1 certificate behavior remains unchanged;
- no plaintext CA key can be persisted, and no CA key location can be chosen by a database writer;
- a signer interface exists;
- profiles are stored data, canonical, and tenant-independent request input cannot override them;
- leaves carry AIA and CRL distribution point extensions;
- all existing tests remain green.

### Milestone B — Tenant issuance

Includes PR-005 and PR-006.

Exit gate:

- a tenant intermediate or platform leaf issuer can be imported or provisioned;
- CSR and generated-key leaf issuance derive the issuer from the target entity's tenant scope;
- returned certificates contain the canonical tenant/entity identity;
- legacy global issuance remains available behind an explicit compatibility mode;
- **tenant issuance remains disabled in production deployments** until Milestone C completes.

### Milestone C — Lifecycle and public PKI

Includes PR-007 through PR-010.

Exit gate:

- renewal rotates leaves into the current issuer for the subject's scope;
- revocation is immediately effective in Atom;
- CRL and OCSP are issuer-specific and carry revocation reasons;
- CRL numbering is continuous across the state-representation cutover;
- old issuer artifacts remain available during rotation and retention;
- the production flag guarding tenant issuance may now be lifted.

### Milestone D — Runtime and operations

Includes PR-011, PR-014, PR-015, and PR-012.

Exit gate:

- runtime lookup is based on fingerprint or issuer plus serial;
- duplicate serials across issuers can safely be enabled;
- subjects can enroll and re-enroll themselves over the native transport, with
  client certificates verified in process;
- enrollment sits behind an adapter boundary, so EST can attach later without
  touching enrollment logic;
- expiry is visible and drives renewal before it becomes an outage;
- relying parties compare the resolved tenant against the scope being accessed;
- legacy serial-only runtime paths are removed or explicitly deprecated.

### Milestone E — Production key isolation

Includes PR-013.

Exit gate:

- PKCS#11 and/or KMS signing works behind the same interface;
- private keys need not be accessible to the public Atom process;
- operational key rotation and failure behavior are documented and tested.

## Sequencing hazard: issuance before issuer-scoped artifacts

PR-006 puts multiple live issuers into production while CRL and OCSP are still
global and signed by the legacy issuer. In that window:

- revoking a certificate issued by a tenant CA writes it into a CRL signed by a
  different CA, which no verifier will accept for that certificate;
- the OCSP responder resolves serials globally, so it answers `good` or `revoked`
  for certificates the queried CA never issued, where the correct answer is
  `unknown`.

Neither is a defect in PR-006; both are consequences of ordering. The mitigation
is mandatory: **tenant and platform leaf issuance ships behind a flag that stays
off in production deployments until PR-010 is merged.** Pre-production use during
the window is expected and fine.

## Cross-cutting non-negotiable requirements

- No OpenBao dependency.
- No standalone certificate service as a second source of truth.
- Root private key must not be loaded by the public Atom service.
- Atom's own transport certificate must not be issued by Atom's PKI.
- Public requests must never choose an issuer, key reference, or CA path.
- Issuer is derived from the target entity's tenant scope.
- Atom never issues a certificate for a subject that is not an Atom entity.
- No downstream product's vocabulary appears in Atom's schema, code, configuration, or APIs.
- Consumer-specific requirements are expressed as profile data, never as code branches.
- No plaintext private keys in logs, database, events, traces, or errors, and no wrapped key material in `Debug` output.
- Every mutation must follow Atom transaction, event-outbox, and audit conventions.
- No second pool connection while holding a transaction.
- Existing API behavior remains compatible until the documented cutover PR.
- A tenant certificate must never reference another tenant's issuer, and a global entity's certificate must reference only the platform leaf issuer.
- Deleting an authority must never delete the certificates it issued.

## Migration policy

1. Existing v1 credentials retain `issuer_id = NULL`.
2. Global serial uniqueness remains until PR-011 migrates all serial-only readers.
3. New tenant issuance starts only after issuer-aware service paths are merged and the production flag is lifted.
4. Existing certificates migrate by renewal, not by rewriting issued certificates.
5. The legacy CA chain, CRL, and OCSP remain available until the last legacy leaf expires plus retention.
6. CRL numbering continues across the fingerprint-keyed to issuer-keyed state cutover.
7. Hard tenant purge may remove tenant authority material only after the product retention policy permits purge, and only in an order that deletes certificate credentials first.

## Required review gates

Security review is mandatory for PR-000, PR-002, PR-003, PR-005, PR-006, PR-010, PR-011, PR-013, and PR-014.

Database review is mandatory for any PR changing authority, credential, CRL, OCSP, migration, purge, or uniqueness semantics.

Relying-party integration review is mandatory for PR-011 and PR-012.

Product review is mandatory for any PR that adds a capability not listed in the PRD's scope section, to confirm it falls inside the boundary rule rather than expanding Atom toward a general secrets manager.

## Completion

The project is complete only when every PR acceptance criterion is met, all CI checks pass, migration and rollback behavior are documented, and the production runbook covers root custody, issuer rotation, backup, restore, compromise, tenant deletion, and certificate expiry response.
