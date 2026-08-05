# PR-003 — Root and Tenant CA Provisioning

## Objective

Implement controlled CA lifecycle operations for offline-root import and tenant-intermediate provisioning.

## Dependencies

PR-001 and PR-002.

## Scope

- Import and validate root certificate metadata as `public_only`.
- Generate tenant-intermediate key and CSR with `CA=true`, `keyCertSign`, `cRLSign`, and `pathLen=0`.
- Export CSR for offline signing.
- Import signed intermediate, verify parent signature, constraints, key match, validity, SKI/AKI, and chain.
- Optional platform-intermediate provisioning path for automated tenant CA signing, protected by a distinct privileged operation.
- Lifecycle: provisioning, pending_signature, active, failed, retiring, retired.
- Idempotency and audit/outbox behavior.

## Non-goals

Leaf issuance and public tenant certificate APIs.

## Acceptance criteria

- Production root private key is never accepted by Atom.
- Tenant identity comes from stored tenant state, not request subject fields.
- Imported tenant CA must match generated key and intended tenant authority row.
- Tenant CA has path length zero and cannot issue another CA.
- CA validity cannot exceed parent validity.
- Failed imports do not activate issuance.
- Repeated provisioning requests are idempotent or return a deterministic conflict.
- One active issuer invariant remains enforced.

## Mandatory tests

Valid offline flow, wrong parent, wrong key, wrong tenant, CA=false, missing key usages, pathLen>0, expired/not-yet-valid parent, duplicate import, concurrent provisioning, and restart recovery.

## Rollback

Provisioning rows may remain disabled. Never delete an imported CA/key automatically during rollback.

## AI execution prompt

Implement only CA provisioning. Do not expose generic certificate signing, root private-key import, or caller-selected hierarchy fields. Validate every imported artifact independently of rcgen assumptions.