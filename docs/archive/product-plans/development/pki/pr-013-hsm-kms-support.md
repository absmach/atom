# PR-013 — Isolated Signer, PKCS#11, and KMS Support

## Objective

Move production CA signing behind hardware or remote key providers without changing Atom certificate APIs.

## Dependencies

PR-002 through PR-012 stable interfaces.

## Scope

- Implement PKCS#11 and/or selected cloud KMS provider.
- Support opaque key references and public-key/certificate matching.
- Optional isolated `atom-pki-signer` internal service using authenticated, authorized, encrypted transport.
- Provider health, timeout, retry, throttling, and circuit behavior.
- Key rotation, disable, destroy, backup/recovery policy where provider supports it.
- Deployment and incident runbooks.

Started persistent provider mutations have a soft deadline: Atom reports that
the deadline was exceeded but waits for the provider's actual result before it
returns or retries. Read-only operations retain the hard timeout. Blocking
provider waits must use the runtime's blocking boundary so they do not pin an
asynchronous worker.

A generated provider key remains owned by the provisioning operation until the
authority mutation and its audit event commit. CSR construction, signing,
database, audit, or outer-transaction failure destroys that key before the
operation returns; only a successful commit transfers ownership to the stored
authority row.

## Non-goals

Multi-cloud abstraction beyond approved providers, generic secrets management, or exposing HSM/KMS controls to tenants.

## Acceptance criteria

- Private key never leaves HSM/KMS for non-exportable configurations.
- Public Atom API cannot invoke arbitrary signing; requests are bound to validated operation, authority, and profile.
- Key reference cannot be supplied by public caller.
- Provider outage fails closed and does not corrupt authority lifecycle.
- Existing encrypted-database provider remains supported where policy allows.
- Rotation between providers preserves old certificate validation and revocation artifacts.
- Audit records operation identifiers without sensitive provider data.

## Mandatory tests

Provider emulator/SoftHSM signing, wrong key/certificate match,
unavailable/throttled provider, timeout/retry idempotency including late
persistent mutations, async-runtime progress during provider waits,
outer-transaction rollback cleanup, signer authentication, arbitrary-sign
prevention, provider rotation, and recovery runbook exercise.

## AI execution prompt

Implement only approved provider(s) behind the existing key-provider contract. Do not broaden Atom into a secrets manager. Prove non-exportability and prevent generic signing or caller-selected key references.
