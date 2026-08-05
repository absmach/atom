# PR-002 — CA Key Provider Abstraction

## Objective

Introduce an Atom-owned signing/key-provider interface and an encrypted-database implementation without changing certificate issuance routing.

## Dependencies

PR-001.

## Scope

- Define key generation, public-key retrieval, signing, key destruction/retirement, and health interfaces.
- Add a dedicated CA KEK configuration separate from JWT and credential secrets.
- Implement envelope encryption: random per-authority DEK, CA KEK wraps DEK, DEK encrypts PKCS#8 key.
- Bind ciphertext with AAD containing authority ID, tenant ID, and version.
- Decrypt only for one operation and zeroize plaintext material.
- Add startup/config validation and non-secret metrics.

## Non-goals

No root-key storage, CA provisioning API, tenant issuance, PKCS#11, or KMS.

## Acceptance criteria

- Public root records remain `public_only` and cannot sign.
- Encrypted provider never persists plaintext key bytes.
- CA KEK is mandatory only when encrypted authorities are used.
- Wrong KEK, corrupted ciphertext, missing fields, and unsupported algorithms fail closed.
- Key material is excluded from debug/serde/log/audit/event output.
- Provider interface can support file, PKCS#11, and KMS implementations later.
- Existing v1 signer behavior remains unchanged.

## Mandatory tests

Encrypt/decrypt round trip, AAD mismatch, wrong KEK, ciphertext corruption, key-ID rotation behavior, signing verification, no-secret serialization, and process-restart loading.

## Rollback

No encrypted authority may be activated until this PR is deployed everywhere. Rollback is safe while no production rows use the new backend.

## AI execution prompt

Implement PR-002 only. Read the PKI PRD, roadmap, AI guidelines, existing key encryption code, and repository transaction rules. Preserve v1 issuance. Do not add CA APIs or OpenBao. Prove no plaintext CA key is persisted or logged.