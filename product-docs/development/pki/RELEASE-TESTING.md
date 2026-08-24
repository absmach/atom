# PKI Release Testing: Human and AI Runbook

This runbook is the release gate for merging the `certificates` branch into
`main`. It converts the PKI test plan into commands that a human operator or an
AI coding agent can execute and report consistently.

The tests use disposable PostgreSQL databases, generated test keys, OpenSSL,
the independent GlobalSign EST client, and (for the full gate) a disposable
SoftHSM token. They must never use production CA keys, HSM credentials, tenant
data, or reusable private-key fixtures.

## Required release gates

| Gate | Purpose | Required result |
| --- | --- | --- |
| PKI smoke | Prove the critical issue-to-revoke path with real DB and crypto implementations | Every selected test binary passes against its own fresh database |
| Rust CI | Format, lint, compile, and execute the complete repository test matrix | All steps pass with the committed `Cargo.lock` |
| PKI full integration | Exercise all PKI specifications, EST interoperability, and PKCS#11 behavior | Every PKI test binary passes; the HSM recovery proof passes in CI |
| API docs | Prove generated GraphQL/gRPC documentation is current | Workflow passes with no generated diff |
| Merge-state check | Test the commit GitHub will merge, including current `main` | Required checks are green on the release PR, not only on an older branch PR |

Do not merge when a gate is skipped, cancelled, stale, or green only on a
different commit.

## Test levels

### Smoke test

`scripts/pki-test.sh smoke` runs a deliberately small but end-to-end set:

- tenant CA provisioning;
- CSR issuance and independent OpenSSL chain verification;
- immediate revocation;
- per-issuer CRL generation and verification;
- per-issuer OCSP good/revoked/unknown responses and verification;
- issuer-plus-serial/fingerprint runtime resolution and tenant isolation;
- RFC 7030 EST enrollment through the independent GlobalSign client.

This is a real integration smoke test. It does not replace the full gate.

### Full PKI integration test

`scripts/pki-test.sh full` discovers and runs every `tests/m??_pki*.rs`
integration binary, including the legacy-certificate migration and purge-after-
revocation regressions. It requires a pre-provisioned disposable SoftHSM token
and the independent EST client. The repository `Rust` workflow is the
authoritative full run because it also provisions the token, proves non-
exportable PKCS#11 behavior, and performs the populated-token backup/restore
signing exercise.

## Local prerequisites

- Rust stable with `rustfmt` and `clippy`;
- PostgreSQL 16 (server and `psql` client);
- OpenSSL;
- `protoc`;
- Go and `github.com/globalsign/est/cmd/estclient@v1.0.7`;
- SoftHSM 2 for the full mode.

Create only a disposable database. The runner refuses a database name that
does not start with `atom_pki_test`.

```bash
export PKI_TEST_MAINT_URL='postgres://atom:atom@localhost:5432/atom'
export PKI_TEST_DATABASE_URL='postgres://atom:atom@localhost:5432/atom_pki_test'
export PKI_TEST_DATABASE_NAME='atom_pki_test'
export ATOM_EST_CLIENT="$(go env GOPATH)/bin/estclient"
go install github.com/globalsign/est/cmd/estclient@v1.0.7
```

The two example URLs are local development credentials only. Do not copy
production connection strings into a shell history, CI log, issue, or PR.

## Human test procedure

1. Check out the exact release PR head and record `git rev-parse HEAD`.
2. Confirm the diff is `certificates → main` and contains no production key,
   PIN, connection string, certificate private key, or generated test secret.
3. Start a disposable PostgreSQL instance and install the prerequisites above.
4. Run the quality and compile gates:

   ```bash
   cargo fmt --check
   cargo clippy --locked -- -D warnings
   cargo test --no-run --locked
   ```

5. Run the smoke gate:

   ```bash
   ./scripts/pki-test.sh smoke
   ```

6. Inspect the output. All seven named binaries must pass; a compile-only
   result is not a smoke-test pass.
7. In GitHub, confirm `Rust` and `API Docs` are green on the current release-PR
   commit. Open the Rust job and confirm its `Run real PKI smoke test` step
   executed; do not rely only on the green summary icon.
8. For a production-like pre-release drill, use a disposable SoftHSM token and
   run the full mode, then follow `PKCS11-RUNBOOK.md` for the backup/restore
   proof. Never substitute the production root or a production HSM partition.
9. Record the commit SHA, workflow run links, date, tester, and any environment
   deviation in the PR description or a PR comment.

### Human acceptance checklist

- A tenant A certificate chains to tenant A's active issuer and the offline
  test root.
- Tenant B cannot issue, resolve, renew, or revoke tenant A's credential.
- Default leaves are not CAs and do not receive server authentication unless
  an explicit combined profile allows it.
- Revocation denies runtime resolution immediately.
- The issuer CRL contains the revoked serial and verifies independently.
- OCSP returns signed `good`, `revoked`, and `unknown` results correctly.
- EST first enrollment and re-enrollment use the same policy/issuer pipeline as
  native enrollment.
- Existing encrypted-database authorities and PKCS#11-backed authorities retain
  their own provider; no fallback silently changes the signer.
- No private key, PIN, opaque provider reference, CSR body, or credential secret
  appears in logs, audit details, GraphQL output, or artifacts.

## AI-agent test procedure

An AI agent follows the same commands and acceptance criteria as a human. It
must additionally:

1. Read `AGENTS.md`, `AI-GUIDELINES.md`, `TEST-PLAN.md`, this runbook, and the
   changed PKI specifications before acting.
2. Resolve and report the exact base SHA, head SHA, and GitHub merge SHA being
   tested. A head-only pass is insufficient when `main` has advanced.
3. Use only disposable local/CI secrets. Never request, reveal, copy, or rotate
   production PKI credentials for a test.
4. Run the commands rather than infer success from code inspection or an older
   workflow. Capture the failing test name and first actionable error when a
   command fails.
5. Fix the implementation or test environment; never weaken an assertion,
   skip a mandatory binary, remove `--locked`, or replace independent crypto
   verification with an Atom-internal check merely to obtain green CI.
6. Re-run every affected gate after a fix and ensure all required checks belong
   to the newest commit.
7. Produce the completion report required by `AGENTS.md`: files changed,
   acceptance criteria, commands/results, migrations, compatibility impact,
   security assumptions, and unresolved risks.

Use this evidence format:

```text
Release PR: <url>
Base/main SHA: <sha>
Head/certificates SHA: <sha>
GitHub merge SHA: <sha>
Smoke: PASS|FAIL — <workflow or local command>
Full Rust/PKI: PASS|FAIL — <workflow run>
API docs: PASS|FAIL — <workflow run>
SoftHSM recovery: PASS|FAIL — <job and step>
Unresolved risks: <none or exact list>
Tester: human|AI (<name>)
UTC time: <timestamp>
```

## Failure handling

- Stop the release on the first reproducible failure.
- Preserve logs that do not contain secrets and link them from the PR.
- Treat cross-tenant access, signer fallback, key export, incorrect chain
  constraints, stale revocation, or unverifiable CRL/OCSP/EST output as release
  blockers.
- If external infrastructure prevents a full local run, use the GitHub-hosted
  gate. Do not mark the missing local execution as passed.
- After any code change, re-run both the focused failing test and the complete
  required workflow on the new commit.
