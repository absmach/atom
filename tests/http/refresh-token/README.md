# Refresh-token manual test

What [`refresh-tokens.http`](refresh-tokens.http) does, in order:

- **Log in:** Get an access token for API requests and a refresh token for getting
  new tokens without logging in again. Save them automatically for later steps.
- **Check access:** Use the access token to read the current login session.
- **Check token usage:** Try using the refresh token as an access token. Atom
  should reject it because refresh tokens are only for getting new tokens.
- **Wait for expiry:** Wait about 95 seconds, including Atom's clock tolerance,
  then check that the old access token no longer works.
- **Refresh the login:** Use the refresh token to get a new access token and a
  new refresh token. The login session stays the same, and the refresh-token
  expiry deadline does not get extended.
- **Check the new access token:** Confirm it can read the same login session.
- **Reuse the old refresh token:** Try the refresh token that was already used.
  Atom should reject it and revoke this login session as a security precaution.
- **Check the new refresh token is blocked:** Confirm it also stops working
  after the session is revoked.
- **Check the new access token is blocked:** Confirm it loses access immediately,
  even though it has not expired yet.

The rejected requests are intentional: the test passes when Atom blocks them
for the expected reason. Run all steps in order; tokens are shared automatically.

## Start Atom

From the repository root, with Docker and Rust installed:

```sh
make db

DATABASE_URL=postgres://atom:atom@localhost:5432/atom \
LISTEN_ADDR=127.0.0.1:8090 \
GRPC_ADDR=127.0.0.1:8091 \
ATOM_PKI_ROOT_CERT_PATH= \
ATOM_PKI_PLATFORM_INTERMEDIATE_CERT_PATH= \
ATOM_PKI_PLATFORM_INTERMEDIATE_KEY_PATH= \
ATOM_REFRESH_TOKENS_ENABLED=true \
ATOM_ACCESS_TOKEN_EXPIRY_SECS=30 \
ATOM_REFRESH_TOKEN_EXPIRY_SECS=600 \
cargo run
```

Use your own database URL if it differs from the local demo defaults. Atom
loads the existing `.env`, including `ATOM_KEY_ENCRYPTION_KEY`; keep that key
unchanged for an existing database. `make db` creates `.env` from the local
demo example if it does not exist.

The three empty PKI path overrides skip optional certificate bootstrapping for
this refresh-token test. A `.env` previously used with Docker can contain
`/certs/...` paths, which exist inside the container but not on the host running
`cargo run`. These command-local overrides leave `.env`, certificate files, and
existing database authorities unchanged. To also bootstrap certificates on the
host, use their actual host paths instead (for example `./certs/pki-root.pem`).

## Run the requests

In another terminal, from the repository root:

```sh
pnpm dlx httpyac send tests/http/refresh-token/refresh-tokens.http --all --bail --output none --output-failed none
```

Alternatively, open the file with the **httpYac** VS Code extension and choose
**Send All Requests**. Run sequentially, starting with login. Expected rejection
requests count as passing tests when the correct GraphQL error is returned.

The run takes approximately 95 seconds: it waits until the original JWT expires,
including Atom's 60-second clock tolerance. The final requests intentionally
revoke only the session created by this run. Run the whole file again to start
with a fresh session. It does not test concurrent requests or database upgrades.

Defaults are `http://localhost:8090`, identifier `admin`, and the local demo
password `12345678`. For a different setup, export `ATOM_TEST_BASE_URL`,
`ATOM_TEST_IDENTIFIER`, and `ATOM_TEST_SECRET` in the HTTPYac process environment.
Do not commit real credentials. The CLI command suppresses response bodies to
avoid printing tokens; the editor can display responses locally for inspection.

HTTPYac reference: [CLI](https://httpyac.github.io/guide/installation_cli.html)
and [scripting](https://httpyac.github.io/guide/scripting.html).
