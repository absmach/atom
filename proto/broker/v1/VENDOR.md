# Vendored broker-callout contract

`auth.proto` is a **byte-identical copy** of FluxMQ's
`proto/auth/v1/auth.proto`. Atom implements `AuthService` so a broker can call
it directly, with no adapter service in between.

| | |
|---|---|
| Source | https://github.com/absmach/fluxmq |
| Path | `proto/auth/v1/auth.proto` |
| Pinned ref | see `REF` in this directory |

## Why it is byte-identical

Nothing Atom-specific belongs in this file. Drift from upstream is detected by a
plain `diff`, and a diff can only stay trustworthy if there is nothing expected
to differ — a locally-edited header would mean the check had to know which
differences to forgive, and a check that forgives differences stops catching the
one that matters. Atom's own notes live in this file and in
`AGENTS.md § Broker auth callout`.

## Checking for drift

```bash
scripts/check-vendored-proto.sh
```

CI runs the same script. It fetches the pinned ref from GitHub and diffs.

## When it fails

A failure means upstream changed the contract Atom implements. That is
information, not a chore — read the diff before syncing:

- **Comments or new optional fields** — re-vendor, bump `REF`, done.
- **A changed `package` line** — the gRPC path a broker dials is derived from
  it, so this is a breaking wire change. Atom, the broker, and any adapter
  service must move together; see the deployment note in `AGENTS.md`.
- **Renamed or renumbered fields** — check `src/broker_auth/service.rs` before
  re-vendoring. `prost` will happily compile a field that now means something
  else.

## Syncing

```bash
curl -fsSL "https://raw.githubusercontent.com/absmach/fluxmq/$(cat proto/broker/v1/REF)/proto/auth/v1/auth.proto" \
  -o proto/broker/v1/auth.proto
cargo test --lib broker_auth
```
