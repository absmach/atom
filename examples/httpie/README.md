# Atom HTTPie Demo

Autoplay-style CLI demo for Atom using HTTPie.

## Prerequisites

- Atom running at the `BASE_URL` used by the script.
  - Default script URL: `http://localhost:8080`
  - Current tape URL: `http://127.0.0.1:18080`
- Admin password bootstrapped with `ADMIN_SECRET=change-me`
- `http` from HTTPie
- `jq`

Optional recording:

- `vhs` from Charmbracelet
- `ffmpeg`
- `ttyd`

VHS must find `ffmpeg` and `ttyd` on `PATH`. If you use the local binaries downloaded in this repo, run VHS with:

```bash
PATH="$PWD/.local-tools:$HOME/.local/bin:$PATH" .local-tools/vhs examples/httpie/atom-httpie-demo.tape
```

Running only this may fail:

```bash
.local-tools/vhs examples/httpie/atom-httpie-demo.tape
```

because `.local-tools/vhs` can start, but it still cannot find `.local-tools/ffmpeg` or `.local-tools/ttyd` unless `.local-tools` is on `PATH`.

## Run Live

```bash
chmod +x examples/httpie/atom-httpie-demo.sh
BASE_URL=http://localhost:8080 ADMIN_SECRET=change-me examples/httpie/atom-httpie-demo.sh
```

If port `8080` is already used, start Atom on another port:

```bash
DATABASE_URL=postgres://atom:atom@localhost:5432/atom \
LISTEN_ADDR=127.0.0.1:18080 \
GRPC_ADDR=127.0.0.1:18081 \
ADMIN_SECRET=change-me \
cargo run
```

Then run:

```bash
PATH="$HOME/.local/bin:$PATH" \
BASE_URL=http://127.0.0.1:18080 \
ADMIN_SECRET=change-me \
examples/httpie/atom-httpie-demo.sh
```

The script demonstrates:

- admin login
- tenant creation
- automatic tenant-admin bootstrap
- device and channel creation
- role and policy assignment
- `authz/check` allow
- explicit deny overriding allow
- tenant freeze blocking authorization
- audit trail

## Record

```bash
PATH="$PWD/.local-tools:$HOME/.local/bin:$PATH" .local-tools/vhs examples/httpie/atom-httpie-demo.tape
```

Output:

```text
examples/httpie/atom-httpie-demo.gif
```
