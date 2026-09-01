#!/usr/bin/env python3
"""Tiny callout server for local Atom testing.

Echoes every request Atom sends and always responds ALLOW. Stdlib only —
runs in `python:3-slim` with no dependencies to install.

Flip the `allow` field in `_reply` to False to exercise the deny path.

Point Atom at it (from another container on the same compose network):
  ATOM_CALLOUTS_FILE=/etc/atom/callout.yaml
  ATOM_CALLOUTS_ENABLED=true
  # callout.yaml -> url: http://callout-server:9099/callout
"""
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse


class Handler(BaseHTTPRequestHandler):
    def _dump(self, body_bytes: bytes) -> None:
        print(f"\n=== {self.command} {self.path} ===", flush=True)
        for k, v in self.headers.items():
            print(f"  {k}: {v}", flush=True)
        if body_bytes:
            try:
                print("  body:", json.dumps(json.loads(body_bytes), indent=2), flush=True)
            except Exception:
                print("  body:", body_bytes.decode(errors="replace"), flush=True)
        else:
            qs = parse_qs(urlparse(self.path).query)
            if qs:
                print("  query:", json.dumps(qs, indent=2), flush=True)

    def _reply(self) -> None:
        # Atom's HTTP callout expects `{"allow": bool, "reason": "..."}`.
        # Flip `allow` to False to exercise the deny path.
        payload = json.dumps({"allow": True, "reason": "ok"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self) -> None:
        n = int(self.headers.get("Content-Length") or 0)
        self._dump(self.rfile.read(n) if n else b"")
        self._reply()

    def do_GET(self) -> None:
        self._dump(b"")
        self._reply()

    def log_message(self, *args, **kwargs) -> None:
        # Silence default access log — the _dump() above is the interesting one.
        pass


if __name__ == "__main__":
    # 0.0.0.0 so other compose services can reach us via the network alias.
    port = int(os.environ.get("PORT", "9099"))
    print(f"callout-server listening on 0.0.0.0:{port}", flush=True)
    try:
        HTTPServer(("0.0.0.0", port), Handler).serve_forever()
    except KeyboardInterrupt:
        sys.exit(0)
