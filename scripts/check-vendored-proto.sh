#!/usr/bin/env bash
#
# Detect drift between Atom's vendored broker-callout contract and the upstream
# it was copied from.
#
# Atom implements a proto it does not own. Nothing rebuilds the vendored copy, so
# without this check an upstream change is discovered at runtime — as an
# UNIMPLEMENTED from a renamed service, or worse, as a field that still decodes
# but no longer means what Atom thinks it means.
#
# See proto/broker/v1/VENDOR.md for what to do when this fails.

set -euo pipefail

readonly VENDOR_DIR="proto/broker/v1"
readonly VENDORED="${VENDOR_DIR}/auth.proto"
readonly REF_FILE="${VENDOR_DIR}/REF"
readonly UPSTREAM_REPO="absmach/fluxmq"
readonly UPSTREAM_PATH="proto/auth/v1/auth.proto"

if [[ ! -f "${VENDORED}" ]]; then
  echo "error: ${VENDORED} not found; run from the repository root" >&2
  exit 2
fi

ref="$(tr -d '[:space:]' <"${REF_FILE}")"
if [[ -z "${ref}" ]]; then
  echo "error: ${REF_FILE} is empty; it must name a branch, tag, or commit" >&2
  exit 2
fi

url="https://raw.githubusercontent.com/${UPSTREAM_REPO}/${ref}/${UPSTREAM_PATH}"
upstream="$(mktemp)"
trap 'rm -f "${upstream}"' EXIT

if ! curl -fsSL "${url}" -o "${upstream}"; then
  echo "error: could not fetch ${url}" >&2
  echo "       check that ${REF_FILE} names a ref that exists upstream" >&2
  exit 2
fi

if diff -u "${upstream}" "${VENDORED}"; then
  echo "vendored proto matches ${UPSTREAM_REPO}@${ref}"
  exit 0
fi

cat >&2 <<EOF

error: ${VENDORED} has drifted from ${UPSTREAM_REPO}@${ref}

The diff above reads: upstream (-) versus Atom's copy (+).

This is a contract Atom implements but does not own. Read the diff before
syncing — a renamed package is a breaking wire change, and a renumbered field
can compile cleanly while meaning something else. See ${VENDOR_DIR}/VENDOR.md.
EOF
exit 1
