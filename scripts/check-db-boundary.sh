#!/usr/bin/env bash
# Guards the database-backend boundary (see product-docs/development/database-backends/).
#
# 1. Application code never names a database driver: every statement goes
#    through crate::db (src/db/), so it can run on PostgreSQL or SQLite.
# 2. The SQLite baseline declares the same tables, indexes and views as the
#    PostgreSQL baseline, so the two schemas cannot drift apart unnoticed.
set -euo pipefail

status=0

# --- 1. no driver types or raw sqlx queries outside src/db/ ------------------
violations="$(
  grep -rnE 'sqlx::(query|query_as|query_scalar|postgres|sqlite|Postgres|Sqlite|PgPool|PgConnection|SqlitePool|SqliteConnection|Pool|Transaction)\b|\bPgPool\b|\bPgConnection\b|\bSqlitePool\b|::migrate!' \
    src --include='*.rs' \
  | grep -v '^src/db/' \
  | grep -vE '^[^:]+:[0-9]+:\s*//' \
  || true
)"
# Test modules may talk to a driver directly to exercise PostgreSQL-specific
# behaviour; production code may not.
violations="$(printf '%s\n' "${violations}" | awk -F: '
  NF > 2 { print }
' | while IFS= read -r line; do
  file="${line%%:*}"
  lineno="$(printf '%s' "${line}" | cut -d: -f2)"
  # Skip lines inside a #[cfg(test)] module (everything after the marker).
  marker="$(grep -n '#\[cfg(test)\]' "${file}" | head -1 | cut -d: -f1 || true)"
  if [[ -n "${marker}" && "${lineno}" -gt "${marker}" ]]; then
    continue
  fi
  printf '%s\n' "${line}"
done)"

if [[ -n "${violations}" ]]; then
  echo "database driver types must stay inside src/db/; found:" >&2
  printf '%s\n' "${violations}" >&2
  status=1
fi

# --- 2. schema parity between the two baselines -------------------------------
if ! python3 - <<'PY'
import re
import sys

import glob
import os

PG_DIR = "migrations"
LITE_DIR = "migrations/sqlite"
ALLOW = "scripts/db-parity-allow.txt"


def migrations(directory):
    return sorted(glob.glob(os.path.join(directory, "*.sql")))


def objects(directory):
    """Tables, views and indexes that exist after every migration's CREATE/DROP statements."""
    text = ""
    for path in migrations(directory):
        text += re.sub(r"--[^\n]*", "", open(path).read()) + "\n"
    found = {"TABLE": set(), "VIEW": set(), "INDEX": set()}
    pattern = re.compile(
        r"\b(CREATE(?:\s+OR\s+REPLACE)?(?:\s+UNIQUE)?|DROP)\s+(TABLE|VIEW|INDEX)\s+(?:IF\s+(?:NOT\s+)?EXISTS\s+)?(?:public\.)?([A-Za-z0-9_]+)",
        re.I,
    )
    for verb, kind, name in pattern.findall(text):
        kind = kind.upper()
        if verb.upper().startswith("CREATE"):
            found[kind].add(name)
        else:
            found[kind].discard(name)
    return found


allowed = set()
for line in open(ALLOW):
    line = line.strip()
    if line and not line.startswith("#"):
        kind, name = line.split()[:2]
        allowed.add((kind.upper(), name))

PG, LITE = PG_DIR, LITE_DIR
pg, lite = objects(PG), objects(LITE)
bad = False
# Every PostgreSQL migration has a same-named SQLite counterpart and vice versa.
pg_names = {os.path.basename(p) for p in migrations(PG)}
lite_names = {os.path.basename(p) for p in migrations(LITE)}
for name in sorted(pg_names - lite_names):
    print(f"migration {name} has no counterpart in {LITE}", file=sys.stderr)
    bad = True
for name in sorted(lite_names - pg_names):
    print(f"migration {name} has no counterpart in {PG}", file=sys.stderr)
    bad = True
for kind in ("TABLE", "VIEW", "INDEX"):
    for name in sorted(pg[kind] - lite[kind]):
        if (kind, name) not in allowed:
            print(f"{kind} {name} is in {PG} but not {LITE}", file=sys.stderr)
            bad = True
    for name in sorted(lite[kind] - pg[kind]):
        if (kind, name) not in allowed:
            print(f"{kind} {name} is in {LITE} but not {PG}", file=sys.stderr)
            bad = True
sys.exit(1 if bad else 0)
PY
then
  status=1
fi

if [[ "${status}" == 0 ]]; then
  echo "database boundary and schema parity checks passed"
fi
exit "${status}"
