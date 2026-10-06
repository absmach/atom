#!/usr/bin/env bash
# Guards the database-backend boundary (see product-docs/development/database-backends/).
#
# Native driver calls belong to private domain adapters or shared DB infrastructure.
# There is no generic query API or runtime translator. The schema checks below
# also require paired forward migrations and matching tables/views/indexes.
# Storage SDK access is restricted to the BlobStore adapter in src/storage/.
set -euo pipefail

status=0
if ! python3 - <<'BOUNDARY'
from pathlib import Path
import re
import sys

bad = []
for legacy in ("src/db/query.rs", "src/db/translate.rs"):
    if Path(legacy).exists():
        bad.append(f"{legacy}: runtime query compatibility layer must not return")

raw = re.compile(r"sqlx::(?:query(?:_as|_scalar)?|postgres|sqlite|Postgres|Sqlite|PgPool|PgConnection|SqlitePool|SqliteConnection|Pool|Transaction)\b|\b(?:PgPool|PgConnection|SqlitePool|SqliteConnection)\b|::migrate!")
legacy = re.compile(r"\b(?:crate::|atom::)?db::(?:translate|query(?:_as|_scalar)?|QueryBuilder|DbArg|ArgKind)\b")
for path in Path("src").rglob("*.rs"):
    source = path.read_text()
    # Ignore test module bodies, not arbitrary cfg(test) imports earlier in a file.
    production = re.split(r"#\[cfg\(test\)\]\s*(?:pub(?:\([^)]*\))?\s+)?(?:mod\s+\w+\s*\{|(?:async\s+)?fn\s+)", source, maxsplit=1)[0]
    infrastructure = path.is_relative_to("src/db")
    adapter = path.name in ("postgres.rs", "sqlite.rs")
    if not infrastructure and not adapter:
        for imported in re.finditer(r"\buse\s+sqlx(?:::|\s+as\s+)\s*([^;]+);", production, re.S):
            if re.search(r"\b(?:query(?:_as|_scalar)?|QueryBuilder|PgPool|PgConnection|SqlitePool|SqliteConnection|Postgres|Sqlite|Executor|Row)\b", imported[1]):
                bad.append(f"{path}: driver/query imports belong in a native adapter")
    if not infrastructure and re.search(r"\bpub(?:\([^)]*\))?\s+use\s+[^;]*(?:postgres|sqlite)::", production):
        bad.append(f"{path}: backend operations must not be publicly re-exported")
    for number, line in enumerate(production.splitlines(), 1):
        if line.lstrip().startswith("//"):
            continue
        if legacy.search(line):
            bad.append(f"{path}:{number}: generic database queries/translation are forbidden")
        if not infrastructure and not adapter and raw.search(line):
            bad.append(f"{path}:{number}: driver types and queries belong in a native adapter")
        public_adapter = re.search(r"\bpub(?:\([^)]*\))?\s+mod\s+(postgres|sqlite)\s*;", line)
        if public_adapter and not infrastructure:
            # These modules only share canonical SQL fragments, never execute queries.
            if str(path) != "src/authz/sql/mod.rs" or "pub(crate)" not in line:
                bad.append(f"{path}:{number}: backend adapters must be private")
    if path.parent == Path("src/authz/sql") and raw.search(production):
        bad.append(f"{path}: shared SQL fragments must not execute database operations")

if bad:
    print("\n".join(bad), file=sys.stderr)
    sys.exit(1)
BOUNDARY
then
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

# --- 3. no storage SDK outside its adapter ----------------------------------
storage_violations="$(
  grep -rnE '(^|[^A-Za-z0-9_])object_store::|\bextern crate object_store\b' src --include='*.rs' \
  | grep -v '^src/storage/object_store_adapter\.rs:' \
  || true
)"
if [[ -n "${storage_violations}" ]]; then
  echo "storage SDK types used outside their adapter (use crate::storage::BlobStore):" >&2
  printf '%s\n' "${storage_violations}" >&2
  status=1
fi

if [[ "${status}" == 0 ]]; then
  echo "database and storage boundary and schema parity checks passed"
fi
exit "${status}"
