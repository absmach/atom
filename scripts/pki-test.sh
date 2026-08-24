#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/pki-test.sh [smoke|full]

Required environment:
  PKI_TEST_MAINT_URL       PostgreSQL URL for creating the disposable DB
  PKI_TEST_DATABASE_URL    PostgreSQL URL whose database is PKI_TEST_DATABASE_NAME
  ATOM_EST_CLIENT          Executable GlobalSign EST client (v1.0.7)

Optional environment:
  PKI_TEST_DATABASE_NAME   Must begin with atom_pki_test (default: atom_pki_test)

Full mode also requires SOFTHSM2_CONF and the ATOM_PKI_PKCS11_* variables.
EOF
}

mode="${1:-smoke}"
case "$mode" in
  smoke|full) ;;
  -h|--help)
    usage
    exit 0
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac

test_db_name="${PKI_TEST_DATABASE_NAME:-atom_pki_test}"
if [[ ! "$test_db_name" =~ ^atom_pki_test(_[a-zA-Z0-9_]+)?$ ]]; then
  echo "PKI_TEST_DATABASE_NAME must be atom_pki_test or use an atom_pki_test_ prefix" >&2
  exit 2
fi

: "${PKI_TEST_MAINT_URL:?PKI_TEST_MAINT_URL is required}"
: "${PKI_TEST_DATABASE_URL:?PKI_TEST_DATABASE_URL is required}"
: "${ATOM_EST_CLIENT:?ATOM_EST_CLIENT is required}"

database_url_without_query="${PKI_TEST_DATABASE_URL%%\?*}"
maint_url_without_query="${PKI_TEST_MAINT_URL%%\?*}"
case "$database_url_without_query" in
  */"$test_db_name") ;;
  *)
    echo "PKI_TEST_DATABASE_URL must point to database $test_db_name" >&2
    exit 2
    ;;
esac
case "$maint_url_without_query" in
  */"$test_db_name")
    echo "PKI_TEST_MAINT_URL must not connect to the disposable test database" >&2
    exit 2
    ;;
esac

for command_name in cargo psql openssl protoc; do
  command -v "$command_name" >/dev/null 2>&1 || {
    echo "$command_name is required" >&2
    exit 2
  }
done

test -x "$ATOM_EST_CLIENT" || {
  echo "ATOM_EST_CLIENT must point to an executable EST client" >&2
  exit 2
}

if [[ "$mode" == "full" ]]; then
  : "${SOFTHSM2_CONF:?SOFTHSM2_CONF is required in full mode}"
  : "${ATOM_PKI_PKCS11_MODULE_PATH:?ATOM_PKI_PKCS11_MODULE_PATH is required in full mode}"
  : "${ATOM_PKI_PKCS11_TOKEN_LABEL:?ATOM_PKI_PKCS11_TOKEN_LABEL is required in full mode}"
  : "${ATOM_PKI_PKCS11_USER_PIN:?ATOM_PKI_PKCS11_USER_PIN is required in full mode}"
  test -r "$ATOM_PKI_PKCS11_MODULE_PATH" || {
    echo "ATOM_PKI_PKCS11_MODULE_PATH is not readable" >&2
    exit 2
  }
fi

smoke_tests=(
  m30_pki_ca_provisioning
  m32_pki_csr_issuance
  m35_pki_revocation
  m36_pki_issuer_crls
  m37_pki_issuer_ocsp
  m38_pki_runtime_resolver_v2
  m41_pki_est
)

full_tests=()
for test_path in tests/m[0-9][0-9]_pki*.rs; do
  test -e "$test_path" || continue
  full_tests+=("$(basename "$test_path" .rs)")
done
test "${#full_tests[@]}" -gt 0 || {
  echo "No PKI integration test binaries found under tests/" >&2
  exit 1
}

reset_database() {
  psql "$PKI_TEST_MAINT_URL" -v ON_ERROR_STOP=1 \
    -c "DROP DATABASE IF EXISTS \"$test_db_name\" WITH (FORCE)" >/dev/null
  psql "$PKI_TEST_MAINT_URL" -v ON_ERROR_STOP=1 \
    -c "CREATE DATABASE \"$test_db_name\"" >/dev/null
}

run_test_binary() {
  local test_name="$1"
  echo "==> Running $test_name against a fresh disposable database"
  reset_database
  DATABASE_URL="$PKI_TEST_DATABASE_URL" \
    cargo test --locked --test "$test_name" -- \
      --include-ignored --test-threads=1
}

if [[ "$mode" == "smoke" ]]; then
  selected_tests=("${smoke_tests[@]}")
else
  selected_tests=("${full_tests[@]}")
fi

for test_name in "${selected_tests[@]}"; do
  test -f "tests/$test_name.rs" || {
    echo "Missing required test binary: tests/$test_name.rs" >&2
    exit 1
  }
  run_test_binary "$test_name"
done

echo "PKI $mode test passed (${#selected_tests[@]} integration binaries)."
