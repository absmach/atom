#!/usr/bin/env bash
set -euo pipefail

readonly candidate_manifest="api/v1/contracts-v1.0.0.sha384"
readonly migration_manifest="api/v1/migrations-v1.0.0.sha384"
readonly contract_paths=(
  api/v1/bootstrap.schema.json
  api/v1/cache-contract.md
  api/v1/cache-wire-v1.json
  api/v1/deployment-config.json
  api/v1/domain-event-catalog.json
  api/v1/domain-event.schema.json
  api/v1/graphql-auth-matrix.json
  api/v1/jwt-contract.json
  "${migration_manifest}"
  api/v1/persisted-semantics.json
  apidocs/openapi.yaml
  apidocs/graphql-schema.graphql
  proto/atom/v1/atom.proto
  proto/atom/v1/callout.proto
  proto/broker/v1/auth.proto
  proto/broker/v1/REF
)

if ! diff -u \
  <(printf '%s\n' "${contract_paths[@]}" | LC_ALL=C sort) \
  <(awk '{print $2}' "${candidate_manifest}" | LC_ALL=C sort); then
  echo "${candidate_manifest} must enumerate every launch contract exactly once" >&2
  exit 1
fi
sha384sum --check "${candidate_manifest}"

if ! diff -u \
  <(find migrations -maxdepth 1 -type f -name '*.sql' -printf '%p\n' | LC_ALL=C sort) \
  <(awk '{print $2}' "${migration_manifest}" | LC_ALL=C sort); then
  echo "${migration_manifest} must enumerate every launch SQL migration exactly once" >&2
  exit 1
fi

migration_count="$(awk 'END { print NR }' "${migration_manifest}")"
if [[ "${migration_count}" != 1 ]]; then
  echo "the launch baseline must contain exactly one SQL migration" >&2
  exit 1
fi
sha384sum --check "${migration_manifest}"

echo "validated launch API contracts and single-migration baseline"
