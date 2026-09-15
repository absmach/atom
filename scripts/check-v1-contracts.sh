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

# migration_manifest pins the frozen v1.0.0 launch baseline
# (migrations/001_initial.sql) forever, by design: the applied baseline must
# never be edited (see AGENTS.md). It deliberately does NOT enumerate every
# migration file that exists today — forward-only NNN_<name>.sql migrations
# are the expected way Atom's schema evolves post-launch, and pinning each
# one's hash here would just be a second migrations directory to keep in
# sync, for no benefit sqlx's own `migrate!` immutability doesn't already
# provide at runtime. This check's job is narrower: prove every migration the
# manifest lists is still present with its content unchanged.
sha384sum --check "${migration_manifest}"

echo "validated launch API contracts and the frozen launch migration baseline"
