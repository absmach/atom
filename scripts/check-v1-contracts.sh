#!/usr/bin/env bash
set -euo pipefail

readonly freeze_tag="v1.0.0"
readonly upgrade_floor_tag="v0.50.0"
readonly upgrade_floor_commit="bd93da1180bf55da7643b77ab8fe5057ee348dbb"
readonly candidate_manifest="api/v1/contracts-v1.0.0.sha384"
readonly v1_migration_manifest="api/v1/migrations-v1.0.0.sha384"
readonly upgrade_floor_migrations=(
  migrations/001_initial.sql
  migrations/002_platform_filtered_permission_scopes.sql
  migrations/003_access_token_usage_and_ceiling_scope.sql
  migrations/004_event_outbox.sql
)
readonly contract_paths=(
  api/v1/bootstrap.schema.json
  api/v1/cache-contract.md
  api/v1/cache-wire-v1.json
  api/v1/deployment-config.json
  api/v1/domain-event-catalog.json
  api/v1/domain-event.schema.json
  api/v1/graphql-auth-matrix.json
  api/v1/jwt-contract.json
  "${v1_migration_manifest}"
  api/v1/persisted-semantics.json
  apidocs/openapi.yaml
  apidocs/graphql-schema.graphql
  proto/atom/v1/atom.proto
  proto/atom/v1/callout.proto
  proto/broker/v1/auth.proto
  proto/broker/v1/REF
)

resolved_upgrade_floor="$(git rev-parse --verify --quiet "refs/tags/${upgrade_floor_tag}^{commit}" || true)"
if [[ -z "${resolved_upgrade_floor}" ]]; then
  echo "required immutable upgrade-floor tag ${upgrade_floor_tag} is missing; fetch tags before running the v1 contract gate" >&2
  exit 1
fi
if [[ "${resolved_upgrade_floor}" != "${upgrade_floor_commit}" ]]; then
  echo "${upgrade_floor_tag} resolves to ${resolved_upgrade_floor}, expected pinned commit ${upgrade_floor_commit}" >&2
  exit 1
fi
if ! diff -u \
  <(printf '%s\n' "${upgrade_floor_migrations[@]}" | LC_ALL=C sort) \
  <(awk '{print $2}' api/v1/migrations-v0.50.0.sha384 | LC_ALL=C sort); then
  echo "api/v1/migrations-v0.50.0.sha384 must enumerate the released ${upgrade_floor_tag} migrations exactly once" >&2
  exit 1
fi
sha384sum --check api/v1/migrations-v0.50.0.sha384
for migration in "${upgrade_floor_migrations[@]}"; do
  if ! git diff --exit-code "${upgrade_floor_commit}" -- "${migration}"; then
    echo "Upgrade-floor migration ${migration} differs from ${upgrade_floor_tag} (${upgrade_floor_commit})." >&2
    exit 1
  fi
done

if ! diff -u \
  <(printf '%s\n' "${contract_paths[@]}" | LC_ALL=C sort) \
  <(awk '{print $2}' "${candidate_manifest}" | LC_ALL=C sort); then
  echo "${candidate_manifest} must enumerate every frozen v1 contract exactly once" >&2
  exit 1
fi
sha384sum --check "${candidate_manifest}"

declare -A frozen_migration_versions=()
max_frozen_migration=0
frozen_migration_count=0
while IFS= read -r migration; do
  filename="${migration##*/}"
  if [[ ! "${filename}" =~ ^([0-9]{3})_.+\.sql$ ]]; then
    echo "Frozen migration ${migration} does not use the required NNN_name.sql form." >&2
    exit 1
  fi
  version=$((10#${BASH_REMATCH[1]}))
  if (( version == 0 )); then
    echo "Frozen migration ${migration} must have a positive version." >&2
    exit 1
  fi
  if [[ -n "${frozen_migration_versions[${version}]+present}" ]]; then
    echo "Frozen migration version ${version} appears more than once." >&2
    exit 1
  fi
  frozen_migration_versions["${version}"]=1
  ((frozen_migration_count += 1))
  if (( version > max_frozen_migration )); then
    max_frozen_migration=${version}
  fi
done < <(awk '{print $2}' "${v1_migration_manifest}")
if (( frozen_migration_count != max_frozen_migration )); then
  echo "Frozen v1 migrations must be a contiguous positive sequence from 001 through $(printf '%03d' "${max_frozen_migration}")." >&2
  exit 1
fi
sha384sum --check "${v1_migration_manifest}"

if ! git rev-parse --verify --quiet "refs/tags/${freeze_tag}^{commit}" >/dev/null; then
  if ! diff -u \
    <(find migrations -maxdepth 1 -type f -name '*.sql' -printf '%p\n' | LC_ALL=C sort) \
    <(awk '{print $2}' "${v1_migration_manifest}" | LC_ALL=C sort); then
    echo "${v1_migration_manifest} must enumerate every candidate v1 migration exactly once" >&2
    exit 1
  fi
  echo "${freeze_tag} is not present; validated the v0.50.0 migration and v1 candidate contract baselines"
  exit 0
fi

if ! diff -u \
  <(git ls-tree -r --name-only "${freeze_tag}^{commit}" -- migrations | sed -n '/\.sql$/p' | LC_ALL=C sort) \
  <(awk '{print $2}' "${v1_migration_manifest}" | LC_ALL=C sort); then
  echo "${v1_migration_manifest} must enumerate every SQL migration shipped by ${freeze_tag} exactly once" >&2
  exit 1
fi

if ! git diff --exit-code "${freeze_tag}^{commit}" -- "${contract_paths[@]}"; then
  echo "The frozen v1 API differs from ${freeze_tag}. Version a new API instead of editing v1."
  exit 1
fi

while IFS= read -r migration; do
  if ! git diff --exit-code "${freeze_tag}^{commit}" -- "${migration}"; then
    echo "Released migration ${migration} was edited or removed. Add a new migration instead."
    exit 1
  fi
done < <(git ls-tree -r --name-only "${freeze_tag}^{commit}" -- migrations | sed -n '/\.sql$/p')

declare -A new_migration_versions=()
while IFS= read -r migration; do
  if awk -v path="${migration}" '$2 == path { found = 1 } END { exit !found }' "${v1_migration_manifest}"; then
    continue
  fi
  filename="${migration##*/}"
  if [[ ! "${filename}" =~ ^([0-9]{3})_.+\.sql$ ]]; then
    echo "New migration ${migration} must use the NNN_name.sql form." >&2
    exit 1
  fi
  version=$((10#${BASH_REMATCH[1]}))
  if (( version <= max_frozen_migration )); then
    echo "New migration ${migration} must have a version greater than the frozen v1 maximum ${max_frozen_migration}." >&2
    exit 1
  fi
  if [[ -n "${new_migration_versions[${version}]+present}" ]]; then
    echo "New migration version ${version} appears more than once." >&2
    exit 1
  fi
  new_migration_versions["${version}"]=1
done < <(find migrations -maxdepth 1 -type f -name '*.sql' -printf '%p\n' | LC_ALL=C sort)

buf breaking --against ".git#tag=${freeze_tag}"
