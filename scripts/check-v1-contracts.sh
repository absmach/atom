#!/usr/bin/env bash
set -euo pipefail

readonly freeze_tag="${ATOM_V1_FREEZE_TAG:-v1.0.0}"
readonly api_paths=(
  apidocs/openapi.yaml
  apidocs/graphql-schema.graphql
  proto/atom/v1/atom.proto
)

sha384sum --check api/v1/migrations-v0.50.0.sha384

if ! git rev-parse --verify --quiet "refs/tags/${freeze_tag}^{commit}" >/dev/null; then
  echo "${freeze_tag} is not present; validated the v0.50.0 migration baseline only"
  exit 0
fi

if ! git diff --exit-code "${freeze_tag}^{commit}" -- "${api_paths[@]}"; then
  echo "The frozen v1 API differs from ${freeze_tag}. Version a new API instead of editing v1."
  exit 1
fi

while IFS= read -r migration; do
  if ! git diff --exit-code "${freeze_tag}^{commit}" -- "${migration}"; then
    echo "Released migration ${migration} was edited or removed. Add a new migration instead."
    exit 1
  fi
done < <(git ls-tree -r --name-only "${freeze_tag}^{commit}" -- migrations | sed -n '/\.sql$/p')

buf breaking --against ".git#tag=${freeze_tag}"
