#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8080}"
ADMIN_IDENTIFIER="${ADMIN_IDENTIFIER:-atom-admin}"
ADMIN_SECRET="${ADMIN_SECRET:-change-me}"
RUN_ID="${RUN_ID:-$(date +%s)}"
DEMO_STEP_SLEEP="${DEMO_STEP_SLEEP:-4}"

need() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing dependency: $1" >&2
    exit 1
  fi
}

need http
need jq

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

say() {
  printf "\n\033[1;36m%s\033[0m\n" "▶ $1"
}

call() {
  local name="$1"
  shift
  say "$name"
  echo "\$ http $*"
  http --check-status --ignore-stdin --body "$@" | tee "$tmp/last.json" | jq .
  sleep "$DEMO_STEP_SLEEP"
}

say "Atom demo: tenant bootstrap, online authorization, deny override, audit"
echo "Base URL: $BASE_URL"
echo "Run ID:   $RUN_ID"

call "Health check" GET "$BASE_URL/health"

call "Login as platform admin" POST "$BASE_URL/auth/login" \
  identifier="$ADMIN_IDENTIFIER" \
  secret="$ADMIN_SECRET"
TOKEN="$(jq -r '.token' "$tmp/last.json")"
ADMIN_ID="$(jq -r '.entity_id' "$tmp/last.json")"

AUTH="Authorization:Bearer $TOKEN"

call "Load seeded capabilities" GET "$BASE_URL/capabilities" "$AUTH"
PUBLISH_CAP="$(jq -r '.items[] | select(.name=="publish" and .resource_kind==null) | .id' "$tmp/last.json" | head -n1)"

call "Create tenant: factory-$RUN_ID" POST "$BASE_URL/tenants" "$AUTH" \
  name="factory-$RUN_ID" \
  alias="factory-$RUN_ID" \
  tags:='["demo","factory"]' \
  attributes:='{"region":"demo","plan":"gold"}'
TENANT_ID="$(jq -r '.id' "$tmp/last.json")"

say "M5 happened automatically"
echo "Atom created tenant-admin role, bound it to the creator, and added tenant membership for human creators."
http --ignore-stdin --body GET "$BASE_URL/roles?tenant_id=$TENANT_ID" "$AUTH" | jq '{tenant_admin: [.items[] | select(.name=="tenant-admin")][0]}'
sleep "$DEMO_STEP_SLEEP"

call "Create device in tenant" POST "$BASE_URL/entities" "$AUTH" \
  kind=device \
  name="sensor-$RUN_ID" \
  tenant_id="$TENANT_ID" \
  attributes:='{"site":"line-1","firmware":"1.0.0"}'
DEVICE_ID="$(jq -r '.id' "$tmp/last.json")"

call "Create channel resource in tenant" POST "$BASE_URL/resources" "$AUTH" \
  kind=channel \
  name="temperature-$RUN_ID" \
  tenant_id="$TENANT_ID" \
  owner_id="$DEVICE_ID" \
  attributes:='{"tags":["production"],"topic":"temperature"}'
CHANNEL_ID="$(jq -r '.id' "$tmp/last.json")"

call "Create publisher role in tenant" POST "$BASE_URL/roles" "$AUTH" \
  name="publisher-$RUN_ID" \
  tenant_id="$TENANT_ID" \
  description="Devices that can publish telemetry"
ROLE_ID="$(jq -r '.id' "$tmp/last.json")"

call "Attach publish capability to role" POST "$BASE_URL/roles/$ROLE_ID/capabilities" "$AUTH" \
  capability_id="$PUBLISH_CAP"

call "Bind publisher role to device for resource:channel" POST "$BASE_URL/policies" "$AUTH" \
  tenant_id="$TENANT_ID" \
  subject_kind=entity \
  subject_id="$DEVICE_ID" \
  grant_kind=role \
  grant_id="$ROLE_ID" \
  scope_kind=object_type \
  scope_ref=resource:channel \
  effect=allow \
  conditions:='{}'
ALLOW_POLICY_ID="$(jq -r '.id' "$tmp/last.json")"

call "PDP check: device can publish to channel" POST "$BASE_URL/authz/check" "$AUTH" \
  subject_id="$DEVICE_ID" \
  action=publish \
  resource_id="$CHANNEL_ID" \
  context:='{"client":"demo"}'

call "Add explicit deny for emergency lockout" POST "$BASE_URL/policies" "$AUTH" \
  tenant_id="$TENANT_ID" \
  subject_kind=entity \
  subject_id="$DEVICE_ID" \
  grant_kind=capability \
  grant_id="$PUBLISH_CAP" \
  scope_kind=object \
  scope_ref="$CHANNEL_ID" \
  effect=deny \
  conditions:='{}'
DENY_POLICY_ID="$(jq -r '.id' "$tmp/last.json")"

call "PDP check: deny overrides allow" POST "$BASE_URL/authz/check" "$AUTH" \
  subject_id="$DEVICE_ID" \
  action=publish \
  resource_id="$CHANNEL_ID" \
  context:='{"client":"demo"}'

call "Explain the denied decision" POST "$BASE_URL/authz/explain" "$AUTH" \
  subject_id="$DEVICE_ID" \
  action=publish \
  resource_id="$CHANNEL_ID" \
  context:='{"client":"demo"}'

call "Freeze tenant lifecycle" POST "$BASE_URL/tenants/$TENANT_ID/freeze" "$AUTH"

call "PDP check: tenant lifecycle blocks access" POST "$BASE_URL/authz/check" "$AUTH" \
  subject_id="$DEVICE_ID" \
  action=publish \
  resource_id="$CHANNEL_ID" \
  context:='{"client":"demo"}'

call "Audit trail for this tenant" GET "$BASE_URL/audit?tenant_id=$TENANT_ID&limit=10&offset=0" "$AUTH"

say "Demo summary"
jq -n \
  --arg admin_id "$ADMIN_ID" \
  --arg tenant_id "$TENANT_ID" \
  --arg device_id "$DEVICE_ID" \
  --arg channel_id "$CHANNEL_ID" \
  --arg allow_policy_id "$ALLOW_POLICY_ID" \
  --arg deny_policy_id "$DENY_POLICY_ID" \
  '{
    admin_id: $admin_id,
    tenant_id: $tenant_id,
    device_id: $device_id,
    channel_id: $channel_id,
    allow_policy_id: $allow_policy_id,
    deny_policy_id: $deny_policy_id
  }'
sleep "$DEMO_STEP_SLEEP"
