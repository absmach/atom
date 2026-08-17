set -e
: "${TOKEN:?run the login step first}"
GQL() { curl -sf -X POST http://localhost:8080/graphql \
  -H "authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  --data-binary "@-"; }

# ── 7. Import offline root ─────────────────────────────
ROOT_PEM=$(jq -Rs . < /tmp/root.pem)
ROOT_ID=$(GQL <<EOF | jq -r .data.importRootAuthority.id
{"query":"mutation(\$pem:String!){importRootAuthority(certificatePem:\$pem){id kind status}}",
 "variables":{"pem":$ROOT_PEM}}
EOF
)
echo "root: $ROOT_ID"

# ── 8. Create tenant ───────────────────────────────────
TENANT_ID=$(GQL <<'EOF' | jq -r .data.createTenant.id
{"query":"mutation{createTenant(input:{name:\"pki-manual\"}){id}}"}
EOF
)
echo "tenant: $TENANT_ID"

# ── 9. Provision tenant issuer automatically ───────────
# NOTE: needs a platform_intermediate first. The automatic path does that
# for you IF one exists. If this fails with "no active platform intermediate",
# call beginPlatformIntermediateProvisioning → sign CSR with root → importSignedAuthority
# once, then rerun this step. Manual test path.
ISSUER_ID=$(GQL <<EOF | jq -r .data.provisionTenantAuthorityAutomatically.authority.id
{"query":"mutation(\$t:ID!){provisionTenantAuthorityAutomatically(tenantId:\$t){authority{id kind status ocspUrl caIssuersUrl crlDistributionPointUrl}}}",
 "variables":{"t":"$TENANT_ID"}}
EOF
)
echo "issuer: $ISSUER_ID"

# ── 10. VERIFY FIX #1 — the URL columns are populated ──
docker exec -e PGPASSWORD=$POSTGRES_PASSWORD atom-postgres-1 \
  psql -U $POSTGRES_USER -d $POSTGRES_DB -c \
  "SELECT id, ocsp_url, ca_issuers_url, crl_distribution_point_url
     FROM pki_authorities WHERE id = '$ISSUER_ID';"
# expect: three non-NULL URLs pointing at http://localhost:8080/certs/...

# ── 11. Create device entity ───────────────────────────
ENTITY_ID=$(GQL <<EOF | jq -r .data.createEntity.id
{"query":"mutation(\$t:ID!){createEntity(input:{name:\"device-1\",tenantId:\$t,kind:DEVICE}){id}}",
 "variables":{"t":"$TENANT_ID"}}
EOF
)
echo "entity: $ENTITY_ID"

# ── 12. Generate device key + CSR ──────────────────────
openssl ecparam -name prime256v1 -genkey -out /tmp/device.key
openssl req -new -key /tmp/device.key -out /tmp/device.csr -subj "/CN=device-1"
CSR_PEM=$(jq -Rs . < /tmp/device.csr)

# ── 13. Enroll: issueCertificateFromCsrV2 ──────────────
CERT=$(GQL <<EOF
{"query":"mutation(\$in:IssueCertificateFromCsrV2Input!){issueCertificateFromCsrV2(input:\$in){certificate{credentialId serialNumber pem}}}",
 "variables":{"in":{"entityId":"$ENTITY_ID","csrPem":$CSR_PEM,"idempotencyKey":"manual-1","ttlSecs":3600}}}
EOF
)
CRED_ID=$(echo "$CERT" | jq -r .data.issueCertificateFromCsrV2.certificate.credentialId)
SERIAL=$(echo  "$CERT" | jq -r .data.issueCertificateFromCsrV2.certificate.serialNumber)
echo "$CERT" | jq -r .data.issueCertificateFromCsrV2.certificate.pem > /tmp/device.pem
echo "cred: $CRED_ID  serial: $SERIAL"
openssl x509 -in /tmp/device.pem -noout -subject -issuer -ext authorityInfoAccess,crlDistributionPoints
# expect: AIA/CRL URLs pointing at your ATOM_PUBLIC_BASE_URL — proves fix #1 end-to-end

# ── 14. Fetch trust bundle, per-issuer CRL, per-issuer OCSP ────
curl -sf http://localhost:8080/certs/trust-bundle.pem | openssl storeutl -certs -noout /dev/stdin | grep -c BEGIN
curl -sf "http://localhost:8080/certs/issuers/$ISSUER_ID/crl" \
  | openssl crl -inform DER -noout -text | grep -E "Serial|Revoked" | head -5
# fetch issuer cert for OCSP
curl -sf http://localhost:8080/certs/trust-bundle.pem > /tmp/chain.pem
openssl ocsp -issuer /tmp/chain.pem -cert /tmp/device.pem \
  -url "http://localhost:8080/certs/issuers/$ISSUER_ID/ocsp" -noverify -text | tail -20
# expect: "Cert Status: good"

# ── 15. Revoke ─────────────────────────────────────────
GQL <<EOF | jq .
{"query":"mutation(\$in:RevokeCertificateV2Input!){revokeCertificateV2(input:\$in){certificate{status} reason revokedAt}}",
 "variables":{"in":{"credentialId":"$CRED_ID","reason":"key_compromise"}}}
EOF

# ── 16. Verify revocation via CRL + OCSP ───────────────
curl -sf "http://localhost:8080/certs/issuers/$ISSUER_ID/crl" \
  | openssl crl -inform DER -noout -text | grep -A1 "Serial Number: $SERIAL"
# expect: the revoked serial appears
openssl ocsp -issuer /tmp/chain.pem -cert /tmp/device.pem \
  -url "http://localhost:8080/certs/issuers/$ISSUER_ID/ocsp" -noverify -text | grep "Cert Status"
# expect: "Cert Status: revoked"

# ── 17. VERIFY FIX #2 — purge the tenant after revocation ───
GQL <<EOF | jq .
{"query":"mutation(\$id:ID!){deleteTenant(id:\$id)}", "variables":{"id":"$TENANT_ID"}}
EOF
GQL <<EOF | jq .
{"query":"mutation(\$id:ID!){purgeTenant(id:\$id)}", "variables":{"id":"$TENANT_ID"}}
EOF
# expect: both return true. Before fix #2 this failed with FK violation.

docker exec -e PGPASSWORD=$POSTGRES_PASSWORD atom-postgres-1 \
  psql -U $POSTGRES_USER -d $POSTGRES_DB -c \
  "SELECT count(*) authorities_left FROM pki_authorities WHERE tenant_id = '$TENANT_ID';
   SELECT issuer_id, issuer_fingerprint_sha256 IS NOT NULL AS fingerprint_kept
     FROM certificate_revocations WHERE serial_number = '$SERIAL';"
# expect: authorities_left = 0, issuer_id = NULL, fingerprint_kept = t

echo "MANUAL TEST PASSED"
