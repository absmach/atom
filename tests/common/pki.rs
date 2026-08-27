//! Shared managed-PKI fixtures for the numbered integration specifications.

use std::{fs, process::Command};

use atom::{
    certs::authority::{provisioning, repo as authority_repo, AuthorityRecord},
    config::Config,
    keys::{ActiveKeys, LoadedKey},
    state::AppState,
};
use p256::{
    ecdsa::SigningKey,
    pkcs8::{EncodePrivateKey, LineEnding},
};
use rand::rngs::OsRng;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyIdMethod, KeyPair,
    KeyUsagePurpose,
};
use sqlx::PgPool;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

pub const OCSP_URL: &str = "https://pki.example.test/tenant/ocsp";
pub const CA_ISSUERS_URL: &str = "https://pki.example.test/tenant/ca.der";
pub const CRL_URL: &str = "https://pki.example.test/tenant/crl.der";

pub struct TestRoot {
    pub params: CertificateParams,
    pub key: KeyPair,
    pub pem: String,
}

pub fn managed_config(generated_key_issuance_enabled: bool, events_enabled: bool) -> Config {
    let mut config = Config::for_tests();
    if events_enabled {
        config.events.amqp_url = Some("amqp://unused-in-managed-pki-test".to_string());
    }
    config.graphql_limits.introspection_enabled = true;
    config.pki_generated_key_issuance_enabled = generated_key_issuance_enabled;
    config
}

pub fn graphql_state(pool: PgPool, config: Config) -> AppState {
    let primary = LoadedKey {
        kid: "test".into(),
        public_key_pem: String::new(),
        private_key_pem: String::new(),
        x_b64: String::new(),
        y_b64: String::new(),
    };
    AppState::new(
        pool,
        config,
        ActiveKeys {
            primary,
            standby: None,
        },
        None,
    )
}

pub fn test_root(label: &str) -> TestRoot {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.distinguished_name.push(DnType::CommonName, label);
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(2));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.key_identifier_method = KeyIdMethod::Sha256;
    params.not_before = OffsetDateTime::now_utc() - Duration::days(1);
    params.not_after = OffsetDateTime::now_utc() + Duration::days(365);
    let pem = params.self_signed(&key).unwrap().pem();
    TestRoot { params, key, pem }
}

/// Bootstrap-style provisioning: mints a fresh platform intermediate key
/// pair (P-256), signs it with the offline test root, imports both the root
/// and the intermediate through the config-bootstrap code paths, then
/// auto-provisions a tenant intermediate under that platform intermediate.
///
/// This mirrors the runtime flow where the operator ships in a pre-signed
/// platform intermediate and Atom onboards tenants automatically.
pub async fn provision_tenant_issuer(
    pool: &PgPool,
    config: &Config,
    root: &TestRoot,
    tenant_id: Uuid,
) -> AuthorityRecord {
    bootstrap_root_and_platform_intermediate(pool, config, root).await;

    let mut tx = pool.begin().await.unwrap();
    let mut provisioned =
        provisioning::provision_tenant_automatically_in_tx(&mut tx, &config.pki_ca_keys, tenant_id)
            .await
            .unwrap();
    assert!(
        provisioned.succeeded(),
        "{:?}",
        provisioned.validation_error
    );
    tx.commit().await.unwrap();
    provisioned.commit_generated_key();
    authority_repo::authority_by_id(pool, provisioned.authority.id)
        .await
        .unwrap()
}

/// Provision a platform leaf issuer for tests that need one. Since the
/// interactive GraphQL flow was removed, this builds a signed leaf-issuer
/// certificate directly in the test process and inserts it as an already-
/// active authority through the same `insert_active_authority` helper the
/// runtime bootstrap uses.
pub async fn provision_platform_leaf_issuer(
    pool: &PgPool,
    config: &Config,
    root: &TestRoot,
) -> AuthorityRecord {
    let root_authority = bootstrap_root(pool, root).await;

    let (cert_pem, pkcs8_der) =
        sign_leaf_issuer("Atom Platform Leaf Issuer v1", root, /*path_len*/ 0);
    insert_active_signing_authority(
        pool,
        config,
        &root_authority,
        atom::certs::authority::AuthorityKind::PlatformLeafIssuer,
        None,
        cert_pem,
        pkcs8_der,
    )
    .await
}

/// Rotate a tenant issuer through the offline-signature test path. Uses the
/// still-exported `begin_tenant_authority_in_tx` + a helper-signed CSR + the
/// still-internal `import_signed_authority_locked` path via the automatic
/// provisioning mutation. In practice for tests we simply re-run the auto
/// provisioning after retiring the previous active row.
pub async fn rotate_tenant_issuer(
    pool: &PgPool,
    config: &Config,
    _root: &TestRoot,
    tenant_id: Uuid,
) -> AuthorityRecord {
    // Retire the currently-active tenant intermediate so
    // `provision_tenant_automatically_in_tx` mints a new one.
    sqlx::query(
        r#"UPDATE pki_authorities
           SET status = 'retiring', issuance_enabled = false,
               retiring_at = now(), updated_at = now()
           WHERE tenant_id = $1
             AND kind = 'tenant_intermediate'
             AND status = 'active'"#,
    )
    .bind(tenant_id)
    .execute(pool)
    .await
    .unwrap();

    let mut tx = pool.begin().await.unwrap();
    let mut provisioned =
        provisioning::provision_tenant_automatically_in_tx(&mut tx, &config.pki_ca_keys, tenant_id)
            .await
            .unwrap();
    assert!(
        provisioned.succeeded(),
        "{:?}",
        provisioned.validation_error
    );
    tx.commit().await.unwrap();
    provisioned.commit_generated_key();
    authority_repo::authority_by_id(pool, provisioned.authority.id)
        .await
        .unwrap()
}

/// Import a root PEM as the managed trust anchor.
async fn bootstrap_root(pool: &PgPool, root: &TestRoot) -> AuthorityRecord {
    let mut tx = pool.begin().await.unwrap();
    let mut outcome = provisioning::import_root_mutation_in_tx(&mut tx, &root.pem)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    outcome.commit_generated_key();
    authority_repo::authority_by_id(pool, outcome.value.id)
        .await
        .unwrap()
}

/// Bootstrap root + platform intermediate through the config-bootstrap paths.
async fn bootstrap_root_and_platform_intermediate(pool: &PgPool, config: &Config, root: &TestRoot) {
    bootstrap_root(pool, root).await;

    let (cert_pem, pkcs8_pem) =
        sign_platform_intermediate("Atom Platform Intermediate CA v1", root);
    let mut tx = pool.begin().await.unwrap();
    let mut outcome = provisioning::import_platform_intermediate_mutation_in_tx(
        &mut tx,
        &config.pki_ca_keys,
        &cert_pem,
        &pkcs8_pem,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    outcome.commit_generated_key();
}

/// Generate a P-256 key, wrap it in the schema Atom expects (path_len=1,
/// key usages for signing subordinate CAs), and sign it with the test root.
/// Returns (certificate PEM, PKCS#8 PEM of the private key).
fn sign_platform_intermediate(common_name: &str, root: &TestRoot) -> (String, String) {
    let key_pair = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(1));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.key_identifier_method = KeyIdMethod::Sha256;
    params.use_authority_key_identifier_extension = true;
    params.not_before = OffsetDateTime::now_utc() - Duration::minutes(1);
    params.not_after = OffsetDateTime::now_utc() + Duration::days(180);
    let cert = params
        .signed_by(&key_pair, &Issuer::from_params(&root.params, &root.key))
        .unwrap();
    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();
    (cert_pem, key_pem)
}

/// Generate a P-256 key + certificate for a leaf-issuer authority with the
/// given path length, signed by the test root. Returns (cert PEM, PKCS#8 DER).
fn sign_leaf_issuer(common_name: &str, root: &TestRoot, path_len: u8) -> (String, Vec<u8>) {
    let signing_key = SigningKey::random(&mut OsRng);
    let pkcs8_der = signing_key.to_pkcs8_der().unwrap().as_bytes().to_vec();
    let pkcs8_pem = signing_key
        .to_pkcs8_pem(LineEnding::LF)
        .unwrap()
        .to_string();
    let key_pair = KeyPair::from_pem(&pkcs8_pem).unwrap();

    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(path_len));
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    params.key_identifier_method = KeyIdMethod::Sha256;
    params.use_authority_key_identifier_extension = true;
    params.not_before = OffsetDateTime::now_utc() - Duration::minutes(1);
    params.not_after = OffsetDateTime::now_utc() + Duration::days(180);
    let cert = params
        .signed_by(&key_pair, &Issuer::from_params(&root.params, &root.key))
        .unwrap();
    (cert.pem(), pkcs8_der)
}

/// Insert an active signing authority (with encrypted key material) directly
/// via `repo::insert_active_authority` — used for kinds without a public
/// provisioning entry point (e.g. platform leaf issuer).
#[allow(clippy::too_many_arguments)]
async fn insert_active_signing_authority(
    pool: &PgPool,
    config: &Config,
    parent: &AuthorityRecord,
    kind: atom::certs::authority::AuthorityKind,
    tenant_id: Option<Uuid>,
    certificate_pem: String,
    pkcs8_der: Vec<u8>,
) -> AuthorityRecord {
    use atom::certs::authority::key_provider::{
        AuthorityKeyAlgorithm, AuthorityKeyContext, AuthorityKeyProvider, ManagedAuthorityKey,
        ManagedAuthorityKeyProvider,
    };
    use ring::digest;

    let ca_keys = &config.pki_ca_keys;
    let provider = ManagedAuthorityKeyProvider::for_provisioning(ca_keys).unwrap();

    let mut tx = pool.begin().await.unwrap();
    let version = atom::certs::authority::repo::next_authority_version(&mut tx, kind, tenant_id)
        .await
        .unwrap();
    let authority_id = Uuid::new_v4();
    let context = AuthorityKeyContext {
        authority_id,
        tenant_id,
        version,
    };
    let generated = provider
        .import_pkcs8(context, AuthorityKeyAlgorithm::EcdsaP256Sha256, &pkcs8_der)
        .unwrap();
    let managed_key = generated.key;

    let (_, pem) = x509_parser::pem::parse_x509_pem(certificate_pem.as_bytes()).unwrap();
    let (_, cert) = x509_parser::parse_x509_certificate(&pem.contents).unwrap();
    let fingerprint = hex::encode(digest::digest(&digest::SHA256, &pem.contents));
    let serial = normalize_hex(&cert.tbs_certificate.raw_serial_as_string());
    let mut subject_key_id = None;
    let mut authority_key_id = None;
    for extension in cert.extensions() {
        match extension.parsed_extension() {
            x509_parser::extensions::ParsedExtension::SubjectKeyIdentifier(key_id) => {
                subject_key_id = Some(hex::encode(key_id.0));
            }
            x509_parser::extensions::ParsedExtension::AuthorityKeyIdentifier(key_id) => {
                authority_key_id = key_id
                    .key_identifier
                    .as_ref()
                    .map(|value| hex::encode(value.0));
            }
            _ => {}
        }
    }

    let parent_chain = parent.chain_pem.as_deref().unwrap();
    let chain_pem = format!("{certificate_pem}{parent_chain}");
    let not_before =
        chrono::DateTime::<chrono::Utc>::from_timestamp(cert.validity().not_before.timestamp(), 0)
            .unwrap();
    let not_after =
        chrono::DateTime::<chrono::Utc>::from_timestamp(cert.validity().not_after.timestamp(), 0)
            .unwrap();
    let completed = atom::certs::authority::repo::CompletedAuthority {
        subject: cert.subject().to_string(),
        serial_number: serial,
        fingerprint_sha256: fingerprint,
        subject_key_id: subject_key_id.unwrap(),
        authority_key_id,
        certificate_pem: certificate_pem.clone(),
        chain_pem,
        not_before,
        not_after,
    };
    let discovery = if kind.can_issue_leaf_credentials() {
        let base = ca_keys
            .artifact_base_url
            .as_deref()
            .unwrap_or("https://pki.example.test")
            .trim_end_matches('/');
        Some(atom::certs::authority::repo::DiscoveryUrls {
            ocsp_url: Some(format!("{base}/certs/issuers/{authority_id}/ocsp")),
            ca_issuers_url: Some(format!("{base}/certs/trust-bundle.pem")),
            crl_distribution_point_url: Some(format!("{base}/certs/issuers/{authority_id}/crl")),
        })
    } else {
        None
    };
    let record = atom::certs::authority::repo::insert_active_authority(
        &mut tx,
        &atom::certs::authority::repo::ActiveAuthorityInsert {
            id: authority_id,
            tenant_id,
            parent_id: parent.id,
            kind,
            version,
            provisioning_mode: "config_bootstrap",
            issuance_enabled: kind.can_issue_leaf_credentials(),
            key: &ManagedAuthorityKey::EncryptedDatabase(match managed_key {
                ManagedAuthorityKey::EncryptedDatabase(key) => key,
                _ => panic!("test helper requires encrypted-database backend"),
            }),
            completed: &completed,
            discovery: discovery.as_ref(),
        },
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    authority_repo::authority_by_id(pool, record.id)
        .await
        .unwrap()
}

fn normalize_hex(value: &str) -> String {
    let normalized: String = value
        .chars()
        .filter(|c| *c != ':' && !c.is_whitespace())
        .flat_map(char::to_lowercase)
        .collect();
    let trimmed = normalized.trim_start_matches('0');
    if trimmed.is_empty() {
        "0".to_string()
    } else {
        trimmed.to_string()
    }
}

pub async fn create_tenant(pool: &PgPool, prefix: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO tenants (id, name) VALUES ($1, $2)")
        .bind(id)
        .bind(format!("{prefix}-{id}"))
        .execute(pool)
        .await
        .unwrap();
    id
}

pub async fn create_entity(pool: &PgPool, tenant_id: Uuid, prefix: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO entities (id, kind, name, tenant_id, status) VALUES ($1, 'device', $2, $3, 'active')",
    )
    .bind(id)
    .bind(format!("{prefix}-{id}"))
    .bind(tenant_id)
    .execute(pool)
    .await
    .unwrap();
    id
}

pub async fn create_global_entity(pool: &PgPool, prefix: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO entities (id, kind, name, status) VALUES ($1, 'service', $2, 'active')",
    )
    .bind(id)
    .bind(format!("{prefix}-{id}"))
    .execute(pool)
    .await
    .unwrap();
    id
}

/// Insert a bare root → platform_intermediate → tenant_intermediate chain
/// via raw SQL and return the tenant_intermediate id. Suitable for tests
/// that need a valid `issuer_id` on a certificate credential without
/// exercising full CSR issuance.
pub async fn insert_bare_tenant_authority(pool: &PgPool, tenant_id: Uuid) -> Uuid {
    let root_id = Uuid::new_v4();
    let platform_id = Uuid::new_v4();
    let tenant_authority_id = Uuid::new_v4();
    let now = time::OffsetDateTime::now_utc();
    let not_before =
        chrono::DateTime::from_timestamp(now.unix_timestamp(), 0).expect("unix time in range");
    let not_after = not_before + chrono::Duration::days(365);
    insert_bare_authority_row(
        pool,
        root_id,
        None,
        None,
        "root",
        1,
        format!("{:064x}", root_id.as_u128()),
        not_before,
        not_after,
    )
    .await;
    insert_bare_authority_row(
        pool,
        platform_id,
        None,
        Some(root_id),
        "platform_intermediate",
        1,
        format!("{:064x}", platform_id.as_u128()),
        not_before,
        not_after,
    )
    .await;
    insert_bare_authority_row(
        pool,
        tenant_authority_id,
        Some(tenant_id),
        Some(platform_id),
        "tenant_intermediate",
        1,
        format!("{:064x}", tenant_authority_id.as_u128()),
        not_before,
        not_after,
    )
    .await;
    tenant_authority_id
}

/// Insert a bare platform_leaf_issuer chain (root → platform_intermediate →
/// platform_leaf_issuer) and return the platform_leaf_issuer id. Used to
/// bind certificate credentials for globally-scoped entities.
pub async fn insert_bare_platform_leaf_authority(pool: &PgPool) -> Uuid {
    let root_id = Uuid::new_v4();
    let platform_id = Uuid::new_v4();
    let leaf_id = Uuid::new_v4();
    let now = time::OffsetDateTime::now_utc();
    let not_before =
        chrono::DateTime::from_timestamp(now.unix_timestamp(), 0).expect("unix time in range");
    let not_after = not_before + chrono::Duration::days(365);
    insert_bare_authority_row(
        pool,
        root_id,
        None,
        None,
        "root",
        1,
        format!("{:064x}", root_id.as_u128()),
        not_before,
        not_after,
    )
    .await;
    insert_bare_authority_row(
        pool,
        platform_id,
        None,
        Some(root_id),
        "platform_intermediate",
        1,
        format!("{:064x}", platform_id.as_u128()),
        not_before,
        not_after,
    )
    .await;
    insert_bare_authority_row(
        pool,
        leaf_id,
        None,
        Some(root_id),
        "platform_leaf_issuer",
        1,
        format!("{:064x}", leaf_id.as_u128()),
        not_before,
        not_after,
    )
    .await;
    leaf_id
}

#[allow(clippy::too_many_arguments)]
async fn insert_bare_authority_row(
    pool: &PgPool,
    id: Uuid,
    tenant_id: Option<Uuid>,
    parent_id: Option<Uuid>,
    kind: &str,
    version: i32,
    fingerprint: String,
    not_before: chrono::DateTime<chrono::Utc>,
    not_after: chrono::DateTime<chrono::Utc>,
) {
    let issuance_enabled = matches!(kind, "platform_leaf_issuer" | "tenant_intermediate");
    sqlx::query(
        r#"
        INSERT INTO pki_authorities (
            id, tenant_id, parent_id, kind, version, status, issuance_enabled,
            subject, serial_number, fingerprint_sha256,
            certificate_pem, chain_pem, not_before, not_after,
            key_backend, key_reference
        ) VALUES ($1, $2, $3, $4, $5, 'active', $6,
                  $7, $8, $9,
                  '-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n',
                  '-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n',
                  $10, $11,
                  'pkcs11', $12)
        "#,
    )
    .bind(id)
    .bind(tenant_id)
    .bind(parent_id)
    .bind(kind)
    .bind(version)
    .bind(issuance_enabled)
    .bind(format!("CN={kind}-{id}"))
    .bind(format!("{:032x}", id.as_u128()))
    .bind(fingerprint)
    .bind(not_before)
    .bind(not_after)
    .bind(format!("pkcs11:object={kind}-{id}"))
    .execute(pool)
    .await
    .expect("insert bare authority row");
}

pub fn assert_chain_with_openssl(leaf_pem: &str, chain_pem: &str, root_pem: &str) {
    let directory = std::env::temp_dir().join(format!("atom-managed-pki-{}", Uuid::new_v4()));
    fs::create_dir_all(&directory).unwrap();
    let leaf_path = directory.join("leaf.pem");
    let chain_path = directory.join("chain.pem");
    let root_path = directory.join("root.pem");
    fs::write(&leaf_path, leaf_pem).unwrap();
    let root_start = chain_pem
        .rfind("-----BEGIN CERTIFICATE-----")
        .expect("managed chain contains its root");
    fs::write(&chain_path, &chain_pem[..root_start]).unwrap();
    fs::write(&root_path, root_pem).unwrap();
    let output = Command::new("openssl")
        .args(["verify", "-purpose", "sslclient", "-CAfile"])
        .arg(&root_path)
        .arg("-untrusted")
        .arg(&chain_path)
        .arg(&leaf_path)
        .output()
        .expect("OpenSSL must be installed for managed PKI verification");
    assert!(
        output.status.success(),
        "OpenSSL verification failed: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    fs::remove_dir_all(directory).unwrap();
}
