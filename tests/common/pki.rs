//! Shared managed-PKI fixtures for the numbered integration specifications.

use std::{fs, process::Command};

use atom::{
    certs::authority::{provisioning, repo as authority_repo, AuthorityRecord},
    config::Config,
    keys::{ActiveKeys, LoadedKey},
    state::AppState,
};
use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequestParams, DnType, IsCa, Issuer,
    KeyIdMethod, KeyPair, KeyUsagePurpose,
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

pub async fn provision_tenant_issuer(
    pool: &PgPool,
    config: &Config,
    root: &TestRoot,
    tenant_id: Uuid,
) -> AuthorityRecord {
    let mut tx = pool.begin().await.unwrap();
    provisioning::import_root_in_tx(&mut tx, &root.pem)
        .await
        .unwrap();
    tx.commit().await.unwrap();

    let mut tx = pool.begin().await.unwrap();
    let mut pending = provisioning::begin_platform_intermediate_in_tx(&mut tx, &config.pki_ca_keys)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    pending.commit_generated_key();
    let signed = sign_authority_csr(&pending, root);
    let mut tx = pool.begin().await.unwrap();
    let imported = provisioning::import_signed_authority_in_tx(
        &mut tx,
        &config.pki_ca_keys,
        pending.id,
        &signed,
    )
    .await
    .unwrap();
    assert!(imported.succeeded(), "{:?}", imported.validation_error);
    tx.commit().await.unwrap();

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

pub async fn provision_platform_leaf_issuer(
    pool: &PgPool,
    config: &Config,
    root: &TestRoot,
) -> AuthorityRecord {
    let mut tx = pool.begin().await.unwrap();
    provisioning::import_root_in_tx(&mut tx, &root.pem)
        .await
        .unwrap();
    tx.commit().await.unwrap();

    let mut tx = pool.begin().await.unwrap();
    let mut pending = provisioning::begin_platform_leaf_issuer_in_tx(&mut tx, &config.pki_ca_keys)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    pending.commit_generated_key();
    let signed = sign_authority_csr(&pending, root);
    let mut tx = pool.begin().await.unwrap();
    let imported = provisioning::import_signed_authority_in_tx(
        &mut tx,
        &config.pki_ca_keys,
        pending.id,
        &signed,
    )
    .await
    .unwrap();
    assert!(imported.succeeded(), "{:?}", imported.validation_error);
    tx.commit().await.unwrap();
    authority_repo::authority_by_id(pool, imported.authority.id)
        .await
        .unwrap()
}

pub async fn rotate_tenant_issuer(
    pool: &PgPool,
    config: &Config,
    root: &TestRoot,
    tenant_id: Uuid,
) -> AuthorityRecord {
    let mut tx = pool.begin().await.unwrap();
    let mut pending =
        provisioning::begin_tenant_authority_in_tx(&mut tx, &config.pki_ca_keys, tenant_id)
            .await
            .unwrap();
    tx.commit().await.unwrap();
    pending.commit_generated_key();
    let signed = sign_authority_csr(&pending, root);
    let mut tx = pool.begin().await.unwrap();
    let imported = provisioning::import_signed_authority_in_tx(
        &mut tx,
        &config.pki_ca_keys,
        pending.id,
        &signed,
    )
    .await
    .unwrap();
    assert!(imported.succeeded(), "{:?}", imported.validation_error);
    tx.commit().await.unwrap();
    authority_repo::authority_by_id(pool, imported.authority.id)
        .await
        .unwrap()
}

fn sign_authority_csr(pending: &AuthorityRecord, root: &TestRoot) -> String {
    let mut csr =
        CertificateSigningRequestParams::from_pem(pending.csr_pem.as_deref().unwrap()).unwrap();
    csr.params.not_before = OffsetDateTime::now_utc() - Duration::minutes(1);
    csr.params.not_after = OffsetDateTime::now_utc() + Duration::days(180);
    csr.params.use_authority_key_identifier_extension = true;
    csr.signed_by(&Issuer::from_params(&root.params, &root.key))
        .unwrap()
        .pem()
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
