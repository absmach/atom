//! PR-013 PKCS#11 provider contract.
//!
//! Run with a disposable SoftHSM token:
//! `cargo test --test m42_pki_pkcs11 -- --include-ignored --test-threads=1`.

mod common;

use atom::{
    certs::{
        authority::{
            key_provider::{
                validate_startup, AuthorityKeyAlgorithm, AuthorityKeyContext, AuthorityKeyProvider,
                AuthorityKeyProviderError, AuthorityKeyProviderStatus,
                EncryptedDatabaseKeyProvider, ManagedAuthorityKeyProvider, Pkcs11KeyProvider,
            },
            provisioning, repo as authority_repo, AuthorityKeyBackend,
        },
        pki_core::PkiArtifactSigner,
    },
    config::{PkiCaKeyConfig, PkiCaProvisioningBackend, PkiPkcs11Config, SecretBytes, SecretText},
    error::AppError,
};
use cryptoki::{
    context::{CInitializeArgs, CInitializeFlags, Pkcs11},
    error::{Error as Pkcs11Error, RvError},
    object::{Attribute, AttributeInfo, AttributeType, KeyType, ObjectClass},
    session::UserType,
    types::AuthPin,
};
use p256::{
    ecdsa::{signature::Verifier, Signature, VerifyingKey},
    pkcs8::DecodePublicKey,
};
use uuid::Uuid;

fn provider_config(pin: &str) -> Option<PkiPkcs11Config> {
    let module_path = std::env::var("ATOM_PKI_PKCS11_MODULE_PATH").ok()?;
    let token_label = std::env::var("ATOM_PKI_PKCS11_TOKEN_LABEL").ok()?;
    Some(PkiPkcs11Config {
        module_path,
        token_label,
        user_pin: SecretText::new(pin.to_string()).expect("test PIN"),
        operation_timeout_ms: 2_000,
        max_retries: 1,
        max_in_flight: 4,
        circuit_failure_threshold: 3,
        circuit_reset_secs: 2,
    })
}

fn context() -> AuthorityKeyContext {
    AuthorityKeyContext {
        authority_id: Uuid::new_v4(),
        tenant_id: Some(Uuid::new_v4()),
        version: 1,
    }
}

fn verify_certificate_signature(certificate_pem: &str, message: &[u8], signature_der: &[u8]) {
    let (_, pem) =
        x509_parser::pem::parse_x509_pem(certificate_pem.as_bytes()).expect("issuer PEM");
    let (_, certificate) =
        x509_parser::parse_x509_certificate(&pem.contents).expect("issuer certificate");
    VerifyingKey::from_public_key_der(certificate.public_key().raw)
        .expect("issuer public key")
        .verify(
            message,
            &Signature::from_der(signature_der).expect("DER ECDSA signature"),
        )
        .expect("independent signature verification");
}

#[tokio::test]
#[ignore = "requires the disposable SoftHSM token configured by CI"]
async fn softhsm_enforces_the_pr013_provider_contract() {
    let Some(correct_config) = provider_config(
        &std::env::var("ATOM_PKI_PKCS11_USER_PIN").unwrap_or_else(|_| "123456".to_string()),
    ) else {
        eprintln!("PKCS#11 test environment is not configured; skipping");
        return;
    };

    let wrong_pin = Pkcs11KeyProvider::new(provider_config("definitely-wrong").expect("config"));
    assert_eq!(
        wrong_pin.health().status,
        AuthorityKeyProviderStatus::Unavailable,
        "the token requires authenticated signer access"
    );

    let mut unavailable_config = correct_config.clone();
    unavailable_config.module_path = "/definitely/missing/libpkcs11.so".to_string();
    unavailable_config.max_retries = 0;
    let unavailable = Pkcs11KeyProvider::new(unavailable_config);
    assert_eq!(
        unavailable.health().status,
        AuthorityKeyProviderStatus::Unavailable,
        "an unavailable provider fails closed"
    );

    let provider = Pkcs11KeyProvider::new(correct_config.clone());
    assert_eq!(provider.health().status, AuthorityKeyProviderStatus::Ready);
    let authority_context = context();
    let generated = provider
        .generate(authority_context, AuthorityKeyAlgorithm::EcdsaP256Sha256)
        .expect("generate non-exportable key");
    let repeated = provider
        .generate(authority_context, AuthorityKeyAlgorithm::EcdsaP256Sha256)
        .expect("retry-safe generation");
    assert_eq!(generated.key.reference(), repeated.key.reference());
    assert_eq!(generated.public_key, repeated.public_key);

    let message = b"validated certificate to-be-signed bytes";
    let signature = provider
        .sign(authority_context, &generated.key, message)
        .expect("PKCS#11 sign");
    let verifying_key =
        VerifyingKey::from_public_key_der(&generated.public_key.subject_public_key_info_der)
            .expect("public key");
    verifying_key
        .verify(
            message,
            &Signature::from_der(&signature.bytes).expect("DER ECDSA signature"),
        )
        .expect("independent signature verification");
    assert_eq!(
        provider
            .sign(
                AuthorityKeyContext {
                    tenant_id: Some(Uuid::new_v4()),
                    ..authority_context
                },
                &generated.key,
                message,
            )
            .expect_err("caller-selected cross-context key reference"),
        AuthorityKeyProviderError::KeyContextMismatch
    );

    verify_token_object_policy(&correct_config, generated.key.reference());

    let encrypted_config = PkiCaKeyConfig {
        key_encryption_key: Some(SecretBytes::new(vec![42; 32]).expect("CA KEK")),
        key_encryption_key_id: "rotation-test:v1".to_string(),
        ..PkiCaKeyConfig::default()
    };
    let encrypted = EncryptedDatabaseKeyProvider::new(encrypted_config.clone());
    let encrypted_context = context();
    let encrypted_key = encrypted
        .generate(encrypted_context, AuthorityKeyAlgorithm::EcdsaP256Sha256)
        .expect("existing encrypted-database authority");
    let pkcs11_config = PkiCaKeyConfig {
        provisioning_backend: PkiCaProvisioningBackend::Pkcs11,
        pkcs11: Some(correct_config.clone()),
        ..encrypted_config
    };
    let selected =
        ManagedAuthorityKeyProvider::for_provisioning(&pkcs11_config).expect("PKCS#11 selected");
    assert_eq!(
        selected.backend(),
        atom::certs::authority::AuthorityKeyBackend::Pkcs11
    );
    encrypted
        .sign(encrypted_context, &encrypted_key.key, b"retained CRL")
        .expect("old encrypted provider remains usable after rotation");

    let old_public = generated.public_key.clone();
    let mut key = generated.key;
    provider
        .destroy(authority_context, &mut key)
        .expect("destroy token objects");
    assert_eq!(
        provider
            .sign(authority_context, &key, message)
            .expect_err("destroyed handle"),
        AuthorityKeyProviderError::Destroyed
    );
    let mut recovered = provider
        .generate(authority_context, AuthorityKeyAlgorithm::EcdsaP256Sha256)
        .expect("re-create a deliberately destroyed test object");
    assert_eq!(recovered.key.reference(), repeated.key.reference());
    assert_ne!(
        recovered.public_key, old_public,
        "regeneration is not certificate recovery; operators must restore the token backup"
    );
    provider
        .destroy(authority_context, &mut recovered.key)
        .expect("clean recovered test object");

    let pool = common::pool().await;
    let mut app_config = common::pki::managed_config(false, false);
    app_config.pki_ca_keys.provisioning_backend = PkiCaProvisioningBackend::Pkcs11;
    app_config.pki_ca_keys.pkcs11 = Some(correct_config.clone());
    let root = common::pki::test_root("PR-013 offline root");
    let tenant = common::pki::create_tenant(&pool, "pkcs11-tenant").await;
    let issuer = common::pki::provision_tenant_issuer(&pool, &app_config, &root, tenant).await;
    assert_eq!(issuer.key_backend, AuthorityKeyBackend::Pkcs11);
    assert!(issuer
        .key_reference
        .as_deref()
        .is_some_and(|reference| reference.starts_with("pkcs11:v1:id=")));
    assert!(issuer.encrypted_private_key.is_none());
    validate_startup(&pool, &app_config.pki_ca_keys)
        .await
        .expect("persisted token keys match their certificates");

    let original_certificate = issuer
        .certificate_pem
        .as_deref()
        .expect("issuer certificate");
    sqlx::query("UPDATE pki_authorities SET certificate_pem = $2 WHERE id = $1")
        .bind(issuer.id)
        .bind(&root.pem)
        .execute(&pool)
        .await
        .expect("inject mismatched public certificate");
    let error = validate_startup(&pool, &app_config.pki_ca_keys)
        .await
        .expect_err("wrong key/certificate pair");
    let AppError::Internal(error) = error else {
        panic!("certificate mismatch must fail as an internal startup error");
    };
    assert_eq!(
        error.to_string(),
        "PKCS#11 authority key does not match its certificate"
    );
    sqlx::query("UPDATE pki_authorities SET certificate_pem = $2 WHERE id = $1")
        .bind(issuer.id)
        .bind(original_certificate)
        .execute(&pool)
        .await
        .expect("restore issuer certificate");

    let platform_leaf_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pki_authorities WHERE kind = 'platform_leaf_issuer'",
    )
    .fetch_one(&pool)
    .await
    .expect("platform leaf count");
    let mut unavailable_keys = app_config.pki_ca_keys.clone();
    unavailable_keys
        .pkcs11
        .as_mut()
        .expect("PKCS#11 config")
        .module_path = "/definitely/missing/libpkcs11.so".to_string();
    let mut tx = pool.begin().await.expect("outage transaction");
    provisioning::begin_platform_leaf_issuer_in_tx(&mut tx, &unavailable_keys)
        .await
        .expect_err("provider outage");
    tx.rollback().await.expect("outage rollback");
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM pki_authorities WHERE kind = 'platform_leaf_issuer'",
        )
        .fetch_one(&pool)
        .await
        .expect("platform leaf count after outage"),
        platform_leaf_count,
        "provider outage cannot corrupt authority lifecycle state"
    );

    let rotated_tenant = common::pki::create_tenant(&pool, "encrypted-rotation").await;
    let mut rotated_keys = app_config.pki_ca_keys.clone();
    rotated_keys.provisioning_backend = PkiCaProvisioningBackend::EncryptedDatabase;
    let mut tx = pool.begin().await.expect("rotation transaction");
    let rotated =
        provisioning::provision_tenant_automatically_in_tx(&mut tx, &rotated_keys, rotated_tenant)
            .await
            .expect("cross-provider rotation");
    assert!(rotated.succeeded(), "{:?}", rotated.validation_error);
    tx.commit().await.expect("commit rotated authority");
    assert_eq!(
        rotated.authority.key_backend,
        AuthorityKeyBackend::EncryptedDatabase
    );
    validate_startup(&pool, &rotated_keys)
        .await
        .expect("both retained providers remain available");

    let artifact_message = b"retained issuer OCSP response data";
    let artifact_signature = PkiArtifactSigner::from_managed_authority(&issuer, &rotated_keys)
        .expect("retained PKCS#11 artifact signer")
        .sign_ocsp_response_data(artifact_message)
        .expect("retained artifact signature")
        .into_bytes();
    verify_certificate_signature(original_certificate, artifact_message, &artifact_signature);
}

#[tokio::test]
#[ignore = "runs after CI restores the populated SoftHSM backup"]
async fn softhsm_restored_backup_can_sign_with_existing_authority() {
    if std::env::var("ATOM_PKI_PKCS11_RECOVERY_CHECK").as_deref() != Ok("1") {
        eprintln!("recovery check is not enabled; skipping");
        return;
    }
    let correct_config = provider_config(
        &std::env::var("ATOM_PKI_PKCS11_USER_PIN").unwrap_or_else(|_| "123456".to_string()),
    )
    .expect("PKCS#11 recovery environment");
    let pool = common::pool().await;
    let mut ca_keys = common::pki::managed_config(false, false).pki_ca_keys;
    ca_keys.provisioning_backend = PkiCaProvisioningBackend::Pkcs11;
    ca_keys.pkcs11 = Some(correct_config);
    validate_startup(&pool, &ca_keys)
        .await
        .expect("restored token matches persisted authorities");
    let authorities = authority_repo::pkcs11_authorities(&pool)
        .await
        .expect("persisted PKCS#11 authorities");
    let issuer = authorities
        .iter()
        .find(|authority| authority.kind.can_issue_leaf_credentials())
        .expect("persisted PKCS#11 leaf issuer");
    let certificate_pem = issuer
        .certificate_pem
        .as_deref()
        .expect("issuer certificate");
    let message = b"post-recovery retained issuer artifact";
    let signature = PkiArtifactSigner::from_managed_authority(issuer, &ca_keys)
        .expect("restored artifact signer")
        .sign_ocsp_response_data(message)
        .expect("post-recovery signature")
        .into_bytes();
    verify_certificate_signature(certificate_pem, message, &signature);
}

fn verify_token_object_policy(config: &PkiPkcs11Config, key_reference: &str) {
    let client = Pkcs11::new(&config.module_path).expect("load PKCS#11 module");
    match client.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)) {
        Ok(()) | Err(Pkcs11Error::Pkcs11(RvError::CryptokiAlreadyInitialized, _)) => {}
        Err(error) => panic!("initialize PKCS#11: {error}"),
    }
    let slot = client
        .get_slots_with_initialized_token()
        .expect("slots")
        .into_iter()
        .find(|slot| {
            client
                .get_token_info(*slot)
                .is_ok_and(|info| info.label().trim() == config.token_label)
        })
        .expect("configured token");
    let session = client.open_rw_session(slot).expect("session");
    let pin = AuthPin::new(config.user_pin.expose().to_string().into());
    match session.login(UserType::User, Some(&pin)) {
        Ok(()) | Err(Pkcs11Error::Pkcs11(RvError::UserAlreadyLoggedIn, _)) => {}
        Err(error) => panic!("login: {error}"),
    }
    let object_id = hex::decode(
        key_reference
            .strip_prefix("pkcs11:v1:id=")
            .expect("opaque reference format"),
    )
    .expect("object id");
    let private = session
        .find_objects(&[
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::KeyType(KeyType::EC),
            Attribute::Id(object_id.clone()),
        ])
        .expect("find private key");
    assert_eq!(private.len(), 1, "generation retries cannot duplicate keys");
    let public = session
        .find_objects(&[
            Attribute::Class(ObjectClass::PUBLIC_KEY),
            Attribute::KeyType(KeyType::EC),
            Attribute::Id(object_id),
        ])
        .expect("find public key");
    assert_eq!(public.len(), 1, "one public object per authority");
    let attributes = session
        .get_attributes(
            private[0],
            &[
                AttributeType::Sensitive,
                AttributeType::Extractable,
                AttributeType::AlwaysSensitive,
                AttributeType::NeverExtractable,
            ],
        )
        .expect("private-key policy attributes");
    assert!(attributes.contains(&Attribute::Sensitive(true)));
    assert!(attributes.contains(&Attribute::Extractable(false)));
    assert!(attributes.contains(&Attribute::AlwaysSensitive(true)));
    assert!(attributes.contains(&Attribute::NeverExtractable(true)));
    let value = session
        .get_attribute_info(private[0], &[AttributeType::Value])
        .expect("private value policy");
    assert!(matches!(value.as_slice(), [AttributeInfo::Sensitive]));
}
