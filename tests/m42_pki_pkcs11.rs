//! PR-013 PKCS#11 provider contract.
//!
//! Run with a disposable SoftHSM token:
//! `cargo test --test m42_pki_pkcs11 -- --include-ignored --test-threads=1`.

use atom::{
    certs::authority::key_provider::{
        AuthorityKeyAlgorithm, AuthorityKeyContext, AuthorityKeyProvider,
        AuthorityKeyProviderError, AuthorityKeyProviderStatus, EncryptedDatabaseKeyProvider,
        ManagedAuthorityKeyProvider, Pkcs11KeyProvider,
    },
    config::{
        PkiCaKeyConfig, PkiCaProvisioningBackend, PkiPkcs11Config, SecretBytes, SecretText,
    },
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

#[test]
#[ignore = "requires the disposable SoftHSM token configured by CI"]
fn softhsm_enforces_the_pr013_provider_contract() {
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
        .generate(
            authority_context,
            AuthorityKeyAlgorithm::EcdsaP256Sha256,
        )
        .expect("generate non-exportable key");
    let repeated = provider
        .generate(
            authority_context,
            AuthorityKeyAlgorithm::EcdsaP256Sha256,
        )
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
        .generate(
            encrypted_context,
            AuthorityKeyAlgorithm::EcdsaP256Sha256,
        )
        .expect("existing encrypted-database authority");
    let pkcs11_config = PkiCaKeyConfig {
        provisioning_backend: PkiCaProvisioningBackend::Pkcs11,
        pkcs11: Some(correct_config),
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
        .generate(
            authority_context,
            AuthorityKeyAlgorithm::EcdsaP256Sha256,
        )
        .expect("re-create a deliberately destroyed test object");
    assert_eq!(recovered.key.reference(), repeated.key.reference());
    assert_ne!(
        recovered.public_key, old_public,
        "regeneration is not certificate recovery; operators must restore the token backup"
    );
    provider
        .destroy(authority_context, &mut recovered.key)
        .expect("clean recovered test object");
}

fn verify_token_object_policy(config: &PkiPkcs11Config, key_reference: &str) {
    let client = Pkcs11::new(&config.module_path).expect("load PKCS#11 module");
    match client.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)) {
        Ok(())
        | Err(Pkcs11Error::Pkcs11(
            RvError::CryptokiAlreadyInitialized,
            _,
        )) => {}
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
        Ok(())
        | Err(Pkcs11Error::Pkcs11(
            RvError::UserAlreadyLoggedIn,
            _,
        )) => {}
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
    assert_eq!(value, vec![AttributeInfo::Sensitive]);
}
