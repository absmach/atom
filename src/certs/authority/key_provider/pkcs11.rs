//! PKCS#11-backed authority keys.
//!
//! The provider stores only a context-bound object identifier in Postgres. EC
//! private key bytes are generated inside the token with `CKA_SENSITIVE=true`
//! and `CKA_EXTRACTABLE=false` and are never returned to Atom.

use std::{
    collections::HashMap,
    fmt,
    sync::{
        atomic::{AtomicU32, Ordering},
        mpsc, Arc, Mutex, OnceLock, RwLock,
    },
    thread,
    time::{Duration, Instant},
};

use cryptoki::{
    context::{CInitializeArgs, CInitializeFlags, Pkcs11},
    error::{Error as Pkcs11Error, RvError},
    mechanism::Mechanism,
    object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle},
    session::{Session, UserType},
    types::AuthPin,
};
use p256::{ecdsa::Signature, pkcs8::EncodePublicKey, PublicKey};
use ring::digest;

use crate::{config::PkiPkcs11Config, metrics};

use super::{
    AuthorityKeyAlgorithm, AuthorityKeyContext, AuthorityKeyProvider, AuthorityKeyProviderError,
    AuthorityKeyProviderHealth, AuthorityKeyProviderStatus, AuthorityPublicKey, AuthoritySignature,
    AuthoritySignatureAlgorithm, GeneratedAuthorityKey,
};
use crate::certs::authority::{AuthorityKeyBackend, AuthorityRecord};

const PROVIDER_NAME: &str = "pkcs11";
const KEY_REFERENCE_PREFIX: &str = "pkcs11:v1:id=";
const P256_OID_DER: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];

static RUNTIMES: OnceLock<Mutex<HashMap<String, Arc<Pkcs11Runtime>>>> = OnceLock::new();

#[derive(Clone)]
pub struct Pkcs11AuthorityKey {
    reference: String,
    object_id: Vec<u8>,
    destroyed: bool,
}

impl fmt::Debug for Pkcs11AuthorityKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pkcs11AuthorityKey")
            .field("backend", &AuthorityKeyBackend::Pkcs11)
            .field("reference", &"[REDACTED]")
            .field("destroyed", &self.destroyed)
            .finish()
    }
}

impl Pkcs11AuthorityKey {
    fn for_context(context: AuthorityKeyContext) -> Self {
        let object_id = object_id(context);
        Self {
            reference: format!("{KEY_REFERENCE_PREFIX}{}", hex::encode(&object_id)),
            object_id,
            destroyed: false,
        }
    }

    pub fn from_authority(authority: &AuthorityRecord) -> Result<Self, AuthorityKeyProviderError> {
        if authority.key_backend != AuthorityKeyBackend::Pkcs11 {
            return Err(AuthorityKeyProviderError::WrongBackend);
        }
        let reference = authority
            .key_reference
            .as_deref()
            .ok_or(AuthorityKeyProviderError::MissingField("key_reference"))?;
        Self::from_reference(reference)
    }

    fn from_reference(reference: &str) -> Result<Self, AuthorityKeyProviderError> {
        let encoded = reference
            .strip_prefix(KEY_REFERENCE_PREFIX)
            .ok_or(AuthorityKeyProviderError::InvalidKeyReference)?;
        if encoded.len() != 64
            || !encoded
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(AuthorityKeyProviderError::InvalidKeyReference);
        }
        let object_id =
            hex::decode(encoded).map_err(|_| AuthorityKeyProviderError::InvalidKeyReference)?;
        Ok(Self {
            reference: reference.to_string(),
            object_id,
            destroyed: false,
        })
    }

    pub fn reference(&self) -> &str {
        &self.reference
    }

    fn ensure_usable(&self, context: AuthorityKeyContext) -> Result<(), AuthorityKeyProviderError> {
        if self.destroyed {
            return Err(AuthorityKeyProviderError::Destroyed);
        }
        if self.object_id != object_id(context) {
            return Err(AuthorityKeyProviderError::KeyContextMismatch);
        }
        Ok(())
    }
}

fn object_id(context: AuthorityKeyContext) -> Vec<u8> {
    let tenant = context
        .tenant_id
        .map(|id| id.to_string())
        .unwrap_or_else(|| "global".to_string());
    let binding = format!(
        "atom:pki:pkcs11-object:v1:{}:{tenant}:{}",
        context.authority_id, context.version
    );
    digest::digest(&digest::SHA256, binding.as_bytes())
        .as_ref()
        .to_vec()
}

#[derive(Default)]
struct CircuitState {
    consecutive_failures: u32,
    opened_at: Option<Instant>,
}

struct Pkcs11Runtime {
    module_path: String,
    token_label: String,
    context: Mutex<Option<Pkcs11>>,
    lifecycle_lock: RwLock<()>,
    circuit: Mutex<CircuitState>,
    in_flight: AtomicU32,
}

impl Pkcs11Runtime {
    fn new(config: &PkiPkcs11Config) -> Self {
        Self {
            module_path: config.module_path.clone(),
            token_label: config.token_label.clone(),
            context: Mutex::new(None),
            lifecycle_lock: RwLock::new(()),
            circuit: Mutex::new(CircuitState::default()),
            in_flight: AtomicU32::new(0),
        }
    }

    fn client(&self) -> Result<Pkcs11, AuthorityKeyProviderError> {
        let mut cached = self
            .context
            .lock()
            .map_err(|_| AuthorityKeyProviderError::ProviderUnavailable)?;
        if let Some(client) = cached.as_ref() {
            return Ok(client.clone());
        }
        let client = Pkcs11::new(&self.module_path).map_err(map_pkcs11_error)?;
        match client.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)) {
            Ok(()) | Err(Pkcs11Error::Pkcs11(RvError::CryptokiAlreadyInitialized, _)) => {}
            Err(error) => return Err(map_pkcs11_error(error)),
        }
        *cached = Some(client.clone());
        Ok(client)
    }

    fn before_operation(&self, reset_after: Duration) -> Result<(), AuthorityKeyProviderError> {
        let mut circuit = self
            .circuit
            .lock()
            .map_err(|_| AuthorityKeyProviderError::ProviderUnavailable)?;
        if let Some(opened_at) = circuit.opened_at {
            if opened_at.elapsed() < reset_after {
                return Err(AuthorityKeyProviderError::CircuitOpen);
            }
            circuit.opened_at = None;
            circuit.consecutive_failures = 0;
        }
        Ok(())
    }

    fn record_success(&self) {
        if let Ok(mut circuit) = self.circuit.lock() {
            circuit.consecutive_failures = 0;
            circuit.opened_at = None;
        }
    }

    fn record_failure(&self, error: &AuthorityKeyProviderError, threshold: u32) {
        if !error.is_transient() {
            return;
        }
        if let Ok(mut circuit) = self.circuit.lock() {
            circuit.consecutive_failures = circuit.consecutive_failures.saturating_add(1);
            if circuit.consecutive_failures >= threshold {
                circuit.opened_at = Some(Instant::now());
            }
        }
    }

    fn circuit_open(&self, reset_after: Duration) -> bool {
        self.before_operation(reset_after).is_err()
    }

    fn acquire_in_flight(
        self: &Arc<Self>,
        maximum: u32,
    ) -> Result<InFlightGuard, AuthorityKeyProviderError> {
        let prior = self.in_flight.fetch_add(1, Ordering::AcqRel);
        if prior >= maximum {
            self.in_flight.fetch_sub(1, Ordering::AcqRel);
            return Err(AuthorityKeyProviderError::ProviderThrottled);
        }
        Ok(InFlightGuard {
            runtime: Arc::clone(self),
        })
    }
}

struct InFlightGuard {
    runtime: Arc<Pkcs11Runtime>,
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.runtime.in_flight.fetch_sub(1, Ordering::AcqRel);
    }
}

#[derive(Clone)]
pub struct Pkcs11KeyProvider {
    config: PkiPkcs11Config,
    runtime: Arc<Pkcs11Runtime>,
}

impl fmt::Debug for Pkcs11KeyProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pkcs11KeyProvider")
            .field("backend", &AuthorityKeyBackend::Pkcs11)
            .field("token_label", &self.config.token_label)
            .field("credentials", &"[REDACTED]")
            .finish()
    }
}

impl Pkcs11KeyProvider {
    pub fn new(config: PkiPkcs11Config) -> Self {
        let runtime_key = format!("{}\0{}", config.module_path, config.token_label);
        let runtimes = RUNTIMES.get_or_init(|| Mutex::new(HashMap::new()));
        let mut runtimes = runtimes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let runtime = if let Some(runtime) = runtimes.get(&runtime_key) {
            Arc::clone(runtime)
        } else {
            let runtime = Arc::new(Pkcs11Runtime::new(&config));
            runtimes.insert(runtime_key, Arc::clone(&runtime));
            runtime
        };
        Self { config, runtime }
    }

    fn execute<T, F>(
        &self,
        operation: &'static str,
        function: F,
    ) -> Result<T, AuthorityKeyProviderError>
    where
        T: Send + 'static,
        F: Fn(&Pkcs11KeyProvider) -> Result<T, AuthorityKeyProviderError> + Send + Sync + 'static,
    {
        let function = Arc::new(function);
        let timeout = Duration::from_millis(self.config.operation_timeout_ms);
        let reset_after = Duration::from_secs(self.config.circuit_reset_secs);
        let mut final_result = Err(AuthorityKeyProviderError::ProviderUnavailable);

        for attempt in 0..=self.config.max_retries {
            if let Err(error) = self.runtime.before_operation(reset_after) {
                final_result = Err(error);
                break;
            }
            let in_flight = match self.runtime.acquire_in_flight(self.config.max_in_flight) {
                Ok(guard) => guard,
                Err(error) => {
                    self.runtime
                        .record_failure(&error, self.config.circuit_failure_threshold);
                    final_result = Err(error);
                    break;
                }
            };
            let provider = self.clone();
            let function = Arc::clone(&function);
            let (sender, receiver) = mpsc::sync_channel(1);
            let spawned = thread::Builder::new()
                .name(format!("atom-pkcs11-{operation}"))
                .spawn(move || {
                    let result = function(&provider);
                    drop(in_flight);
                    let _ = sender.send(result);
                });
            if spawned.is_err() {
                let error = AuthorityKeyProviderError::ProviderUnavailable;
                self.runtime
                    .record_failure(&error, self.config.circuit_failure_threshold);
                final_result = Err(error);
            } else {
                final_result = match receiver.recv_timeout(timeout) {
                    Ok(result) => result,
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        Err(AuthorityKeyProviderError::OperationTimedOut)
                    }
                    Err(mpsc::RecvTimeoutError::Disconnected) => {
                        Err(AuthorityKeyProviderError::ProviderUnavailable)
                    }
                };
                match &final_result {
                    Ok(_) => self.runtime.record_success(),
                    Err(error) => self
                        .runtime
                        .record_failure(error, self.config.circuit_failure_threshold),
                }
            }

            let retry = final_result
                .as_ref()
                .err()
                .is_some_and(AuthorityKeyProviderError::is_transient)
                && attempt < self.config.max_retries;
            if !retry {
                break;
            }
        }

        metrics::record_pki_key_provider_operation(
            PROVIDER_NAME,
            operation,
            if final_result.is_ok() {
                "success"
            } else {
                "error"
            },
        );
        final_result
    }

    fn session<T>(
        &self,
        function: impl FnOnce(&Session) -> Result<T, AuthorityKeyProviderError>,
    ) -> Result<T, AuthorityKeyProviderError> {
        let client = self.runtime.client()?;
        let slot = client
            .get_slots_with_initialized_token()
            .map_err(map_pkcs11_error)?
            .into_iter()
            .find(|slot| {
                client
                    .get_token_info(*slot)
                    .is_ok_and(|info| info.label().trim() == self.runtime.token_label)
            })
            .ok_or(AuthorityKeyProviderError::ProviderUnavailable)?;
        let session = client.open_rw_session(slot).map_err(map_pkcs11_error)?;
        let pin = AuthPin::new(self.config.user_pin.expose().to_string().into());
        match session.login(UserType::User, Some(&pin)) {
            Ok(()) | Err(Pkcs11Error::Pkcs11(RvError::UserAlreadyLoggedIn, _)) => {}
            Err(error) => return Err(map_pkcs11_error(error)),
        }
        function(&session)
    }

    fn probe_once(&self) -> Result<(), AuthorityKeyProviderError> {
        self.session(|_| Ok(()))
    }

    fn generate_once(
        &self,
        context: AuthorityKeyContext,
    ) -> Result<GeneratedAuthorityKey<Pkcs11AuthorityKey>, AuthorityKeyProviderError> {
        let _lifecycle = self
            .runtime
            .lifecycle_lock
            .write()
            .map_err(|_| AuthorityKeyProviderError::ProviderUnavailable)?;
        let key = Pkcs11AuthorityKey::for_context(context);
        let object_id = key.object_id.clone();
        let label = format!("atom-pki-{}", hex::encode(&object_id)).into_bytes();
        let public_key = self.session(|session| {
            let public = find_unique(session, ObjectClass::PUBLIC_KEY, &object_id)?;
            let private = find_unique(session, ObjectClass::PRIVATE_KEY, &object_id)?;
            let public = match (public, private) {
                (Some(public), Some(private)) => {
                    validate_non_exportable(session, private)?;
                    public
                }
                (None, None) => {
                    let public_template = [
                        Attribute::Token(true),
                        Attribute::Private(false),
                        Attribute::Verify(true),
                        Attribute::KeyType(KeyType::EC),
                        Attribute::EcParams(P256_OID_DER.to_vec()),
                        Attribute::Id(object_id.clone()),
                        Attribute::Label(label.clone()),
                    ];
                    let private_template = [
                        Attribute::Token(true),
                        Attribute::Private(true),
                        Attribute::Sensitive(true),
                        Attribute::Extractable(false),
                        Attribute::Sign(true),
                        Attribute::Id(object_id.clone()),
                        Attribute::Label(label),
                    ];
                    let (public, private) = session
                        .generate_key_pair(
                            &Mechanism::EccKeyPairGen,
                            &public_template,
                            &private_template,
                        )
                        .map_err(map_pkcs11_error)?;
                    validate_non_exportable(session, private)?;
                    public
                }
                _ => return Err(AuthorityKeyProviderError::ProviderStateCorrupt),
            };
            public_key(session, public)
        })?;
        Ok(GeneratedAuthorityKey { public_key, key })
    }

    fn public_key_once(
        &self,
        context: AuthorityKeyContext,
        key: &Pkcs11AuthorityKey,
    ) -> Result<AuthorityPublicKey, AuthorityKeyProviderError> {
        let _lifecycle = self
            .runtime
            .lifecycle_lock
            .read()
            .map_err(|_| AuthorityKeyProviderError::ProviderUnavailable)?;
        key.ensure_usable(context)?;
        let object_id = key.object_id.clone();
        self.session(|session| {
            let public = find_unique(session, ObjectClass::PUBLIC_KEY, &object_id)?
                .ok_or(AuthorityKeyProviderError::KeyNotFound)?;
            let private = find_unique(session, ObjectClass::PRIVATE_KEY, &object_id)?
                .ok_or(AuthorityKeyProviderError::KeyNotFound)?;
            validate_non_exportable(session, private)?;
            public_key(session, public)
        })
    }

    fn sign_once(
        &self,
        context: AuthorityKeyContext,
        key: &Pkcs11AuthorityKey,
        message: &[u8],
    ) -> Result<AuthoritySignature, AuthorityKeyProviderError> {
        let _lifecycle = self
            .runtime
            .lifecycle_lock
            .read()
            .map_err(|_| AuthorityKeyProviderError::ProviderUnavailable)?;
        key.ensure_usable(context)?;
        let object_id = key.object_id.clone();
        self.session(|session| {
            let private = find_unique(session, ObjectClass::PRIVATE_KEY, &object_id)?
                .ok_or(AuthorityKeyProviderError::KeyNotFound)?;
            validate_non_exportable(session, private)?;
            let message_digest = digest::digest(&digest::SHA256, message);
            let raw_signature = session
                .sign(&Mechanism::Ecdsa, private, message_digest.as_ref())
                .map_err(map_pkcs11_error)?;
            let signature = Signature::from_slice(&raw_signature)
                .map_err(|_| AuthorityKeyProviderError::CryptographicFailure)?;
            Ok(AuthoritySignature {
                algorithm: AuthoritySignatureAlgorithm::EcdsaP256Sha256,
                bytes: signature.to_der().as_bytes().to_vec(),
            })
        })
    }

    fn retire_once(
        &self,
        context: AuthorityKeyContext,
        key: &Pkcs11AuthorityKey,
    ) -> Result<(), AuthorityKeyProviderError> {
        let _lifecycle = self
            .runtime
            .lifecycle_lock
            .read()
            .map_err(|_| AuthorityKeyProviderError::ProviderUnavailable)?;
        key.ensure_usable(context)?;
        let object_id = key.object_id.clone();
        self.session(|session| {
            find_unique(session, ObjectClass::PUBLIC_KEY, &object_id)?
                .ok_or(AuthorityKeyProviderError::KeyNotFound)?;
            let private = find_unique(session, ObjectClass::PRIVATE_KEY, &object_id)?
                .ok_or(AuthorityKeyProviderError::KeyNotFound)?;
            validate_non_exportable(session, private)
        })
    }

    fn destroy_once(
        &self,
        context: AuthorityKeyContext,
        key: &Pkcs11AuthorityKey,
    ) -> Result<(), AuthorityKeyProviderError> {
        let _lifecycle = self
            .runtime
            .lifecycle_lock
            .write()
            .map_err(|_| AuthorityKeyProviderError::ProviderUnavailable)?;
        key.ensure_usable(context)?;
        let object_id = key.object_id.clone();
        self.session(|session| {
            let public = find_unique(session, ObjectClass::PUBLIC_KEY, &object_id)?;
            let private = find_unique(session, ObjectClass::PRIVATE_KEY, &object_id)?;
            if let Some(private) = private {
                session.destroy_object(private).map_err(map_pkcs11_error)?;
            }
            if let Some(public) = public {
                session.destroy_object(public).map_err(map_pkcs11_error)?;
            }
            Ok(())
        })
    }

    fn audit_result<T>(
        operation: &'static str,
        context: AuthorityKeyContext,
        result: Result<T, AuthorityKeyProviderError>,
    ) -> Result<T, AuthorityKeyProviderError> {
        let operation_id = uuid::Uuid::new_v4();
        tracing::debug!(
            provider = PROVIDER_NAME,
            operation,
            operation_id = %operation_id,
            authority_id = %context.authority_id,
            outcome = if result.is_ok() { "success" } else { "error" },
            "PKI provider operation completed"
        );
        result
    }
}

impl AuthorityKeyProvider for Pkcs11KeyProvider {
    type Key = Pkcs11AuthorityKey;

    fn backend(&self) -> AuthorityKeyBackend {
        AuthorityKeyBackend::Pkcs11
    }

    fn health(&self) -> AuthorityKeyProviderHealth {
        let reset_after = Duration::from_secs(self.config.circuit_reset_secs);
        let status = if self.runtime.circuit_open(reset_after) {
            AuthorityKeyProviderStatus::CircuitOpen
        } else {
            match self.execute("health", |provider| provider.probe_once()) {
                Ok(()) => AuthorityKeyProviderStatus::Ready,
                Err(AuthorityKeyProviderError::CircuitOpen) => {
                    AuthorityKeyProviderStatus::CircuitOpen
                }
                Err(_) => AuthorityKeyProviderStatus::Unavailable,
            }
        };
        AuthorityKeyProviderHealth {
            backend: self.backend(),
            status,
        }
    }

    fn generate(
        &self,
        context: AuthorityKeyContext,
        algorithm: AuthorityKeyAlgorithm,
    ) -> Result<GeneratedAuthorityKey<Self::Key>, AuthorityKeyProviderError> {
        if algorithm != AuthorityKeyAlgorithm::EcdsaP256Sha256 {
            return Err(AuthorityKeyProviderError::UnsupportedKeyAlgorithm);
        }
        let result = self.execute("generate", move |provider| provider.generate_once(context));
        Self::audit_result("generate", context, result)
    }

    fn public_key(
        &self,
        context: AuthorityKeyContext,
        key: &Self::Key,
    ) -> Result<AuthorityPublicKey, AuthorityKeyProviderError> {
        let key = key.clone();
        let result = self.execute("public_key", move |provider| {
            provider.public_key_once(context, &key)
        });
        Self::audit_result("public_key", context, result)
    }

    fn sign(
        &self,
        context: AuthorityKeyContext,
        key: &Self::Key,
        message: &[u8],
    ) -> Result<AuthoritySignature, AuthorityKeyProviderError> {
        let key = key.clone();
        let message = message.to_vec();
        let result = self.execute("sign", move |provider| {
            provider.sign_once(context, &key, &message)
        });
        Self::audit_result("sign", context, result)
    }

    fn retire(
        &self,
        context: AuthorityKeyContext,
        key: &Self::Key,
    ) -> Result<(), AuthorityKeyProviderError> {
        let key = key.clone();
        let result = self.execute("retire", move |provider| {
            provider.retire_once(context, &key)
        });
        Self::audit_result("retire", context, result)
    }

    fn destroy(
        &self,
        context: AuthorityKeyContext,
        key: &mut Self::Key,
    ) -> Result<(), AuthorityKeyProviderError> {
        let owned = key.clone();
        let result = self.execute("destroy", move |provider| {
            provider.destroy_once(context, &owned)
        });
        if result.is_ok() {
            key.destroyed = true;
        }
        Self::audit_result("destroy", context, result)
    }
}

fn find_unique(
    session: &Session,
    class: ObjectClass,
    object_id: &[u8],
) -> Result<Option<ObjectHandle>, AuthorityKeyProviderError> {
    let objects = session
        .find_objects(&[
            Attribute::Class(class),
            Attribute::KeyType(KeyType::EC),
            Attribute::Id(object_id.to_vec()),
        ])
        .map_err(map_pkcs11_error)?;
    match objects.as_slice() {
        [] => Ok(None),
        [object] => Ok(Some(*object)),
        _ => Err(AuthorityKeyProviderError::ProviderStateCorrupt),
    }
}

fn validate_non_exportable(
    session: &Session,
    private: ObjectHandle,
) -> Result<(), AuthorityKeyProviderError> {
    let attributes = session
        .get_attributes(
            private,
            &[AttributeType::Sensitive, AttributeType::Extractable],
        )
        .map_err(map_pkcs11_error)?;
    if attributes.as_slice() != [Attribute::Sensitive(true), Attribute::Extractable(false)] {
        return Err(AuthorityKeyProviderError::NonExportablePolicyViolation);
    }
    Ok(())
}

fn public_key(
    session: &Session,
    public: ObjectHandle,
) -> Result<AuthorityPublicKey, AuthorityKeyProviderError> {
    let attributes = session
        .get_attributes(public, &[AttributeType::EcParams, AttributeType::EcPoint])
        .map_err(map_pkcs11_error)?;
    let [Attribute::EcParams(parameters), Attribute::EcPoint(point)] = attributes.as_slice() else {
        return Err(AuthorityKeyProviderError::ProviderStateCorrupt);
    };
    if parameters.as_slice() != P256_OID_DER {
        return Err(AuthorityKeyProviderError::UnsupportedKeyAlgorithm);
    }
    let point = unwrap_ec_point(point)?;
    let public_key = PublicKey::from_sec1_bytes(point)
        .map_err(|_| AuthorityKeyProviderError::CryptographicFailure)?;
    let public_key = public_key
        .to_public_key_der()
        .map_err(|_| AuthorityKeyProviderError::CryptographicFailure)?;
    Ok(AuthorityPublicKey {
        algorithm: AuthorityKeyAlgorithm::EcdsaP256Sha256,
        subject_public_key_info_der: public_key.as_bytes().to_vec(),
    })
}

fn unwrap_ec_point(value: &[u8]) -> Result<&[u8], AuthorityKeyProviderError> {
    if value.len() == 65 && value.first() == Some(&0x04) {
        return Ok(value);
    }
    if value.len() < 2 || value[0] != 0x04 {
        return Err(AuthorityKeyProviderError::CryptographicFailure);
    }
    let (length, offset) = match value[1] {
        length @ 0..=0x7f => (usize::from(length), 2),
        0x81 if value.len() >= 3 => (usize::from(value[2]), 3),
        0x82 if value.len() >= 4 => (usize::from(u16::from_be_bytes([value[2], value[3]])), 4),
        _ => return Err(AuthorityKeyProviderError::CryptographicFailure),
    };
    if value.len() != offset + length {
        return Err(AuthorityKeyProviderError::CryptographicFailure);
    }
    let point = &value[offset..];
    if point.len() != 65 || point.first() != Some(&0x04) {
        return Err(AuthorityKeyProviderError::CryptographicFailure);
    }
    Ok(point)
}

fn map_pkcs11_error(error: Pkcs11Error) -> AuthorityKeyProviderError {
    match error {
        Pkcs11Error::Pkcs11(
            RvError::SessionCount | RvError::DeviceMemory | RvError::HostMemory,
            _,
        ) => AuthorityKeyProviderError::ProviderThrottled,
        Pkcs11Error::Pkcs11(
            RvError::DeviceError
            | RvError::DeviceRemoved
            | RvError::TokenNotPresent
            | RvError::TokenNotRecognized
            | RvError::FunctionFailed
            | RvError::GeneralError
            | RvError::CryptokiNotInitialized,
            _,
        )
        | Pkcs11Error::LibraryLoading(_)
        | Pkcs11Error::MissingSymbol(_)
        | Pkcs11Error::NullFunctionPointer => AuthorityKeyProviderError::ProviderUnavailable,
        Pkcs11Error::Pkcs11(RvError::ObjectHandleInvalid | RvError::KeyHandleInvalid, _) => {
            AuthorityKeyProviderError::KeyNotFound
        }
        _ => AuthorityKeyProviderError::CryptographicFailure,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;

    use crate::config::SecretText;

    use super::*;

    fn executor_config(name: &str) -> PkiPkcs11Config {
        PkiPkcs11Config {
            module_path: format!("/nonexistent/{name}.so"),
            token_label: name.to_string(),
            user_pin: SecretText::new("test-pin".to_string()).expect("PIN"),
            operation_timeout_ms: 10,
            max_retries: 0,
            max_in_flight: 1,
            circuit_failure_threshold: 10,
            circuit_reset_secs: 60,
        }
    }

    #[test]
    fn opaque_reference_is_context_bound_and_strict() {
        let context = AuthorityKeyContext {
            authority_id: uuid::Uuid::new_v4(),
            tenant_id: Some(uuid::Uuid::new_v4()),
            version: 7,
        };
        let key = Pkcs11AuthorityKey::for_context(context);
        assert!(key.reference().starts_with(KEY_REFERENCE_PREFIX));
        assert!(!key.reference().contains(&context.authority_id.to_string()));
        key.ensure_usable(context).expect("matching context");
        assert_eq!(
            key.ensure_usable(AuthorityKeyContext {
                version: 8,
                ..context
            })
            .expect_err("wrong context"),
            AuthorityKeyProviderError::KeyContextMismatch
        );
        assert_eq!(
            Pkcs11AuthorityKey::from_reference("pkcs11:object=caller-controlled")
                .expect_err("unsupported reference"),
            AuthorityKeyProviderError::InvalidKeyReference
        );
    }

    #[test]
    fn ec_point_decoder_accepts_raw_and_der_wrapped_points() {
        let mut point = vec![0x04];
        point.extend([7_u8; 64]);
        assert_eq!(unwrap_ec_point(&point).expect("raw"), point);
        let mut wrapped = vec![0x04, 65];
        wrapped.extend(&point);
        assert_eq!(unwrap_ec_point(&wrapped).expect("wrapped"), point);
    }

    #[test]
    fn executor_bounds_time_and_in_flight_work() {
        let provider = Pkcs11KeyProvider::new(executor_config("timeout-throttle"));
        assert_eq!(
            provider
                .execute("test_timeout", |_| {
                    thread::sleep(Duration::from_millis(100));
                    Ok(())
                })
                .expect_err("operation must time out"),
            AuthorityKeyProviderError::OperationTimedOut
        );
        assert_eq!(
            provider
                .execute("test_throttle", |_| Ok(()))
                .expect_err("late worker occupies the only slot"),
            AuthorityKeyProviderError::ProviderThrottled
        );
        thread::sleep(Duration::from_millis(110));
    }

    #[test]
    fn executor_retries_transient_failures_and_opens_circuit() {
        let mut retry_config = executor_config("retry");
        retry_config.max_in_flight = 2;
        retry_config.max_retries = 1;
        let retry_provider = Pkcs11KeyProvider::new(retry_config);
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&calls);
        retry_provider
            .execute("test_retry", move |_| {
                if observed.fetch_add(1, Ordering::SeqCst) == 0 {
                    Err(AuthorityKeyProviderError::ProviderUnavailable)
                } else {
                    Ok(())
                }
            })
            .expect("bounded retry succeeds");
        assert_eq!(calls.load(Ordering::SeqCst), 2);

        let mut circuit_config = executor_config("circuit");
        circuit_config.max_in_flight = 2;
        circuit_config.circuit_failure_threshold = 1;
        let circuit_provider = Pkcs11KeyProvider::new(circuit_config);
        assert_eq!(
            circuit_provider
                .execute("test_circuit_timeout", |_| {
                    thread::sleep(Duration::from_millis(100));
                    Ok(())
                })
                .expect_err("timeout"),
            AuthorityKeyProviderError::OperationTimedOut
        );
        assert_eq!(
            circuit_provider
                .execute("test_circuit_open", |_| Ok(()))
                .expect_err("circuit is open"),
            AuthorityKeyProviderError::CircuitOpen
        );
        thread::sleep(Duration::from_millis(110));
    }
}
