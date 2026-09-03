use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{Duration, Utc};
use ipnet::IpNet;
use serde::Deserialize;
use std::{fmt, str::FromStr};
use uuid::Uuid;
use zeroize::Zeroize;

// 00000000-0000-0000-0000-000000000001
pub const ADMIN_ENTITY_ID: Uuid =
    Uuid::from_bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
pub const SERVICE_ENTITY_ID: Uuid =
    Uuid::from_bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3]);

#[derive(Debug, Clone)]
pub struct Config {
    pub database_url: String,
    pub db_pool: DbPoolConfig,
    pub logging: LoggingConfig,
    pub listen_addr: String,
    pub http_server: HttpServerConfig,
    pub grpc_addr: String,
    /// In-process TLS for the gRPC server. `None` = plaintext (the transport
    /// must then be secured by the deployment: private network / service mesh).
    pub grpc_tls: Option<GrpcTlsConfig>,
    /// Dedicated public TLS listener for subject certificate enrollment.
    /// Disabled by default; when enabled, TLS is always terminated in process.
    pub enrollment: EnrollmentConfig,
    /// Replica-safe certificate expiry visibility and bounded fleet operations.
    /// Background automation is opt-in; query and mutation APIs remain usable.
    pub pki_lifecycle: PkiLifecycleConfig,
    pub signing_keys: SigningKeyConfig,
    pub pki_ca_keys: PkiCaKeyConfig,
    pub audit_policy: AuditPolicyConfig,
    pub audit_retention: AuditRetentionConfig,
    pub purge: PurgeConfig,
    pub rate_limits: RateLimitConfig,
    pub events: EventsConfig,
    pub body_limits: BodyLimitConfig,
    pub graphql_limits: GraphqlLimitConfig,
    pub metrics: MetricsConfig,
    pub jwt_expiry_secs: u64,
    pub jwt_issuer: String,
    pub jwt_audience: String,
    /// UUID of the seeded admin entity. Defaults to the well-known seed UUID.
    pub admin_entity_id: Uuid,
    /// If set, the admin entity's password credential is created on first boot.
    pub admin_secret: Option<String>,
    /// If set, the service entity's password credential is created on first boot.
    pub service_secret: Option<String>,
    pub service_entity_id: Uuid,
    /// Path to a YAML bootstrap file applied idempotently at startup. `None`
    /// disables config-file bootstrap (env-var/API bootstrap is unaffected).
    pub bootstrap_file: Option<String>,
    /// Enables unauthenticated global human self-registration.
    pub self_registration_enabled: bool,
    /// Development-only: allow password login before the signup email is verified.
    pub dev_allow_unverified_email_login: bool,
    pub public_base_url: String,
    pub cors_allowed_origins: Vec<String>,
    pub auth_cookie_secure: bool,
    pub auth_cookie_domain: Option<String>,
    pub email_verification_redirect: String,
    pub password_reset_redirect: String,
    pub invitation_redirect: String,
    pub oauth_success_redirect: String,
    pub oauth_error_redirect: String,
    pub oidc_providers: Vec<OidcProviderConfig>,
    pub smtp: Option<SmtpConfig>,
    /// Operator-mounted directory overriding the built-in email templates
    /// shipped at `mail::DEFAULT_TEMPLATES_DIR`. `None` means every template
    /// uses its built-in default. Files present here take precedence
    /// per-file, so an override directory need only contain the templates an
    /// operator actually wants to customize.
    pub email_templates_dir: Option<String>,
    pub email_verification_expiry_secs: u64,
    pub invitation_expiry_secs: u64,
    pub oauth_state_expiry_secs: u64,
    pub auth_exchange_code_expiry_secs: u64,
    pub login_failure_limit: i64,
    pub login_failure_window_secs: i64,
    /// One-time managed leaf-key bootstrap. This remains opt-in until the
    /// issuer-aware revocation publication path is complete.
    pub pki_generated_key_issuance_enabled: bool,
    /// Path to a PEM-encoded root CA certificate that Atom imports as the
    /// managed root trust anchor on startup. Idempotent — a subsequent
    /// restart with the same PEM finds the existing row by fingerprint and
    /// leaves it in place. `None` skips the bootstrap step; the platform
    /// then has no active root and cannot provision downstream authorities.
    pub pki_root_cert_path: Option<String>,
    /// Path to a PEM-encoded platform intermediate CA certificate that must
    /// already be signed by the configured root. Paired with
    /// [`Self::pki_platform_intermediate_key_path`]. Idempotent by fingerprint.
    pub pki_platform_intermediate_cert_path: Option<String>,
    /// Path to a PEM-encoded platform intermediate CA private key (PKCS#8).
    /// Atom wraps the key with the CA KEK before persisting.
    pub pki_platform_intermediate_key_path: Option<String>,
    pub cache: CacheConfig,
    pub broker_auth: BrokerAuthConfig,
}

/// How a topic segment addresses an object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BrokerTopicRef {
    /// The bound segment is a tenant-scoped alias slug, resolved through the
    /// same path as `AliasService.ResolveAlias`.
    #[default]
    Alias,
    /// The bound segment is the object's UUID; no resolution step.
    Uuid,
}

impl BrokerTopicRef {
    fn from_env_value(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "" | "alias" => Ok(Self::Alias),
            "uuid" => Ok(Self::Uuid),
            other => anyhow::bail!("ATOM_BROKER_TOPIC_REF must be alias or uuid, got {other}"),
        }
    }
}

/// The broker auth callout — Atom implementing FluxMQ's `AuthService` so a
/// broker can call it with no adapter service in between.
///
/// **Off by default, and deliberately so.** The callout has no bearer token to
/// check: a broker's gRPC client sends no `authorization` metadata, so the
/// endpoint authenticates its caller at the transport, via the gRPC listener's
/// mTLS client CA. Enabling it on a plaintext listener lets anything that can
/// reach the port authenticate and authorize as any principal. Enable it
/// together with `ATOM_GRPC_TLS_CLIENT_CA_PATH`, scoped to a CA that signs
/// brokers and nothing else.
#[derive(Debug, Clone)]
pub struct BrokerAuthConfig {
    pub enabled: bool,
    pub topic_templates: crate::broker_auth::TopicTemplateSet,
    pub topic_ref: BrokerTopicRef,
    /// Which credential kind a broker's username/password pair is checked
    /// against. One kind, one lookup — the callout runs on the connect path and
    /// trying both would double the cost of every rejected connection.
    pub credential_kind: crate::models::enums::CredentialKind,
    /// Topics authorized without consulting the PDP. Empty by default; see
    /// [`crate::broker_auth::TopicAllowList`] for why it exists and how narrow
    /// a pattern should be.
    pub topic_allow: crate::broker_auth::TopicAllowList,
}

/// First segment names the object, the rest is unconstrained — the near
/// universal MQTT convention, and the one that survives `+`/`#` in a filter.
pub const DEFAULT_BROKER_TOPIC_TEMPLATE: &str = "{resource}/#";

impl Default for BrokerAuthConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            topic_templates: crate::broker_auth::TopicTemplateSet::parse_list(&[
                DEFAULT_BROKER_TOPIC_TEMPLATE.to_string(),
            ])
            .expect("the built-in default template must parse"),
            topic_ref: BrokerTopicRef::default(),
            credential_kind: crate::models::enums::CredentialKind::Password,
            topic_allow: crate::broker_auth::TopicAllowList::default(),
        }
    }
}

/// Split a comma-separated env var, dropping blanks. Absent or blank yields an
/// empty list.
fn comma_list(name: &str) -> Vec<String> {
    nonempty_env(name)
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|entry| !entry.is_empty())
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn broker_credential_kind_from_env() -> Result<crate::models::enums::CredentialKind> {
    use crate::models::enums::CredentialKind;
    match std::env::var("ATOM_BROKER_CREDENTIAL_KIND")
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "" | "password" => Ok(CredentialKind::Password),
        "shared_key" => Ok(CredentialKind::SharedKey),
        other => {
            anyhow::bail!("ATOM_BROKER_CREDENTIAL_KIND must be password or shared_key, got {other}")
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DbPoolConfig {
    pub max_connections: u32,
    pub min_connections: u32,
    pub acquire_timeout_secs: u64,
    pub connect_timeout_secs: u64,
    pub idle_timeout_secs: u64,
    pub max_lifetime_secs: u64,
}

impl Default for DbPoolConfig {
    fn default() -> Self {
        Self {
            max_connections: 20,
            min_connections: 0,
            acquire_timeout_secs: 30,
            connect_timeout_secs: 10,
            idle_timeout_secs: 600,
            max_lifetime_secs: 1800,
        }
    }
}

/// Upper bound on any single `ATOM_CACHE_TTL_*` value, enforced by
/// [`cache_from_env`].
const MAX_CACHE_TTL_SECS: u64 = 24 * 60 * 60;

/// Per-category TTLs, applied to cached entries as a defense-in-depth safety
/// net (not the primary invalidation mechanism — see `src/cache/mod.rs`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheTtlConfig {
    pub session_secs: u64,
    pub entity_status_secs: u64,
    pub tenant_status_secs: u64,
    pub credential_secs: u64,
    pub credential_ceiling_secs: u64,
    pub grants_secs: u64,
}

impl Default for CacheTtlConfig {
    fn default() -> Self {
        Self {
            session_secs: 60,
            entity_status_secs: 60,
            tenant_status_secs: 60,
            credential_secs: 60,
            credential_ceiling_secs: 60,
            grants_secs: 60,
        }
    }
}

/// Deployment mode for the Redis-backed AuthN/AuthZ cache.
///
/// `Prepare` is the compatibility bridge for rolling deployments: it keeps
/// reads on Postgres while making every v1 writer participate in Redis
/// invalidation. Once every pre-v1/disabled writer is gone, replicas can roll
/// from `Prepare` to `Enabled` without creating a stale-cache window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CacheMode {
    #[default]
    Disabled,
    Prepare,
    Enabled,
}

impl CacheMode {
    fn from_env_value(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "" | "disabled" => Ok(Self::Disabled),
            "prepare" => Ok(Self::Prepare),
            "enabled" => Ok(Self::Enabled),
            other => {
                anyhow::bail!("ATOM_CACHE_MODE must be disabled, prepare, or enabled, got {other}")
            }
        }
    }

    pub fn configured(self) -> bool {
        !matches!(self, Self::Disabled)
    }

    pub fn reads_enabled(self) -> bool {
        matches!(self, Self::Enabled)
    }
}

/// Redis-backed cache for AuthN/AuthZ decision inputs. Off by default — this
/// is a pure performance optimization; every check works correctly with it
/// disabled, since Postgres remains authoritative. See `src/cache/mod.rs` for
/// the consistency model this configures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheConfig {
    pub mode: CacheMode,
    pub redis_url: String,
    /// Deployment-unique Redis key prefix. Required in prepare/enabled mode so
    /// two Atom databases can never consume one another's cached auth state.
    pub namespace: String,
    /// Explicitly create the namespace incarnation marker when it is absent.
    /// This is a one-startup bootstrap/recovery switch, not a steady-state
    /// setting: initialization is only safe after every Atom process and
    /// in-flight request using the namespace has been fully drained.
    pub initialize_namespace: bool,
    pub pool_max_size: u32,
    pub connect_timeout_ms: u64,
    pub op_timeout_ms: u64,
    /// When Redis is configured and unreachable at startup, abort instead of
    /// starting unready. Redis remains a mutation dependency in both prepare
    /// and enabled mode, so production deployments should keep this true.
    pub fail_fast_on_startup: bool,
    pub ttl: CacheTtlConfig,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            mode: CacheMode::Disabled,
            redis_url: String::new(),
            namespace: String::new(),
            initialize_namespace: false,
            pool_max_size: 20,
            connect_timeout_ms: 2_000,
            op_timeout_ms: 50,
            fail_fast_on_startup: false,
            ttl: CacheTtlConfig::default(),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    pub fn new(bytes: Vec<u8>) -> Result<Self> {
        if bytes.len() != 32 {
            anyhow::bail!("secret bytes must be exactly 32 bytes");
        }
        Ok(Self(bytes))
    }

    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Redacted, zeroizing configuration text for provider credentials whose
/// length is provider-defined (for example, a PKCS#11 user PIN).
#[derive(Clone, PartialEq, Eq)]
pub struct SecretText(String);

impl SecretText {
    pub fn new(value: String) -> Result<Self> {
        if value.trim().is_empty() {
            anyhow::bail!("secret text must not be blank");
        }
        Ok(Self(value))
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

impl Drop for SecretText {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningKeyConfig {
    pub key_encryption_key: Option<SecretBytes>,
    pub key_encryption_key_id: String,
    pub allow_plaintext_signing_keys: bool,
}

impl Default for SigningKeyConfig {
    fn default() -> Self {
        Self {
            key_encryption_key: None,
            key_encryption_key_id: "local:v1".to_string(),
            allow_plaintext_signing_keys: false,
        }
    }
}

/// Dedicated key-encryption-key configuration for managed CA private keys.
///
/// This is intentionally separate from [`SigningKeyConfig`]: compromise or
/// rotation of JWT/credential encryption must not grant access to CA keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PkiCaProvisioningBackend {
    EncryptedDatabase,
    Pkcs11,
}

impl PkiCaProvisioningBackend {
    pub fn from_env_value(value: &str) -> Result<Self> {
        match value {
            "encrypted_database" => Ok(Self::EncryptedDatabase),
            "pkcs11" => Ok(Self::Pkcs11),
            other => anyhow::bail!(
                "ATOM_PKI_CA_KEY_BACKEND must be encrypted_database or pkcs11, got {other}"
            ),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::EncryptedDatabase => "encrypted_database",
            Self::Pkcs11 => "pkcs11",
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PkiPkcs11Config {
    pub module_path: String,
    pub token_label: String,
    pub user_pin: SecretText,
    pub operation_timeout_ms: u64,
    /// Hard upper bound on how long a Mutating PKCS#11 operation may block
    /// after it has already blown the `operation_timeout_ms` soft deadline.
    /// A wedged token holding the deployment-wide provisioning advisory lock
    /// still frees the lock at this deadline; a late completion becomes an
    /// orphaned side effect that operators must reconcile manually. Must be
    /// >= `operation_timeout_ms`.
    pub mutation_hard_timeout_ms: u64,
    pub max_retries: u32,
    pub max_in_flight: u32,
    pub circuit_failure_threshold: u32,
    pub circuit_reset_secs: u64,
}

impl fmt::Debug for PkiPkcs11Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PkiPkcs11Config")
            .field("module_path", &self.module_path)
            .field("token_label", &self.token_label)
            .field("user_pin", &"<redacted>")
            .field("operation_timeout_ms", &self.operation_timeout_ms)
            .field("mutation_hard_timeout_ms", &self.mutation_hard_timeout_ms)
            .field("max_retries", &self.max_retries)
            .field("max_in_flight", &self.max_in_flight)
            .field("circuit_failure_threshold", &self.circuit_failure_threshold)
            .field("circuit_reset_secs", &self.circuit_reset_secs)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PkiCaKeyConfig {
    pub key_encryption_key: Option<SecretBytes>,
    pub key_encryption_key_id: String,
    pub provisioning_backend: PkiCaProvisioningBackend,
    pub pkcs11: Option<PkiPkcs11Config>,
    /// Public HTTPS base URL under which the `/certs/issuers/{id}/{ocsp,crl}`
    /// artifact routes and `/certs/trust-bundle.pem` are served. Populated only
    /// when `ATOM_PUBLIC_BASE_URL` is explicitly configured; carried on
    /// `PkiCaKeyConfig` so provisioning helpers can embed per-authority
    /// discovery URLs at activation without a separate signature parameter.
    /// `None` preserves the legacy manual-SQL workflow.
    pub artifact_base_url: Option<String>,
}

impl Default for PkiCaKeyConfig {
    fn default() -> Self {
        Self {
            key_encryption_key: None,
            key_encryption_key_id: "local-ca:v1".to_string(),
            provisioning_backend: PkiCaProvisioningBackend::EncryptedDatabase,
            pkcs11: None,
            artifact_base_url: None,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AuditPolicyConfig {
    /// Persist successful high-volume auth/authz events to `audit_logs`.
    ///
    /// Disabled by default: allow volume is better handled by metrics/traces in
    /// production. Denies/errors, explicit explain/debug actions, and admin or
    /// lifecycle mutations still use durable DB audit.
    pub hot_path_allow_db_enabled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditRetentionConfig {
    pub enabled: bool,
    pub days: i64,
    pub cleanup_interval_secs: u64,
    pub cleanup_batch_size: i64,
}

impl Default for AuditRetentionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            days: 365,
            cleanup_interval_secs: 86_400,
            cleanup_batch_size: 5_000,
        }
    }
}

/// Physical purge of soft-deleted rows. Disabled by default: for an identity/
/// authorization system, keeping tombstones indefinitely (and purging only on a
/// deliberate, explicit decision) is the safe default — "never" until opted in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PurgeConfig {
    pub enabled: bool,
    pub retention_days: i64,
    pub interval_secs: u64,
    pub batch_size: i64,
}

impl Default for PurgeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            retention_days: 90,
            interval_secs: 86_400,
            batch_size: 1_000,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimitPolicyConfig {
    pub max_requests: u32,
    pub window_secs: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpServerConfig {
    pub max_connections: usize,
    pub max_connections_per_ip: usize,
    pub http_header_timeout_secs: u64,
    pub request_timeout_secs: u64,
    pub connection_timeout_secs: u64,
    pub shutdown_drain_timeout_secs: u64,
}

impl Default for HttpServerConfig {
    fn default() -> Self {
        Self {
            max_connections: 1_024,
            // Keep the topology-safe default equal to the global cap: a
            // reverse proxy may legitimately be the TCP peer for every user.
            // Directly exposed deployments can lower this independently.
            max_connections_per_ip: 1_024,
            http_header_timeout_secs: 10,
            request_timeout_secs: 30,
            connection_timeout_secs: 300,
            shutdown_drain_timeout_secs: 30,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollmentTlsConfig {
    pub cert_path: String,
    pub key_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollmentConfig {
    pub enabled: bool,
    pub listen_addr: String,
    pub tls: Option<EnrollmentTlsConfig>,
    pub entity_rate_limit: RateLimitPolicyConfig,
    pub tenant_rate_limit: RateLimitPolicyConfig,
    pub max_csr_bytes: usize,
    pub max_connections: usize,
    pub max_connections_per_ip: usize,
    /// IPv6 sources are grouped by this prefix before applying the
    /// per-source connection cap. A /64 is the standard routed allocation.
    pub ipv6_prefix_len: u8,
    /// Whether HTTP/1.1 connections may serve more than one request.
    pub http_keep_alive: bool,
    pub trust_bundle_refresh_secs: u64,
    pub tls_handshake_timeout_secs: u64,
    pub http_header_timeout_secs: u64,
    /// Total time allowed for an enrollment request, including body receipt
    /// and handler execution.
    pub request_timeout_secs: u64,
    pub connection_timeout_secs: u64,
    pub shutdown_drain_timeout_secs: u64,
}

impl Default for EnrollmentConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen_addr: "0.0.0.0:8443".to_string(),
            tls: None,
            entity_rate_limit: RateLimitPolicyConfig {
                max_requests: 10,
                window_secs: 60,
            },
            tenant_rate_limit: RateLimitPolicyConfig {
                max_requests: 1_000,
                window_secs: 60,
            },
            max_csr_bytes: 64 * 1024,
            max_connections: 256,
            max_connections_per_ip: 8,
            ipv6_prefix_len: 64,
            http_keep_alive: false,
            trust_bundle_refresh_secs: 60,
            tls_handshake_timeout_secs: 10,
            http_header_timeout_secs: 10,
            request_timeout_secs: 30,
            connection_timeout_secs: 300,
            shutdown_drain_timeout_secs: 30,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PkiLifecycleConfig {
    pub enabled: bool,
    pub interval_secs: u64,
    pub batch_size: i64,
    pub expiry_warning_secs: u64,
    pub authority_warning_secs: u64,
}

impl Default for PkiLifecycleConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_secs: 60,
            batch_size: 250,
            expiry_warning_secs: 86_400,
            // Thirty days leaves time for the documented PR-003 rotation
            // procedure and a controlled rollout of the successor chain.
            authority_warning_secs: 30 * 86_400,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateLimitConfig {
    pub enabled: bool,
    pub auth_routes: RateLimitPolicyConfig,
    pub public_routes: RateLimitPolicyConfig,
    pub enrollment: RateLimitPolicyConfig,
    pub graphql: RateLimitPolicyConfig,
    pub custom_endpoints: RateLimitPolicyConfig,
    pub admin_routes: RateLimitPolicyConfig,
    /// IPv6 client addresses are grouped by this prefix for IP buckets.
    pub ipv6_prefix_len: u8,
    pub trusted_proxy_cidrs: Vec<IpNet>,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            auth_routes: RateLimitPolicyConfig {
                max_requests: 30,
                window_secs: 60,
            },
            public_routes: RateLimitPolicyConfig {
                max_requests: 120,
                window_secs: 60,
            },
            enrollment: RateLimitPolicyConfig {
                // Keep a shared NAT gateway from becoming stricter than the
                // durable per-tenant enrollment limit by default. Operators
                // may lower this independent public-surface policy.
                max_requests: 1_000,
                window_secs: 60,
            },
            graphql: RateLimitPolicyConfig {
                max_requests: 120,
                window_secs: 60,
            },
            custom_endpoints: RateLimitPolicyConfig {
                max_requests: 120,
                window_secs: 60,
            },
            admin_routes: RateLimitPolicyConfig {
                max_requests: 300,
                window_secs: 60,
            },
            ipv6_prefix_len: 64,
            trusted_proxy_cidrs: Vec::new(),
        }
    }
}

/// Generic domain-event publishing: audit-worthy events are optionally
/// mirrored to an AMQP broker. Gated by *presence* of `amqp_url`, not a
/// separate enabled flag — unconfigured (the default) means zero behavior
/// change: no outbox rows are written and no delivery task is spawned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventsConfig {
    /// AMQP broker URL (e.g. `amqp://user:pass@host:5672/%2f`, or
    /// `amqps://user:pass@host:port/%2f` for TLS). `None` (the default)
    /// disables event publishing entirely.
    pub amqp_url: Option<String>,
    /// AMQP exchange events are published to. Empty string (the default)
    /// means the default exchange — every event is published with
    /// `amqp_routing_key` as the routing key, which the default exchange
    /// treats as a queue name. This is standard AMQP 0-9-1 (works against
    /// any compliant broker) and matches brokers whose operators only grant
    /// Atom publish access to one fixed, pre-provisioned queue rather than
    /// letting it declare arbitrary topology. Set a non-empty name to
    /// publish to a custom (e.g. topic) exchange instead, in which case Atom
    /// declares it on connect.
    pub amqp_exchange: String,
    /// Routing key used for every published event, regardless of event
    /// type. Consumers distinguish event types via the payload's own
    /// `event` field, not via AMQP routing.
    pub amqp_routing_key: String,
    /// Optional client TLS identity for mTLS to the broker. Both
    /// `amqp_tls_client_cert_path` and `amqp_tls_client_key_path` must be set
    /// together, or neither.
    pub amqp_tls_client_cert_path: Option<String>,
    pub amqp_tls_client_key_path: Option<String>,
    /// Optional CA bundle used to verify the broker's server certificate.
    /// Only meaningful with an `amqps://` URL.
    pub amqp_tls_ca_path: Option<String>,
    pub outbox_poll_interval_secs: u64,
    pub outbox_batch_size: i64,
    pub outbox_max_attempts: i32,
    /// Bounds how long Atom waits on the broker for any single operation:
    /// both one outbox delivery tick and the initial connect at startup
    /// (`AmqpPublisher::connect`). Guards against a broker that accepts the
    /// connection but stalls internally rather than erroring outright, which
    /// would otherwise hang indefinitely — the delivery task while holding a
    /// pool connection and the outbox's advisory lock, or Atom's startup
    /// itself.
    pub publish_timeout_secs: u64,
}

impl EventsConfig {
    pub fn enabled(&self) -> bool {
        self.amqp_url.is_some()
    }
}

impl Default for EventsConfig {
    fn default() -> Self {
        Self {
            amqp_url: None,
            amqp_exchange: String::new(),
            amqp_routing_key: "atom.events".to_string(),
            amqp_tls_client_cert_path: None,
            amqp_tls_client_key_path: None,
            amqp_tls_ca_path: None,
            outbox_poll_interval_secs: 5,
            outbox_batch_size: 100,
            outbox_max_attempts: 10,
            publish_timeout_secs: 30,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BodyLimitConfig {
    pub auth_bytes: usize,
    pub graphql_bytes: usize,
    pub custom_endpoint_bytes: usize,
}

impl Default for BodyLimitConfig {
    fn default() -> Self {
        Self {
            auth_bytes: 32 * 1024,
            graphql_bytes: 1024 * 1024,
            custom_endpoint_bytes: 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GraphqlLimitConfig {
    pub max_depth: usize,
    pub max_complexity: usize,
    pub introspection_enabled: bool,
}

impl Default for GraphqlLimitConfig {
    fn default() -> Self {
        Self {
            max_depth: 20,
            max_complexity: 1_000,
            // Off by default: introspection exposes the full schema, so
            // production is safe without remembering to disable it. Dev opts in
            // with ATOM_GRAPHQL_INTROSPECTION_ENABLED=true.
            introspection_enabled: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrpcTlsConfig {
    /// PEM server certificate (chain) path.
    pub cert_path: String,
    /// PEM private key path.
    pub key_path: String,
    /// Optional PEM CA bundle. When set, the server requires and verifies client
    /// certificates (mTLS); when unset, server-side TLS only.
    pub client_ca_path: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetricsConfig {
    /// When true (default), the Prometheus recorder is installed at startup and
    /// `/metrics` is mounted. Set ATOM_METRICS_ENABLED=false to skip both for
    /// maximum-performance runs without a rebuild. (For a truly zero-cost build,
    /// compile with `--no-default-features`.)
    pub enabled: bool,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoggingConfig {
    /// Tracing filter directive. `ATOM_LOG_LEVEL` wins over legacy `RUST_LOG`.
    pub level: String,
    pub format: LogFormat,
}

impl LoggingConfig {
    pub fn from_env() -> Result<Self> {
        let level = non_empty_env("ATOM_LOG_LEVEL")
            .or_else(|| non_empty_env("RUST_LOG"))
            .unwrap_or_else(|| "info".to_string());
        let format = LogFormat::from_env_value(
            &std::env::var("ATOM_LOG_FORMAT").unwrap_or_else(|_| "text".to_string()),
        )?;

        Ok(Self { level, format })
    }
}

fn non_empty_env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            format: LogFormat::Text,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    Text,
    Json,
}

impl LogFormat {
    pub fn from_env_value(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "" | "text" => Ok(Self::Text),
            "json" => Ok(Self::Json),
            other => anyhow::bail!("ATOM_LOG_FORMAT must be text or json, got {other}"),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Json => "json",
        }
    }
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let public_base_url = std::env::var("ATOM_PUBLIC_BASE_URL")
            .unwrap_or_else(|_| "http://localhost:8080".into());
        let ui_auth_callback = public_url(&public_base_url, "/auth/callback");
        let signing_keys = signing_keys_from_env()?;
        let grpc_tls = grpc_tls_from_env()?;
        let broker_auth = broker_auth_from_env()?;
        if broker_auth.enabled
            && grpc_tls
                .as_ref()
                .and_then(|tls| tls.client_ca_path.as_deref())
                .is_none()
        {
            anyhow::bail!(
                "ATOM_BROKER_AUTH_ENABLED=true requires gRPC mTLS: set \
                 ATOM_GRPC_TLS_CERT_PATH, ATOM_GRPC_TLS_KEY_PATH, and \
                 ATOM_GRPC_TLS_CLIENT_CA_PATH"
            );
        }
        let mut pki_ca_keys = pki_ca_keys_from_env()?;
        // `public_base_url` has a localhost default for local UI and auth
        // flows. Certificate discovery URLs are permanent certificate
        // metadata, so they must never inherit that implicit development
        // value. Without an explicitly configured public URL, leave them
        // unset and let leaf issuance fail closed instead of minting
        // certificates with unreachable CRL/AIA endpoints.
        pki_ca_keys.artifact_base_url =
            nonempty_env("ATOM_PUBLIC_BASE_URL").map(|url| url.trim_end_matches('/').to_string());
        if let (Some(signing_kek), Some(ca_kek)) = (
            signing_keys.key_encryption_key.as_ref(),
            pki_ca_keys.key_encryption_key.as_ref(),
        ) {
            if signing_kek.expose() == ca_kek.expose() {
                anyhow::bail!(
                    "ATOM_PKI_CA_KEY_ENCRYPTION_KEY must not reuse ATOM_KEY_ENCRYPTION_KEY"
                );
            }
        }
        Ok(Config {
            database_url: std::env::var("DATABASE_URL").context("DATABASE_URL must be set")?,
            db_pool: db_pool_from_env()?,
            logging: LoggingConfig::from_env()?,
            listen_addr: std::env::var("LISTEN_ADDR")
                .unwrap_or_else(|_| "0.0.0.0:8080".to_string()),
            http_server: http_server_from_env()?,
            grpc_addr: std::env::var("GRPC_ADDR").unwrap_or_else(|_| "0.0.0.0:8081".to_string()),
            grpc_tls,
            enrollment: enrollment_from_env()?,
            pki_lifecycle: pki_lifecycle_from_env()?,
            signing_keys,
            pki_ca_keys,
            audit_policy: AuditPolicyConfig {
                hot_path_allow_db_enabled: env_bool_default(
                    "ATOM_AUDIT_HOT_PATH_ALLOW_DB_ENABLED",
                    AuditPolicyConfig::default().hot_path_allow_db_enabled,
                )?,
            },
            audit_retention: audit_retention_from_env()?,
            purge: purge_from_env()?,
            rate_limits: rate_limits_from_env()?,
            events: events_from_env()?,
            body_limits: body_limits_from_env()?,
            graphql_limits: graphql_limits_from_env()?,
            metrics: MetricsConfig {
                enabled: env_bool_default("ATOM_METRICS_ENABLED", true)?,
            },
            jwt_expiry_secs: env_positive_lifetime_secs("JWT_EXPIRY_SECS", 3_600)?,
            jwt_issuer: std::env::var("ATOM_JWT_ISSUER")
                .unwrap_or_else(|_| public_base_url.trim_end_matches('/').to_string()),
            jwt_audience: std::env::var("ATOM_JWT_AUDIENCE")
                .unwrap_or_else(|_| "magistrala".to_string()),
            admin_entity_id: env_parse("ADMIN_ENTITY_ID", ADMIN_ENTITY_ID)?,
            admin_secret: std::env::var("ADMIN_SECRET").ok(),
            service_secret: std::env::var("ATOM_SERVICE_SECRET").ok(),
            service_entity_id: env_parse("ATOM_SERVICE_ENTITY_ID", SERVICE_ENTITY_ID)?,
            bootstrap_file: nonempty_env("ATOM_BOOTSTRAP_FILE"),
            self_registration_enabled: env_bool_default("ATOM_SELF_REGISTRATION_ENABLED", true)?,
            dev_allow_unverified_email_login: env_bool("ATOM_ALLOW_UNVERIFIED_EMAIL_LOGIN")?,
            cors_allowed_origins: parse_cors_allowed_origins(&public_base_url),
            auth_cookie_secure: env_bool_default(
                "ATOM_AUTH_COOKIE_SECURE",
                public_base_url.starts_with("https://"),
            )?,
            auth_cookie_domain: std::env::var("ATOM_AUTH_COOKIE_DOMAIN")
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty()),
            email_verification_redirect: std::env::var("ATOM_EMAIL_VERIFICATION_REDIRECT")
                .unwrap_or_else(|_| public_url(&public_base_url, "/auth/email/verify")),
            password_reset_redirect: std::env::var("ATOM_PASSWORD_RESET_REDIRECT")
                .unwrap_or_else(|_| public_url(&public_base_url, "/reset-password")),
            invitation_redirect: std::env::var("ATOM_INVITATION_REDIRECT")
                .unwrap_or_else(|_| public_url(&public_base_url, "/invitations/accept")),
            oauth_success_redirect: std::env::var("ATOM_OAUTH_SUCCESS_REDIRECT")
                .unwrap_or_else(|_| ui_auth_callback.clone()),
            oauth_error_redirect: std::env::var("ATOM_OAUTH_ERROR_REDIRECT")
                .unwrap_or_else(|_| ui_auth_callback.clone()),
            oidc_providers: parse_oidc_providers()?,
            smtp: smtp_from_env(),
            email_templates_dir: nonempty_env("ATOM_EMAIL_TEMPLATES_DIR"),
            email_verification_expiry_secs: env_positive_lifetime_secs(
                "ATOM_EMAIL_VERIFICATION_EXPIRY_SECS",
                86_400,
            )?,
            invitation_expiry_secs: env_positive_lifetime_secs(
                "ATOM_INVITATION_EXPIRY_SECS",
                604_800,
            )?,
            oauth_state_expiry_secs: env_positive_lifetime_secs(
                "ATOM_OAUTH_STATE_EXPIRY_SECS",
                600,
            )?,
            auth_exchange_code_expiry_secs: env_positive_lifetime_secs(
                "ATOM_AUTH_EXCHANGE_CODE_EXPIRY_SECS",
                300,
            )?,
            login_failure_limit: env_positive_i64("ATOM_LOGIN_FAILURE_LIMIT", 5)?,
            login_failure_window_secs: env_positive_i64("ATOM_LOGIN_FAILURE_WINDOW_SECS", 15 * 60)?,
            pki_generated_key_issuance_enabled: env_bool_default(
                "ATOM_PKI_GENERATED_KEY_ISSUANCE_ENABLED",
                false,
            )?,
            pki_root_cert_path: nonempty_env("ATOM_PKI_ROOT_CERT_PATH"),
            pki_platform_intermediate_cert_path: nonempty_env(
                "ATOM_PKI_PLATFORM_INTERMEDIATE_CERT_PATH",
            ),
            pki_platform_intermediate_key_path: nonempty_env(
                "ATOM_PKI_PLATFORM_INTERMEDIATE_KEY_PATH",
            ),
            cache: cache_from_env()?,
            broker_auth,
            public_base_url,
        })
    }

    #[doc(hidden)]
    pub fn for_tests() -> Self {
        Self {
            database_url: "postgres://atom:atom@localhost/atom_test".into(),
            db_pool: DbPoolConfig::default(),
            logging: LoggingConfig::default(),
            listen_addr: "127.0.0.1:0".into(),
            http_server: HttpServerConfig::default(),
            grpc_addr: "127.0.0.1:0".into(),
            grpc_tls: None,
            enrollment: EnrollmentConfig::default(),
            pki_lifecycle: PkiLifecycleConfig::default(),
            signing_keys: SigningKeyConfig {
                allow_plaintext_signing_keys: true,
                // Provide a deterministic KEK so tests exercise encryption at rest
                // for recoverable secrets (shared keys).
                key_encryption_key: SecretBytes::new(vec![7u8; 32]).ok(),
                ..SigningKeyConfig::default()
            },
            pki_ca_keys: PkiCaKeyConfig {
                key_encryption_key: SecretBytes::new(vec![8u8; 32]).ok(),
                artifact_base_url: Some("https://pki.example.test".into()),
                ..PkiCaKeyConfig::default()
            },
            audit_policy: AuditPolicyConfig::default(),
            audit_retention: AuditRetentionConfig::default(),
            purge: PurgeConfig::default(),
            rate_limits: RateLimitConfig {
                enabled: false,
                ..RateLimitConfig::default()
            },
            events: EventsConfig::default(),
            body_limits: BodyLimitConfig::default(),
            graphql_limits: GraphqlLimitConfig::default(),
            metrics: MetricsConfig::default(),
            jwt_expiry_secs: 3600,
            jwt_issuer: "http://localhost:8080".to_string(),
            jwt_audience: "magistrala".to_string(),
            admin_entity_id: ADMIN_ENTITY_ID,
            admin_secret: None,
            service_secret: None,
            service_entity_id: SERVICE_ENTITY_ID,
            bootstrap_file: None,
            self_registration_enabled: false,
            dev_allow_unverified_email_login: false,
            public_base_url: "http://localhost:8080".into(),
            cors_allowed_origins: vec!["http://localhost:8080".into()],
            auth_cookie_secure: false,
            auth_cookie_domain: None,
            email_verification_redirect: "http://localhost:8080/auth/email/verify".into(),
            password_reset_redirect: "http://localhost:8080/reset-password".into(),
            invitation_redirect: "http://localhost:8080/invitations/accept".into(),
            oauth_success_redirect: "http://localhost:8080".into(),
            oauth_error_redirect: "http://localhost:8080".into(),
            oidc_providers: vec![],
            smtp: None,
            email_templates_dir: None,
            email_verification_expiry_secs: 86_400,
            invitation_expiry_secs: 604_800,
            oauth_state_expiry_secs: 600,
            auth_exchange_code_expiry_secs: 300,
            login_failure_limit: 5,
            login_failure_window_secs: 15 * 60,
            pki_generated_key_issuance_enabled: false,
            pki_root_cert_path: None,
            pki_platform_intermediate_cert_path: None,
            pki_platform_intermediate_key_path: None,
            cache: CacheConfig::default(),
            broker_auth: BrokerAuthConfig::default(),
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::for_tests()
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct OidcProviderConfig {
    pub name: String,
    pub issuer: String,
    pub client_id: String,
    pub client_secret: String,
    #[serde(default = "default_oidc_scopes")]
    pub scopes: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct SmtpConfig {
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    pub from: String,
    pub tls: SmtpTls,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmtpTls {
    None,
    StartTls,
    Tls,
}

fn env_bool(name: &str) -> Result<bool> {
    env_bool_default(name, false)
}

pub(crate) fn env_bool_default(name: &str, default: bool) -> Result<bool> {
    Ok(env_optional_bool(name)?.unwrap_or(default))
}

fn env_optional_bool(name: &str) -> Result<Option<bool>> {
    match std::env::var(name) {
        Ok(value) => parse_env_bool(name, &value).map(Some),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => {
            anyhow::bail!("{name} must be valid Unicode")
        }
    }
}

fn parse_env_bool(name: &str, value: &str) -> Result<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => anyhow::bail!("{name} must be one of true, false, 1, 0, yes, no, on, or off"),
    }
}

fn env_parse<T>(name: &str, default: T) -> Result<T>
where
    T: FromStr,
    T::Err: fmt::Display,
{
    match std::env::var(name) {
        Ok(value) => value
            .parse()
            .map_err(|err| anyhow::anyhow!("{name} must be a valid value: {err}")),
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(std::env::VarError::NotUnicode(_)) => {
            anyhow::bail!("{name} must be valid Unicode")
        }
    }
}

fn env_positive_i64(name: &str, default: i64) -> Result<i64> {
    let value = env_parse(name, default)?;
    if value <= 0 {
        anyhow::bail!("{name} must be greater than zero");
    }
    Ok(value)
}

fn env_positive_lifetime_secs(name: &str, default: u64) -> Result<u64> {
    let value = env_parse(name, default)?;
    if value == 0 {
        anyhow::bail!("{name} must be greater than zero");
    }
    let seconds = i64::try_from(value)
        .with_context(|| format!("{name} is too large to represent as a duration"))?;
    let duration = Duration::try_seconds(seconds)
        .with_context(|| format!("{name} is too large to represent as a duration"))?;
    Utc::now()
        .checked_add_signed(duration)
        .with_context(|| format!("{name} is too large to represent as an expiration time"))?;
    Ok(value)
}

fn db_pool_from_env() -> Result<DbPoolConfig> {
    let default = DbPoolConfig::default();
    let cfg = DbPoolConfig {
        max_connections: env_parse("ATOM_DB_MAX_CONNECTIONS", default.max_connections)?,
        min_connections: env_parse("ATOM_DB_MIN_CONNECTIONS", default.min_connections)?,
        acquire_timeout_secs: env_parse(
            "ATOM_DB_ACQUIRE_TIMEOUT_SECS",
            default.acquire_timeout_secs,
        )?,
        connect_timeout_secs: env_parse(
            "ATOM_DB_CONNECT_TIMEOUT_SECS",
            default.connect_timeout_secs,
        )?,
        idle_timeout_secs: env_parse("ATOM_DB_IDLE_TIMEOUT_SECS", default.idle_timeout_secs)?,
        max_lifetime_secs: env_parse("ATOM_DB_MAX_LIFETIME_SECS", default.max_lifetime_secs)?,
    };
    if cfg.max_connections == 0 {
        anyhow::bail!("ATOM_DB_MAX_CONNECTIONS must be greater than zero");
    }
    if cfg.min_connections > cfg.max_connections {
        anyhow::bail!("ATOM_DB_MIN_CONNECTIONS cannot exceed ATOM_DB_MAX_CONNECTIONS");
    }
    Ok(cfg)
}

fn http_server_from_env() -> Result<HttpServerConfig> {
    let default = HttpServerConfig::default();
    let cfg = HttpServerConfig {
        max_connections: env_parse("ATOM_HTTP_MAX_CONNECTIONS", default.max_connections)?,
        max_connections_per_ip: env_parse(
            "ATOM_HTTP_MAX_CONNECTIONS_PER_IP",
            default.max_connections_per_ip,
        )?,
        http_header_timeout_secs: env_parse(
            "ATOM_HTTP_HEADER_TIMEOUT_SECS",
            default.http_header_timeout_secs,
        )?,
        request_timeout_secs: env_parse(
            "ATOM_HTTP_REQUEST_TIMEOUT_SECS",
            default.request_timeout_secs,
        )?,
        connection_timeout_secs: env_parse(
            "ATOM_HTTP_CONNECTION_TIMEOUT_SECS",
            default.connection_timeout_secs,
        )?,
        shutdown_drain_timeout_secs: env_parse(
            "ATOM_HTTP_SHUTDOWN_DRAIN_TIMEOUT_SECS",
            default.shutdown_drain_timeout_secs,
        )?,
    };
    for (name, value) in [
        ("ATOM_HTTP_MAX_CONNECTIONS", cfg.max_connections as u64),
        (
            "ATOM_HTTP_MAX_CONNECTIONS_PER_IP",
            cfg.max_connections_per_ip as u64,
        ),
        (
            "ATOM_HTTP_HEADER_TIMEOUT_SECS",
            cfg.http_header_timeout_secs,
        ),
        ("ATOM_HTTP_REQUEST_TIMEOUT_SECS", cfg.request_timeout_secs),
        (
            "ATOM_HTTP_CONNECTION_TIMEOUT_SECS",
            cfg.connection_timeout_secs,
        ),
        (
            "ATOM_HTTP_SHUTDOWN_DRAIN_TIMEOUT_SECS",
            cfg.shutdown_drain_timeout_secs,
        ),
    ] {
        if value == 0 {
            anyhow::bail!("{name} must be greater than zero");
        }
    }
    if cfg.max_connections_per_ip > cfg.max_connections {
        anyhow::bail!("ATOM_HTTP_MAX_CONNECTIONS_PER_IP cannot exceed ATOM_HTTP_MAX_CONNECTIONS");
    }
    Ok(cfg)
}

fn cache_from_env() -> Result<CacheConfig> {
    let default = CacheConfig::default();
    let default_ttl = CacheTtlConfig::default();
    let cfg = CacheConfig {
        mode: cache_mode_from_env()?,
        redis_url: std::env::var("ATOM_CACHE_REDIS_URL").unwrap_or_default(),
        namespace: nonempty_env("ATOM_CACHE_NAMESPACE").unwrap_or_default(),
        initialize_namespace: env_bool_default("ATOM_CACHE_INITIALIZE_NAMESPACE", false)?,
        pool_max_size: env_parse("ATOM_CACHE_POOL_MAX_SIZE", default.pool_max_size)?,
        connect_timeout_ms: env_parse("ATOM_CACHE_CONNECT_TIMEOUT_MS", default.connect_timeout_ms)?,
        op_timeout_ms: env_parse("ATOM_CACHE_OP_TIMEOUT_MS", default.op_timeout_ms)?,
        fail_fast_on_startup: env_bool_default(
            "ATOM_CACHE_FAIL_FAST_ON_STARTUP",
            default.fail_fast_on_startup,
        )?,
        ttl: CacheTtlConfig {
            session_secs: env_parse("ATOM_CACHE_TTL_SESSION_SECS", default_ttl.session_secs)?,
            entity_status_secs: env_parse(
                "ATOM_CACHE_TTL_ENTITY_STATUS_SECS",
                default_ttl.entity_status_secs,
            )?,
            tenant_status_secs: env_parse(
                "ATOM_CACHE_TTL_TENANT_STATUS_SECS",
                default_ttl.tenant_status_secs,
            )?,
            credential_secs: env_parse(
                "ATOM_CACHE_TTL_CREDENTIAL_SECS",
                default_ttl.credential_secs,
            )?,
            credential_ceiling_secs: env_parse(
                "ATOM_CACHE_TTL_CREDENTIAL_CEILING_SECS",
                default_ttl.credential_ceiling_secs,
            )?,
            grants_secs: env_parse("ATOM_CACHE_TTL_GRANTS_SECS", default_ttl.grants_secs)?,
        },
    };
    if cfg.mode.configured() {
        if cfg.redis_url.trim().is_empty() {
            anyhow::bail!(
                "ATOM_CACHE_REDIS_URL must be set when ATOM_CACHE_MODE is prepare or enabled"
            );
        }
        if !valid_cache_namespace(&cfg.namespace) {
            anyhow::bail!(
                "ATOM_CACHE_NAMESPACE must be 1-64 ASCII letters, digits, dots, underscores, or hyphens when ATOM_CACHE_MODE is prepare or enabled"
            );
        }
        if cfg.pool_max_size == 0 {
            anyhow::bail!("ATOM_CACHE_POOL_MAX_SIZE must be greater than zero");
        }
        if cfg.connect_timeout_ms == 0 {
            anyhow::bail!("ATOM_CACHE_CONNECT_TIMEOUT_MS must be greater than zero");
        }
        if cfg.op_timeout_ms == 0 {
            anyhow::bail!("ATOM_CACHE_OP_TIMEOUT_MS must be greater than zero");
        }
        let ttl = &cfg.ttl;
        let ttls = [
            ttl.session_secs,
            ttl.entity_status_secs,
            ttl.tenant_status_secs,
            ttl.credential_secs,
            ttl.credential_ceiling_secs,
            ttl.grants_secs,
        ];
        if ttls.contains(&0) {
            anyhow::bail!("ATOM_CACHE_TTL_* values must all be greater than zero");
        }
        // Bound the Redis PEXPIRE millisecond conversion before any cache
        // operation and reject operationally nonsensical auth/authz staleness
        // windows. A day is already far beyond a useful cache lifetime.
        if ttls.iter().any(|secs| *secs > MAX_CACHE_TTL_SECS) {
            anyhow::bail!(
                "ATOM_CACHE_TTL_* values must not exceed {MAX_CACHE_TTL_SECS} seconds (24h)"
            );
        }
    }
    Ok(cfg)
}

fn cache_mode_from_env() -> Result<CacheMode> {
    let explicit_mode = nonempty_env("ATOM_CACHE_MODE")
        .map(|value| CacheMode::from_env_value(&value))
        .transpose()?;
    let legacy_enabled = env_optional_bool("ATOM_CACHE_ENABLED")?;

    match (explicit_mode, legacy_enabled) {
        (Some(mode), Some(enabled)) => {
            let compatible = matches!(
                (mode, enabled),
                (CacheMode::Enabled, true) | (CacheMode::Disabled, false)
            );
            if !compatible {
                anyhow::bail!(
                    "ATOM_CACHE_MODE conflicts with deprecated ATOM_CACHE_ENABLED; remove ATOM_CACHE_ENABLED"
                );
            }
            Ok(mode)
        }
        (Some(mode), None) => Ok(mode),
        (None, Some(true)) => Ok(CacheMode::Enabled),
        (None, Some(false)) | (None, None) => Ok(CacheMode::Disabled),
    }
}

fn valid_cache_namespace(namespace: &str) -> bool {
    !namespace.is_empty()
        && namespace.len() <= 64
        && namespace
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn signing_keys_from_env() -> Result<SigningKeyConfig> {
    let default = SigningKeyConfig::default();
    Ok(SigningKeyConfig {
        key_encryption_key: parse_key_encryption_key()?,
        key_encryption_key_id: std::env::var("ATOM_KEY_ENCRYPTION_KEY_ID")
            .unwrap_or(default.key_encryption_key_id),
        allow_plaintext_signing_keys: env_bool_default(
            "ATOM_ALLOW_PLAINTEXT_SIGNING_KEYS",
            default.allow_plaintext_signing_keys,
        )?,
    })
}

fn parse_key_encryption_key() -> Result<Option<SecretBytes>> {
    let value = match std::env::var("ATOM_KEY_ENCRYPTION_KEY") {
        Ok(value) if !value.trim().is_empty() => value,
        _ => return Ok(None),
    };
    let bytes = STANDARD
        .decode(value.trim())
        .context("ATOM_KEY_ENCRYPTION_KEY must be base64 encoded")?;
    SecretBytes::new(bytes)
        .map(Some)
        .context("ATOM_KEY_ENCRYPTION_KEY must decode to exactly 32 bytes")
}

fn pki_ca_keys_from_env() -> Result<PkiCaKeyConfig> {
    let default = PkiCaKeyConfig::default();
    let key_encryption_key = parse_secret_key_env("ATOM_PKI_CA_KEY_ENCRYPTION_KEY")?;
    let key_encryption_key_id =
        std::env::var("ATOM_PKI_CA_KEY_ENCRYPTION_KEY_ID").unwrap_or(default.key_encryption_key_id);
    if key_encryption_key.is_some() && key_encryption_key_id.trim().is_empty() {
        anyhow::bail!("ATOM_PKI_CA_KEY_ENCRYPTION_KEY_ID must not be blank when the CA KEK is set");
    }
    let provisioning_backend = PkiCaProvisioningBackend::from_env_value(
        &std::env::var("ATOM_PKI_CA_KEY_BACKEND")
            .unwrap_or_else(|_| default.provisioning_backend.as_str().to_string()),
    )?;
    let pkcs11_names = [
        "ATOM_PKI_PKCS11_MODULE_PATH",
        "ATOM_PKI_PKCS11_TOKEN_LABEL",
        "ATOM_PKI_PKCS11_USER_PIN",
    ];
    let pkcs11_requested = provisioning_backend == PkiCaProvisioningBackend::Pkcs11
        || pkcs11_names
            .iter()
            .any(|name| std::env::var(name).is_ok_and(|value| !value.trim().is_empty()));
    let pkcs11 = if pkcs11_requested {
        let required = |name: &'static str| -> Result<String> {
            let value = std::env::var(name).with_context(|| format!("{name} must be set"))?;
            if value.trim().is_empty() {
                anyhow::bail!("{name} must not be blank");
            }
            Ok(value)
        };
        let operation_timeout_ms = env_parse("ATOM_PKI_PKCS11_OPERATION_TIMEOUT_MS", 2_000_u64)?;
        let mutation_hard_timeout_ms =
            env_parse("ATOM_PKI_PKCS11_MUTATION_HARD_TIMEOUT_MS", 60_000_u64)?;
        let max_retries = env_parse("ATOM_PKI_PKCS11_MAX_RETRIES", 1_u32)?;
        let max_in_flight = env_parse("ATOM_PKI_PKCS11_MAX_IN_FLIGHT", 8_u32)?;
        let circuit_failure_threshold =
            env_parse("ATOM_PKI_PKCS11_CIRCUIT_FAILURE_THRESHOLD", 3_u32)?;
        let circuit_reset_secs = env_parse("ATOM_PKI_PKCS11_CIRCUIT_RESET_SECS", 30_u64)?;
        if operation_timeout_ms == 0 {
            anyhow::bail!("ATOM_PKI_PKCS11_OPERATION_TIMEOUT_MS must be greater than zero");
        }
        if mutation_hard_timeout_ms < operation_timeout_ms {
            anyhow::bail!(
                "ATOM_PKI_PKCS11_MUTATION_HARD_TIMEOUT_MS must be >= ATOM_PKI_PKCS11_OPERATION_TIMEOUT_MS"
            );
        }
        if max_retries > 3 {
            anyhow::bail!("ATOM_PKI_PKCS11_MAX_RETRIES must be at most 3");
        }
        if max_in_flight == 0 {
            anyhow::bail!("ATOM_PKI_PKCS11_MAX_IN_FLIGHT must be greater than zero");
        }
        if circuit_failure_threshold == 0 {
            anyhow::bail!("ATOM_PKI_PKCS11_CIRCUIT_FAILURE_THRESHOLD must be greater than zero");
        }
        if circuit_reset_secs == 0 {
            anyhow::bail!("ATOM_PKI_PKCS11_CIRCUIT_RESET_SECS must be greater than zero");
        }
        Some(PkiPkcs11Config {
            module_path: required("ATOM_PKI_PKCS11_MODULE_PATH")?,
            token_label: required("ATOM_PKI_PKCS11_TOKEN_LABEL")?,
            user_pin: SecretText::new(required("ATOM_PKI_PKCS11_USER_PIN")?)?,
            operation_timeout_ms,
            mutation_hard_timeout_ms,
            max_retries,
            max_in_flight,
            circuit_failure_threshold,
            circuit_reset_secs,
        })
    } else {
        None
    };
    Ok(PkiCaKeyConfig {
        key_encryption_key,
        key_encryption_key_id,
        provisioning_backend,
        pkcs11,
        artifact_base_url: None,
    })
}

fn parse_secret_key_env(name: &str) -> Result<Option<SecretBytes>> {
    let value = match std::env::var(name) {
        Ok(value) if !value.trim().is_empty() => value,
        _ => return Ok(None),
    };
    let bytes = STANDARD
        .decode(value.trim())
        .with_context(|| format!("{name} must be base64 encoded"))?;
    SecretBytes::new(bytes)
        .map(Some)
        .with_context(|| format!("{name} must decode to exactly 32 bytes"))
}

fn audit_retention_from_env() -> Result<AuditRetentionConfig> {
    let default = AuditRetentionConfig::default();
    let cfg = AuditRetentionConfig {
        enabled: env_bool_default("ATOM_AUDIT_RETENTION_ENABLED", default.enabled)?,
        days: env_parse("ATOM_AUDIT_RETENTION_DAYS", default.days)?,
        cleanup_interval_secs: env_parse(
            "ATOM_AUDIT_CLEANUP_INTERVAL_SECS",
            default.cleanup_interval_secs,
        )?,
        cleanup_batch_size: env_parse("ATOM_AUDIT_CLEANUP_BATCH_SIZE", default.cleanup_batch_size)?,
    };
    if cfg.days <= 0 {
        anyhow::bail!("ATOM_AUDIT_RETENTION_DAYS must be greater than zero");
    }
    if cfg.cleanup_interval_secs == 0 {
        anyhow::bail!("ATOM_AUDIT_CLEANUP_INTERVAL_SECS must be greater than zero");
    }
    if cfg.cleanup_batch_size <= 0 {
        anyhow::bail!("ATOM_AUDIT_CLEANUP_BATCH_SIZE must be greater than zero");
    }
    Ok(cfg)
}

fn purge_from_env() -> Result<PurgeConfig> {
    let default = PurgeConfig::default();
    let cfg = PurgeConfig {
        enabled: env_bool_default("ATOM_PURGE_ENABLED", default.enabled)?,
        retention_days: env_parse("ATOM_PURGE_RETENTION_DAYS", default.retention_days)?,
        interval_secs: env_parse("ATOM_PURGE_INTERVAL_SECS", default.interval_secs)?,
        batch_size: env_parse("ATOM_PURGE_BATCH_SIZE", default.batch_size)?,
    };
    if cfg.enabled {
        if cfg.retention_days <= 0 {
            anyhow::bail!("ATOM_PURGE_RETENTION_DAYS must be greater than zero");
        }
        if cfg.interval_secs == 0 {
            anyhow::bail!("ATOM_PURGE_INTERVAL_SECS must be greater than zero");
        }
        if cfg.batch_size <= 0 {
            anyhow::bail!("ATOM_PURGE_BATCH_SIZE must be greater than zero");
        }
    }
    Ok(cfg)
}

fn rate_limits_from_env() -> Result<RateLimitConfig> {
    let default = RateLimitConfig::default();
    let cfg = RateLimitConfig {
        enabled: env_bool_default("ATOM_RATE_LIMIT_ENABLED", default.enabled)?,
        auth_routes: rate_limit_policy_from_env(
            "ATOM_HTTP_RATE_LIMIT_AUTH_ROUTES",
            "ATOM_HTTP_RATE_LIMIT_AUTH_WINDOW_SECS",
            default.auth_routes,
        )?,
        public_routes: rate_limit_policy_from_env(
            "ATOM_HTTP_RATE_LIMIT_PUBLIC_ROUTES",
            "ATOM_HTTP_RATE_LIMIT_PUBLIC_WINDOW_SECS",
            default.public_routes,
        )?,
        enrollment: rate_limit_policy_from_env(
            "ATOM_HTTP_RATE_LIMIT_ENROLLMENT",
            "ATOM_HTTP_RATE_LIMIT_ENROLLMENT_WINDOW_SECS",
            default.enrollment,
        )?,
        graphql: rate_limit_policy_from_env(
            "ATOM_HTTP_RATE_LIMIT_GRAPHQL",
            "ATOM_HTTP_RATE_LIMIT_GRAPHQL_WINDOW_SECS",
            default.graphql,
        )?,
        custom_endpoints: rate_limit_policy_from_env(
            "ATOM_HTTP_RATE_LIMIT_CUSTOM_ENDPOINTS",
            "ATOM_HTTP_RATE_LIMIT_CUSTOM_ENDPOINTS_WINDOW_SECS",
            default.custom_endpoints,
        )?,
        admin_routes: rate_limit_policy_from_env(
            "ATOM_HTTP_RATE_LIMIT_ADMIN_ROUTES",
            "ATOM_HTTP_RATE_LIMIT_ADMIN_WINDOW_SECS",
            default.admin_routes,
        )?,
        ipv6_prefix_len: env_parse(
            "ATOM_HTTP_RATE_LIMIT_IPV6_PREFIX_LEN",
            default.ipv6_prefix_len,
        )?,
        trusted_proxy_cidrs: trusted_proxy_cidrs_from_env()?,
    };
    if cfg.ipv6_prefix_len == 0 || cfg.ipv6_prefix_len > 128 {
        anyhow::bail!("ATOM_HTTP_RATE_LIMIT_IPV6_PREFIX_LEN must be between 1 and 128");
    }
    Ok(cfg)
}

fn events_from_env() -> Result<EventsConfig> {
    let default = EventsConfig::default();
    let cfg = EventsConfig {
        amqp_url: nonempty_env("ATOM_EVENTS_AMQP_URL"),
        amqp_exchange: std::env::var("ATOM_EVENTS_AMQP_EXCHANGE").unwrap_or(default.amqp_exchange),
        amqp_routing_key: std::env::var("ATOM_EVENTS_AMQP_ROUTING_KEY")
            .unwrap_or(default.amqp_routing_key),
        amqp_tls_client_cert_path: nonempty_env("ATOM_EVENTS_AMQP_TLS_CLIENT_CERT_PATH"),
        amqp_tls_client_key_path: nonempty_env("ATOM_EVENTS_AMQP_TLS_CLIENT_KEY_PATH"),
        amqp_tls_ca_path: nonempty_env("ATOM_EVENTS_AMQP_TLS_CA_PATH"),
        outbox_poll_interval_secs: env_parse(
            "ATOM_EVENTS_OUTBOX_POLL_INTERVAL_SECS",
            default.outbox_poll_interval_secs,
        )?,
        outbox_batch_size: env_parse("ATOM_EVENTS_OUTBOX_BATCH_SIZE", default.outbox_batch_size)?,
        outbox_max_attempts: env_parse(
            "ATOM_EVENTS_OUTBOX_MAX_ATTEMPTS",
            default.outbox_max_attempts,
        )?,
        publish_timeout_secs: env_parse(
            "ATOM_EVENTS_PUBLISH_TIMEOUT_SECS",
            default.publish_timeout_secs,
        )?,
    };
    if cfg.outbox_poll_interval_secs == 0 {
        anyhow::bail!("ATOM_EVENTS_OUTBOX_POLL_INTERVAL_SECS must be greater than zero");
    }
    if cfg.outbox_batch_size <= 0 {
        anyhow::bail!("ATOM_EVENTS_OUTBOX_BATCH_SIZE must be greater than zero");
    }
    if cfg.outbox_max_attempts <= 0 {
        anyhow::bail!("ATOM_EVENTS_OUTBOX_MAX_ATTEMPTS must be greater than zero");
    }
    if cfg.publish_timeout_secs == 0 {
        anyhow::bail!("ATOM_EVENTS_PUBLISH_TIMEOUT_SECS must be greater than zero");
    }
    if cfg.amqp_tls_client_cert_path.is_some() != cfg.amqp_tls_client_key_path.is_some() {
        anyhow::bail!(
            "ATOM_EVENTS_AMQP_TLS_CLIENT_CERT_PATH and ATOM_EVENTS_AMQP_TLS_CLIENT_KEY_PATH must both be set, or neither"
        );
    }
    Ok(cfg)
}

fn rate_limit_policy_from_env(
    max_name: &str,
    window_name: &str,
    default: RateLimitPolicyConfig,
) -> Result<RateLimitPolicyConfig> {
    let policy = RateLimitPolicyConfig {
        max_requests: env_parse(max_name, default.max_requests)?,
        window_secs: env_parse(window_name, default.window_secs)?,
    };
    if policy.max_requests == 0 {
        anyhow::bail!("{max_name} must be greater than zero");
    }
    if policy.window_secs == 0 {
        anyhow::bail!("{window_name} must be greater than zero");
    }
    Ok(policy)
}

fn trusted_proxy_cidrs_from_env() -> Result<Vec<IpNet>> {
    let value = match std::env::var("ATOM_TRUSTED_PROXY_CIDRS") {
        Ok(value) if !value.trim().is_empty() => value,
        _ => return Ok(Vec::new()),
    };

    value
        .split(',')
        .map(str::trim)
        .filter(|cidr| !cidr.is_empty())
        .map(|cidr| {
            cidr.parse::<IpNet>()
                .with_context(|| format!("ATOM_TRUSTED_PROXY_CIDRS contains invalid CIDR {cidr}"))
        })
        .collect()
}

fn body_limits_from_env() -> Result<BodyLimitConfig> {
    let default = BodyLimitConfig::default();
    Ok(BodyLimitConfig {
        auth_bytes: env_parse("ATOM_AUTH_BODY_LIMIT_BYTES", default.auth_bytes)?,
        graphql_bytes: env_parse("ATOM_GRAPHQL_BODY_LIMIT_BYTES", default.graphql_bytes)?,
        custom_endpoint_bytes: env_parse(
            "ATOM_CUSTOM_ENDPOINT_BODY_LIMIT_BYTES",
            default.custom_endpoint_bytes,
        )?,
    })
}

fn graphql_limits_from_env() -> Result<GraphqlLimitConfig> {
    let default = GraphqlLimitConfig::default();
    let cfg = GraphqlLimitConfig {
        max_depth: env_parse("ATOM_GRAPHQL_MAX_DEPTH", default.max_depth)?,
        max_complexity: env_parse("ATOM_GRAPHQL_MAX_COMPLEXITY", default.max_complexity)?,
        introspection_enabled: env_bool_default(
            "ATOM_GRAPHQL_INTROSPECTION_ENABLED",
            default.introspection_enabled,
        )?,
    };
    if cfg.max_depth == 0 {
        anyhow::bail!("ATOM_GRAPHQL_MAX_DEPTH must be greater than zero");
    }
    if cfg.max_complexity == 0 {
        anyhow::bail!("ATOM_GRAPHQL_MAX_COMPLEXITY must be greater than zero");
    }
    Ok(cfg)
}

/// gRPC TLS is enabled when both cert and key paths are set. Setting only one is
/// a misconfiguration and fails fast at startup. `client_ca_path` (mTLS) is
/// independent and optional. Blank values are treated as unset for Compose.
fn grpc_tls_from_env() -> Result<Option<GrpcTlsConfig>> {
    let cert_path = nonempty_env("ATOM_GRPC_TLS_CERT_PATH");
    let key_path = nonempty_env("ATOM_GRPC_TLS_KEY_PATH");
    let client_ca_path = nonempty_env("ATOM_GRPC_TLS_CLIENT_CA_PATH");
    match (cert_path, key_path) {
        (Some(cert_path), Some(key_path)) => Ok(Some(GrpcTlsConfig {
            cert_path,
            key_path,
            client_ca_path,
        })),
        (None, None) => {
            if client_ca_path.is_some() {
                anyhow::bail!(
                    "ATOM_GRPC_TLS_CLIENT_CA_PATH is set but ATOM_GRPC_TLS_CERT_PATH/ATOM_GRPC_TLS_KEY_PATH are not"
                );
            }
            Ok(None)
        }
        _ => anyhow::bail!(
            "gRPC TLS requires both ATOM_GRPC_TLS_CERT_PATH and ATOM_GRPC_TLS_KEY_PATH"
        ),
    }
}

fn broker_auth_from_env() -> Result<BrokerAuthConfig> {
    let defaults = BrokerAuthConfig::default();
    let enabled = env_bool_default("ATOM_BROKER_AUTH_ENABLED", defaults.enabled)?;
    if !enabled {
        return Ok(defaults);
    }

    let raw = nonempty_env("ATOM_BROKER_TOPIC_TEMPLATE")
        .unwrap_or_else(|| DEFAULT_BROKER_TOPIC_TEMPLATE.to_string());
    // Templates are tried in order, so a deployment with more than one topic
    // shape does not need a second Atom.
    let templates: Vec<String> = raw
        .split(',')
        .map(str::trim)
        .filter(|template| !template.is_empty())
        .map(ToOwned::to_owned)
        .collect();
    if templates.is_empty() {
        anyhow::bail!("ATOM_BROKER_TOPIC_TEMPLATE must list at least one template");
    }

    Ok(BrokerAuthConfig {
        enabled,
        topic_templates: crate::broker_auth::TopicTemplateSet::parse_list(&templates)?,
        topic_ref: BrokerTopicRef::from_env_value(
            &std::env::var("ATOM_BROKER_TOPIC_REF").unwrap_or_default(),
        )?,
        credential_kind: broker_credential_kind_from_env()?,
        topic_allow: crate::broker_auth::TopicAllowList::parse_list(&comma_list(
            "ATOM_BROKER_TOPIC_ALLOW",
        ))?,
    })
}

fn enrollment_from_env() -> Result<EnrollmentConfig> {
    if std::env::var_os("ATOM_PKI_ENROLLMENT_REQUEST_BODY_TIMEOUT_SECS").is_some() {
        anyhow::bail!(
            "ATOM_PKI_ENROLLMENT_REQUEST_BODY_TIMEOUT_SECS was renamed to ATOM_PKI_ENROLLMENT_REQUEST_TIMEOUT_SECS"
        );
    }
    let default = EnrollmentConfig::default();
    let enabled = env_bool_default("ATOM_PKI_ENROLLMENT_ENABLED", default.enabled)?;
    let cert_path = nonempty_env("ATOM_PKI_ENROLLMENT_TLS_CERT_PATH");
    let key_path = nonempty_env("ATOM_PKI_ENROLLMENT_TLS_KEY_PATH");
    let tls = match (cert_path, key_path) {
        (Some(cert_path), Some(key_path)) => Some(EnrollmentTlsConfig {
            cert_path,
            key_path,
        }),
        (None, None) => None,
        _ => anyhow::bail!(
            "enrollment TLS requires both ATOM_PKI_ENROLLMENT_TLS_CERT_PATH and ATOM_PKI_ENROLLMENT_TLS_KEY_PATH"
        ),
    };
    if enabled && tls.is_none() {
        anyhow::bail!(
            "ATOM_PKI_ENROLLMENT_ENABLED requires enrollment TLS certificate and key paths"
        );
    }

    let cfg = EnrollmentConfig {
        enabled,
        listen_addr: std::env::var("ATOM_PKI_ENROLLMENT_LISTEN_ADDR")
            .unwrap_or(default.listen_addr),
        tls,
        entity_rate_limit: rate_limit_policy_from_env(
            "ATOM_PKI_ENROLLMENT_ENTITY_RATE_LIMIT",
            "ATOM_PKI_ENROLLMENT_ENTITY_RATE_WINDOW_SECS",
            default.entity_rate_limit,
        )?,
        tenant_rate_limit: rate_limit_policy_from_env(
            "ATOM_PKI_ENROLLMENT_TENANT_RATE_LIMIT",
            "ATOM_PKI_ENROLLMENT_TENANT_RATE_WINDOW_SECS",
            default.tenant_rate_limit,
        )?,
        max_csr_bytes: env_parse("ATOM_PKI_ENROLLMENT_MAX_CSR_BYTES", default.max_csr_bytes)?,
        max_connections: env_parse(
            "ATOM_PKI_ENROLLMENT_MAX_CONNECTIONS",
            default.max_connections,
        )?,
        max_connections_per_ip: env_parse(
            "ATOM_PKI_ENROLLMENT_MAX_CONNECTIONS_PER_IP",
            default.max_connections_per_ip,
        )?,
        ipv6_prefix_len: env_parse(
            "ATOM_PKI_ENROLLMENT_IPV6_PREFIX_LEN",
            default.ipv6_prefix_len,
        )?,
        http_keep_alive: env_bool_default(
            "ATOM_PKI_ENROLLMENT_HTTP_KEEP_ALIVE",
            default.http_keep_alive,
        )?,
        trust_bundle_refresh_secs: env_parse(
            "ATOM_PKI_ENROLLMENT_TRUST_REFRESH_SECS",
            default.trust_bundle_refresh_secs,
        )?,
        tls_handshake_timeout_secs: env_parse(
            "ATOM_PKI_ENROLLMENT_TLS_HANDSHAKE_TIMEOUT_SECS",
            default.tls_handshake_timeout_secs,
        )?,
        http_header_timeout_secs: env_parse(
            "ATOM_PKI_ENROLLMENT_HTTP_HEADER_TIMEOUT_SECS",
            default.http_header_timeout_secs,
        )?,
        request_timeout_secs: env_parse(
            "ATOM_PKI_ENROLLMENT_REQUEST_TIMEOUT_SECS",
            default.request_timeout_secs,
        )?,
        connection_timeout_secs: env_parse(
            "ATOM_PKI_ENROLLMENT_CONNECTION_TIMEOUT_SECS",
            default.connection_timeout_secs,
        )?,
        shutdown_drain_timeout_secs: env_parse(
            "ATOM_PKI_ENROLLMENT_SHUTDOWN_DRAIN_TIMEOUT_SECS",
            default.shutdown_drain_timeout_secs,
        )?,
    };
    if cfg.max_csr_bytes == 0 {
        anyhow::bail!("ATOM_PKI_ENROLLMENT_MAX_CSR_BYTES must be greater than zero");
    }
    if cfg.max_connections == 0 {
        anyhow::bail!("ATOM_PKI_ENROLLMENT_MAX_CONNECTIONS must be greater than zero");
    }
    if cfg.max_connections_per_ip == 0 {
        anyhow::bail!("ATOM_PKI_ENROLLMENT_MAX_CONNECTIONS_PER_IP must be greater than zero");
    }
    if cfg.ipv6_prefix_len == 0 || cfg.ipv6_prefix_len > 128 {
        anyhow::bail!("ATOM_PKI_ENROLLMENT_IPV6_PREFIX_LEN must be between 1 and 128");
    }
    if cfg.trust_bundle_refresh_secs == 0 {
        anyhow::bail!("ATOM_PKI_ENROLLMENT_TRUST_REFRESH_SECS must be greater than zero");
    }
    if cfg.tls_handshake_timeout_secs == 0 {
        anyhow::bail!("ATOM_PKI_ENROLLMENT_TLS_HANDSHAKE_TIMEOUT_SECS must be greater than zero");
    }
    if cfg.http_header_timeout_secs == 0 {
        anyhow::bail!("ATOM_PKI_ENROLLMENT_HTTP_HEADER_TIMEOUT_SECS must be greater than zero");
    }
    if cfg.request_timeout_secs == 0 {
        anyhow::bail!("ATOM_PKI_ENROLLMENT_REQUEST_TIMEOUT_SECS must be greater than zero");
    }
    if cfg.connection_timeout_secs == 0 {
        anyhow::bail!("ATOM_PKI_ENROLLMENT_CONNECTION_TIMEOUT_SECS must be greater than zero");
    }
    if cfg.shutdown_drain_timeout_secs == 0 {
        anyhow::bail!("ATOM_PKI_ENROLLMENT_SHUTDOWN_DRAIN_TIMEOUT_SECS must be greater than zero");
    }
    Ok(cfg)
}

fn pki_lifecycle_from_env() -> Result<PkiLifecycleConfig> {
    let default = PkiLifecycleConfig::default();
    let cfg = PkiLifecycleConfig {
        enabled: env_bool_default("ATOM_PKI_LIFECYCLE_ENABLED", default.enabled)?,
        interval_secs: env_parse("ATOM_PKI_LIFECYCLE_INTERVAL_SECS", default.interval_secs)?,
        batch_size: env_parse("ATOM_PKI_LIFECYCLE_BATCH_SIZE", default.batch_size)?,
        expiry_warning_secs: env_parse(
            "ATOM_PKI_EXPIRY_WARNING_SECS",
            default.expiry_warning_secs,
        )?,
        authority_warning_secs: env_parse(
            "ATOM_PKI_AUTHORITY_WARNING_SECS",
            default.authority_warning_secs,
        )?,
    };
    if cfg.interval_secs == 0 {
        anyhow::bail!("ATOM_PKI_LIFECYCLE_INTERVAL_SECS must be greater than zero");
    }
    if !(1..=1_000).contains(&cfg.batch_size) {
        anyhow::bail!("ATOM_PKI_LIFECYCLE_BATCH_SIZE must be between 1 and 1000");
    }
    if cfg.expiry_warning_secs == 0 {
        anyhow::bail!("ATOM_PKI_EXPIRY_WARNING_SECS must be greater than zero");
    }
    if cfg.authority_warning_secs == 0 {
        anyhow::bail!("ATOM_PKI_AUTHORITY_WARNING_SECS must be greater than zero");
    }
    Ok(cfg)
}

fn nonempty_env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
}

fn parse_cors_allowed_origins(public_base_url: &str) -> Vec<String> {
    std::env::var("ATOM_CORS_ALLOWED_ORIGINS")
        .ok()
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|origin| !origin.is_empty())
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>()
        })
        .filter(|origins| !origins.is_empty())
        .unwrap_or_else(|| vec![public_base_url.trim_end_matches('/').to_string()])
}

fn parse_oidc_providers() -> Result<Vec<OidcProviderConfig>> {
    match std::env::var("ATOM_OIDC_PROVIDERS") {
        Ok(value) if !value.trim().is_empty() => {
            serde_json::from_str(&value).context("ATOM_OIDC_PROVIDERS must be valid JSON")
        }
        _ => Ok(Vec::new()),
    }
}

fn smtp_from_env() -> Option<SmtpConfig> {
    let host = std::env::var("ATOM_SMTP_HOST").ok()?;
    let from = std::env::var("ATOM_SMTP_FROM").ok()?;
    let tls = match std::env::var("ATOM_SMTP_TLS")
        .unwrap_or_else(|_| "starttls".into())
        .to_ascii_lowercase()
        .as_str()
    {
        "none" => SmtpTls::None,
        "tls" => SmtpTls::Tls,
        "starttls" => SmtpTls::StartTls,
        _ => SmtpTls::StartTls,
    };
    Some(SmtpConfig {
        host,
        port: std::env::var("ATOM_SMTP_PORT")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(match tls {
                SmtpTls::None => 25,
                SmtpTls::StartTls => 587,
                SmtpTls::Tls => 465,
            }),
        username: std::env::var("ATOM_SMTP_USERNAME").ok(),
        password: std::env::var("ATOM_SMTP_PASSWORD").ok(),
        from,
        tls,
    })
}

fn default_oidc_scopes() -> Vec<String> {
    vec!["openid".into(), "email".into(), "profile".into()]
}

fn public_url(public_base_url: &str, path: &str) -> String {
    format!(
        "{}{}",
        public_base_url.trim_end_matches('/'),
        path.strip_prefix('/')
            .map(|p| format!("/{p}"))
            .unwrap_or_else(|| path.to_string())
    )
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::{
        parse_env_bool, public_url, CacheMode, Config, LogFormat, PkiCaProvisioningBackend,
        ADMIN_ENTITY_ID, SERVICE_ENTITY_ID,
    };

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn public_url_joins_base_and_ui_paths() {
        assert_eq!(
            public_url("http://localhost:8080/", "/auth/callback"),
            "http://localhost:8080/auth/callback"
        );
        assert_eq!(
            public_url("https://atom.example", "/invitations/accept"),
            "https://atom.example/invitations/accept"
        );
    }

    #[test]
    fn deployment_booleans_require_explicit_values() {
        for value in ["1", "true", "yes", "on", " TRUE ", "YeS"] {
            assert!(parse_env_bool("ATOM_TEST_BOOLEAN", value).expect("true value"));
        }
        for value in ["0", "false", "no", "off", " FALSE ", "nO"] {
            assert!(!parse_env_bool("ATOM_TEST_BOOLEAN", value).expect("false value"));
        }
        for (name, value) in [
            ("ATOM_CALLOUTS_ENABLED", ""),
            ("ATOM_CACHE_ENABLED", "   "),
            ("ATOM_METRICS_ENABLED", "truthy"),
        ] {
            let error = parse_env_bool(name, value).expect_err("invalid boolean");
            assert!(error.to_string().contains(name));
        }
    }

    #[test]
    fn production_hardening_config_defaults_are_parsed() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        clear_hardening_env();
        let _db_guard = DatabaseUrlGuard::set();
        let _rust_log_guard = EnvVarGuard::unset("RUST_LOG");

        let cfg = Config::from_env().expect("config");

        assert_eq!(cfg.logging.level, "info");
        assert_eq!(cfg.logging.format, LogFormat::Text);
        assert_eq!(cfg.db_pool.max_connections, 20);
        assert_eq!(cfg.db_pool.acquire_timeout_secs, 30);
        assert_eq!(cfg.http_server.max_connections, 1_024);
        assert_eq!(cfg.http_server.max_connections_per_ip, 1_024);
        assert_eq!(cfg.http_server.http_header_timeout_secs, 10);
        assert_eq!(cfg.http_server.request_timeout_secs, 30);
        assert_eq!(cfg.http_server.connection_timeout_secs, 300);
        assert_eq!(cfg.http_server.shutdown_drain_timeout_secs, 30);
        assert!(!cfg.signing_keys.allow_plaintext_signing_keys);
        assert!(cfg.signing_keys.key_encryption_key.is_none());
        assert!(cfg.pki_ca_keys.key_encryption_key.is_none());
        assert_eq!(
            cfg.pki_ca_keys.provisioning_backend,
            PkiCaProvisioningBackend::EncryptedDatabase
        );
        assert!(cfg.pki_ca_keys.pkcs11.is_none());
        assert!(
            cfg.pki_ca_keys.artifact_base_url.is_none(),
            "certificate discovery URLs must not inherit the localhost UI default"
        );
        assert!(!cfg.audit_policy.hot_path_allow_db_enabled);
        assert_eq!(cfg.audit_retention.days, 365);
        assert_eq!(cfg.login_failure_limit, 5);
        assert_eq!(cfg.login_failure_window_secs, 900);
        assert!(
            !cfg.pki_generated_key_issuance_enabled,
            "managed generated-key issuance must default off"
        );
        assert!(cfg.rate_limits.enabled);
        assert_eq!(cfg.jwt_expiry_secs, 3_600);
        assert_eq!(cfg.admin_entity_id, ADMIN_ENTITY_ID);
        assert_eq!(cfg.service_entity_id, SERVICE_ENTITY_ID);
        assert_eq!(cfg.email_verification_expiry_secs, 86_400);
        assert_eq!(cfg.invitation_expiry_secs, 604_800);
        assert_eq!(cfg.oauth_state_expiry_secs, 600);
        assert_eq!(cfg.auth_exchange_code_expiry_secs, 300);
        assert!(
            !cfg.graphql_limits.introspection_enabled,
            "GraphQL introspection must default off"
        );

        clear_hardening_env();
    }

    #[test]
    fn identity_overrides_and_auth_lifetimes_are_strictly_parsed() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        clear_hardening_env();
        let _db_guard = DatabaseUrlGuard::set();

        let _admin_guard =
            EnvVarGuard::set("ADMIN_ENTITY_ID", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
        let _service_guard = EnvVarGuard::set(
            "ATOM_SERVICE_ENTITY_ID",
            "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        );
        let _jwt_guard = EnvVarGuard::set("JWT_EXPIRY_SECS", "7200");
        let _verification_guard = EnvVarGuard::set("ATOM_EMAIL_VERIFICATION_EXPIRY_SECS", "120");
        let _invitation_guard = EnvVarGuard::set("ATOM_INVITATION_EXPIRY_SECS", "240");
        let _oauth_guard = EnvVarGuard::set("ATOM_OAUTH_STATE_EXPIRY_SECS", "360");
        let _exchange_guard = EnvVarGuard::set("ATOM_AUTH_EXCHANGE_CODE_EXPIRY_SECS", "480");

        let cfg = Config::from_env().expect("strict identity and lifetime config");
        assert_eq!(
            cfg.admin_entity_id,
            uuid::Uuid::parse_str("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").expect("admin UUID")
        );
        assert_eq!(
            cfg.service_entity_id,
            uuid::Uuid::parse_str("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb").expect("service UUID")
        );
        assert_eq!(cfg.jwt_expiry_secs, 7_200);
        assert_eq!(cfg.email_verification_expiry_secs, 120);
        assert_eq!(cfg.invitation_expiry_secs, 240);
        assert_eq!(cfg.oauth_state_expiry_secs, 360);
        assert_eq!(cfg.auth_exchange_code_expiry_secs, 480);

        clear_hardening_env();
    }

    #[test]
    fn invalid_identity_overrides_and_auth_lifetimes_fail_config() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        clear_hardening_env();
        let _db_guard = DatabaseUrlGuard::set();

        for (name, value) in [
            ("ADMIN_ENTITY_ID", "not-a-uuid"),
            ("ATOM_SERVICE_ENTITY_ID", ""),
            ("JWT_EXPIRY_SECS", "not-a-number"),
            ("JWT_EXPIRY_SECS", "0"),
            ("JWT_EXPIRY_SECS", "18446744073709551615"),
            ("ATOM_EMAIL_VERIFICATION_EXPIRY_SECS", "0"),
            ("ATOM_INVITATION_EXPIRY_SECS", "0"),
            ("ATOM_OAUTH_STATE_EXPIRY_SECS", "0"),
            ("ATOM_AUTH_EXCHANGE_CODE_EXPIRY_SECS", "0"),
        ] {
            let value_guard = EnvVarGuard::set(name, value);
            let error = Config::from_env().expect_err("invalid deployment config");
            assert!(
                error.to_string().contains(name),
                "error for {name} did not identify the variable: {error}"
            );
            drop(value_guard);
        }

        clear_hardening_env();
    }

    #[test]
    fn primary_http_transport_limits_are_configurable_and_bounded() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        clear_hardening_env();
        let _db_guard = DatabaseUrlGuard::set();

        std::env::set_var("ATOM_HTTP_MAX_CONNECTIONS", "200");
        std::env::set_var("ATOM_HTTP_MAX_CONNECTIONS_PER_IP", "20");
        std::env::set_var("ATOM_HTTP_HEADER_TIMEOUT_SECS", "11");
        std::env::set_var("ATOM_HTTP_REQUEST_TIMEOUT_SECS", "31");
        std::env::set_var("ATOM_HTTP_CONNECTION_TIMEOUT_SECS", "301");
        std::env::set_var("ATOM_HTTP_SHUTDOWN_DRAIN_TIMEOUT_SECS", "32");
        let cfg = Config::from_env().expect("custom HTTP server config");
        assert_eq!(cfg.http_server.max_connections, 200);
        assert_eq!(cfg.http_server.max_connections_per_ip, 20);
        assert_eq!(cfg.http_server.http_header_timeout_secs, 11);
        assert_eq!(cfg.http_server.request_timeout_secs, 31);
        assert_eq!(cfg.http_server.connection_timeout_secs, 301);
        assert_eq!(cfg.http_server.shutdown_drain_timeout_secs, 32);

        std::env::set_var("ATOM_HTTP_MAX_CONNECTIONS_PER_IP", "201");
        let error = Config::from_env().expect_err("per-IP cap above global cap");
        assert!(error.to_string().contains("cannot exceed"));

        clear_hardening_env();
    }

    #[test]
    fn logging_config_reads_atom_env_and_keeps_rust_log_fallback() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        clear_hardening_env();
        let _db_guard = DatabaseUrlGuard::set();
        let _rust_log_guard = EnvVarGuard::set("RUST_LOG", "warn");

        let cfg = Config::from_env().expect("config");
        assert_eq!(cfg.logging.level, "warn");
        assert_eq!(cfg.logging.format, LogFormat::Text);

        std::env::set_var("ATOM_LOG_LEVEL", " ");
        std::env::set_var("ATOM_LOG_FORMAT", " ");

        let cfg = Config::from_env().expect("config");
        assert_eq!(cfg.logging.level, "warn");
        assert_eq!(cfg.logging.format, LogFormat::Text);

        std::env::set_var("ATOM_LOG_LEVEL", "debug");
        std::env::set_var("ATOM_LOG_FORMAT", "json");

        let cfg = Config::from_env().expect("config");
        assert_eq!(cfg.logging.level, "debug");
        assert_eq!(cfg.logging.format, LogFormat::Json);

        clear_hardening_env();
    }

    #[test]
    fn invalid_logging_format_fails_config() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        clear_hardening_env();
        let _db_guard = DatabaseUrlGuard::set();
        std::env::set_var("ATOM_LOG_FORMAT", "xml");

        let err = Config::from_env().expect_err("invalid log format");
        assert!(err.to_string().contains("ATOM_LOG_FORMAT"));

        clear_hardening_env();
    }

    #[test]
    fn blank_grpc_tls_env_is_treated_as_unset() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        clear_hardening_env();
        let _db_guard = DatabaseUrlGuard::set();
        std::env::set_var("ATOM_GRPC_TLS_CERT_PATH", "");
        std::env::set_var("ATOM_GRPC_TLS_KEY_PATH", " ");
        std::env::set_var("ATOM_GRPC_TLS_CLIENT_CA_PATH", "");

        let cfg = Config::from_env().expect("config");
        assert!(cfg.grpc_tls.is_none());

        clear_hardening_env();
    }

    #[test]
    fn broker_auth_requires_grpc_mutual_tls() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        clear_hardening_env();
        let _db_guard = DatabaseUrlGuard::set();
        std::env::set_var("ATOM_BROKER_AUTH_ENABLED", "true");

        let plaintext = Config::from_env().expect_err("plaintext broker auth");
        assert!(plaintext.to_string().contains("requires gRPC mTLS"));

        std::env::set_var("ATOM_GRPC_TLS_CERT_PATH", "/tls/server.crt");
        std::env::set_var("ATOM_GRPC_TLS_KEY_PATH", "/tls/server.key");
        let server_tls_only = Config::from_env().expect_err("server-only broker TLS");
        assert!(server_tls_only.to_string().contains("requires gRPC mTLS"));

        std::env::set_var("ATOM_GRPC_TLS_CLIENT_CA_PATH", "/tls/client-ca.crt");
        let cfg = Config::from_env().expect("mTLS broker config");
        assert!(cfg.broker_auth.enabled);

        clear_hardening_env();
    }

    #[test]
    fn blank_email_templates_dir_env_is_treated_as_unset() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        clear_hardening_env();
        let _db_guard = DatabaseUrlGuard::set();
        std::env::set_var("ATOM_EMAIL_TEMPLATES_DIR", "  ");

        let cfg = Config::from_env().expect("config");
        assert!(cfg.email_templates_dir.is_none());

        clear_hardening_env();
    }

    #[test]
    fn email_templates_dir_env_is_read() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        clear_hardening_env();
        let _db_guard = DatabaseUrlGuard::set();
        std::env::set_var("ATOM_EMAIL_TEMPLATES_DIR", "/email-templates");

        let cfg = Config::from_env().expect("config");
        assert_eq!(cfg.email_templates_dir.as_deref(), Some("/email-templates"));

        clear_hardening_env();
    }

    #[test]
    fn graphql_introspection_opts_in_via_env() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        clear_hardening_env();
        let _db_guard = DatabaseUrlGuard::set();
        std::env::set_var("ATOM_GRAPHQL_INTROSPECTION_ENABLED", "true");

        let cfg = Config::from_env().expect("config");
        assert!(cfg.graphql_limits.introspection_enabled);

        clear_hardening_env();
    }

    #[test]
    fn managed_generated_key_issuance_requires_explicit_opt_in() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        clear_hardening_env();
        let _db_guard = DatabaseUrlGuard::set();

        let cfg = Config::from_env().expect("config");
        assert!(!cfg.pki_generated_key_issuance_enabled);

        std::env::set_var("ATOM_PKI_GENERATED_KEY_ISSUANCE_ENABLED", "true");
        let cfg = Config::from_env().expect("config");
        assert!(cfg.pki_generated_key_issuance_enabled);

        clear_hardening_env();
    }

    #[test]
    fn cache_is_disabled_by_default() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        clear_hardening_env();
        let _db_guard = DatabaseUrlGuard::set();

        let cfg = Config::from_env().expect("config");
        assert_eq!(cfg.cache.mode, CacheMode::Disabled);
        assert!(!cfg.cache.fail_fast_on_startup);

        clear_hardening_env();
    }

    #[test]
    fn certificate_artifact_base_url_requires_explicit_public_url() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        clear_hardening_env();
        let _db_guard = DatabaseUrlGuard::set();

        let cfg = Config::from_env().expect("default config");
        assert!(cfg.pki_ca_keys.artifact_base_url.is_none());

        std::env::set_var("ATOM_PUBLIC_BASE_URL", "https://pki.example.test/");
        let cfg = Config::from_env().expect("explicit public URL");
        assert_eq!(
            cfg.pki_ca_keys.artifact_base_url.as_deref(),
            Some("https://pki.example.test")
        );

        clear_hardening_env();
    }

    #[test]
    fn cache_enabled_without_redis_url_fails_config() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        clear_hardening_env();
        let _db_guard = DatabaseUrlGuard::set();
        std::env::set_var("ATOM_CACHE_ENABLED", "true");

        let err = Config::from_env().expect_err("cache enabled without a redis url");
        assert!(err.to_string().contains("ATOM_CACHE_REDIS_URL"));

        clear_hardening_env();
    }

    #[test]
    fn cache_mode_requires_a_deployment_namespace() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        clear_hardening_env();
        let _db_guard = DatabaseUrlGuard::set();
        std::env::set_var("ATOM_CACHE_MODE", "prepare");
        std::env::set_var("ATOM_CACHE_REDIS_URL", "redis://localhost:6379/0");

        let err = Config::from_env().expect_err("cache namespace");
        assert!(err.to_string().contains("ATOM_CACHE_NAMESPACE"));

        std::env::set_var("ATOM_CACHE_NAMESPACE", "deployment-a");
        std::env::set_var("ATOM_CACHE_INITIALIZE_NAMESPACE", "true");
        let cfg = Config::from_env().expect("prepare cache config");
        assert_eq!(cfg.cache.mode, CacheMode::Prepare);
        assert!(cfg.cache.initialize_namespace);

        clear_hardening_env();
    }

    #[test]
    fn deprecated_cache_enabled_alias_is_compatible_but_conflicts_fail() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        clear_hardening_env();
        let _db_guard = DatabaseUrlGuard::set();
        std::env::set_var("ATOM_CACHE_ENABLED", "true");
        std::env::set_var("ATOM_CACHE_REDIS_URL", "redis://localhost:6379/0");
        std::env::set_var("ATOM_CACHE_NAMESPACE", "deployment-a");
        assert_eq!(
            Config::from_env().expect("legacy enabled").cache.mode,
            CacheMode::Enabled
        );

        std::env::set_var("ATOM_CACHE_MODE", "prepare");
        let err = Config::from_env().expect_err("conflicting cache settings");
        assert!(err.to_string().contains("conflicts"));

        std::env::set_var("ATOM_CACHE_MODE", "enabled");
        std::env::set_var("ATOM_CACHE_ENABLED", "");
        let err = Config::from_env().expect_err("blank legacy alias");
        assert!(err.to_string().contains("ATOM_CACHE_ENABLED"));

        std::env::remove_var("ATOM_CACHE_MODE");
        std::env::set_var("ATOM_CACHE_ENABLED", " OFF ");
        assert_eq!(
            Config::from_env()
                .expect("explicit false legacy alias")
                .cache
                .mode,
            CacheMode::Disabled
        );

        clear_hardening_env();
    }

    #[test]
    fn cache_enabled_with_zero_ttl_fails_config() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        clear_hardening_env();
        let _db_guard = DatabaseUrlGuard::set();
        std::env::set_var("ATOM_CACHE_ENABLED", "true");
        std::env::set_var("ATOM_CACHE_REDIS_URL", "redis://localhost:6379/0");
        std::env::set_var("ATOM_CACHE_NAMESPACE", "config-test");
        std::env::set_var("ATOM_CACHE_TTL_GRANTS_SECS", "0");

        let err = Config::from_env().expect_err("zero grants ttl");
        assert!(err.to_string().contains("ATOM_CACHE_TTL"));

        clear_hardening_env();
    }

    #[test]
    fn cache_enabled_with_zero_pool_size_fails_config() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        clear_hardening_env();
        let _db_guard = DatabaseUrlGuard::set();
        std::env::set_var("ATOM_CACHE_ENABLED", "true");
        std::env::set_var("ATOM_CACHE_REDIS_URL", "redis://localhost:6379/0");
        std::env::set_var("ATOM_CACHE_NAMESPACE", "config-test");
        std::env::set_var("ATOM_CACHE_POOL_MAX_SIZE", "0");

        let err = Config::from_env().expect_err("zero pool size");
        assert!(err.to_string().contains("ATOM_CACHE_POOL_MAX_SIZE"));

        clear_hardening_env();
    }

    #[test]
    fn cache_disabled_ignores_missing_redis_url() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        clear_hardening_env();
        let _db_guard = DatabaseUrlGuard::set();
        // ATOM_CACHE_ENABLED left unset (false) — an absent/invalid redis url
        // must not fail config parsing when caching is off.
        let cfg = Config::from_env().expect("config");
        assert_eq!(cfg.cache.mode, CacheMode::Disabled);
        assert!(cfg.cache.redis_url.is_empty());

        clear_hardening_env();
    }

    #[test]
    fn hot_path_allow_db_audit_opts_in_via_env() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        clear_hardening_env();
        let _db_guard = DatabaseUrlGuard::set();
        std::env::set_var("ATOM_AUDIT_HOT_PATH_ALLOW_DB_ENABLED", "true");

        let cfg = Config::from_env().expect("config");
        assert!(cfg.audit_policy.hot_path_allow_db_enabled);

        clear_hardening_env();
    }

    #[test]
    fn invalid_pool_env_value_fails_config() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        clear_hardening_env();
        let _db_guard = DatabaseUrlGuard::set();
        std::env::set_var("ATOM_DB_MAX_CONNECTIONS", "not-a-number");

        let err = Config::from_env().expect_err("invalid config");
        assert!(err.to_string().contains("ATOM_DB_MAX_CONNECTIONS"));

        clear_hardening_env();
    }

    #[test]
    fn key_encryption_key_must_be_base64_32_bytes() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        clear_hardening_env();
        let _db_guard = DatabaseUrlGuard::set();
        std::env::set_var("ATOM_KEY_ENCRYPTION_KEY", "too-short");

        let err = Config::from_env().expect_err("invalid key");
        assert!(err.to_string().contains("ATOM_KEY_ENCRYPTION_KEY"));

        clear_hardening_env();
    }

    #[test]
    fn pki_ca_key_is_separate_and_must_be_base64_32_bytes() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        clear_hardening_env();
        let _db_guard = DatabaseUrlGuard::set();
        std::env::set_var(
            "ATOM_KEY_ENCRYPTION_KEY",
            "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
        );

        let cfg = Config::from_env().expect("config");
        assert!(cfg.signing_keys.key_encryption_key.is_some());
        assert!(cfg.pki_ca_keys.key_encryption_key.is_none());

        std::env::set_var("ATOM_PKI_CA_KEY_ENCRYPTION_KEY", "too-short");
        let err = Config::from_env().expect_err("invalid CA key");
        assert!(err.to_string().contains("ATOM_PKI_CA_KEY_ENCRYPTION_KEY"));

        std::env::set_var(
            "ATOM_PKI_CA_KEY_ENCRYPTION_KEY",
            "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
        );
        let err = Config::from_env().expect_err("reused signing and CA KEK");
        assert!(err
            .to_string()
            .contains("must not reuse ATOM_KEY_ENCRYPTION_KEY"));

        std::env::set_var(
            "ATOM_PKI_CA_KEY_ENCRYPTION_KEY",
            "ZmVkY2JhOTg3NjU0MzIxMGZlZGNiYTk4NzY1NDMyMTA=",
        );
        std::env::set_var("ATOM_PKI_CA_KEY_ENCRYPTION_KEY_ID", " ");
        let err = Config::from_env().expect_err("blank CA key id");
        assert!(err
            .to_string()
            .contains("ATOM_PKI_CA_KEY_ENCRYPTION_KEY_ID"));

        std::env::set_var("ATOM_PKI_CA_KEY_ENCRYPTION_KEY_ID", "local-ca:v1");
        let cfg = Config::from_env().expect("distinct CA KEK");
        assert_ne!(
            cfg.signing_keys
                .key_encryption_key
                .as_ref()
                .expect("signing KEK")
                .expose(),
            cfg.pki_ca_keys
                .key_encryption_key
                .as_ref()
                .expect("CA KEK")
                .expose(),
        );

        clear_hardening_env();
    }

    #[test]
    fn pkcs11_configuration_is_operator_only_and_fail_closed() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        clear_hardening_env();
        let _db_guard = DatabaseUrlGuard::set();
        std::env::set_var("ATOM_PKI_CA_KEY_BACKEND", "pkcs11");

        let err = Config::from_env().expect_err("missing PKCS#11 configuration");
        assert!(err.to_string().contains("ATOM_PKI_PKCS11_MODULE_PATH"));

        std::env::set_var("ATOM_PKI_PKCS11_MODULE_PATH", "/opt/hsm/libpkcs11.so");
        std::env::set_var("ATOM_PKI_PKCS11_TOKEN_LABEL", "atom-production-ca");
        std::env::set_var("ATOM_PKI_PKCS11_USER_PIN", "provider-pin");
        let cfg = Config::from_env().expect("PKCS#11 config");
        assert_eq!(
            cfg.pki_ca_keys.provisioning_backend,
            PkiCaProvisioningBackend::Pkcs11
        );
        let pkcs11 = cfg.pki_ca_keys.pkcs11.expect("PKCS#11 provider");
        assert_eq!(pkcs11.token_label, "atom-production-ca");
        assert!(!format!("{pkcs11:?}").contains("provider-pin"));

        std::env::set_var("ATOM_PKI_PKCS11_OPERATION_TIMEOUT_MS", "0");
        let err = Config::from_env().expect_err("zero timeout");
        assert!(err
            .to_string()
            .contains("ATOM_PKI_PKCS11_OPERATION_TIMEOUT_MS"));

        clear_hardening_env();
    }

    #[test]
    fn trusted_proxy_cidrs_must_be_valid() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        clear_hardening_env();
        let _db_guard = DatabaseUrlGuard::set();
        std::env::set_var("ATOM_TRUSTED_PROXY_CIDRS", "10.0.0.0/8,not-a-cidr");

        let err = Config::from_env().expect_err("invalid trusted proxy cidr");
        assert!(err.to_string().contains("ATOM_TRUSTED_PROXY_CIDRS"));

        clear_hardening_env();
    }

    #[test]
    fn enrollment_listener_is_opt_in_and_requires_in_process_tls() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        clear_hardening_env();
        let _db_guard = DatabaseUrlGuard::set();

        let cfg = Config::from_env().expect("default config");
        assert!(!cfg.enrollment.enabled);
        assert!(cfg.enrollment.tls.is_none());
        assert_eq!(cfg.enrollment.max_csr_bytes, 64 * 1024);
        assert_eq!(cfg.enrollment.max_connections_per_ip, 8);
        assert_eq!(cfg.enrollment.ipv6_prefix_len, 64);
        assert!(!cfg.enrollment.http_keep_alive);
        assert_eq!(cfg.enrollment.tls_handshake_timeout_secs, 10);
        assert_eq!(cfg.enrollment.http_header_timeout_secs, 10);
        assert_eq!(cfg.enrollment.request_timeout_secs, 30);
        assert_eq!(cfg.enrollment.connection_timeout_secs, 300);
        assert_eq!(cfg.enrollment.shutdown_drain_timeout_secs, 30);

        std::env::set_var("ATOM_PKI_ENROLLMENT_ENABLED", "true");
        let err = Config::from_env().expect_err("enabled listener without TLS");
        assert!(err.to_string().contains("requires enrollment TLS"));

        std::env::set_var("ATOM_PKI_ENROLLMENT_TLS_CERT_PATH", "/tls/server.pem");
        let err = Config::from_env().expect_err("partial TLS configuration");
        assert!(err.to_string().contains("requires both"));

        std::env::set_var("ATOM_PKI_ENROLLMENT_TLS_KEY_PATH", "/tls/server-key.pem");
        std::env::set_var("ATOM_PKI_ENROLLMENT_ENTITY_RATE_LIMIT", "7");
        std::env::set_var("ATOM_PKI_ENROLLMENT_TENANT_RATE_LIMIT", "70");
        std::env::set_var("ATOM_PKI_ENROLLMENT_MAX_CONNECTIONS_PER_IP", "3");
        std::env::set_var("ATOM_PKI_ENROLLMENT_IPV6_PREFIX_LEN", "56");
        std::env::set_var("ATOM_PKI_ENROLLMENT_HTTP_KEEP_ALIVE", "true");
        std::env::set_var("ATOM_PKI_ENROLLMENT_TLS_HANDSHAKE_TIMEOUT_SECS", "11");
        std::env::set_var("ATOM_PKI_ENROLLMENT_HTTP_HEADER_TIMEOUT_SECS", "12");
        std::env::set_var("ATOM_PKI_ENROLLMENT_REQUEST_TIMEOUT_SECS", "32");
        std::env::set_var("ATOM_PKI_ENROLLMENT_CONNECTION_TIMEOUT_SECS", "301");
        std::env::set_var("ATOM_PKI_ENROLLMENT_SHUTDOWN_DRAIN_TIMEOUT_SECS", "31");
        let cfg = Config::from_env().expect("enrollment config");
        assert!(cfg.enrollment.enabled);
        assert_eq!(cfg.enrollment.entity_rate_limit.max_requests, 7);
        assert_eq!(cfg.enrollment.tenant_rate_limit.max_requests, 70);
        assert_eq!(cfg.enrollment.max_connections_per_ip, 3);
        assert_eq!(cfg.enrollment.ipv6_prefix_len, 56);
        assert!(cfg.enrollment.http_keep_alive);
        assert_eq!(cfg.enrollment.tls_handshake_timeout_secs, 11);
        assert_eq!(cfg.enrollment.http_header_timeout_secs, 12);
        assert_eq!(cfg.enrollment.request_timeout_secs, 32);
        assert_eq!(cfg.enrollment.connection_timeout_secs, 301);
        assert_eq!(cfg.enrollment.shutdown_drain_timeout_secs, 31);
        assert_eq!(
            cfg.enrollment
                .tls
                .as_ref()
                .map(|tls| tls.cert_path.as_str()),
            Some("/tls/server.pem")
        );

        clear_hardening_env();
    }

    #[test]
    fn renamed_enrollment_request_timeout_is_rejected() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        clear_hardening_env();
        let _db_guard = DatabaseUrlGuard::set();

        std::env::set_var("ATOM_PKI_ENROLLMENT_REQUEST_BODY_TIMEOUT_SECS", "32");
        let error = Config::from_env().expect_err("renamed timeout must fail fast");
        assert!(error
            .to_string()
            .contains("was renamed to ATOM_PKI_ENROLLMENT_REQUEST_TIMEOUT_SECS"));

        clear_hardening_env();
    }

    #[test]
    fn enrollment_ip_rate_limit_has_its_own_policy() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        clear_hardening_env();
        let _db_guard = DatabaseUrlGuard::set();

        let cfg = Config::from_env().expect("default config");
        assert_eq!(cfg.rate_limits.enrollment.max_requests, 1_000);
        assert_eq!(cfg.rate_limits.enrollment.window_secs, 60);
        assert_eq!(cfg.rate_limits.ipv6_prefix_len, 64);

        std::env::set_var("ATOM_HTTP_RATE_LIMIT_ENROLLMENT", "321");
        std::env::set_var("ATOM_HTTP_RATE_LIMIT_ENROLLMENT_WINDOW_SECS", "45");
        std::env::set_var("ATOM_HTTP_RATE_LIMIT_IPV6_PREFIX_LEN", "56");
        let cfg = Config::from_env().expect("custom enrollment rate limit");
        assert_eq!(cfg.rate_limits.enrollment.max_requests, 321);
        assert_eq!(cfg.rate_limits.enrollment.window_secs, 45);
        assert_eq!(cfg.rate_limits.ipv6_prefix_len, 56);

        clear_hardening_env();
    }

    #[test]
    fn pki_lifecycle_automation_is_opt_in_and_bounded() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        clear_hardening_env();
        let _db_guard = DatabaseUrlGuard::set();

        let cfg = Config::from_env().expect("default config");
        assert!(!cfg.pki_lifecycle.enabled);
        assert_eq!(cfg.pki_lifecycle.authority_warning_secs, 30 * 86_400);

        std::env::set_var("ATOM_PKI_LIFECYCLE_ENABLED", "true");
        std::env::set_var("ATOM_PKI_LIFECYCLE_BATCH_SIZE", "75");
        std::env::set_var("ATOM_PKI_EXPIRY_WARNING_SECS", "3600");
        let cfg = Config::from_env().expect("lifecycle config");
        assert!(cfg.pki_lifecycle.enabled);
        assert_eq!(cfg.pki_lifecycle.batch_size, 75);
        assert_eq!(cfg.pki_lifecycle.expiry_warning_secs, 3600);

        std::env::set_var("ATOM_PKI_LIFECYCLE_BATCH_SIZE", "1001");
        let error = Config::from_env().expect_err("oversized lifecycle batch");
        assert!(error.to_string().contains("between 1 and 1000"));

        clear_hardening_env();
    }

    /// Sets `DATABASE_URL` to a fixture value for config-parsing tests and
    /// restores the prior value (or unsets it) on drop, so DB-gated tests that
    /// share the same test binary keep the real `DATABASE_URL`.
    struct DatabaseUrlGuard(Option<String>);

    impl DatabaseUrlGuard {
        fn set() -> Self {
            let prev = std::env::var("DATABASE_URL").ok();
            std::env::set_var("DATABASE_URL", "postgres://atom:atom@localhost/atom");
            Self(prev)
        }
    }

    impl Drop for DatabaseUrlGuard {
        fn drop(&mut self) {
            match self.0.take() {
                Some(value) => std::env::set_var("DATABASE_URL", value),
                None => std::env::remove_var("DATABASE_URL"),
            }
        }
    }

    struct EnvVarGuard {
        name: &'static str,
        prev: Option<String>,
    }

    impl EnvVarGuard {
        fn set(name: &'static str, value: &str) -> Self {
            let prev = std::env::var(name).ok();
            std::env::set_var(name, value);
            Self { name, prev }
        }

        fn unset(name: &'static str) -> Self {
            let prev = std::env::var(name).ok();
            std::env::remove_var(name);
            Self { name, prev }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            match self.prev.take() {
                Some(value) => std::env::set_var(self.name, value),
                None => std::env::remove_var(self.name),
            }
        }
    }

    fn clear_hardening_env() {
        for name in [
            "ADMIN_ENTITY_ID",
            "ATOM_SERVICE_ENTITY_ID",
            "JWT_EXPIRY_SECS",
            "ATOM_LOG_LEVEL",
            "ATOM_LOG_FORMAT",
            "ATOM_DB_MAX_CONNECTIONS",
            "ATOM_DB_MIN_CONNECTIONS",
            "ATOM_DB_ACQUIRE_TIMEOUT_SECS",
            "ATOM_DB_CONNECT_TIMEOUT_SECS",
            "ATOM_DB_IDLE_TIMEOUT_SECS",
            "ATOM_DB_MAX_LIFETIME_SECS",
            "ATOM_HTTP_MAX_CONNECTIONS",
            "ATOM_HTTP_MAX_CONNECTIONS_PER_IP",
            "ATOM_HTTP_HEADER_TIMEOUT_SECS",
            "ATOM_HTTP_REQUEST_TIMEOUT_SECS",
            "ATOM_HTTP_CONNECTION_TIMEOUT_SECS",
            "ATOM_HTTP_SHUTDOWN_DRAIN_TIMEOUT_SECS",
            "ATOM_KEY_ENCRYPTION_KEY",
            "ATOM_KEY_ENCRYPTION_KEY_ID",
            "ATOM_ALLOW_PLAINTEXT_SIGNING_KEYS",
            "ATOM_PKI_CA_KEY_ENCRYPTION_KEY",
            "ATOM_PKI_CA_KEY_ENCRYPTION_KEY_ID",
            "ATOM_PKI_CA_KEY_BACKEND",
            "ATOM_PKI_PKCS11_MODULE_PATH",
            "ATOM_PKI_PKCS11_TOKEN_LABEL",
            "ATOM_PKI_PKCS11_USER_PIN",
            "ATOM_PKI_PKCS11_OPERATION_TIMEOUT_MS",
            "ATOM_PKI_PKCS11_MAX_RETRIES",
            "ATOM_PKI_PKCS11_MAX_IN_FLIGHT",
            "ATOM_PKI_PKCS11_CIRCUIT_FAILURE_THRESHOLD",
            "ATOM_PKI_PKCS11_CIRCUIT_RESET_SECS",
            "ATOM_AUDIT_HOT_PATH_ALLOW_DB_ENABLED",
            "ATOM_AUDIT_RETENTION_DAYS",
            "ATOM_AUDIT_RETENTION_ENABLED",
            "ATOM_AUDIT_CLEANUP_INTERVAL_SECS",
            "ATOM_AUDIT_CLEANUP_BATCH_SIZE",
            "ATOM_METRICS_ENABLED",
            "ATOM_SELF_REGISTRATION_ENABLED",
            "ATOM_ALLOW_UNVERIFIED_EMAIL_LOGIN",
            "ATOM_AUTH_COOKIE_SECURE",
            "ATOM_EMAIL_VERIFICATION_EXPIRY_SECS",
            "ATOM_INVITATION_EXPIRY_SECS",
            "ATOM_OAUTH_STATE_EXPIRY_SECS",
            "ATOM_AUTH_EXCHANGE_CODE_EXPIRY_SECS",
            "ATOM_LOGIN_FAILURE_LIMIT",
            "ATOM_LOGIN_FAILURE_WINDOW_SECS",
            "ATOM_PKI_GENERATED_KEY_ISSUANCE_ENABLED",
            "ATOM_PUBLIC_BASE_URL",
            "ATOM_RATE_LIMIT_ENABLED",
            "ATOM_HTTP_RATE_LIMIT_ENROLLMENT",
            "ATOM_HTTP_RATE_LIMIT_ENROLLMENT_WINDOW_SECS",
            "ATOM_HTTP_RATE_LIMIT_IPV6_PREFIX_LEN",
            "ATOM_TRUSTED_PROXY_CIDRS",
            "ATOM_GRAPHQL_INTROSPECTION_ENABLED",
            "ATOM_GRPC_TLS_CERT_PATH",
            "ATOM_GRPC_TLS_KEY_PATH",
            "ATOM_GRPC_TLS_CLIENT_CA_PATH",
            "ATOM_BROKER_AUTH_ENABLED",
            "ATOM_BROKER_TOPIC_TEMPLATE",
            "ATOM_BROKER_TOPIC_REF",
            "ATOM_BROKER_CREDENTIAL_KIND",
            "ATOM_BROKER_TOPIC_ALLOW",
            "ATOM_PKI_ENROLLMENT_ENABLED",
            "ATOM_PKI_ENROLLMENT_LISTEN_ADDR",
            "ATOM_PKI_ENROLLMENT_TLS_CERT_PATH",
            "ATOM_PKI_ENROLLMENT_TLS_KEY_PATH",
            "ATOM_PKI_ENROLLMENT_ENTITY_RATE_LIMIT",
            "ATOM_PKI_ENROLLMENT_ENTITY_RATE_WINDOW_SECS",
            "ATOM_PKI_ENROLLMENT_TENANT_RATE_LIMIT",
            "ATOM_PKI_ENROLLMENT_TENANT_RATE_WINDOW_SECS",
            "ATOM_PKI_ENROLLMENT_MAX_CSR_BYTES",
            "ATOM_PKI_ENROLLMENT_MAX_CONNECTIONS",
            "ATOM_PKI_ENROLLMENT_MAX_CONNECTIONS_PER_IP",
            "ATOM_PKI_ENROLLMENT_IPV6_PREFIX_LEN",
            "ATOM_PKI_ENROLLMENT_HTTP_KEEP_ALIVE",
            "ATOM_PKI_ENROLLMENT_TRUST_REFRESH_SECS",
            "ATOM_PKI_ENROLLMENT_TLS_HANDSHAKE_TIMEOUT_SECS",
            "ATOM_PKI_ENROLLMENT_HTTP_HEADER_TIMEOUT_SECS",
            "ATOM_PKI_ENROLLMENT_REQUEST_BODY_TIMEOUT_SECS",
            "ATOM_PKI_ENROLLMENT_REQUEST_TIMEOUT_SECS",
            "ATOM_PKI_ENROLLMENT_CONNECTION_TIMEOUT_SECS",
            "ATOM_PKI_ENROLLMENT_SHUTDOWN_DRAIN_TIMEOUT_SECS",
            "ATOM_PKI_LIFECYCLE_ENABLED",
            "ATOM_PKI_LIFECYCLE_INTERVAL_SECS",
            "ATOM_PKI_LIFECYCLE_BATCH_SIZE",
            "ATOM_PKI_EXPIRY_WARNING_SECS",
            "ATOM_PKI_AUTHORITY_WARNING_SECS",
            "ATOM_EMAIL_TEMPLATES_DIR",
            "ATOM_CACHE_ENABLED",
            "ATOM_CACHE_MODE",
            "ATOM_CACHE_REDIS_URL",
            "ATOM_CACHE_NAMESPACE",
            "ATOM_CACHE_INITIALIZE_NAMESPACE",
            "ATOM_CACHE_POOL_MAX_SIZE",
            "ATOM_CACHE_CONNECT_TIMEOUT_MS",
            "ATOM_CACHE_OP_TIMEOUT_MS",
            "ATOM_CACHE_FAIL_FAST_ON_STARTUP",
            "ATOM_CACHE_TTL_SESSION_SECS",
            "ATOM_CACHE_TTL_ENTITY_STATUS_SECS",
            "ATOM_CACHE_TTL_TENANT_STATUS_SECS",
            "ATOM_CACHE_TTL_CREDENTIAL_SECS",
            "ATOM_CACHE_TTL_CREDENTIAL_CEILING_SECS",
            "ATOM_CACHE_TTL_GRANTS_SECS",
        ] {
            std::env::remove_var(name);
        }
    }
}
