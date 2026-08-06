//! Stored certificate profiles and subject-derived profile resolution.
//!
//! This module deliberately contains no certificate-library types.  It is the
//! policy boundary between stored profile data and the PKI encoder.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{FromRow, PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::error::{db_err, AppError};

const PROFILE_COLUMNS: &str = r#"
    id,
    tenant_id,
    base_profile_id,
    name,
    permitted_key_algorithms,
    default_ttl_seconds,
    maximum_ttl_seconds,
    renewal_threshold_seconds,
    key_usages,
    extended_key_usages,
    san_policy,
    identity_uri_template,
    basic_constraints
"#;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyAlgorithm {
    Ecdsa,
    Rsa,
    Ed25519,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyAlgorithmRule {
    pub algorithm: KeyAlgorithm,
    pub sizes: Vec<u16>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyUsage {
    DigitalSignature,
    ContentCommitment,
    KeyEncipherment,
    DataEncipherment,
    KeyAgreement,
}

impl KeyUsage {
    fn parse(value: &str) -> Result<Self, AppError> {
        match value {
            "digital_signature" => Ok(Self::DigitalSignature),
            "content_commitment" => Ok(Self::ContentCommitment),
            "key_encipherment" => Ok(Self::KeyEncipherment),
            "data_encipherment" => Ok(Self::DataEncipherment),
            "key_agreement" => Ok(Self::KeyAgreement),
            _ => Err(invalid_profile("unsupported key usage")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExtendedKeyUsage {
    ServerAuth,
    ClientAuth,
    CodeSigning,
    EmailProtection,
    TimeStamping,
    OcspSigning,
}

impl ExtendedKeyUsage {
    fn parse(value: &str) -> Result<Self, AppError> {
        match value {
            "server_auth" => Ok(Self::ServerAuth),
            "client_auth" => Ok(Self::ClientAuth),
            "code_signing" => Ok(Self::CodeSigning),
            "email_protection" => Ok(Self::EmailProtection),
            "time_stamping" => Ok(Self::TimeStamping),
            "ocsp_signing" => Ok(Self::OcspSigning),
            _ => Err(invalid_profile("unsupported extended key usage")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SanRuleMode {
    Deny,
    Allowlist,
    EntityTemplate,
    Identity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SanRule {
    pub mode: SanRuleMode,
    pub values: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SanPolicy {
    pub dns: SanRule,
    pub ip: SanRule,
    pub email: SanRule,
    pub uri: SanRule,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeafBasicConstraints {
    pub ca: bool,
    pub path_len: Option<u8>,
}

#[derive(Debug, Clone)]
pub struct CertificateProfile {
    pub(crate) id: Uuid,
    pub(crate) tenant_id: Option<Uuid>,
    pub(crate) base_profile_id: Option<Uuid>,
    pub(crate) name: String,
    pub(crate) permitted_key_algorithms: Vec<KeyAlgorithmRule>,
    pub(crate) default_ttl_seconds: u64,
    pub(crate) maximum_ttl_seconds: u64,
    pub(crate) renewal_threshold_seconds: u64,
    pub(crate) key_usages: Vec<KeyUsage>,
    pub(crate) extended_key_usages: Vec<ExtendedKeyUsage>,
    pub(crate) san_policy: SanPolicy,
    pub(crate) identity_uri_template: String,
    pub(crate) basic_constraints: LeafBasicConstraints,
}

impl CertificateProfile {
    pub fn id(&self) -> Uuid {
        self.id
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn default_ttl_seconds(&self) -> u64 {
        self.default_ttl_seconds
    }

    pub fn maximum_ttl_seconds(&self) -> u64 {
        self.maximum_ttl_seconds
    }

    pub fn renewal_threshold_seconds(&self) -> u64 {
        self.renewal_threshold_seconds
    }

    pub fn extended_key_usages(&self) -> &[ExtendedKeyUsage] {
        &self.extended_key_usages
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, FromRow)]
pub struct StoredSubject {
    entity_id: Uuid,
    tenant_id: Option<Uuid>,
}

impl StoredSubject {
    pub fn entity_id(&self) -> Uuid {
        self.entity_id
    }

    pub fn tenant_id(&self) -> Option<Uuid> {
        self.tenant_id
    }
}

#[derive(Debug, FromRow)]
struct ProfileRow {
    id: Uuid,
    tenant_id: Option<Uuid>,
    base_profile_id: Option<Uuid>,
    name: String,
    permitted_key_algorithms: Value,
    default_ttl_seconds: i64,
    maximum_ttl_seconds: i64,
    renewal_threshold_seconds: i64,
    key_usages: Vec<String>,
    extended_key_usages: Vec<String>,
    san_policy: Value,
    identity_uri_template: String,
    basic_constraints: Value,
}

pub async fn load_subject<'e, E>(executor: E, entity_id: Uuid) -> Result<StoredSubject, AppError>
where
    E: sqlx::Executor<'e, Database = Postgres>,
{
    sqlx::query_as::<_, StoredSubject>(
        r#"
        SELECT e.id AS entity_id, e.tenant_id
        FROM entities e
        LEFT JOIN tenants t ON t.id = e.tenant_id
        WHERE e.id = $1
          AND e.status = 'active'
          AND e.deleted_at IS NULL
          AND (e.tenant_id IS NULL OR (t.status = 'active' AND t.deleted_at IS NULL))
        "#,
    )
    .bind(entity_id)
    .fetch_one(executor)
    .await
    .map_err(db_err)
}

/// Resolve a tenant override when one exists, otherwise the platform profile.
/// The scope is taken only from [`StoredSubject`], which itself can only be
/// created by loading the entity row above.
pub async fn resolve_for_subject(
    pool: &PgPool,
    subject: &StoredSubject,
    name: &str,
) -> Result<CertificateProfile, AppError> {
    let query = format!(
        r#"
        SELECT {PROFILE_COLUMNS}
        FROM certificate_profiles
        WHERE name = $1
          AND (tenant_id IS NULL OR tenant_id = $2)
        ORDER BY (tenant_id IS NULL) ASC
        LIMIT 1
        "#
    );
    let row = sqlx::query_as::<_, ProfileRow>(&query)
        .bind(name)
        .bind(subject.tenant_id)
        .fetch_one(pool)
        .await
        .map_err(db_err)?;
    let profile = CertificateProfile::try_from(row)?;

    if let Some(base_profile_id) = profile.base_profile_id {
        let base = profile_by_id(pool, base_profile_id).await?;
        validate_override(&profile, &base)?;
    }
    Ok(profile)
}

/// Transaction-scoped profile resolution for issuance paths.  Both the
/// override and its platform ceiling are read through the caller's existing
/// connection, so a constrained pool cannot deadlock on a nested acquire.
pub async fn resolve_for_subject_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    subject: &StoredSubject,
    name: &str,
) -> Result<CertificateProfile, AppError> {
    let query = format!(
        r#"
        SELECT {PROFILE_COLUMNS}
        FROM certificate_profiles
        WHERE name = $1
          AND (tenant_id IS NULL OR tenant_id = $2)
        ORDER BY (tenant_id IS NULL) ASC
        LIMIT 1
        "#
    );
    let row = sqlx::query_as::<_, ProfileRow>(&query)
        .bind(name)
        .bind(subject.tenant_id)
        .fetch_one(&mut **tx)
        .await
        .map_err(db_err)?;
    let profile = CertificateProfile::try_from(row)?;
    if let Some(base_profile_id) = profile.base_profile_id {
        let base = profile_by_id(&mut **tx, base_profile_id).await?;
        validate_override(&profile, &base)?;
    }
    Ok(profile)
}

pub async fn profile_by_id<'e, E>(
    executor: E,
    profile_id: Uuid,
) -> Result<CertificateProfile, AppError>
where
    E: sqlx::Executor<'e, Database = Postgres>,
{
    let query = format!("SELECT {PROFILE_COLUMNS} FROM certificate_profiles WHERE id = $1");
    let row = sqlx::query_as::<_, ProfileRow>(&query)
        .bind(profile_id)
        .fetch_one(executor)
        .await
        .map_err(db_err)?;
    CertificateProfile::try_from(row)
}

impl TryFrom<ProfileRow> for CertificateProfile {
    type Error = AppError;

    fn try_from(row: ProfileRow) -> Result<Self, Self::Error> {
        let permitted_key_algorithms: Vec<KeyAlgorithmRule> =
            serde_json::from_value(row.permitted_key_algorithms)
                .map_err(|_| invalid_profile("invalid key algorithm policy"))?;
        validate_key_algorithms(&permitted_key_algorithms)?;

        let key_usages = row
            .key_usages
            .iter()
            .map(|usage| KeyUsage::parse(usage))
            .collect::<Result<Vec<_>, _>>()?;
        require_unique(&key_usages, "duplicate key usage")?;

        let extended_key_usages = row
            .extended_key_usages
            .iter()
            .map(|usage| ExtendedKeyUsage::parse(usage))
            .collect::<Result<Vec<_>, _>>()?;
        require_unique(&extended_key_usages, "duplicate extended key usage")?;

        let san_policy: SanPolicy = serde_json::from_value(row.san_policy)
            .map_err(|_| invalid_profile("invalid SAN policy"))?;
        validate_san_policy(&san_policy)?;
        let basic_constraints: LeafBasicConstraints = serde_json::from_value(row.basic_constraints)
            .map_err(|_| invalid_profile("invalid basic constraints"))?;
        if basic_constraints.ca || basic_constraints.path_len.is_some() {
            return Err(invalid_profile("leaf profile cannot be a CA"));
        }
        if row.identity_uri_template != "urn:atom:{scope}entity:{entity_id}" {
            return Err(invalid_profile("invalid identity URI template"));
        }

        let default_ttl_seconds = positive_u64(row.default_ttl_seconds, "default TTL")?;
        let maximum_ttl_seconds = positive_u64(row.maximum_ttl_seconds, "maximum TTL")?;
        let renewal_threshold_seconds =
            positive_u64(row.renewal_threshold_seconds, "renewal threshold")?;
        if default_ttl_seconds > maximum_ttl_seconds
            || renewal_threshold_seconds > maximum_ttl_seconds
        {
            return Err(invalid_profile("invalid profile time limits"));
        }

        Ok(Self {
            id: row.id,
            tenant_id: row.tenant_id,
            base_profile_id: row.base_profile_id,
            name: row.name,
            permitted_key_algorithms,
            default_ttl_seconds,
            maximum_ttl_seconds,
            renewal_threshold_seconds,
            key_usages,
            extended_key_usages,
            san_policy,
            identity_uri_template: row.identity_uri_template,
            basic_constraints,
        })
    }
}

fn validate_key_algorithms(rules: &[KeyAlgorithmRule]) -> Result<(), AppError> {
    if rules.is_empty() {
        return Err(invalid_profile("key algorithm policy cannot be empty"));
    }
    let mut algorithms = HashSet::new();
    for rule in rules {
        if !algorithms.insert(rule.algorithm) || rule.sizes.is_empty() {
            return Err(invalid_profile("invalid key algorithm policy"));
        }
        let mut sizes = HashSet::new();
        for size in &rule.sizes {
            if !sizes.insert(*size)
                || match rule.algorithm {
                    KeyAlgorithm::Ecdsa => !matches!(*size, 256 | 384),
                    KeyAlgorithm::Rsa => *size < 2048 || *size % 256 != 0,
                    KeyAlgorithm::Ed25519 => *size != 255,
                }
            {
                return Err(invalid_profile("invalid key size policy"));
            }
        }
    }
    Ok(())
}

fn validate_san_policy(policy: &SanPolicy) -> Result<(), AppError> {
    validate_rule(
        &policy.dns,
        &[
            SanRuleMode::Deny,
            SanRuleMode::Allowlist,
            SanRuleMode::EntityTemplate,
        ],
    )?;
    validate_rule(&policy.ip, &[SanRuleMode::Deny, SanRuleMode::Allowlist])?;
    validate_rule(&policy.email, &[SanRuleMode::Deny, SanRuleMode::Allowlist])?;
    validate_rule(&policy.uri, &[SanRuleMode::Identity])?;
    if !policy.uri.values.is_empty() {
        return Err(invalid_profile("identity URI rule cannot contain values"));
    }
    Ok(())
}

fn validate_rule(rule: &SanRule, allowed_modes: &[SanRuleMode]) -> Result<(), AppError> {
    if !allowed_modes.contains(&rule.mode) {
        return Err(invalid_profile("SAN rule mode is not valid for its type"));
    }
    if matches!(rule.mode, SanRuleMode::Deny | SanRuleMode::Identity) && !rule.values.is_empty() {
        return Err(invalid_profile("SAN rule values must be empty"));
    }
    if matches!(
        rule.mode,
        SanRuleMode::Allowlist | SanRuleMode::EntityTemplate
    ) && rule.values.is_empty()
    {
        return Err(invalid_profile("SAN rule values cannot be empty"));
    }
    if rule.values.iter().any(|value| value.trim().is_empty()) {
        return Err(invalid_profile("SAN rule value cannot be empty"));
    }
    if rule.mode == SanRuleMode::EntityTemplate
        && rule
            .values
            .iter()
            .any(|value| !value.contains("{entity_id}"))
    {
        return Err(invalid_profile("SAN template must bind the entity ID"));
    }
    let values = rule.values.iter().collect::<HashSet<_>>();
    if values.len() != rule.values.len() {
        return Err(invalid_profile("duplicate SAN rule value"));
    }
    Ok(())
}

fn validate_override(
    profile: &CertificateProfile,
    ceiling: &CertificateProfile,
) -> Result<(), AppError> {
    if ceiling.tenant_id.is_some()
        || profile.tenant_id.is_none()
        || profile.name != ceiling.name
        || profile.permitted_key_algorithms != ceiling.permitted_key_algorithms
        || profile.default_ttl_seconds > ceiling.default_ttl_seconds
        || profile.maximum_ttl_seconds > ceiling.maximum_ttl_seconds
        || profile.renewal_threshold_seconds > ceiling.renewal_threshold_seconds
        || !is_subset(&profile.key_usages, &ceiling.key_usages)
        || !is_subset(&profile.extended_key_usages, &ceiling.extended_key_usages)
        || profile.identity_uri_template != ceiling.identity_uri_template
        || profile.basic_constraints != ceiling.basic_constraints
        || !san_policy_is_subset(&profile.san_policy, &ceiling.san_policy)
    {
        return Err(invalid_profile("tenant profile exceeds platform ceiling"));
    }
    Ok(())
}

fn san_policy_is_subset(child: &SanPolicy, ceiling: &SanPolicy) -> bool {
    san_rule_is_subset(&child.dns, &ceiling.dns)
        && san_rule_is_subset(&child.ip, &ceiling.ip)
        && san_rule_is_subset(&child.email, &ceiling.email)
        && san_rule_is_subset(&child.uri, &ceiling.uri)
}

fn san_rule_is_subset(child: &SanRule, ceiling: &SanRule) -> bool {
    match ceiling.mode {
        SanRuleMode::Deny => child.mode == SanRuleMode::Deny,
        SanRuleMode::Identity => child.mode == SanRuleMode::Identity,
        SanRuleMode::Allowlist | SanRuleMode::EntityTemplate => {
            child.mode == SanRuleMode::Deny
                || (child.mode == ceiling.mode
                    && child
                        .values
                        .iter()
                        .all(|value| ceiling.values.contains(value)))
        }
    }
}

fn is_subset<T: Eq + std::hash::Hash>(child: &[T], ceiling: &[T]) -> bool {
    let ceiling = ceiling.iter().collect::<HashSet<_>>();
    child.iter().all(|value| ceiling.contains(value))
}

fn require_unique<T: Eq + std::hash::Hash>(values: &[T], message: &str) -> Result<(), AppError> {
    let unique = values.iter().collect::<HashSet<_>>();
    if unique.len() == values.len() {
        Ok(())
    } else {
        Err(invalid_profile(message))
    }
}

fn positive_u64(value: i64, label: &str) -> Result<u64, AppError> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| invalid_profile(format!("{label} must be positive")))
}

fn invalid_profile(message: impl Into<String>) -> AppError {
    AppError::Internal(anyhow::anyhow!(
        "invalid stored certificate profile: {}",
        message.into()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(mode: SanRuleMode, values: &[&str]) -> SanRule {
        SanRule {
            mode,
            values: values.iter().map(|value| value.to_string()).collect(),
        }
    }

    #[test]
    fn san_narrowing_is_fail_closed() {
        let ceiling = rule(SanRuleMode::Allowlist, &["a.example", "b.example"]);
        assert!(san_rule_is_subset(
            &rule(SanRuleMode::Allowlist, &["a.example"]),
            &ceiling
        ));
        assert!(san_rule_is_subset(&rule(SanRuleMode::Deny, &[]), &ceiling));
        assert!(!san_rule_is_subset(
            &rule(SanRuleMode::Allowlist, &["outside.example"]),
            &ceiling
        ));
        assert!(!san_rule_is_subset(
            &rule(SanRuleMode::EntityTemplate, &["{entity_id}.example"]),
            &ceiling
        ));
    }

    #[test]
    fn entity_template_must_bind_stored_entity() {
        assert!(validate_rule(
            &rule(SanRuleMode::EntityTemplate, &["{entity_id}.example"]),
            &[SanRuleMode::EntityTemplate]
        )
        .is_ok());
        assert!(validate_rule(
            &rule(SanRuleMode::EntityTemplate, &["static.example"]),
            &[SanRuleMode::EntityTemplate]
        )
        .is_err());
    }
}
