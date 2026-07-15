//! Declarative startup bootstrap from a YAML configuration file.
//!
//! Standing up a fresh Atom deployment previously meant either setting a handful
//! of `*_SECRET` env vars or driving the API by hand to create the initial
//! entities and their credentials. Neither is friendly for repeatable, reviewable
//! platform management.
//!
//! This module lets an operator describe the desired baseline in a single YAML
//! file (pointed to by `ATOM_BOOTSTRAP_FILE`). The file is loaded once at
//! startup, right after migrations, and applied **idempotently**: re-running it
//! against an already-provisioned database is a no-op. Existing entities and
//! credentials are never mutated or clobbered — bootstrap only fills in what is
//! missing, keyed on the stable UUIDs declared in the file.
//!
//! ## Example
//!
//! ```yaml
//! entities:
//!   - id: 00000000-0000-0000-0000-000000000001
//!     kind: human
//!     name: admin
//!     credentials:
//!       - kind: password
//!         secret: change-me-please
//!   - id: 11111111-1111-1111-1111-111111111111
//!     kind: service
//!     name: ingest-service
//!     credentials:
//!       - kind: shared_key
//!         key: super-secret-machine-key
//!         description: ingest pipeline
//! ```

use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

use crate::config::SigningKeyConfig;
use crate::identity;
use crate::models::alias::validate_alias_opt;
use crate::models::enums::{CredentialKind, EntityKind, EntityStatus};
use crate::models::token::CreateSharedKey;

/// Root of the bootstrap document.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct BootstrapConfig {
    #[serde(default)]
    pub entities: Vec<BootstrapEntity>,
}

/// A single entity to ensure exists, together with its credentials.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct BootstrapEntity {
    /// Stable UUID. Required so re-runs are deterministic and idempotent — it is
    /// the key we upsert on. Use the well-known seed UUIDs to attach credentials
    /// to the pre-seeded `admin`/`example-service` entities.
    pub id: Uuid,
    pub kind: EntityKind,
    pub name: String,
    /// Optional human-friendly slug (unique per tenant). Validated with the same
    /// rules as the API.
    #[serde(default)]
    pub alias: Option<String>,
    #[serde(default)]
    pub status: EntityStatus,
    /// Free-form JSON object. Defaults to `{}`.
    #[serde(default)]
    pub attributes: Option<Value>,
    #[serde(default)]
    pub credentials: Vec<BootstrapCredential>,
}

/// A credential to ensure exists for an entity. The secret material is declared
/// inline, exactly like the existing `ADMIN_SECRET` env var — protect the file
/// accordingly (mount it as a secret, keep it out of version control).
// `deny_unknown_fields` is intentionally omitted: serde does not support it on
// internally tagged enums (it would reject the `kind` discriminant itself).
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BootstrapCredential {
    /// A password credential. Validated against the configured strength policy.
    Password { secret: String },
    /// A retrievable machine shared key. Only valid for non-human entities. The
    /// key must be supplied explicitly so bootstrap stays deterministic (an
    /// auto-generated key would be lost, never surfaced to the operator).
    SharedKey {
        key: String,
        #[serde(default)]
        description: Option<String>,
    },
}

impl BootstrapConfig {
    /// Structural validation performed before touching the database, so a
    /// malformed file aborts startup with a clear message instead of a partial,
    /// half-applied bootstrap.
    pub fn validate(&self) -> Result<()> {
        let mut seen_ids = std::collections::HashSet::new();
        for entity in &self.entities {
            if !seen_ids.insert(entity.id) {
                bail!("duplicate bootstrap entity id {}", entity.id);
            }
            if entity.name.trim().is_empty() {
                bail!("bootstrap entity {} has an empty name", entity.id);
            }
            if let Some(attrs) = &entity.attributes {
                if !attrs.is_object() {
                    bail!(
                        "bootstrap entity {} attributes must be a JSON object",
                        entity.id
                    );
                }
            }

            let mut passwords = 0;
            let mut shared_keys = 0;
            for cred in &entity.credentials {
                match cred {
                    BootstrapCredential::Password { .. } => passwords += 1,
                    BootstrapCredential::SharedKey { .. } => {
                        shared_keys += 1;
                        if !CredentialKind::SharedKey.allowed_for(&entity.kind) {
                            bail!(
                                "bootstrap entity {} is a human; shared keys are only valid for machine entities",
                                entity.id
                            );
                        }
                    }
                }
            }
            if passwords > 1 {
                bail!(
                    "bootstrap entity {} declares more than one password credential",
                    entity.id
                );
            }
            if shared_keys > 1 {
                bail!(
                    "bootstrap entity {} declares more than one shared_key credential",
                    entity.id
                );
            }
        }
        Ok(())
    }
}

/// Read and parse a bootstrap file, validating its structure.
pub fn load(path: &Path) -> Result<BootstrapConfig> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read bootstrap file {}", path.display()))?;
    parse(&contents).with_context(|| format!("invalid bootstrap file {}", path.display()))
}

fn parse(contents: &str) -> Result<BootstrapConfig> {
    let cfg: BootstrapConfig = serde_yaml::from_str(contents).context("failed to parse YAML")?;
    cfg.validate()?;
    Ok(cfg)
}

/// Apply the bootstrap config against the database. Idempotent.
pub async fn apply(
    pool: &PgPool,
    signing_keys: &SigningKeyConfig,
    cfg: &BootstrapConfig,
) -> Result<()> {
    for entity in &cfg.entities {
        ensure_entity(pool, entity).await?;
        for cred in &entity.credentials {
            ensure_credential(pool, signing_keys, entity, cred).await?;
        }
    }
    Ok(())
}

/// Create the entity if its UUID is not already present. Existing rows are left
/// untouched, so a bootstrap re-run never overwrites runtime edits.
async fn ensure_entity(pool: &PgPool, entity: &BootstrapEntity) -> Result<()> {
    let alias = validate_alias_opt(entity.alias.clone())
        .map_err(|e| anyhow!("bootstrap entity {}: {e}", entity.id))?;
    let attributes = entity
        .attributes
        .clone()
        .unwrap_or_else(|| serde_json::json!({}));

    let result = sqlx::query(
        r#"INSERT INTO entities (id, kind, name, alias, status, attributes)
           VALUES ($1, $2, $3, $4, $5, $6)
           ON CONFLICT (id) DO NOTHING"#,
    )
    .bind(entity.id)
    .bind(&entity.kind)
    .bind(&entity.name)
    .bind(alias)
    .bind(&entity.status)
    .bind(attributes)
    .execute(pool)
    .await
    .with_context(|| format!("failed to insert bootstrap entity {}", entity.id))?;

    if result.rows_affected() == 0 {
        tracing::info!(entity_id = %entity.id, "bootstrap: entity already present, skipped");
    } else {
        tracing::info!(entity_id = %entity.id, kind = ?entity.kind, "bootstrap: entity created");
    }
    Ok(())
}

/// Create the credential only if the entity has no active credential of that
/// kind yet. Reuses the identity service so hashing, strength validation and
/// shared-key envelope encryption stay identical to the API path.
async fn ensure_credential(
    pool: &PgPool,
    signing_keys: &SigningKeyConfig,
    entity: &BootstrapEntity,
    cred: &BootstrapCredential,
) -> Result<()> {
    match cred {
        BootstrapCredential::Password { secret } => {
            if active_credential_exists(pool, entity.id, CredentialKind::Password).await? {
                tracing::info!(entity_id = %entity.id, "bootstrap: password already present, skipped");
                return Ok(());
            }
            identity::service::create_password(pool, entity.id, secret)
                .await
                .map_err(|e| anyhow!("bootstrap password for entity {}: {e}", entity.id))?;
            tracing::info!(entity_id = %entity.id, "bootstrap: password credential created");
        }
        BootstrapCredential::SharedKey { key, description } => {
            if active_credential_exists(pool, entity.id, CredentialKind::SharedKey).await? {
                tracing::info!(entity_id = %entity.id, "bootstrap: shared key already present, skipped");
                return Ok(());
            }
            identity::service::create_shared_key(
                pool,
                signing_keys,
                entity.id,
                CreateSharedKey {
                    expires_at: None,
                    description: description.clone(),
                    key: Some(key.clone()),
                },
            )
            .await
            .map_err(|e| anyhow!("bootstrap shared key for entity {}: {e}", entity.id))?;
            tracing::info!(entity_id = %entity.id, "bootstrap: shared key credential created");
        }
    }
    Ok(())
}

async fn active_credential_exists(
    pool: &PgPool,
    entity_id: Uuid,
    kind: CredentialKind,
) -> Result<bool> {
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM credentials WHERE entity_id = $1 AND kind = $2 AND status = 'active'",
    )
    .bind(entity_id)
    .bind(kind)
    .fetch_one(pool)
    .await
    .context("failed to check existing bootstrap credential")?;
    Ok(count > 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_entities_with_credentials() {
        let yaml = r#"
entities:
  - id: 00000000-0000-0000-0000-000000000001
    kind: human
    name: admin
    attributes:
      role: admin
    credentials:
      - kind: password
        secret: change-me-please
  - id: 11111111-1111-1111-1111-111111111111
    kind: service
    name: ingest
    alias: ingest-svc
    credentials:
      - kind: shared_key
        key: super-secret-key
        description: ingest pipeline
"#;
        let cfg = parse(yaml).expect("parse");
        assert_eq!(cfg.entities.len(), 2);

        let admin = &cfg.entities[0];
        assert_eq!(admin.kind, EntityKind::Human);
        assert_eq!(admin.name, "admin");
        assert_eq!(admin.status, EntityStatus::Active);
        assert_eq!(
            admin.credentials,
            vec![BootstrapCredential::Password {
                secret: "change-me-please".to_string()
            }]
        );

        let svc = &cfg.entities[1];
        assert_eq!(svc.kind, EntityKind::Service);
        assert_eq!(svc.alias.as_deref(), Some("ingest-svc"));
        assert_eq!(
            svc.credentials,
            vec![BootstrapCredential::SharedKey {
                key: "super-secret-key".to_string(),
                description: Some("ingest pipeline".to_string()),
            }]
        );
    }

    #[test]
    fn empty_document_is_valid_and_empty() {
        let cfg = parse("entities: []").expect("parse");
        assert!(cfg.entities.is_empty());
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let yaml = r#"
entities:
  - id: 00000000-0000-0000-0000-000000000001
    kind: human
    name: admin
    typo_field: oops
"#;
        assert!(parse(yaml).is_err(), "unknown field should be rejected");
    }

    #[test]
    fn duplicate_entity_ids_are_rejected() {
        let yaml = r#"
entities:
  - id: 00000000-0000-0000-0000-000000000001
    kind: human
    name: admin
  - id: 00000000-0000-0000-0000-000000000001
    kind: human
    name: admin-two
"#;
        let err = parse(yaml).expect_err("duplicate ids");
        assert!(err.to_string().contains("duplicate bootstrap entity id"));
    }

    #[test]
    fn shared_key_on_human_is_rejected() {
        let yaml = r#"
entities:
  - id: 00000000-0000-0000-0000-000000000001
    kind: human
    name: admin
    credentials:
      - kind: shared_key
        key: nope
"#;
        let err = parse(yaml).expect_err("human shared key");
        assert!(err.to_string().contains("shared keys are only valid"));
    }

    #[test]
    fn multiple_passwords_per_entity_are_rejected() {
        let yaml = r#"
entities:
  - id: 00000000-0000-0000-0000-000000000001
    kind: human
    name: admin
    credentials:
      - kind: password
        secret: one-secret
      - kind: password
        secret: two-secret
"#;
        let err = parse(yaml).expect_err("two passwords");
        assert!(err.to_string().contains("more than one password"));
    }

    #[test]
    fn non_object_attributes_are_rejected() {
        let yaml = r#"
entities:
  - id: 00000000-0000-0000-0000-000000000001
    kind: human
    name: admin
    attributes: "not-an-object"
"#;
        let err = parse(yaml).expect_err("scalar attributes");
        assert!(err.to_string().contains("must be a JSON object"));
    }
}
