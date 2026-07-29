//! Cache-transport DTOs. Deliberately distinct from the DB row models in
//! `crate::models` — each holds only the fields its read path actually needs,
//! never a full row dump, and never a plaintext secret.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::models::enums::{CredentialStatus, EntityStatus, TenantStatus};

/// The current SQL check backing `auth_from_jwt` verifies both the session id
/// *and* that it belongs to the claimed entity (`WHERE s.id = $1 AND
/// s.entity_id = $2`). `entity_id` is carried here so a cache hit can
/// re-verify that same invariant against the JWT's `sub` claim, rather than
/// trusting the key lookup alone.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionCacheEntry {
    pub entity_id: Uuid,
    pub revoked_at: Option<DateTime<Utc>>,
    pub expires_at: DateTime<Utc>,
}

/// Shared between JWT and API-key authentication — one entity deactivation
/// invalidates both paths' view of the entity at once.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityStatusCacheEntry {
    pub status: EntityStatus,
    pub deleted_at: Option<DateTime<Utc>>,
    pub tenant_id: Option<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantStatusCacheEntry {
    pub status: TenantStatus,
    pub deleted_at: Option<DateTime<Utc>>,
}

/// Never carries the plaintext API-key secret — only what
/// `auth_from_api_key`'s existing verification step consumes.
///
/// Deliberately has no `tenant_id` field: a credential's tenant is really the
/// owning entity's tenant, which can change (entity moved to another tenant)
/// independently of this entry ever being invalidated. A duplicated copy here
/// would go stale on that move with nothing to invalidate it, and
/// `auth_from_api_key` would have no way to know. Always read tenant context
/// from the entity's own `EntityStatusCacheEntry` instead, which *is*
/// invalidated on a tenant move.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialCacheEntry {
    pub entity_id: Uuid,
    pub status: CredentialStatus,
    pub secret_hash: Option<String>,
    pub secret_lookup_hash: Option<Vec<u8>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub scoped: bool,
}
