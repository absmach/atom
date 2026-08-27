//! Pure key-naming functions. Namespaced `atom:v1:` so an incompatible future
//! payload-shape change can roll out as `atom:v2:` without needing a flush.

use uuid::Uuid;

const NAMESPACE: &str = "atom:v1";

pub fn session(session_id: Uuid) -> String {
    format!("{NAMESPACE}:session:{session_id}")
}

pub fn entity_status(entity_id: Uuid) -> String {
    format!("{NAMESPACE}:entity_status:{entity_id}")
}

pub fn tenant_status(tenant_id: Uuid) -> String {
    format!("{NAMESPACE}:tenant_status:{tenant_id}")
}

pub fn credential(credential_id: Uuid) -> String {
    format!("{NAMESPACE}:credential:{credential_id}")
}

pub fn cred_ceiling(credential_id: Uuid) -> String {
    format!("{NAMESPACE}:cred_ceiling:{credential_id}")
}

pub fn grants(subject_id: Uuid) -> String {
    format!("{NAMESPACE}:grants:{subject_id}")
}
