//! Small helpers for domain repositories that write native SQL per backend
//! (see `product-docs/development/database-backends/REPOSITORY-PATTERN.md`)
//! instead of going through the [`super::translate`] compatibility layer.
//! This is deliberately thin: encoding conventions shared by every SQLite
//! adapter, not a query-building API.

use uuid::Uuid;

/// Encodes `ids` the same way SQLite stores a UUID array column: a JSON array
/// of lower-case 32-hex `.simple()` strings (no hyphens). Bind this as the
/// parameter of an `id IN (SELECT unhex(value) FROM json_each($1))` filter, or
/// of `NULLIF(instr($1, lower(hex(id))), 0)` to recover the caller's ordering
/// (`instr` position is monotonic with array index because every element is
/// the same fixed width). Kept in sync with `crate::db::arg`'s `UuidArray`
/// encoding so a native SQLite adapter's wire format matches the general
/// query layer's.
pub fn uuid_array_json(ids: &[Uuid]) -> String {
    let simple: Vec<String> = ids.iter().map(|id| id.simple().to_string()).collect();
    serde_json::to_string(&simple).expect("a vec of strings always serializes")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_as_a_json_array_of_simple_hex_strings() {
        let a = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
        let b = Uuid::parse_str("11111111-2222-3333-4444-555555555555").unwrap();
        assert_eq!(
            uuid_array_json(&[a, b]),
            r#"["00000000000000000000000000000001","11111111222233334444555555555555"]"#
        );
        assert_eq!(uuid_array_json(&[]), "[]");
    }
}
