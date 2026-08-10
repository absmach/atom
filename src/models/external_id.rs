//! Entity `external_id` normalization.
//!
//! An `external_id` is an identifier assigned outside Atom — a serial number, a
//! MAC address, an employee number, a SKU. It is a foreign key into someone
//! else's namespace, so Atom stores, indexes and enforces uniqueness on it but
//! never interprets it. There is deliberately **no format validation**:
//! uppercase, `/`, `.`, interior spaces, embedded quotes and unicode are all
//! valid. Consumers may impose their own rules (Magistrala rejects `/` because
//! the value travels verbatim in a topic) — that is the consumer's rule, not
//! Atom's.
//!
//! Contrast with [`crate::models::alias`], which is the opposite trade: a
//! human-friendly handle Atom owns and constrains to a lowercase slug.
//!
//! Two normalization decisions are fixed here and mirrored by CHECK constraints
//! in `migrations/006_entity_external_id.sql`:
//!
//! * **Case-sensitive.** `ABC123` and `abc123` are two different entities. The
//!   value is never case-folded. Vendor schemes may legitimately distinguish
//!   case, and folding would silently merge two physical devices into one row
//!   with no way back.
//! * **Trimmed.** `"ABC123 "` and `"ABC123"` are the same entity. Leading and
//!   trailing whitespace is a transport artifact (a trailing newline off a
//!   serial console, a padded CSV cell), never data. Interior whitespace is
//!   preserved.

use crate::error::AppError;
use serde::{Deserialize, Deserializer};

/// Sanity cap, in characters (not bytes — matching Postgres `length()`). Not a
/// format rule: a btree index entry over a multi-kilobyte value is pathological,
/// and 255 is far beyond any real serial, MAC or SKU.
pub const MAX_EXTERNAL_ID_LEN: usize = 255;

fn trim_external_id(external_id: Option<String>) -> Option<String> {
    external_id
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

/// Trim an external identifier for storage or lookup. Whitespace-only (and
/// empty) input is absent, not a value. Case is preserved.
///
/// This is the lookup-side normalization: it never fails, so an invalid filter
/// value simply matches nothing instead of erroring.
pub fn normalize_external_id(external_id: Option<String>) -> Option<String> {
    trim_external_id(external_id).map(|value| {
        if value.contains('\0') {
            "x".repeat(MAX_EXTERNAL_ID_LEN + 1)
        } else {
            value
        }
    })
}

/// Normalize an optional external identifier for a write, enforcing the length
/// cap. Empty/whitespace-only is treated as absent (`None`).
pub fn validate_external_id_opt(external_id: Option<String>) -> Result<Option<String>, AppError> {
    let external_id = trim_external_id(external_id);
    if let Some(value) = external_id.as_deref() {
        if value.chars().count() > MAX_EXTERNAL_ID_LEN {
            return Err(AppError::bad_request(format!(
                "externalId must be at most {MAX_EXTERNAL_ID_LEN} characters"
            )));
        }
        // Not format validation — a physical limit of the storage type. A
        // Postgres `TEXT` value cannot contain a NUL byte under any encoding, so
        // this is unstorable rather than disallowed. Rejecting it here turns an
        // opaque `22021 invalid byte sequence` 500 into a message the caller can
        // act on.
        if value.contains('\0') {
            return Err(AppError::bad_request(
                "externalId must not contain a NUL byte",
            ));
        }
    }
    Ok(external_id)
}

/// Validate an optional external-identifier update while preserving patch
/// semantics: `None` leaves the field unchanged, `Some(None)` clears it, and
/// `Some(Some(value))` stores the normalized value.
pub fn validate_external_id_update(
    external_id: Option<Option<String>>,
) -> Result<Option<Option<String>>, AppError> {
    external_id.map(validate_external_id_opt).transpose()
}

/// Serde helper for PATCH-style `external_id` fields. A missing field remains
/// `None`, explicit JSON `null` becomes `Some(None)`, and a string becomes
/// `Some(Some(value))`.
pub fn deserialize_external_id_update<'de, D>(
    deserializer: D,
) -> Result<Option<Option<String>>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer).map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_arbitrary_opaque_values() {
        // No format validation: the shapes `alias` rejects are all valid here.
        for value in [
            "WM-2024-ABC.123",
            "00:1B:44:11:3A:B7",
            "topic/with/slashes",
            "serial with spaces",
            "quote's \"embedded\"",
            "序列号-42",
            "465358f9-07f4-4ea0-8cbb-2abc654442bd",
        ] {
            assert_eq!(
                validate_external_id_opt(Some(value.to_string())).unwrap(),
                Some(value.to_string()),
                "{value} must round-trip unchanged"
            );
        }
    }

    #[test]
    fn is_case_sensitive() {
        // The one-way door: never case-folded, unlike `alias`.
        assert_eq!(
            validate_external_id_opt(Some("ABC123".into())).unwrap(),
            Some("ABC123".to_string())
        );
        assert_eq!(
            validate_external_id_opt(Some("abc123".into())).unwrap(),
            Some("abc123".to_string())
        );
    }

    #[test]
    fn trims_edges_but_not_interior() {
        assert_eq!(
            validate_external_id_opt(Some("  ABC123  ".into())).unwrap(),
            Some("ABC123".to_string())
        );
        assert_eq!(
            validate_external_id_opt(Some("\tABC123\n".into())).unwrap(),
            Some("ABC123".to_string())
        );
        assert_eq!(
            validate_external_id_opt(Some(" A B C ".into())).unwrap(),
            Some("A B C".to_string())
        );
    }

    #[test]
    fn blank_is_absent() {
        assert_eq!(validate_external_id_opt(None).unwrap(), None);
        assert_eq!(validate_external_id_opt(Some("".into())).unwrap(), None);
        assert_eq!(validate_external_id_opt(Some("   ".into())).unwrap(), None);
    }

    #[test]
    fn enforces_length_cap_in_characters() {
        let at_cap = "é".repeat(MAX_EXTERNAL_ID_LEN);
        assert_eq!(
            validate_external_id_opt(Some(at_cap.clone())).unwrap(),
            Some(at_cap)
        );

        let over_cap = "x".repeat(MAX_EXTERNAL_ID_LEN + 1);
        let err = validate_external_id_opt(Some(over_cap)).expect_err("over-cap must be rejected");
        assert!(
            matches!(err, AppError::BadRequest(ref msg) if msg.contains("255")),
            "expected an actionable length error, got {err:?}"
        );
    }

    #[test]
    fn length_cap_applies_after_trimming() {
        let padded = format!("  {}  ", "x".repeat(MAX_EXTERNAL_ID_LEN));
        assert!(
            validate_external_id_opt(Some(padded)).is_ok(),
            "padding must not push a legal value over the cap"
        );
    }

    #[test]
    fn update_preserves_undefined_clear_and_value_states() {
        assert_eq!(validate_external_id_update(None).unwrap(), None);
        assert_eq!(validate_external_id_update(Some(None)).unwrap(), Some(None));
        assert_eq!(
            validate_external_id_update(Some(Some(" WM-2024 ".into()))).unwrap(),
            Some(Some("WM-2024".to_string()))
        );
    }

    #[test]
    fn rejects_the_one_byte_text_cannot_hold() {
        let err = validate_external_id_opt(Some("ab\0cd".into()))
            .expect_err("a NUL byte is unstorable in a TEXT column");
        assert!(
            matches!(err, AppError::BadRequest(ref msg) if msg.contains("NUL")),
            "expected an actionable NUL error, got {err:?}"
        );
    }

    #[test]
    fn normalize_never_fails_for_lookups() {
        let over_cap = "x".repeat(MAX_EXTERNAL_ID_LEN + 1);
        assert_eq!(
            normalize_external_id(Some(over_cap.clone())),
            Some(over_cap),
            "an over-long filter must match nothing, not error"
        );
        assert_eq!(
            normalize_external_id(Some("ab\0cd".into())),
            Some("x".repeat(MAX_EXTERNAL_ID_LEN + 1)),
            "a NUL-bearing filter must match nothing without binding a NUL to Postgres"
        );
        assert_eq!(normalize_external_id(Some("  ".into())), None);
    }

    #[test]
    fn patch_deserialization_distinguishes_missing_null_and_value() {
        #[derive(Deserialize)]
        struct Patch {
            #[serde(default, deserialize_with = "deserialize_external_id_update")]
            external_id: Option<Option<String>>,
        }

        assert_eq!(
            serde_json::from_str::<Patch>("{}").unwrap().external_id,
            None
        );
        assert_eq!(
            serde_json::from_str::<Patch>(r#"{"external_id":null}"#)
                .unwrap()
                .external_id,
            Some(None)
        );
        assert_eq!(
            serde_json::from_str::<Patch>(r#"{"external_id":"WM-1"}"#)
                .unwrap()
                .external_id,
            Some(Some("WM-1".to_string()))
        );
    }
}
